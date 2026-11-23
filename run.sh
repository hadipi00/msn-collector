#!/usr/bin/env bash
# MSN Collector (ALL-IN-ONE repo) — one update cycle:
# pull user edits of sources.txt/channels.txt -> run ALL collectors -> push snapshot
#   1) collector.py            — V2Ray/Xray subscription collector (sources.txt)
#   2) mtproto_collector.py    — MTProto/SOCKS proxies (channels.txt + proxybolt.link) + WireGuard
#   3) openvpn_collector.py    — OpenVPN .ovpn configs (openvpn_channels.txt + VPNBook)
#   4) plain_proxy_collector.py— HTTP/SOCKS4/SOCKS5 (publicvpnlist.com exports)
# Strategy: NORMAL push always (guaranteed freshness), then best-effort
# history collapse to a single commit (needs Force Push enabled in repo settings).
set -e
cd "$(dirname "$0")"

# pick up user edits (sources.txt / channels.txt) made via GitHub web UI
git pull --rebase --autostash origin main

python3 collector.py || echo "[run.sh] V2Ray collector FAILED — keeping previous outputs"
python3 mtproto_collector.py || echo "[run.sh] MTProto/WireGuard collector FAILED — keeping previous outputs"
python3 openvpn_collector.py || echo "[run.sh] OpenVPN collector FAILED — keeping previous outputs"
python3 plain_proxy_collector.py || echo "[run.sh] plain-proxy collector FAILED — keeping previous outputs"

git add -f outlinekeys_cache.json 2>/dev/null || true
git add -A
if git diff --cached --quiet; then
  echo "[run.sh] no changes to push"
  exit 0
fi

git commit -q -m "auto-update: $(date -u '+%Y-%m-%d %H:%M') UTC"
git push -q origin main
echo "[run.sh] PUSHED OK (normal)"

# best-effort: collapse history to a single snapshot commit (repo size stays constant)
if git checkout --orphan _snapshot -q; then
  git add -A
  git commit -q -m "auto-update: $(date -u '+%Y-%m-%d %H:%M') UTC"
  if git push --force -q origin _snapshot:main 2>/dev/null; then
    git fetch -q origin
    git checkout -f -q -B main origin/main
    git branch -D _snapshot -q
    echo "[run.sh] history collapsed to single commit"
  else
    git checkout -f -q main
    git branch -D _snapshot -q
    echo "[run.sh] collapse skipped (force push not permitted on this remote — keeping full history)"
  fi
fi
