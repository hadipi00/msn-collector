#!/usr/bin/env bash
# MSN Collector — idempotent operations entry point. Safe to run any time.
# 1) starts the 2h scheduler daemon if not already alive (catch-up runs at once
#    when the last cycle is stale — e.g. right after a sandbox reset)
# 2) restores the outlinekeys page cache from the remote "cache" branch
# 3) re-launches the outlinekeys full harvester when cache coverage is incomplete
# 4) pushes a cache snapshot to the "cache" branch after harvests (fast-forward)
set -u
cd "$(dirname "$0")"
REPO="$PWD"

# ---------- 1) scheduler daemon ----------
pid=$(cat .scheduler.pid 2>/dev/null || echo 0)
if [ "$pid" != "0" ] && ps -p "$pid" -o cmd= 2>/dev/null | grep -q "scheduler.sh"; then
  echo "[ensure] scheduler alive (pid $pid)"
else
  python3 launch_daemon.py >/dev/null 2>&1
  sleep 1
  pid=$(cat .scheduler.pid 2>/dev/null || echo 0)
  echo "[ensure] scheduler started (pid $pid)"
fi

# ---------- 2) restore outlinekeys cache after a reset ----------
CACHE=outlinekeys_cache.json
if [ ! -f "$CACHE" ]; then
  if git fetch -q origin cache 2>/dev/null && git cat-file -p FETCH_HEAD:"$CACHE" > "$CACHE" 2>/dev/null; then
    echo "[ensure] outlinekeys cache restored from remote cache branch ($(stat -c%s "$CACHE") bytes)"
  else
    echo "[ensure] no remote cache branch — harvester will build the cache from scratch"
  fi
fi

# ---------- 3) relaunch full harvester if needed ----------
if [ -f outlinekeys_harvest.lock ]; then
  echo "[ensure] outlinekeys harvest already running (pid $(cat outlinekeys_harvest.lock))"
else
  python3 launch_harvest.py >/dev/null 2>&1
  echo "[ensure] harvest check launched (exits quickly if cache is complete)"
fi

# ---------- 4) push cache snapshot when it grew >10% since last push ----------
if [ -f "$CACHE" ] && [ ! -f outlinekeys_harvest.lock ]; then
  pushed=$(cat .cache_pushed_size 2>/dev/null || echo 0)
  size=$(stat -c%s "$CACHE")
  if [ "$size" -gt $(( pushed + pushed / 10 + 200000 )) ]; then
    tmpd=$(mktemp -d)
    if git clone -q "$REPO" "$tmpd/push" 2>/dev/null; then
      (
        cd "$tmpd/push"
        git checkout -q origin/cache 2>/dev/null || git checkout -q --orphan _cachepush
        git rm -rq --cached . 2>/dev/null
        cp "$REPO/$CACHE" .
        git add -f "$CACHE"
        git commit -qm "outlinekeys cache snapshot $(date -u '+%F %T') UTC"
        git push -q origin HEAD:cache
      ) >/dev/null 2>&1 && echo "$size" > .cache_pushed_size && \
        echo "[ensure] cache branch updated ($size bytes)"
    fi
    rm -rf "$tmpd"
  fi
fi
