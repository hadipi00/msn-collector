#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MSN Plain Proxy Collector — HTTP / SOCKS4 / SOCKS5 from publicvpnlist.com
=========================================================================
- Downloads the official, registration-free exports of publicvpnlist.com:
      /proxies/export.php?format=json&protocol=http|socks4|socks5
  (JSON records carry protocol, ip, port, country, latency and check time)
- Dedupes, then TCP alive-checks every proxy (same pattern as mtproto_collector)
- Writes plain_http.txt / plain_socks4.txt / plain_socks5.txt / plain_all.txt
  plus plain_all.csv (country + latency metadata) / plain_stats.json
  / plain_last_update.txt
- Pure Python 3 stdlib — no external dependencies.

Note: publicvpnlist.com also serves VPN datasets (OpenVPN, VLESS, Trojan,
VMess, Shadowsocks, Hysteria2, TUIC, WireGuard, IKEv2) but those are gated
behind a 24-hour reCAPTCHA key, so they cannot be fetched unattended; only
the free proxy exports are automated here.
"""
import asyncio
import csv
import json
import os
import socket
import time
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))

ALIVE_TIMEOUT = 4.0      # seconds for TCP connect check
CHECK_CONCURRENCY = 500  # parallel alive checks
FETCH_TIMEOUT = 40       # seconds per export download
MAX_TEST = 20000         # safety cap on unique proxies tested per run

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

PROTOCOLS = ("http", "socks4", "socks5")
EXPORT_URL = ("https://publicvpnlist.com/proxies/export.php"
              "?format=json&protocol={proto}")

HTTP_FILE = "plain_http.txt"
SOCKS4_FILE = "plain_socks4.txt"
SOCKS5_FILE = "plain_socks5.txt"
ALL_FILE = "plain_all.txt"
CSV_FILE = "plain_all.csv"
STATS_FILE = "plain_stats.json"
LASTUPD_FILE = "plain_last_update.txt"


# ---------------------------------------------------------------- fetching

def _fetch_json(proto):
    url = EXPORT_URL.format(proto=proto)
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
        data = json.loads(r.read().decode("utf-8", "replace"))
    return data


def fetch_all_protocols():
    """Fetch publicvpnlist JSON exports -> {proto: [record, ...]}."""
    out = {}
    for proto in PROTOCOLS:
        try:
            data = _fetch_json(proto)
            records = data.get("proxies") or []
            gen = data.get("generated_at", "")
            out[proto] = records
            print(f"[+] publicvpnlist {proto}: {len(records)} records "
                  f"(generated {gen})")
        except Exception as e:
            out[proto] = []
            print(f"[x] publicvpnlist {proto} fetch failed: "
                  f"{type(e).__name__}: {e}")
    return out


# ---------------------------------------------------------------- parsing

def _normalize(records, proto):
    """JSON records -> proxy dicts with a canonical 'link' field."""
    out = []
    for r in records:
        try:
            ip = str(r["ip"]).strip()
            port = int(r["port"])
        except (KeyError, TypeError, ValueError):
            continue
        if not ip or not (0 < port < 65536) or "/" in ip:
            continue
        out.append({
            "kind": proto,
            "server": ip,
            "port": port,
            "country": str(r.get("country_code") or "").strip() or None,
            "latency_ms": r.get("latency_ms"),
            "checked_at": r.get("checked_at"),
            "https_ok": bool(r.get("https_ok")),
            "link": f"{proto}://{ip}:{port}",
        })
    return out


def dedupe(proxies):
    seen, out = set(), []
    for p in proxies:
        key = (p["kind"], p["server"].lower(), p["port"])
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


# ------------------------------------------------------------- alive check

async def _check(server, port, sem):
    async with sem:
        w = None
        try:
            w = await asyncio.wait_for(
                asyncio.open_connection(server, port), timeout=ALIVE_TIMEOUT)
            return True
        except Exception:
            return False
        finally:
            if w:
                try:
                    w.close()
                    await asyncio.wait_for(w.wait_closed(), timeout=1.0)
                except Exception:
                    pass


def run_alive_checks(proxies):
    pairs = {}
    for p in proxies:
        pairs.setdefault((p["server"], p["port"]), False)
    sem = asyncio.Semaphore(CHECK_CONCURRENCY)

    async def run():
        keys = list(pairs.keys())
        total = len(keys)
        print(f"[i] alive-check on {total} unique server:port "
              f"(timeout {ALIVE_TIMEOUT}s, x{CHECK_CONCURRENCY})")
        t0 = time.time()
        results = []
        BATCH = 2000
        for i in range(0, len(keys), BATCH):
            chunk = [_check(h, p, sem) for h, p in keys[i:i + BATCH]]
            results.extend(await asyncio.gather(*chunk))
            el = time.time() - t0
            print(f"    ... {min(i + BATCH, total)}/{total} checked "
                  f"({min(i + BATCH, total) / max(el, 0.001):.0f}/s, {el:.0f}s)")
        for (h, p), ok in zip(keys, results):
            pairs[(h, p)] = ok
        return pairs

    return asyncio.run(run())


# ---------------------------------------------------------------- outputs

def write_outputs(alive, meta):
    for f in [HTTP_FILE, SOCKS4_FILE, SOCKS5_FILE, ALL_FILE, CSV_FILE,
              STATS_FILE, LASTUPD_FILE]:
        p = os.path.join(ROOT, f)
        if os.path.exists(p):
            os.remove(p)
    by_kind = {}
    for p in alive:
        by_kind.setdefault(p["kind"], []).append(p)
    for proto, fname in [("http", HTTP_FILE), ("socks4", SOCKS4_FILE),
                         ("socks5", SOCKS5_FILE)]:
        links = [p["link"] for p in by_kind.get(proto, [])]
        if links:
            with open(os.path.join(ROOT, fname), "w", encoding="utf-8") as f:
                f.write("\n".join(links) + "\n")
    all_links = [p["link"] for p in alive]
    with open(os.path.join(ROOT, ALL_FILE), "w", encoding="utf-8") as f:
        f.write("\n".join(all_links) + "\n")
    with open(os.path.join(ROOT, CSV_FILE), "w", encoding="utf-8",
              newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["protocol", "ip", "port", "country", "latency_ms",
                     "source_checked_at", "alive_check"])
        for p in alive:
            wr.writerow([p["kind"], p["server"], p["port"],
                         p.get("country") or "", p.get("latency_ms") or "",
                         p.get("checked_at") or "", "tcp-connect-ok"])
    with open(os.path.join(ROOT, LASTUPD_FILE), "w", encoding="utf-8") as f:
        f.write(meta["last_update"] + "\n")
    with open(os.path.join(ROOT, STATS_FILE), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)


# -------------------------------------------------------------------- main

def main():
    t0 = time.time()
    print("=" * 60)
    print("MSN Plain Proxy Collector started (publicvpnlist.com)")
    fetched = fetch_all_protocols()
    raw = []
    for proto, records in fetched.items():
        raw.extend(_normalize(records, proto))
    uniq = dedupe(raw)
    uniq = uniq[:MAX_TEST]
    dups = len(raw) - len(uniq)
    print(f"[i] raw: {len(raw)} | duplicates removed: {dups} | unique: {len(uniq)}")
    if not uniq:
        print("[!] nothing parsed — aborting (keeping previous outputs)")
        return 1

    pairs = run_alive_checks(uniq)
    alive = [p for p in uniq if pairs.get((p["server"], p["port"]))]
    by_kind = {}
    for p in alive:
        by_kind[p["kind"]] = by_kind.get(p["kind"], 0) + 1
    print("[i] ALIVE by kind:")
    for k in PROTOCOLS:
        print(f"    {k:<8} {by_kind.get(k, 0)}")
    print(f"[i] total alive: {len(alive)} / {len(uniq)} tested")
    if not alive:
        print("[!] no alive proxies — keeping previous outputs")
        return 1

    meta = {
        "last_update": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "duration_sec": round(time.time() - t0, 1),
        "source": "publicvpnlist.com official proxy exports (free)",
        "raw_records": len(raw), "unique_tested": len(uniq),
        "duplicates_removed": dups, "alive_proxies": len(alive),
        "kinds": by_kind,
    }
    write_outputs(alive, meta)
    print(f"[i] outputs written in {meta['duration_sec']}s "
          f"({ALL_FILE}, {CSV_FILE}, per-kind .txt, {STATS_FILE})")
    return 0


if __name__ == "__main__":
    sys_exit = main()
    raise SystemExit(sys_exit)
