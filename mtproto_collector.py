#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MSN MTProto Collector — Telegram MTProto / SOCKS5 proxy + WireGuard collector
=============================================================================
- Reads Telegram channels from channels.txt (one @channel per line, '#' = comment)
- Scrapes public channel previews https://t.me/s/<name> (paginated)
- Fetches MTProto proxies from the proxybolt.link web API (paginated, all pages)
- Extracts tg://proxy (MTProto) and tg://socks (SOCKS5) links — any param order,
  plus t.me/proxy, t.me/socks and socks5:// URI variants
- Also reads wireguard_channels.txt and extracts WireGuard configs
  ([Interface]/[Peer] blocks incl. AmneziaWG + wireguard:// URIs)
- Dedupes, TCP alive-checks MTProto/SOCKS servers (WG is UDP — no TCP check)
- Writes mtproto.txt / socks.txt / all.txt + wireguard.txt / _b64 / _conf
- Names WG configs @mehdisedighinasab-N-🇩🇪DE (GeoIP via local geoip.py)
- Annotates channels.txt + wireguard_channels.txt with per-channel counts
Pure Python 3 stdlib — no external dependencies.
"""
import asyncio
import base64
import hashlib
import html
import json
import os
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.abspath(__file__))
CHANNELS_FILE = os.path.join(ROOT, "channels.txt")
WG_CHANNELS_FILE = os.path.join(ROOT, "wireguard_channels.txt")
sys.path.insert(0, ROOT)
import geoip  # local module — country lookup for config naming

ALIVE_TIMEOUT = 4.0      # seconds for TCP connect check
CHECK_CONCURRENCY = 500  # parallel alive checks
FETCH_WORKERS = 6        # parallel channel fetches
FETCH_TIMEOUT = 20       # seconds per page download
PAGES_PER_CHANNEL = 8    # each preview page shows ~20 recent posts
PAGE_DELAY = 0.4         # politeness delay between pages of the same channel
MAX_TEST = 20000         # safety cap on unique proxies tested per run
PROXYBOLT_PAGES = 150    # safety cap: proxybolt.link API pages (15 proxies each)
PROXYBOLT_DELAY = 0.3    # politeness delay between proxybolt API pages

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# NOTE: lives inside the msn-collector repo together with collector.py —
# output filenames are prefixed (mtproto_* / wireguard*) so they never
# collide with the V2Ray collector's all.txt / stats.json / last_update.txt
MTPROTO_FILE = "mtproto.txt"          # alive MTProto proxies, tg://proxy links
SOCKS_FILE = "mtproto_socks.txt"      # alive SOCKS5 proxies, tg://socks links
ALL_FILE = "mtproto_all.txt"          # both kinds combined
WG_FILE = "wireguard.txt"             # wireguard:// URIs (Hiddify / v2rayNG import)
WG_B64_FILE = "wireguard_b64.txt"
WG_CONF_FILE = "wireguard_conf.txt"   # raw .conf blocks (WireGuard app)
STATS_FILE = "mtproto_stats.json"
LASTUPD_FILE = "mtproto_last_update.txt"

NAMING_PREFIX = "@mehdisedighinasab"   # WG configs named PREFIX-N-<flag><CC>

NAME_RE = re.compile(r"^[A-Za-z0-9_]{3,64}$")
TME_RE = re.compile(r"^(?:https?://)?t\.me/([A-Za-z0-9_]+)/?$")
QUERY_PATTERNS = [
    (re.compile(r"tg://proxy\?([^\s\"<>]+)"), "mtproto"),
    (re.compile(r"t\.me/proxy\?([^\s\"<>]+)"), "mtproto"),
    (re.compile(r"tg://socks\?([^\s\"<>]+)"), "socks"),
    (re.compile(r"t\.me/socks\?([^\s\"<>]+)"), "socks"),
]
SOCKS5_RE = re.compile(
    r"socks5://(?:([^:@/\s\"<>]+):([^@/\s\"<>]+)@)?([A-Za-z0-9_.\-\[\]]+):(\d+)")
SECRET_RE = re.compile(r"^[A-Za-z0-9_\-]{16,}$")
SERVER_RE = re.compile(r"^[A-Za-z0-9_.\-\[\]]+$")

# --- WireGuard ---
WG_URI_RE = re.compile(
    r"wireguard://([A-Za-z0-9+/=_\-]+)@([A-Za-z0-9_.\-\[\]]+):(\d+)\?([^\s\"<>#]*)")
WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
WG_AMNEZIA = {"jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
              "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"}


# ---------------------------------------------------------------- channels

def load_channels(path=None):
    """Parse a channels file -> ordered unique channel names (inline # comments ok)."""
    path = path or CHANNELS_FILE
    names = []
    if not os.path.exists(path):
        print(f"[!] channels file not found at {path}")
        return names
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            m = TME_RE.match(line)
            name = m.group(1) if m else line.lstrip("@").strip()
            if NAME_RE.match(name) and name not in names:
                names.append(name)
    return names


def annotate_channels(stats, path=None, noun="proxies"):
    """Rewrite a channels file, appending/refreshing ' # N <noun>, M live' after
    each channel line. Blank lines and '#' comments are preserved."""
    path = path or CHANNELS_FILE
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as e:
        print(f"[!] annotate_channels: cannot read {path}: {e}")
        return
    out, changed = [], False
    for line in lines:
        s = line.split("#", 1)[0].strip()
        if not s:
            out.append(line)
            continue
        m = TME_RE.match(s)
        name = m.group(1) if m else s.lstrip("@").strip()
        st = stats.get(name)
        if st is None:
            out.append(line)
            continue
        if "error" in st:
            tag = "fetch failed"
        elif "alive" in st:
            tag = f"{st.get('total', 0)} {noun}, {st['alive']} live"
        else:
            tag = f"{st.get('total', 0)} {noun}"
        new = f"@{name}  # {tag}"
        if new != line.rstrip():
            changed = True
        out.append(new)
    if changed:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        os.replace(tmp, path)
        print("[i] channels.txt annotated with per-channel proxy counts")


# ---------------------------------------------------------------- fetching

def _fetch_page(url):
    req = urllib.request.Request(
        url, headers={"User-Agent": UA, "Accept-Language": "en"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
        return r.read().decode("utf-8", "replace")


def fetch_channel(name):
    """Return unescaped HTML of up to PAGES_PER_CHANNEL recent preview pages."""
    pages, before = [], None
    for _ in range(PAGES_PER_CHANNEL):
        url = f"https://t.me/s/{name}" + (f"?before={before}" if before else "")
        try:
            text = _fetch_page(url)
        except Exception:
            break
        pages.append(html.unescape(text))
        ids = [int(i) for i in re.findall(r'data-post="[^"]+/(\d+)"', text)]
        if not ids:
            break
        before = min(ids)
        if len(ids) < 5:      # reached the beginning of the channel
            break
        time.sleep(PAGE_DELAY)
    return pages


def fetch_all(names):
    def work(name):
        try:
            pages = fetch_channel(name)
            return name, pages, None if pages else "no pages fetched"
        except Exception as e:
            return name, [], f"{type(e).__name__}: {e}"
    with ThreadPoolExecutor(FETCH_WORKERS) as ex:
        return list(ex.map(work, names))


def fetch_proxybolt():
    """Fetch MTProto proxies from the proxybolt.link web API (paginated).

    GET https://proxybolt.link/api/proxies?platform=all&offset=N&locale=en
    returns {"html": ..., "next": <offset>, "done": <bool>}; the HTML contains
    data-copy="tg://proxy?server=...&port=...&secret=..." attributes which are
    parsed with the same QUERY_PATTERNS used for channel posts.
    """
    out, offset, pages = [], 0, 0
    while pages < PROXYBOLT_PAGES:
        url = ("https://proxybolt.link/api/proxies?platform=all"
               f"&offset={offset}&locale=en")
        try:
            data = json.loads(_fetch_page(url))
        except Exception as e:
            print(f"    [x] proxybolt page {pages + 1} failed: "
                  f"{type(e).__name__}: {e}")
            break
        text = html.unescape(data.get("html", ""))
        got = extract_from_pages([text])
        out.extend(got)
        pages += 1
        if data.get("done") or not got:
            break
        try:
            nxt = int(data.get("next"))
        except (TypeError, ValueError):
            break
        if nxt <= offset:
            break
        offset = nxt
        time.sleep(PROXYBOLT_DELAY)
    if pages:
        print(f"[i] proxybolt.link: {pages} pages fetched")
    return out


# ---------------------------------------------------------------- parsing

def _build(kind, server, port, secret="", user="", pw=""):
    server = server.strip().strip(".,;:)]")
    if not SERVER_RE.match(server) or not (0 < port < 65536):
        return None
    if kind == "mtproto":
        if not SECRET_RE.match(secret):
            return None
        link = f"tg://proxy?server={server}&port={port}&secret={secret}"
        return {"kind": "mtproto", "server": server, "port": port,
                "secret": secret, "link": link}
    link = f"tg://socks?server={server}&port={port}"
    if user or pw:
        link += (f"&user={urllib.parse.quote(user, safe='')}"
                 f"&pass={urllib.parse.quote(pw, safe='')}")
    return {"kind": "socks", "server": server, "port": port,
            "user": user, "pass": pw, "link": link}


def extract_from_pages(pages):
    """Extract MTProto + SOCKS proxies from unescaped t.me/s HTML pages."""
    out = []
    for text in pages:
        for pat, kind in QUERY_PATTERNS:
            for m in pat.finditer(text):
                q = m.group(1).rstrip(".,;:)]")
                try:
                    params = urllib.parse.parse_qs(q)
                except Exception:
                    continue
                if "server" not in params or "port" not in params:
                    continue
                try:
                    port = int(params["port"][0])
                except Exception:
                    continue
                p = _build(kind, params["server"][0], port,
                           secret=params.get("secret", [""])[0],
                           user=params.get("user", [""])[0],
                           pw=params.get("pass", [""])[0])
                if p:
                    out.append(p)
        for m in SOCKS5_RE.finditer(text):
            p = _build("socks", m.group(3), int(m.group(4)),
                       user=m.group(1) or "", pw=m.group(2) or "")
            if p:
                out.append(p)
    return out


def dedupe(proxies):
    seen, out = set(), []
    for p in proxies:
        key = (p["kind"], p["server"].lower(), p["port"],
               p.get("secret", ""), p.get("user", ""), p.get("pass", ""))
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


# ------------------------------------------------------------- wireguard

def _norm_wg_key(s):
    """Normalize a WG key to 44-char standard base64 (32 bytes)."""
    s = (s or "").strip()
    if not s:
        return ""
    try:
        pad = s + "=" * (-len(s) % 4)
        raw = base64.urlsafe_b64decode(pad)
    except Exception:
        return ""
    if len(raw) != 32:
        return ""
    return base64.b64encode(raw).decode()


def _b64url_nopad(b64_std):
    raw = base64.b64decode(b64_std)
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _html_to_text(text):
    t = re.sub(r"(?i)<br\s*/?>", "\n", text)
    t = re.sub(r"(?i)</p>|</blockquote>", "\n", t)
    t = re.sub(r"<[^>]+>", "", t)
    return t


def build_wg(priv, pub, host, port, address="", dns="", mtu="",
             psk="", allowed="", amnezia=None):
    priv = _norm_wg_key(priv)
    pub = _norm_wg_key(pub)
    if not priv or not pub:
        return None
    host = host.strip().strip(".,;:)]")
    if not SERVER_RE.match(host) or not (0 < port < 65536):
        return None
    return {"kind": "wireguard", "priv": priv, "pub": pub, "host": host,
            "port": port, "address": address.strip(), "dns": dns.strip(),
            "mtu": str(mtu).strip(), "psk": psk.strip(),
            "allowed": allowed.strip(), "amnezia": amnezia or {}}


def extract_wg_from_pages(pages):
    """Extract WireGuard configs from unescaped t.me/s HTML: both
    wireguard:// URIs and [Interface]/[Peer] .conf blocks (incl. AmneziaWG)."""
    out = []
    for text in pages:
        # a) wireguard:// URI form
        for m in WG_URI_RE.finditer(text):
            priv, host, port_s, q = m.groups()
            try:
                params = urllib.parse.parse_qs(q)
            except Exception:
                continue
            p = build_wg(priv, params.get("publicKey", [""])[0], host, int(port_s),
                         address=params.get("address", [""])[0],
                         dns=params.get("dns", [""])[0],
                         mtu=params.get("mtu", [""])[0])
            if p:
                out.append(p)
        # b) [Interface]/[Peer] conf blocks (strip <br/> and tags first)
        plain = _html_to_text(text)
        for m in re.finditer(r"\[Interface\][^\[]{0,6000}?\[Peer\][^\[]{0,4000}", plain, re.S):
            iface, peer, cur = {}, {}, None
            for line in m.group(0).splitlines():
                line = line.strip()
                if not line:
                    continue
                low = line.lower()
                if low.startswith("[interface]"):
                    cur = iface
                    continue
                if low.startswith("[peer]"):
                    cur = peer
                    continue
                if cur is None or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                cur[k.strip().lower()] = v.strip()
            if not iface:
                continue
            amnezia = {k: v for k, v in iface.items() if k in WG_AMNEZIA}
            endpoint = peer.get("endpoint", "")
            if ":" not in endpoint:
                continue
            host, _, port_s = endpoint.rpartition(":")
            try:
                port = int(port_s)
            except ValueError:
                continue
            p = build_wg(iface.get("privatekey", ""), peer.get("publickey", ""),
                         host, port, address=iface.get("address", ""),
                         dns=iface.get("dns", ""), mtu=iface.get("mtu", ""),
                         psk=peer.get("presharedkey", ""),
                         allowed=peer.get("allowedips", ""), amnezia=amnezia)
            if p:
                out.append(p)
    return out


def dedupe_wg(items):
    seen, out = set(), []
    for p in items:
        key = (p["host"].lower(), p["port"],
               hashlib.md5((p["priv"] + p["pub"]).encode()).hexdigest())
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def wg_conf_text(p, name):
    lines = [f"# {name}", "[Interface]", f"PrivateKey = {p['priv']}"]
    if p["address"]:
        lines.append(f"Address = {p['address']}")
    if p["dns"]:
        lines.append(f"DNS = {p['dns']}")
    if p["mtu"]:
        lines.append(f"MTU = {p['mtu']}")
    for k, v in p["amnezia"].items():   # AmneziaWG params, original case kept
        lines.append(f"{k} = {v}")
    lines += ["", "[Peer]", f"PublicKey = {p['pub']}"]
    if p["psk"]:
        lines.append(f"PresharedKey = {p['psk']}")
    if p["allowed"]:
        lines.append(f"AllowedIPs = {p['allowed']}")
    lines.append(f"Endpoint = {p['host']}:{p['port']}")
    return "\n".join(lines)


def wg_uri(p, name):
    q = [f"publicKey={_b64url_nopad(p['pub'])}"]
    if p["address"]:
        q.append("address=" + urllib.parse.quote(p["address"], safe=""))
    if p["dns"]:
        q.append("dns=" + urllib.parse.quote(p["dns"], safe=""))
    if p["mtu"]:
        q.append(f"mtu={p['mtu']}")
    if p["psk"]:
        q.append("presharedKey=" + _b64url_nopad(p["psk"]))
    return (f"wireguard://{_b64url_nopad(p['priv'])}@{p['host']}:{p['port']}"
            f"?{'&'.join(q)}#{urllib.parse.quote(name)}")


def wg_resolve_countries(wg_items):
    """Resolve each WG endpoint -> IP -> ISO code (threaded; few endpoints)."""
    def work(p):
        ip = geoip.resolve(p["host"])
        cc = geoip.country(ip) if ip else None
        return cc
    with ThreadPoolExecutor(24) as ex:
        for p, cc in zip(wg_items, ex.map(work, wg_items)):
            p["cc"] = cc
    return wg_items


def write_wg_outputs(wg_items, meta):
    """Number + country-name the WG configs and write the three output files."""
    uris, blocks = [], []
    for i, p in enumerate(wg_items):
        name = f"{NAMING_PREFIX}-{i + 1}"
        cc = p.get("cc")
        if cc:
            fl = geoip.flag(cc)
            if fl:
                name += f"-{fl}{cc.upper()}"
        uris.append(wg_uri(p, name))
        blocks.append(wg_conf_text(p, name))
    for f in [WG_FILE, WG_B64_FILE, WG_CONF_FILE]:
        fp = os.path.join(ROOT, f)
        if os.path.exists(fp):
            os.remove(fp)
    if uris:
        with open(os.path.join(ROOT, WG_FILE), "w", encoding="utf-8") as f:
            f.write("\n".join(uris) + "\n")
        with open(os.path.join(ROOT, WG_B64_FILE), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(uris).encode("utf-8", "replace")).decode() + "\n")
        with open(os.path.join(ROOT, WG_CONF_FILE), "w", encoding="utf-8") as f:
            f.write("\n\n".join(blocks) + "\n")
    meta["wireguard_configs"] = len(uris)
    return len(uris)


# ---------------------------------------------------------------- alive

async def _check(server, port, sem):
    async with sem:
        try:
            w = None
            try:
                _r, w = await asyncio.wait_for(
                    asyncio.open_connection(server, port), timeout=ALIVE_TIMEOUT)
            finally:
                if w:
                    try:
                        w.close()
                        await asyncio.wait_for(w.wait_closed(), timeout=1.0)
                    except Exception:
                        pass
            return True
        except Exception:
            return False


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
            chunk = [ _check(h, p, sem) for h, p in keys[i:i + BATCH] ]
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
    for f in [MTPROTO_FILE, SOCKS_FILE, ALL_FILE, STATS_FILE, LASTUPD_FILE]:
        p = os.path.join(ROOT, f)
        if os.path.exists(p):
            os.remove(p)
    mt = [p["link"] for p in alive if p["kind"] == "mtproto"]
    sk = [p["link"] for p in alive if p["kind"] == "socks"]
    if mt:
        with open(os.path.join(ROOT, MTPROTO_FILE), "w", encoding="utf-8") as f:
            f.write("\n".join(mt) + "\n")
    if sk:
        with open(os.path.join(ROOT, SOCKS_FILE), "w", encoding="utf-8") as f:
            f.write("\n".join(sk) + "\n")
    with open(os.path.join(ROOT, ALL_FILE), "w", encoding="utf-8") as f:
        f.write("\n".join(mt + sk) + "\n")
    with open(os.path.join(ROOT, LASTUPD_FILE), "w", encoding="utf-8") as f:
        f.write(meta["last_update"] + "\n")
    with open(os.path.join(ROOT, STATS_FILE), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)


def main():
    t0 = time.time()
    print("=" * 60)
    print("MSN MTProto Collector started")
    geoip.geo()   # country db for WG naming (cached)
    channels = load_channels()
    if not channels:
        print("[!] no channels — check channels.txt")
        return 1
    print(f"[i] {len(channels)} Telegram channels loaded")

    results = fetch_all(channels)
    per_channel, channel_stats = {}, {}
    ok = fail = 0
    failed_channels = []
    raw = []
    for name, pages, err in results:
        if err:
            fail += 1
            failed_channels.append(name)
            channel_stats[name] = {"error": err}
            print(f"    [x] FETCH FAILED: @{name} ({err})")
            continue
        got = extract_from_pages(pages)
        uniq_src = dedupe(got)
        per_channel[name] = uniq_src
        channel_stats[name] = {"total": len(uniq_src)}
        ok += 1
        print(f"    [+] {len(uniq_src):4d} proxies  @{name} ({len(pages)} pages)")
        raw.extend(got)

    # ---------------- proxybolt.link (web API source) ----------------
    pb = fetch_proxybolt()
    if pb:
        pb_uniq = dedupe(pb)
        per_channel["proxybolt.link"] = pb_uniq
        channel_stats["proxybolt.link"] = {"total": len(pb_uniq)}
        raw.extend(pb)
        print(f"    [+] {len(pb_uniq):4d} proxies  proxybolt.link (web API)")

    uniq = dedupe(raw)
    dups_removed = len(raw) - len(uniq)
    uniq = uniq[:MAX_TEST]
    print(f"[i] channels ok/failed: {ok}/{fail} | raw proxies: {len(raw)} | "
          f"duplicates removed: {dups_removed} | unique: {len(uniq)}")
    if not uniq:
        print("[!] nothing parsed — aborting (keeping previous outputs)")
        return 1

    pairs = run_alive_checks(uniq)
    alive = [p for p in uniq if pairs.get((p["server"], p["port"]))]
    for name, lst in per_channel.items():
        channel_stats[name]["alive"] = sum(
            1 for p in lst if pairs.get((p["server"], p["port"])))
    by_kind = {}
    for p in alive:
        by_kind[p["kind"]] = by_kind.get(p["kind"], 0) + 1
    print("[i] ALIVE by kind:")
    for k, v in by_kind.items():
        print(f"    {k:<8} {v}")
    print(f"[i] total alive: {len(alive)} / {len(uniq)} tested")

    meta = {
        "last_update": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "duration_sec": round(time.time() - t0, 1),
        "channels_ok": ok, "channels_failed": fail,
        "failed_channels": failed_channels,
        "raw_proxies": len(raw), "unique_proxies": len(uniq),
        "duplicates_removed": dups_removed,
        "alive_proxies": len(alive),
        "kinds": by_kind,
        "channel_stats": dict(sorted(channel_stats.items(),
                                     key=lambda kv: -kv[1].get("total", 0))),
    }
    write_outputs(alive, meta)
    annotate_channels(channel_stats)

    # ---------------- WireGuard channels ----------------
    wg_channels = load_channels(WG_CHANNELS_FILE)
    if wg_channels:
        print(f"[i] {len(wg_channels)} WireGuard channels loaded")
        wg_results = fetch_all(wg_channels)
        wg_stats, wg_raw = {}, []
        wg_ok = wg_fail = 0
        for name, pages, err in wg_results:
            if err:
                wg_fail += 1
                wg_stats[name] = {"error": err}
                print(f"    [x] FETCH FAILED: @{name} ({err})")
                continue
            got = extract_wg_from_pages(pages)
            got = dedupe_wg(got)
            wg_stats[name] = {"total": len(got)}
            wg_ok += 1
            print(f"    [+] {len(got):4d} wireguard configs  @{name} ({len(pages)} pages)")
            wg_raw.extend(got)
        wg_uniq = dedupe_wg(wg_raw)
        print(f"[i] wireguard: channels ok/failed: {wg_ok}/{wg_fail} | "
              f"raw: {len(wg_raw)} | unique: {len(wg_uniq)}")
        wg_uniq = wg_resolve_countries(wg_uniq)
        n_wg = write_wg_outputs(wg_uniq, meta)
        meta["wg_channels_ok"] = wg_ok
        meta["wg_channels_failed"] = wg_fail
        meta["wg_channel_stats"] = wg_stats
        annotate_channels(wg_stats, path=WG_CHANNELS_FILE, noun="configs")
        print(f"[i] wireguard outputs written: {n_wg} configs")

    # stats.json rewritten so WG fields are included
    with open(os.path.join(ROOT, STATS_FILE), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    print(f"[✓] done in {meta['duration_sec']}s — outputs written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
