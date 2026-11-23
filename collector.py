#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MSN Collector — V2Ray/Xray free proxy config collector
======================================================
- Reads subscription links from sources.txt (one URL per line, '#' = comment)
- Downloads, parses, deduplicates configs (vmess/vless/trojan/ss/ssr/hysteria/hysteria2/tuic)
- TCP alive-checks every unique host:port — only reachable configs are kept
- Regenerates per-protocol output files on every run (old files replaced)
- Renames every config remark to @mehdisedighinasab-N (sequential, unique per run)
- Annotates sources.txt: each source line gets ' # N configs, M live' (auto-updated every run)
Pure Python 3 stdlib — no external dependencies.
"""
import asyncio
import base64
import fcntl
import gzip
import hashlib
import json
import os
import re
import ssl
import sys
import time
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.abspath(__file__))
SOURCES_FILE = os.path.join(ROOT, "sources.txt")
sys.path.insert(0, ROOT)
import geoip  # local module — country lookup for config naming

ALIVE_TIMEOUT = 4.0        # seconds for TCP connect check
CHECK_CONCURRENCY = 800    # parallel alive checks
FETCH_WORKERS = 32         # parallel source downloads
SOURCE_TIMEOUT = 30        # seconds per source download
MAX_TEST = 100000          # safety cap on unique configs tested per run

UA = "v2rayNG/1.9.16"

# --- outlinekeys.com (sitemap -> per-key HTML pages) -----------------------
KEYPAGE_WORKERS = 20      # site throttles hard above ~24 parallel requests
KEYPAGE_TIMEOUT = 45      # pages can be slow (PHP + ad scripts)
OK_HOST = "outlinekeys.com"
OK_CACHE = os.path.join(ROOT, "outlinekeys_cache.json")   # gitignored
OK_LOCK = OK_CACHE + ".lock"
OK_HARVEST = os.path.join(ROOT, "outlinekeys_harvest.lock")  # PID sentinel while full harvest runs

PROTO_FILE = {
    "vmess":     "vmess.txt",
    "vless":     "vless.txt",
    "trojan":    "trojan.txt",
    "ss":        "ss.txt",
    "hysteria2": "hysteria2.txt",
    "tuic":      "tuic.txt",
    "hysteria":  "hysteria.txt",
    "ssr":       "ssr.txt",
}
ALL_FILE = "all.txt"        # all alive configs, plain URIs
SUB_FILE = "sub.txt"        # all alive configs, base64 subscription
STATS_FILE = "stats.json"
LASTUPD_FILE = "last_update.txt"

NAMING_PREFIX = "@mehdisedighinasab"   # every config renamed to PREFIX-1, PREFIX-2, ...

# ---------------------------------------------------------------- helpers

def b64d(s):
    """Tolerant base64 decode (url-safe variants, missing padding)."""
    s = "".join(s.split()).replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return None


def b64e(s):
    return base64.b64encode(s.encode("utf-8", "replace")).decode()


def split_hostport(hostport):
    """Split 'host:port' or '[ipv6]:port'. Returns (host, port|None)."""
    hostport = hostport.strip().strip("/")
    if hostport.startswith("["):
        m = re.match(r"^\[(.+)\]:(\d+)$", hostport)
        if m:
            return m.group(1), int(m.group(2))
        return hostport.strip("[]"), None
    if ":" not in hostport:
        return hostport, None
    host, _, port_s = hostport.rpartition(":")
    try:
        port = int(port_s)
    except ValueError:
        return hostport.strip("[]"), None
    if not (0 < port < 65536):
        return host.strip("[]"), None
    return host.strip("[]"), port


# ---------------------------------------------------------------- parsers

def parse_vmess(uri):
    payload = uri[len("vmess://"):].split("#", 1)[0]
    raw = b64d(payload)
    obj = None
    if raw:
        try:
            obj = json.loads(raw)
        except Exception:
            obj = None
    if obj is None:
        try:  # plain json variant
            obj = json.loads(uri[len("vmess://"):])
        except Exception:
            return None
    if not isinstance(obj, dict):
        return None
    host = str(obj.get("add") or obj.get("address") or "").strip()
    try:
        port = int(str(obj.get("port")).strip())
    except Exception:
        return None
    if not host or not (0 < port < 65536):
        return None
    obj["add"], obj["port"] = host, str(port)
    canon = "vmess://" + b64e(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))
    return ("vmess", host, port, canon)


def parse_userinfo(uri):
    """vless:// trojan:// hysteria2:// hy2:// tuic://  (userinfo@host:port?query#frag)"""
    scheme, _, rest = uri.partition("://")
    scheme = scheme.lower()
    if scheme == "hy2":
        scheme = "hysteria2"
    frag = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
    rest = rest.strip("/")
    if "@" in rest:
        userinfo, _, hostport = rest.rpartition("@")
    else:
        userinfo, hostport = "", rest
    host, port = split_hostport(hostport)
    if not host:
        return None
    if port is None:  # default ports
        port = 443 if scheme in ("vless", "trojan", "hysteria2", "tuic") else None
    if not port:
        return None
    netloc = f"{userinfo}@{host}:{port}" if userinfo else f"{host}:{port}"
    canon = f"{scheme}://{netloc}"
    if query:
        canon += "?" + query
    if frag:
        canon += "#" + urllib.parse.quote(frag)
    return (scheme, host, port, canon)


def parse_ss(uri):
    body = uri[len("ss://"):]
    frag = ""
    if "#" in body:
        body, frag = body.split("#", 1)
    frag = frag.strip()
    method_pass = hostport = query = None
    if "@" in body:
        userinfo, _, rest = body.partition("@")
        if "?" in rest:
            rest, query = rest.split("?", 1)
        rest = rest.split("/", 1)[0]
        dec = b64d(userinfo)
        if dec and ":" in dec:
            method_pass = dec
        elif ":" in userinfo:
            method_pass = userinfo
        else:
            return None
        hostport = rest
    else:
        core = body.split("?", 1)[0].split("/", 1)[0]
        dec = b64d(core)
        if not dec or "@" not in dec:
            return None
        method_pass, _, hostport = dec.rpartition("@")
        hostport = hostport.split("?", 1)[0].split("/", 1)[0]
    host, port = split_hostport(hostport)
    if not host or not method_pass:
        return None
    port = port or 443
    canon = f"ss://{b64e(method_pass)}@{host}:{port}"
    if query:
        canon += "?" + query
    if frag:
        canon += "#" + urllib.parse.quote(frag)
    return ("ss", host, port, canon)


def parse_hysteria1(uri):
    rest = uri[len("hysteria://"):]
    frag = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
    host, port = split_hostport(rest)
    if not host:
        return None
    if not port:
        m = re.search(r"(?:^|&)mport=(\d+)", query)
        port = int(m.group(1)) if m else 443
    canon = f"hysteria://{host}:{port}"
    if query:
        canon += "?" + query
    if frag:
        canon += "#" + urllib.parse.quote(frag)
    return ("hysteria", host, port, canon)


def parse_ssr(uri):
    raw = b64d(uri[len("ssr://"):])
    if not raw or ":" not in raw:
        return None
    main = raw.split("/?", 1)[0]
    try:
        left, _proto, _method, _obfs, _p = main.rsplit(":", 4)
    except ValueError:
        return None
    host, port = split_hostport(left)
    if not host or not port:
        return None
    return ("ssr", host, port, "ssr://" + b64e(raw))


def parse_line(line):
    low = line.lower()
    if low.startswith("vmess://"):
        return parse_vmess(line)
    if low.startswith("vless://") or low.startswith("trojan://"):
        return parse_userinfo(line)
    if low.startswith("hysteria2://") or low.startswith("hy2://"):
        return parse_userinfo(line)
    if low.startswith("tuic://"):
        return parse_userinfo(line)
    if low.startswith("ss://"):
        return parse_ss(line)
    if low.startswith("ssr://"):
        return parse_ssr(line)
    if low.startswith("hysteria://"):
        return parse_hysteria1(line)
    return None


# ------------------------------------------------- JSON (xray-json-full)

def parse_json_configs(text):
    out = []
    try:
        data = json.loads(text)
    except Exception:
        return out

    def build_vmess(host, port, user):
        obj = {"add": host, "port": str(port), "id": user.get("id", ""),
               "aid": str(user.get("alterId", 0) or 0), "net": "tcp", "ps": "msn"}
        if user.get("security"):
            obj["scy"] = user["security"]
        return "vmess://" + b64e(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))

    def walk(o):
        if isinstance(o, dict):
            proto = o.get("protocol")
            st = o.get("settings") if isinstance(o.get("settings"), dict) else {}
            if isinstance(proto, str):
                try:
                    if proto == "vmess" and st.get("vnext"):
                        for v in st["vnext"]:
                            for u in v.get("users") or [{}]:
                                out.append(("vmess", v["address"], int(v.get("port", 443)),
                                            build_vmess(v["address"], int(v.get("port", 443)), u)))
                    elif proto in ("shadowsocks",) and st.get("servers"):
                        for v in st["servers"]:
                            m, p = v.get("method"), v.get("password")
                            if m and p is not None:
                                out.append(("ss", v["address"], int(v.get("port", 443)),
                                            f"ss://{b64e(m + ':' + str(p))}@{v['address']}:{int(v.get('port', 443))}"))
                    elif proto == "trojan" and st.get("servers"):
                        for v in st["servers"]:
                            pw = str(v.get("password", ""))
                            out.append(("trojan", v["address"], int(v.get("port", 443)),
                                        f"trojan://{urllib.parse.quote(pw)}@{v['address']}:{int(v.get('port', 443))}"))
                except Exception:
                    pass
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(data)
    return out


# ------------------------------------------------------------ Clash YAML

def _kv(s):
    d = {}
    for m in re.finditer(r"([\w-]+)\s*:\s*(\"[^\"]*\"|'[^']*'|[^,}]+)", s):
        d[m.group(1)] = m.group(2).strip().strip("\"'")
    return d


def clash_regex(text):
    proxies = []
    for m in re.finditer(r"-\s*\{([^}]*)\}", text):
        d = _kv(m.group(1))
        if d.get("server") and d.get("port"):
            proxies.append(d)
    if proxies:
        return proxies
    cur = None
    for line in text.splitlines():
        s = line.strip()
        if re.match(r"^[A-Za-z_-]+:", line):   # new top-level key -> stop
            if cur:
                proxies.append(cur)
                cur = None
            continue
        if s.startswith("- name") or s.startswith("- {"):
            if cur:
                proxies.append(cur)
            s2 = re.sub(r"^-\s*", "", s)
            if s2.startswith("{"):
                proxies.append(_kv(s2.strip("{}")))
                cur = None
            else:
                cur = _kv(s2)
        elif cur is not None and ":" in s:
            k, _, v = s.partition(":")
            cur[k.strip()] = v.strip().strip("\"'")
    if cur:
        proxies.append(cur)
    return proxies


def parse_clash(text):
    out = []
    try:
        import yaml  # optional
        data = yaml.safe_load(text)
        proxies = data.get("proxies") if isinstance(data, dict) else None
    except Exception:
        proxies = None
    if not proxies:
        proxies = clash_regex(text)
    for p in proxies or []:
        try:
            if not isinstance(p, dict):
                continue
            t = str(p.get("type", "")).lower()
            server = str(p.get("server", "")).strip()
            port = int(p.get("port", 0))
            name = str(p.get("name", "")).strip()
            if not server or not (0 < port < 65536):
                continue
            q = lambda s: urllib.parse.quote(s)
            if t == "vmess":
                net = str(p.get("network") or "tcp")
                obj = {"add": server, "port": str(port), "id": str(p.get("uuid", "")),
                       "aid": str(p.get("alterId", 0) or 0), "ps": name, "net": net,
                       "tls": "tls" if p.get("tls") else ""}
                ws = p.get("ws-opts") or {}
                if ws.get("path"):
                    obj["path"] = str(ws["path"])
                if ws.get("headers", {}).get("Host"):
                    obj["host"] = str(ws["headers"]["Host"])
                sn = p.get("servername") or p.get("sni")
                if sn:
                    obj["sni"] = str(sn)
                out.append(("vmess", server, port,
                            "vmess://" + b64e(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))))
            elif t == "ss" and p.get("cipher") and p.get("password") is not None:
                out.append(("ss", server, port,
                            f"ss://{b64e(str(p['cipher']) + ':' + str(p['password']))}@{server}:{port}#{q(name)}"))
            elif t == "trojan" and p.get("password") is not None:
                qq = []
                if p.get("sni"):
                    qq.append("sni=" + str(p["sni"]))
                if p.get("skip-cert-verify"):
                    qq.append("allowInsecure=1")
                out.append(("trojan", server, port,
                            f"trojan://{q(str(p['password']))}@{server}:{port}"
                            + ("?" + "&".join(qq) if qq else "") + f"#{q(name)}"))
            elif t == "vless" and p.get("uuid"):
                out.append(("vless", server, port, f"vless://{p['uuid']}@{server}:{port}#{q(name)}"))
            elif t == "hysteria2":
                auth = str(p.get("auth") or p.get("password") or "")
                out.append(("hysteria2", server, port, f"hysteria2://{q(auth)}@{server}:{port}#{q(name)}"))
            elif t == "hysteria":
                auth = str(p.get("auth-str") or p.get("auth") or "")
                out.append(("hysteria", server, port, f"hysteria://{server}:{port}?auth={q(auth)}#{q(name)}"))
            elif t == "tuic" and p.get("uuid"):
                out.append(("tuic", server, port,
                            f"tuic://{p['uuid']}:{p.get('password', '')}@{server}:{port}#{q(name)}"))
        except Exception:
            continue
    return out


# ------------------------------------------------- sing-box outbounds


def _sb_params(o):
    """Build URI query params from a sing-box outbound's tls/transport."""
    q = []
    tls = o.get("tls") or {}
    tr = o.get("transport") or {}
    if tls.get("enabled"):
        rel = tls.get("reality") or {}
        q.append("security=" + ("reality" if rel else "tls"))
        if tls.get("server_name"):
            q.append("sni=" + urllib.parse.quote(str(tls["server_name"])))
        fp = (tls.get("utls") or {}).get("fingerprint")
        if fp:
            q.append("fp=" + str(fp))
        if rel.get("public_key"):
            q.append("pbk=" + str(rel["public_key"]))
        if rel.get("short_id"):
            q.append("sid=" + str(rel["short_id"]))
        if tls.get("insecure") or tls.get("allow_insecure"):
            q.append("allowInsecure=1")
    net = tr.get("type")
    if net == "ws":
        q.append("type=ws")
        if tr.get("path"):
            q.append("path=" + urllib.parse.quote(str(tr["path"])))
        host = (tr.get("headers") or {}).get("Host") or (tr.get("headers") or {}).get("host")
        if host:
            q.append("host=" + urllib.parse.quote(str(host)))
    elif net == "grpc":
        q.append("type=grpc")
        if tr.get("service_name"):
            q.append("serviceName=" + urllib.parse.quote(str(tr["service_name"])))
    elif net in ("http", "h2"):
        q.append("type=http")
        if tr.get("path"):
            q.append("path=" + urllib.parse.quote(str(tr["path"])))
        hosts = tr.get("host")
        if isinstance(hosts, list) and hosts:
            q.append("host=" + urllib.parse.quote(str(hosts[0])))
        elif isinstance(hosts, str):
            q.append("host=" + urllib.parse.quote(hosts))
    return q


def parse_singbox_configs(text):
    """Parse sing-box outbounds (type/server/server_port) -> standard URIs."""
    out = []
    try:
        data = json.loads(text)
    except Exception:
        return out
    PROTO_SET = ("vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic")

    def walk(o):
        if isinstance(o, dict):
            t = o.get("type")
            server = o.get("server")
            port = o.get("server_port")
            if t in PROTO_SET and server and isinstance(port, int) and 0 < port < 65536:
                try:
                    name = urllib.parse.quote(str(o.get("tag") or ""))
                    q = _sb_params(o)
                    qs = ("?" + "&".join(q)) if q else ""
                    if t == "vless" and o.get("uuid"):
                        qq = []
                        if o.get("flow"):
                            qq.append("flow=" + str(o["flow"]))
                        qq += q
                        qs2 = ("?" + "&".join(qq)) if qq else ""
                        out.append(("vless", server, port,
                                    f"vless://{o['uuid']}@{server}:{port}{qs2}#{name}"))
                    elif t == "vmess" and o.get("uuid"):
                        tls = o.get("tls") or {}
                        tr = o.get("transport") or {}
                        obj = {"add": server, "port": str(port), "id": o["uuid"],
                               "aid": str(o.get("alter_id", 0) or 0),
                               "ps": str(o.get("tag") or ""),
                               "net": tr.get("type") or "tcp"}
                        if tr.get("path"):
                            obj["path"] = str(tr["path"])
                        h = (tr.get("headers") or {}).get("Host")
                        if h:
                            obj["host"] = str(h)
                        if tls.get("enabled"):
                            obj["tls"] = "tls"
                        if tls.get("server_name"):
                            obj["sni"] = str(tls["server_name"])
                        out.append(("vmess", server, port,
                                    "vmess://" + b64e(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))))
                    elif t == "trojan" and o.get("password") is not None:
                        out.append(("trojan", server, port,
                                    f"trojan://{urllib.parse.quote(str(o['password']))}@{server}:{port}{qs}#{name}"))
                    elif t == "shadowsocks" and o.get("method") and o.get("password") is not None:
                        out.append(("ss", server, port,
                                    f"ss://{b64e(str(o['method']) + ':' + str(o['password']))}@{server}:{port}#{name}"))
                    elif t == "hysteria2":
                        auth = str(o.get("password") or o.get("auth") or "")
                        out.append(("hysteria2", server, port,
                                    f"hysteria2://{urllib.parse.quote(auth)}@{server}:{port}{qs}#{name}"))
                    elif t == "tuic" and o.get("uuid"):
                        qq = []
                        if o.get("congestion_control"):
                            qq.append("congestion_control=" + str(o["congestion_control"]))
                        if o.get("alpn"):
                            qq.append("alpn=" + ",".join(map(str, o["alpn"])))
                        qs2 = ("?" + "&".join(qq)) if qq else ""
                        out.append(("tuic", server, port,
                                    f"tuic://{o['uuid']}:{urllib.parse.quote(str(o.get('password') or ''))}@{server}:{port}{qs2}#{name}"))
                except Exception:
                    pass
            else:
                for v in o.values():
                    walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(data)
    return out


# ------------------------------------------------------------- pipeline

def extract_from_text(text):
    if not text:
        return []
    results = []
    for line in text.splitlines():            # 1) direct URI lines
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if "://" in line:
            r = parse_line(line)
            if r:
                results.append(r)
        elif len(line) > 24 and " " not in line:   # per-line base64
            dec = b64d(line)
            if dec and "://" in dec:
                for sub in dec.splitlines():
                    r = parse_line(sub.strip())
                    if r:
                        results.append(r)
    if results:
        return results
    dec = b64d(text)                              # 2) whole-content base64
    if dec:
        for line in dec.splitlines():
            r = parse_line(line.strip())
            if r:
                results.append(r)
        if results:
            return results
    r = parse_json_configs(text)                  # 3) xray json
    r += parse_singbox_configs(text)              # 3b) sing-box outbounds
    if r:
        return r
    return parse_clash(text)                      # 4) clash yaml


def load_sources():
    """Parse sources.txt -> ordered unique list of (url, proto_filter).
    A line whose inline comment contains 'tuic-only' restricts that source to
    TUIC configs only (all other protocols parsed from it are discarded)."""
    srcs = []
    if not os.path.exists(SOURCES_FILE):
        print(f"[!] sources.txt not found at {SOURCES_FILE}")
        return srcs
    with open(SOURCES_FILE, encoding="utf-8") as f:
        for line in f:
            u = line.strip()
            if u and not u.startswith("#") and "://" in u:
                url, _, comment = u.partition("#")
                filt = {"tuic"} if "tuic-only" in comment.lower() else None
                srcs.append((url.strip(), filt))
    seen, out = set(), []
    for u, flt in srcs:
        if u not in seen:
            seen.add(u)
            out.append((u, flt))
    return out


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*",
                                               "Accept-Encoding": "gzip"})
    with urllib.request.urlopen(req, timeout=SOURCE_TIMEOUT) as r:
        data = r.read()
        if data[:2] == b"\x1f\x8b":            # server sent gzip
            try:
                data = gzip.decompress(data)
            except Exception:
                pass
        return data.decode("utf-8", "replace")


# ------------------------------------------------- outlinekeys.com source

OK_TA_RE = re.compile(r'<textarea[^>]*id="accessKey"[^>]*>(.*?)</textarea>', re.S)
OK_URI_RE = re.compile(r'(?:ss|vless|trojan|vmess|hy2|hysteria2?|tuic|ssr)://[^\s<>"\'\']+')
OK_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>")


def _ok_lock():
    f = open(OK_LOCK, "w")
    fcntl.flock(f, fcntl.LOCK_EX)
    return f


def _ok_cache_load():
    try:
        with _ok_lock():
            with open(OK_CACHE, encoding="utf-8") as fh:
                return json.load(fh)
    except Exception:
        return {}


def _ok_cache_merge(entries):
    """Merge entries into the on-disk cache atomically (flock-protected)."""
    if not entries:
        return
    with _ok_lock():
        try:
            with open(OK_CACHE, encoding="utf-8") as fh:
                disk = json.load(fh)
        except Exception:
            disk = {}
        disk.update(entries)
        tmp = OK_CACHE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(disk, fh, ensure_ascii=False)
        os.replace(tmp, OK_CACHE)


def _ok_extract(html):
    m = OK_TA_RE.search(html)
    if m:
        u = m.group(1).strip()
        if "://" in u:
            return u.split()[0]
    m = OK_URI_RE.search(html)
    return m.group(0) if m else None


def _ok_fetch(url):
    """Returns (status, text); text None on error."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*",
                                                   "Accept-Encoding": "gzip"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=KEYPAGE_TIMEOUT, context=ctx) as r:
            data = r.read()
            if data[:2] == b"\x1f\x8b":
                try:
                    data = gzip.decompress(data)
                except Exception:
                    pass
            return r.status, data.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return 0, None


def _harvest_running():
    """True while scripts/harvest_outlinekeys.py is doing its one-time full scan
    (its PID is written in OK_HARVEST). We then skip new-page fetching so we
    don't double-hit the throttled server; cached keys are still served."""
    try:
        with open(OK_HARVEST, encoding="utf-8") as f:
            pid = int(f.read().strip() or 0)
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def expand_outlinekeys(sitemap_url):
    """outlinekeys.com publishes one key per /key/<id>/ page, indexed by its
    sitemap.xml. Pages are slow (~1-10s) and the server throttles hard, so we
    keep a local cache (url -> uri|None, gitignored) and each cycle fetch ONLY
    pages not seen before. Cached URIs are re-injected every run so the global
    dedupe + alive-check still decide what reaches the outputs. If the sitemap
    itself fails, cached keys are still served."""
    st, xml = _ok_fetch(sitemap_url)
    if st != 200 or not xml:
        cache = _ok_cache_load()
        uris = [v for v in cache.values() if v]
        if uris:
            print(f"[!] outlinekeys sitemap failed; serving {len(uris)} cached keys")
            return "\n".join(uris)
        return None
    pages = [u for u in OK_LOC_RE.findall(xml) if "/key/" in u]
    if not pages:
        return None
    cache = _ok_cache_load()
    todo = [u for u in pages if u not in cache]
    if todo and _harvest_running():
        print(f"[i] outlinekeys: full harvest in progress — skipping {len(todo)} new pages this cycle")
        todo = []
    print(f"[i] outlinekeys: {len(pages)} key pages in sitemap, {len(todo)} new to fetch")
    if todo:
        entries = {}

        def work(u):
            s, html = _ok_fetch(u)
            return u, s, html

        with ThreadPoolExecutor(KEYPAGE_WORKERS) as ex:
            for u, s, html in ex.map(work, todo):
                if s == 200 and html is not None:
                    entries[u] = _ok_extract(html)
                elif s in (404, 410):
                    entries[u] = None          # confirmed gone -> remember
                # transient errors stay uncached -> retried next cycle
        _ok_cache_merge(entries)
        cache = _ok_cache_load()
    uris = [cache[u] for u in pages if cache.get(u)]
    print(f"[i] outlinekeys: {len(uris)} keys available")
    # empty (not None) when the sitemap was fine but the cache is still being
    # built — shows as '0 configs' instead of a scary 'fetch failed'
    return "\n".join(uris) if uris else ""


def fetch_all(urls):
    def work(u):
        try:
            if OK_HOST in u and u.rstrip("/").endswith(".xml"):
                return (u, expand_outlinekeys(u))
            return (u, fetch(u))
        except Exception:
            return (u, None)
    with ThreadPoolExecutor(FETCH_WORKERS) as ex:
        return list(ex.map(work, urls))


def dedupe(items):
    """Global dedupe. Key = protocol + host + port + account identity.
    vmess identity = the uuid INSIDE its JSON (different sources often carry
    the same server/uuid under different names/params); every other protocol
    identity = the userinfo part. Names (#frag) and query params are ignored,
    so the same config coming from N sources appears exactly once."""
    seen, out = set(), []
    for proto, host, port, uri in items:
        if not host or not port or proto not in PROTO_FILE:
            continue
        core = uri.split("#", 1)[0]
        _scheme, _, rest = core.partition("://")
        rest = rest.split("?", 1)[0]
        cred = ""
        if proto == "vmess":
            raw = b64d(rest)
            try:
                obj = json.loads(raw) if raw else None
            except Exception:
                obj = None
            if isinstance(obj, dict) and obj.get("id"):
                cred = str(obj["id"])
            elif "@" in rest:
                cred = rest.rpartition("@")[0]
            if not cred:
                cred = rest
        elif "@" in rest:
            cred = rest.rpartition("@")[0]
        key = f"{proto}|{host}|{port}|{hashlib.md5(cred.encode()).hexdigest()}"
        if key not in seen:
            seen.add(key)
            out.append((proto, host, port, uri))
    return out


async def _check(host, port, sem):
    """TCP connect check. Returns the resolved peer IP on success, else None
    (the IP feeds the GeoIP country lookup for naming)."""
    async with sem:
        w = None
        try:
            _r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=ALIVE_TIMEOUT)
            peer = w.get_extra_info("peername")
            return peer[0] if peer else None
        except Exception:
            return None
        finally:
            if w:
                try:
                    w.close()
                    await asyncio.wait_for(w.wait_closed(), timeout=1.0)
                except Exception:
                    pass


def run_alive_checks(items):
    """Returns {(host, port): resolved_ip_or_None} — truthy = alive."""
    pairs = {}
    for proto, host, port, _u in items:
        pairs.setdefault((host, port), None)
    sem = asyncio.Semaphore(CHECK_CONCURRENCY)

    async def run():
        keys = list(pairs.keys())
        total = len(keys)
        print(f"[i] alive-check on {total} unique host:port (timeout {ALIVE_TIMEOUT}s, x{CHECK_CONCURRENCY})")
        t0 = time.time()
        coros = [_check(h, p, sem) for h, p in keys]
        done = 0
        results = []
        BATCH = 4000
        for i in range(0, len(coros), BATCH):
            chunk = coros[i:i + BATCH]
            res = await asyncio.gather(*chunk)
            results.extend(res)
            done += len(chunk)
            el = time.time() - t0
            print(f"    ... {done}/{total} checked ({done / max(el, 0.001):.0f}/s, {el:.0f}s)")
        for (h, p), ok in zip(keys, results):
            pairs[(h, p)] = ok
        return pairs

    return asyncio.run(run())


def rename_uri(proto, uri, n, cc=None):
    """Set a config's remark/name to PREFIX-N (sequential, unique across all
    outputs of this run), suffixed with the flag + ISO code of the server's
    country, e.g. '@mehdisedighinasab-12-🇩🇪DE'. vmess -> rewrite the 'ps'
    field inside its JSON; every other protocol -> replace the URI fragment.
    Returns the new URI."""
    name = f"{NAMING_PREFIX}-{n}"
    if cc:
        fl = geoip.flag(cc)
        if fl:
            name += f"-{fl}{cc.upper()}"
    if proto == "vmess":
        raw = b64d(uri[8:])
        try:
            obj = json.loads(raw) if raw else None
        except Exception:
            obj = None
        if isinstance(obj, dict):
            obj["ps"] = name
            return "vmess://" + b64e(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))
    return uri.split("#", 1)[0] + "#" + name


def write_outputs(alive_items, meta, ccmap=None):
    ccmap = ccmap or {}
    for f in list(PROTO_FILE.values()) + [ALL_FILE, SUB_FILE, STATS_FILE, LASTUPD_FILE]:
        p = os.path.join(ROOT, f)
        if os.path.exists(p):
            os.remove(p)
    by_proto = {}
    for proto, _h, _p, uri in alive_items:
        by_proto.setdefault(proto, []).append(uri)
    all_lines = []
    n = 0
    for proto, fname in PROTO_FILE.items():
        uris = by_proto.get(proto) or []
        if not uris:
            continue
        items = [it for it in alive_items if it[0] == proto]
        named = []
        for i, (p2, h, port, u) in enumerate(items):
            named.append(rename_uri(p2, u, n + i + 1, ccmap.get((h, port))))
        n += len(named)
        with open(os.path.join(ROOT, fname), "w", encoding="utf-8") as f:
            f.write("\n".join(named) + "\n")
        with open(os.path.join(ROOT, fname.replace(".txt", "_b64.txt")), "w", encoding="utf-8") as f:
            f.write(b64e("\n".join(named)) + "\n")
        all_lines.extend(named)
    with open(os.path.join(ROOT, ALL_FILE), "w", encoding="utf-8") as f:
        f.write("\n".join(all_lines) + "\n")
    with open(os.path.join(ROOT, SUB_FILE), "w", encoding="utf-8") as f:
        f.write(b64e("\n".join(all_lines)) + "\n")
    with open(os.path.join(ROOT, LASTUPD_FILE), "w", encoding="utf-8") as f:
        f.write(meta["last_update"] + "\n")
    with open(os.path.join(ROOT, STATS_FILE), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)


def annotate_sources(stats, path=None):
    """Rewrite sources.txt, appending an inline ' # N configs, M live' comment
    after each source URL so per-source counts are visible right in the repo.
    Blank lines and '#' comment lines are preserved; a previous inline count is
    replaced; a 'tuic-only' protocol tag (if present) is preserved. Lines whose
    URL is not in `stats` are left untouched."""
    path = path or SOURCES_FILE
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as e:
        print(f"[!] annotate_sources: cannot read {path}: {e}")
        return
    out, changed = [], False
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#") or "://" not in s:
            out.append(line)
            continue
        url, _, comment = s.partition("#")         # drop previous inline count
        url = url.strip()
        keep = "tuic-only" in comment.lower()      # preserve protocol tag
        st = stats.get(url)
        if st is None:
            out.append(line)
            continue
        if "error" in st:
            tag = "fetch failed"
        else:
            tag = f"{st.get('total', 0)} configs, {st.get('alive', 0)} live"
        new = f"{url}  # {tag}" + (" • tuic-only" if keep else "")
        if new != line.rstrip():
            changed = True
        out.append(new)
    if changed:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        os.replace(tmp, path)
        print("[i] sources.txt annotated with per-source config counts")


def main():
    t0 = time.time()
    print("=" * 60)
    print("MSN Collector started")
    geoip.geo()   # load/build country db (cached; names configs with flags)
    srcs = load_sources()
    if not srcs:
        print("[!] no sources — check sources.txt")
        return 1
    print(f"[i] {len(srcs)} subscription sources loaded")
    filters = dict(srcs)                      # url -> {"tuic"} or None
    texts = fetch_all([u for u, _f in srcs])
    items, ok, fail, failed_urls = [], 0, 0, []
    per_source = {}      # url -> unique configs parsed from that source
    source_stats = {}    # url -> {total, alive} or {error}
    for url, text in texts:
        if text is None:
            fail += 1
            failed_urls.append(url)
            source_stats[url] = {"error": "fetch failed"}
            print(f"    [x] FETCH FAILED: {url[:100]}")
            continue
        ok += 1
        got = extract_from_text(text)
        filt = filters.get(url)
        if filt:                                  # per-source protocol filter
            got = [it for it in got if it[0] in filt]
        uniq_src = dedupe(got)
        per_source[url] = uniq_src
        source_stats[url] = {"total": len(uniq_src)}
        note = " [tuic-only]" if filt else ""
        print(f"    [+] {len(got):5d} raw ({len(uniq_src):5d} unique){note}  {url[:80]}")
        items.extend(got)
    uniq_all = dedupe(items)
    dups_removed = len(items) - len(uniq_all)
    uniq = uniq_all[:MAX_TEST]
    print(f"[i] sources ok/failed: {ok}/{fail} | raw configs: {len(items)} | "
          f"duplicates removed: {dups_removed} | unique: {len(uniq)}")
    if not uniq:
        print("[!] nothing parsed — aborting (keeping previous outputs)")
        return 1
    pairs = run_alive_checks(uniq)
    alive_items = [it for it in uniq if pairs.get((it[1], it[2]))]
    ccmap = {}                    # (host, port) -> ISO code for naming
    for (h, p), ip in pairs.items():
        if ip:
            cc = geoip.country(ip)
            if cc:
                ccmap[(h, p)] = cc
    for url, lst in per_source.items():   # per-source alive attribution
        source_stats[url]["alive"] = sum(1 for it in lst if pairs.get((it[1], it[2])))
    counts = {}
    ccounts = {}
    for proto, h, p, _u in alive_items:
        counts[proto] = counts.get(proto, 0) + 1
        cc = ccmap.get((h, p))
        if cc:
            ccounts[cc] = ccounts.get(cc, 0) + 1
    print("[i] ALIVE per protocol:")
    for proto in PROTO_FILE:
        if counts.get(proto):
            print(f"    {proto:<10} {counts[proto]}")
    top_c = sorted(ccounts.items(), key=lambda kv: -kv[1])[:15]
    if top_c:
        print("[i] top countries: " + ", ".join(f"{geoip.flag(c)}{c} {v}" for c, v in top_c))
    print(f"[i] total alive: {len(alive_items)} / {len(uniq)} tested")
    meta = {
        "last_update": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "duration_sec": round(time.time() - t0, 1),
        "sources_ok": ok, "sources_failed": fail,
        "failed_sources": failed_urls,
        "raw_configs": len(items), "unique_configs": len(uniq),
        "duplicates_removed": dups_removed,
        "alive_configs": len(alive_items),
        "protocols": counts,
        "countries": dict(sorted(ccounts.items(), key=lambda kv: -kv[1])),
        "source_stats": dict(sorted(source_stats.items(),
                                    key=lambda kv: -kv[1].get("total", 0))),
    }
    write_outputs(alive_items, meta, ccmap)
    annotate_sources(source_stats)
    print(f"[✓] done in {meta['duration_sec']}s — outputs written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
