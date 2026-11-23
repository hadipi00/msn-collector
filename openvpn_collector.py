#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MSN OpenVPN Collector — standalone additive collector
=====================================================
Collects ONLY OpenVPN configs (.ovpn / inline OpenVPN text) from:
  1. Telegram channels listed in openvpn_channels.txt
     - discovery/dates/text via the public t.me/s/ preview (no auth needed)
     - .ovpn attachments via the official MTProto API (Telethon) when
       OPENVPN_TG_API_ID / OPENVPN_TG_API_HASH / OPENVPN_TG_SESSION are set —
       the web preview can not serve files, so credentials are required for
       attachments.  Without them attachments are reported as unavailable.
  2. VPNBook (https://www.vpnbook.com/freevpn/openvpn)
     - official download endpoint, per-server metadata from the page
     - auto-fetches the public username/password and embeds a standard
       <auth-user-pass> block so users never type credentials manually

Freshness rules (spec):
  - only posts newer than FRESHNESS_HOURS (default 24h) are collected
  - the last processed Message ID per channel is stored in openvpn_state.json
    and older posts are never re-processed (OPENVPN_REWIND=n to roll back)
  - duplicates are detected by SHA256 of the canonical config content

Outputs (all new files — nothing existing is touched or rewritten):
  openvpn.json, openvpn.zip, openvpn/<name>.ovpn (one file per config),
  openvpn_state.json, openvpn_last_update.txt

Pure Python 3 stdlib + optional Telethon (only when MTProto creds are set).
Never imports collector.py / mtproto_collector.py — fully isolated.
"""
import asyncio
import hashlib
import html as html_mod
import json
import os
import random
import re
import struct
import subprocess
import sys
import time
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import geoip                      # existing local module (unmodified) — country lookup
import openvpn_config as cfg      # new settings module (this collector only)

REWIND = int(os.environ.get("OPENVPN_REWIND", "0") or 0)

TME_RE = re.compile(r"^(?:https?://)?t\.me/([A-Za-z0-9_]+)/?$")
MSG_DIV_RE = re.compile(r'<div[^>]*class="tgme_widget_message\s[^"]*"[^>]*data-post="([^"]+/(\d+))"')
TIME_RE = re.compile(r'<time[^>]*datetime="([^"]+)"')
DOC_TITLE_RE = re.compile(r'tgme_widget_message_document_title[^>]*>(.*?)</div>', re.S)

REMOTE_RE = re.compile(r"(?mi)^\s*remote\s+([^\s]+)(?:\s+(\d+))?\s*$")
PROTO_RE = re.compile(r"(?mi)^\s*proto\s+(tcp|udp)")
CLIENT_RE = re.compile(r"(?mi)^\s*client\s*$")
AUTHUP_RE = re.compile(r"(?mi)^\s*auth-user-pass\b.*$")
VPNBOOK_SERVER_RE = re.compile(
    r'\{"id":"([a-z0-9]+)","name":"([^"]+)","hostname":"([^"]+)"'
    r',"ipAddress":"([^"]*)","countryCode":"([A-Z]{2})","countryName":"([^"]+)"')
VPNBOOK_CREDS_RE = re.compile(r"Username:\s*([A-Za-z0-9_]+)\.?\s*Password:\s*([A-Za-z0-9_-]+)")
VPNBOOK_CHANGED_RE = re.compile(r"last changed on ([A-Za-z]{3,9} \d{1,2}, \d{4})")


# ------------------------------------------------------------------ helpers

def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_iso(s):
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def http_get(url, timeout=cfg.VPNBOOK_TIMEOUT, binary=False):
    req = urllib.request.Request(url, headers={
        "User-Agent": cfg.UA, "Accept-Language": "en",
        "Accept": "*/*",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    return data if binary else data.decode("utf-8", "replace")


def sha_hex(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def load_state():
    st = load_json(os.path.join(ROOT, cfg.OPENVPN_STATE_FILE), {})
    st.setdefault("version", 1)
    st.setdefault("channels", {})          # name -> {last_msg_id, updated}
    st.setdefault("registry", {})          # sha -> config entry
    st.setdefault("country_seq", {})       # country -> next number
    st.setdefault("vpnbook_names", {})     # server_id -> {num, filename, hash}
    st.setdefault("vpnbook", {})
    st.setdefault("manifest", {})          # filename -> sha (zip change detection)
    st.setdefault("runs", [])
    return st


def save_state(st):
    save_json(os.path.join(ROOT, cfg.OPENVPN_STATE_FILE), st)


def _tag_balance_slice(text, start):
    """Return the inner content of the <div ...> opening at `start`, balanced."""
    depth, i, n = 0, start, len(text)
    open_re = re.compile(r"<div\b", re.I)
    close_re = re.compile(r"</div\s*>", re.I)
    pos = start
    while pos < n:
        mo = open_re.search(text, pos)
        mc = close_re.search(text, pos)
        if mc and (not mo or mc.start() < mo.start()):
            depth -= 1
            pos = mc.end()
            if depth == 0:
                return text[start:mc.start()]
        elif mo:
            depth += 1
            pos = mo.end()
        else:
            break
    return text[start:pos]


def html_to_text(fragment):
    """HTML fragment -> plain text (tags stripped BEFORE entity unescape so
    OpenVPN <ca>/<cert> blocks inside message text survive)."""
    t = re.sub(r"(?i)<br\s*/?>", "\n", fragment)
    t = re.sub(r"(?i)</p>|</pre>|</blockquote>|</li>", "\n", t)
    t = re.sub(r"<[^>]+>", "", t)
    return html_mod.unescape(t)


# ------------------------------------------------------------------ channels

def load_channels():
    names = []
    if not os.path.exists(cfg.TELEGRAM_CHANNELS_FILE):
        print(f"[!] {os.path.basename(cfg.TELEGRAM_CHANNELS_FILE)} not found")
        return names
    with open(cfg.TELEGRAM_CHANNELS_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            m = TME_RE.match(line)
            name = m.group(1) if m else line.lstrip("@").strip()
            if re.match(r"^[A-Za-z0-9_]{3,64}$", name) and name not in names:
                names.append(name)
    return names


def annotate_channels(ch_stats):
    """Refresh the per-channel comment in openvpn_channels.txt (project style)."""
    path = cfg.TELEGRAM_CHANNELS_FILE
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return
    out, changed = [], False
    for line in lines:
        s = line.split("#", 1)[0].strip()
        if not s:
            out.append(line)
            continue
        m = TME_RE.match(s)
        name = m.group(1) if m else s.lstrip("@").strip()
        st = ch_stats.get(name)
        if st:
            if st.get("error"):
                tag = st["error"]
            else:
                tag = f"{st.get('attachments', 0)} ovpn files, {st.get('new_configs', 0)} new"
            new = f"@{name}  # {tag}"
            if new != line.rstrip():
                changed = True
            out.append(new)
        else:
            out.append(line)
    if changed:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        os.replace(tmp, path)


# ------------------------------------------------------- telegram preview

def fetch_preview(name, state, cutoff):
    """Fetch recent preview pages, stopping early once posts are old/known."""
    ch_state = state["channels"].get(name, {})
    last_id = max(int(ch_state.get("last_msg_id", 0)) - REWIND, 0)
    pages, before = [], None
    for _ in range(cfg.TG_PAGES_MAX):
        url = f"https://t.me/s/{name}" + (f"?before={before}" if before else "")
        try:
            text = http_get(url, timeout=cfg.TG_FETCH_TIMEOUT)
        except Exception:
            break
        pages.append(text)
        # stop when every post on this page is older than the freshness window
        dates = [d for d in TIME_RE.findall(text)]
        ids = [int(i) for i in re.findall(r'data-post="[^"]+/(\d+)"', text)]
        if not ids:
            break
        if all(parse_iso(d) and parse_iso(d) < cutoff for d in dates if d) and not (
                last_id and max(ids) > last_id):
            break
        before = min(ids)
        if len(ids) < 5:
            break
        time.sleep(cfg.TG_FETCH_DELAY)
    return pages


def parse_messages(name, pages):
    """Split preview pages into message dicts: id, date, text, doc titles."""
    msgs, seen = [], set()
    for text in pages:
        text = html_mod.unescape(text).replace("\\\"", "\"")
        bounds = [m.start() for m in MSG_DIV_RE.finditer(text)]
        for idx, start in enumerate(bounds):
            m = MSG_DIV_RE.match(text, start)
            post, mid = m.group(1), int(m.group(2))
            end = bounds[idx + 1] if idx + 1 < len(bounds) else len(text)
            if post in seen:
                continue
            seen.add(post)
            slice_ = text[start:end]
            tm = TIME_RE.search(slice_)
            dt = parse_iso(tm.group(1)) if tm else None
            titles = []
            for dm in DOC_TITLE_RE.finditer(slice_):
                title = html_mod.unescape(re.sub(r"<[^>]+>", "", dm.group(1))).strip()
                titles.append(title)
            body = ""
            tm_text = re.search(r'<div class="tgme_widget_message_text[^"]*"[^>]*>', slice_)
            if tm_text:
                body = html_to_text(_tag_balance_slice(slice_, tm_text.start()))
            msgs.append({"id": mid, "date": dt, "text": body, "docs": titles})
    msgs.sort(key=lambda x: x["id"])
    return msgs


def extract_ovpn_blocks(plain):
    """Pull full OpenVPN config texts out of a plain-text message body."""
    blocks = []
    for m in CLIENT_RE.finditer(plain):
        start = m.start()
        end_ca = plain.find("</ca>", start)
        if end_ca != -1 and end_ca - start < 20000:
            end = end_ca + 5
        else:
            end = min(start + 12000, len(plain))
        block = plain[start:end].strip()
        if REMOTE_RE.search(block):
            blocks.append(block)
    return blocks


# ------------------------------------------------- MTProto (official API)

def mtproto_collect(channels, state, cutoff, add_item):
    """Download .ovpn attachments of new posts via Telethon (official API).
    Returns a short status string; add_item(content, source, dt) is called
    for every OpenVPN config found."""
    if not (cfg.TG_API_ID and cfg.TG_API_HASH and cfg.TG_SESSION):
        return "no MTProto credentials (attachments not downloadable)"
    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession
        from telethon.errors import FloodWaitError
    except ImportError:
        return "telethon not installed (pip3 install telethon)"

    import asyncio

    async def run():
        status = "ok"
        client = TelegramClient(StringSession(cfg.TG_SESSION),
                                cfg.TG_API_ID, cfg.TG_API_HASH)
        await client.connect()
        try:
            if not await client.is_user_authorized():
                return "MTProto session not authorized"
            for name in channels:
                try:
                    entity = await client.get_entity(name)
                except Exception as e:
                    status = f"@{name}: {type(e).__name__}"
                    continue
                last_id = max(int(state["channels"].get(name, {})
                                  .get("last_msg_id", 0)) - REWIND, 0)
                max_id, count = last_id, 0
                try:
                    async for msg in client.iter_messages(
                            entity, min_id=last_id, reverse=True,
                            limit=cfg.TG_ITER_LIMIT):
                        if msg.date and msg.date < cutoff:
                            max_id = max(max_id, msg.id)
                            continue
                        max_id = max(max_id, msg.id)
                        if msg.document:
                            fname = ""
                            for a in (msg.document.attributes or []):
                                if getattr(a, "file_name", None):
                                    fname = a.file_name
                                    break
                            if fname.lower().endswith(".ovpn"):
                                data = await client.download_media(msg, file=bytes)
                                if data:
                                    add_item(data.decode("utf-8", "replace"),
                                             name, msg.date)
                                    count += 1
                        if msg.text and CLIENT_RE.search(msg.text) \
                                and REMOTE_RE.search(msg.text):
                            for blk in extract_ovpn_blocks(msg.text):
                                add_item(blk, name, msg.date)
                except FloodWaitError as e:
                    status = f"@{name}: flood wait {e.seconds}s"
                    continue
                except Exception as e:
                    status = f"@{name}: {type(e).__name__}: {e}"
                    continue
                st = state["channels"].setdefault(name, {})
                st["last_msg_id"] = max(int(st.get("last_msg_id", 0)), max_id)
                st["updated"] = iso(now_utc())
        finally:
            try:
                await client.disconnect()
            except Exception:
                pass
        return status

    try:
        return asyncio.run(run())
    except Exception as e:
        return f"MTProto failed: {type(e).__name__}: {e}"


# ------------------------------------------------------------------ VPNBook

def vpnbook_fetch_servers():
    """Server list (id, name, hostname, ip, cc, country) from the page payload."""
    raw = ""
    for url in cfg.VPNBOOK_PAGE_URLS:
        try:
            raw = http_get(url)
            if '"id":"' in raw:
                break
        except Exception:
            continue
    if not raw:
        return [], "vpnbook page unreachable"
    s = raw.replace('\\"', '"')
    servers, seen = [], set()
    for sid, name, host, ip, cc, country in VPNBOOK_SERVER_RE.findall(s):
        if sid in seen:
            continue
        seen.add(sid)
        num_m = re.search(r"(\d+)\s*$", name)
        servers.append({"id": sid, "name": name, "hostname": host, "ip": ip,
                        "cc": cc.upper(), "country": country,
                        "num": int(num_m.group(1)) if num_m else len(servers) + 1})
    if not servers:
        return [], "no servers found in vpnbook page"
    return servers, None


def vpnbook_credentials(page_html):
    """Public VPNBook username/password.  Primary: JSON-LD/FAQ text embedded
    in the page.  Fallback: OCR of the password image via tesseract, if any."""
    s = (page_html or "").replace('\\"', '"')
    m = VPNBOOK_CREDS_RE.search(s)
    if m:
        chg = VPNBOOK_CHANGED_RE.search(s)
        return {"username": m.group(1), "password": m.group(2),
                "changed": chg.group(1) if chg else "", "via": "page"}
    # OCR fallback (older page layouts showed the password as an image)
    img = None
    im = re.search(r'<img[^>]+src="([^"]*password[^"]*)"', s, re.I)
    if im:
        src = im.group(1)
        url = "https://www.vpnbook.com" + src if src.startswith("/") else src
        try:
            data = http_get(url, binary=True)
            img = os.path.join(ROOT, ".vpnbook_password.img")
            with open(img, "wb") as f:
                f.write(data)
            if os.path.exists("/usr/bin/tesseract"):
                out = subprocess.run(["tesseract", img, "stdout", "--psm", "7"],
                                     capture_output=True, text=True, timeout=30).stdout
                om = re.search(r"([A-Za-z0-9_-]{4,20})", out or "")
                if om:
                    return {"username": "vpnbook", "password": om.group(1),
                            "changed": "", "via": "ocr"}
        except Exception:
            pass
        finally:
            if img and os.path.exists(img):
                os.remove(img)
    return None


def _quote(s):
    from urllib.parse import quote
    return quote(s, safe="")


def vpnbook_download_config(server, proto_key):
    """Download one .ovpn from the official endpoint."""
    q = f"hostname={_quote(server['hostname'])}&protocol={proto_key}"
    if server.get("ip"):
        q += f"&ip={_quote(server['ip'])}"
    text = http_get(f"{cfg.VPNBOOK_API_URL}?{q}")
    if not text.lstrip().lower().startswith("client"):
        raise ValueError("response is not an OpenVPN config")
    return text


def inject_inline_creds(text, user, pw):
    """Embed username/password in the standard OpenVPN 2.4+ inline form so the
    user never types credentials.  The original `auth-user-pass` line (or a
    file reference) is replaced by an <auth-user-pass> block."""
    block = f"<auth-user-pass>\n{user}\n{pw}\n</auth-user-pass>"
    if re.search(r"(?mi)^\s*auth-user-pass\s*$", text):
        return re.sub(r"(?mi)^\s*auth-user-pass\s*$", block, text, count=1)
    if re.search(r"(?mi)^\s*auth-user-pass\s+\S+", text):
        return re.sub(r"(?mi)^\s*auth-user-pass\s+\S+.*$", block, text, count=1)
    return text.rstrip() + "\n" + block + "\n"


# ------------------------------------------------------------- validation

def parse_ovpn(text):
    """Structural validation.  Returns (info, status)."""
    info = {"has_client": bool(CLIENT_RE.search(text))}
    remotes = REMOTE_RE.findall(text)
    host, port = "", 0
    if remotes:
        host = remotes[0][0].strip().strip(".,;:)]")
        try:
            port = int(remotes[0][1]) if remotes[0][1] else 1194  # OpenVPN default
        except ValueError:
            port = 0
    pm = PROTO_RE.search(text)
    transport = "UDP"
    if pm:
        transport = "TCP" if pm.group(1).startswith("tcp") else "UDP"
    has_ca = ("<ca>" in text.lower()) or bool(re.search(r"(?mi)^\s*ca\s+\S+", text))
    info.update({"server": host, "port": port, "transport": transport,
                 "has_ca": has_ca})
    if not info["has_client"] or not host or not (0 < port < 65536):
        return info, "invalid"
    if not has_ca:
        return info, "unverified"          # structure ok, cert missing/external
    return info, "valid_structure"


# -------------------------------------------------------- naming/registry

def country_name(cc=None, fallback=None):
    if fallback:
        return fallback.replace(" ", "-")
    if cc and cc.upper() in cfg.COUNTRY_NAMES:
        return cfg.COUNTRY_NAMES[cc.upper()]
    return cfg.UNKNOWN_COUNTRY


def taken_filenames(state):
    used = {e["filename"] for e in state["registry"].values()}
    used |= {v["filename"] for v in state["vpnbook_names"].values()
             if isinstance(v, dict) and v.get("filename")}
    return used


def assign_telegram_name(state, country, transport, port):
    used = taken_filenames(state)
    seq = int(state["country_seq"].get(country, 0)) + 1
    while f"{cfg.NAMING_PREFIX}-{country}-{seq}-{transport}-{port}.ovpn" in used:
        seq += 1
    state["country_seq"][country] = seq
    return f"{cfg.NAMING_PREFIX}-{country}-{seq}-{transport}-{port}.ovpn"


def assign_vpnbook_name(state, server, country, transport, port, sha):
    """Stable per-server filename: VPNBook's own server number is kept when
    free; collisions (with older telegram configs) bump the number once and
    the assignment is stored, so it never changes again."""
    entry = state["vpnbook_names"].get(server["id"], {})
    if entry.get("filename") and entry.get("hash") == sha:
        return entry["filename"], entry["num"]
    used = taken_filenames(state)
    seq = int(entry.get("num") or server["num"])
    while True:
        fn = f"{cfg.NAMING_PREFIX}-{country}-{seq}-{transport}-{port}.ovpn"
        if fn not in used:
            break
        seq += 1
    state["vpnbook_names"][server["id"]] = {"num": seq, "filename": fn, "hash": sha}
    return fn, seq


# ------------------------------------------------------------ item intake

class Collector:
    def __init__(self, state):
        self.state = state
        self.stats = {"raw": 0, "added": 0, "duplicate": 0, "invalid": 0,
                      "by_source": {}}

    def add(self, content, source, published_dt, vpnbook_id=None,
            vpnbook_server=None, vpnbook_creds=None):
        """Validate + dedupe + name + register one candidate config."""
        self.stats["raw"] += 1
        st = self.state
        text = content.replace("\r\n", "\n").strip() + "\n"
        sha = sha_hex(text)
        info, status = parse_ovpn(text)
        if status == "invalid":
            self.stats["invalid"] += 1
            self._bump(source, "invalid")
            return "invalid"
        reg = st["registry"]
        if sha in reg:
            self.stats["duplicate"] += 1
            self._bump(source, "duplicate")
            return "duplicate"

        country = cfg.UNKNOWN_COUNTRY
        cc = ""
        flag = ""
        if vpnbook_server:                      # trusted metadata from VPNBook
            cc = vpnbook_server.get("cc", "")
            country = country_name(cc, fallback=vpnbook_server.get("country"))
        else:
            ip = geoip.resolve(info["server"]) if info["server"] else None
            cc = (geoip.country(ip) or "") if ip else ""
            country = country_name(cc or None)
        if cc:
            flag = geoip.flag(cc)

        if vpnbook_id:
            filename, _num = assign_vpnbook_name(
                st, vpnbook_server, country, info["transport"], info["port"], sha)
            # content changed for this server -> drop the old version
            old = st["vpnbook_names"].get(vpnbook_id, {})
            if old.get("hash") and old["hash"] != sha and old["hash"] in reg:
                reg.pop(old["hash"], None)
        else:
            filename = assign_telegram_name(st, country, info["transport"],
                                            info["port"])

        out = {
            "id": f"ovpn-{sha[:16]}",
            "filename": filename,
            "country": country,
            "country_code": cc,
            "flag": flag,
            "city": "",
            "server": info["server"],
            "port": info["port"],
            "transport": info["transport"],
            "source": source,
            "published_at": iso(published_dt or now_utc()),
            "collected_at": iso(now_utc()),
            "hash": sha,
            "status": "new" if status == "valid_structure" else status,
            "config": text,
            "vpnbook_id": vpnbook_id or "",
        }
        reg[sha] = out
        self.stats["added"] += 1
        self._bump(source, "added")
        return "added"

    def _bump(self, source, key):
        self.stats["by_source"].setdefault(source, {}).setdefault(key, 0)
        self.stats["by_source"][source][key] += 1


# ------------------------------------------------------------------ alive

OV_TCP_TIMEOUT = 4.0        # seconds per TCP connect
OV_UDP_TIMEOUT = 3.0        # seconds to wait for the OpenVPN handshake reply

REMOTE_RE = re.compile(r"(?m)^\s*remote\s+(\S+)\s+(\d+)\s*$")
PROTO_RE = re.compile(r"(?m)^\s*proto\s+(udp4?|tcp4?)\s*$")
TLS_SECRET_RE = re.compile(r"(?i)<tls-(?:auth|crypt)>")


def _udp_reset_packet():
    """Minimal OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2 — real servers answer
    with the server hard-reset (opcode 0x40) unless tls-auth/crypt drops it."""
    return (b"\x38" + struct.pack(">Q", random.getrandbits(64))
            + struct.pack(">I", 1))


async def _ov_check(host, port, transport, has_tls_secret, sem):
    """Returns latency_ms when the server answered, None when it did not.
    UDP configs that carry a tls-auth/tls-crypt secret are left untested (the
    plain handshake probe would be silently dropped) and stay in the list."""
    async with sem:
        if has_tls_secret:
            return -1                                    # untested — keep
        t0 = time.monotonic()
        if transport == "tcp":
            w = None
            try:
                w = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=OV_TCP_TIMEOUT)
                return int((time.monotonic() - t0) * 1000)
            except Exception:
                return None
            finally:
                if w:
                    try:
                        w.close()
                    except Exception:
                        pass
        loop = asyncio.get_running_loop()
        fut = loop.create_future()

        class _P(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                if not fut.done():
                    fut.set_result(data)

            def error_received(self, exc):
                if not fut.done() and isinstance(exc, Exception):
                    fut.set_exception(exc)

        tr = None
        try:
            tr, _pr = await asyncio.wait_for(
                loop.create_datagram_endpoint(_P, remote_addr=(host, port)),
                timeout=OV_UDP_TIMEOUT)
            tr.sendto(_udp_reset_packet())
            data = await asyncio.wait_for(fut, timeout=OV_UDP_TIMEOUT)
            return int((time.monotonic() - t0) * 1000) if data else None
        except Exception:
            return None
        finally:
            if tr:
                try:
                    tr.close()
                except Exception:
                    pass


PINGS_FILE = os.path.join(ROOT, "pings.json")


def _save_pings(pings_new):
    """Merge fresh {host:port: latency_ms} into the shared pings.json."""
    try:
        with open(PINGS_FILE, encoding="utf-8") as f:
            merged = json.load(f)
    except Exception:
        merged = {}
    merged.update(pings_new)
    try:
        tmp = PINGS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(merged, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, PINGS_FILE)
        print(f"[+] pings.json: {len(merged)} entries")
    except Exception as e:
        print(f"[x] pings.json write failed: {type(e).__name__}: {e}")


def run_openvpn_alive_checks(entries):
    """entries: {hash: entry}. Returns {filename: latency_ms or -1 (untested)
    or None (dead)}. Dead configs are dropped from publication this run."""
    probes = {}
    for e in entries.values():
        rm = REMOTE_RE.search(e["config"])
        pm = PROTO_RE.search(e["config"])
        if not rm or not pm:
            probes[e["filename"]] = (None, None, None, False)
            continue
        transport = pm.group(1).rstrip("4")
        probes[e["filename"]] = (rm.group(1), int(rm.group(2)), transport,
                                 bool(TLS_SECRET_RE.search(e["config"])))
    sem = asyncio.Semaphore(300)

    async def run():
        items = list(probes.items())
        print(f"[i] openvpn alive-check on {len(items)} configs")
        results = {}
        BATCH = 1000
        for i in range(0, len(items), BATCH):
            chunk = items[i:i + BATCH]
            out = await asyncio.gather(*[
                _ov_check(h, p, t, tls, sem)
                for _fn, (h, p, t, tls) in chunk])
            results.update({fn: ms for (fn, _pr), ms in zip(chunk, out)})
        return results

    results = asyncio.run(run())
    pings, alive, dead = {}, {}, 0
    for fn, ms in results.items():
        h, p, _t, _tls = probes[fn]
        if ms is None:
            dead += 1
            alive[fn] = None
        else:
            alive[fn] = ms                       # -1 = untested, >0 = ms
            if ms > 0 and h and p:
                pings[f"{h}:{p}"] = ms
    if pings:
        _save_pings(pings)
    n_alive = sum(1 for v in alive.values() if v is not None)
    print(f"[i] openvpn alive: {n_alive} / {len(alive)} (dead: {dead})")
    return alive


# ------------------------------------------------------------------ outputs

def prune_registry(state):
    reg = state["registry"]
    if len(reg) <= cfg.MAX_REGISTRY:
        return
    keep = sorted(reg.items(), key=lambda kv: kv[1]["collected_at"],
                  reverse=True)[:cfg.MAX_REGISTRY]
    state["registry"] = dict(keep)


def build_zip(path, files):
    buf = zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED)
    try:
        for name in sorted(files):
            buf.writestr(name, files[name])
    finally:
        buf.close()


def write_outputs(state, creds, run_meta):
    now = now_utc()
    reg = state["registry"]
    # statuses from earlier runs: "new" ages into "valid_structure"
    run_start = run_meta.get("run_start_iso", "")
    for e in reg.values():
        if e["status"] == "new" and (not run_start or e["collected_at"] < run_start):
            e["status"] = "valid_structure"

    # configs still young enough to be published (VPNBook is always fresh)
    retention_cut = now - timedelta(hours=cfg.RETENTION_HOURS)
    active = {h: e for h, e in reg.items()
              if e.get("vpnbook_id")
              or (parse_iso(e["collected_at"]) or now) >= retention_cut}

    # ---------- alive-check: only configs that actually answer get published --
    alive = run_openvpn_alive_checks(active)
    active = {h: e for h, e in active.items()
              if alive.get(e["filename"]) is not None}

    # ---------- openvpn.json (no source fields, no config bodies) ------------
    countries = {}
    for e in active.values():
        c = countries.setdefault(e["country"], {
            "country": e["country"], "country_code": e["country_code"],
            "flag": e["flag"], "count": 0})
        c["count"] += 1
    embed = bool(creds and cfg.VPNBOOK_EMBED_CREDS)
    doc = {
        "project": "MSN Collector",
        "developer": "Mehdi Sedighinasab",
        "protocol": "OpenVPN",
        "last_update": iso(now),
        "total": len(active),
        "countries": sorted(countries.values(), key=lambda c: -c["count"]),
        "configs": sorted(
            [{"id": e["id"], "filename": e["filename"], "country": e["country"],
              "country_code": e["country_code"], "flag": e["flag"],
              "port": e["port"], "transport": e["transport"],
              "server": e["server"], "collected_at": e["collected_at"]}
             for e in active.values()],
            key=lambda e: (e["country"], e["filename"])),
    }
    save_json(os.path.join(ROOT, cfg.OPENVPN_JSON_FILE), doc)
    # byte-exact copy of the repo-level JSON ships inside the ZIP too
    with open(os.path.join(ROOT, cfg.OPENVPN_JSON_FILE), "rb") as fh:
        json_bytes = fh.read()

    # ---------- openvpn/<name>.ovpn — one standalone file per config ---------
    # credentials are embedded inside the .ovpn text itself, so every single
    # file works on its own when downloaded individually.
    ov_dir = os.path.join(ROOT, cfg.OPENVPN_DIR)
    os.makedirs(ov_dir, exist_ok=True)
    wanted = {}
    for e in active.values():
        content = e["config"]
        if e.get("vpnbook_id") and embed:
            content = inject_inline_creds(content, creds["username"],
                                          creds["password"])
        wanted[e["filename"]] = content.encode("utf-8")
    for name, data in wanted.items():
        with open(os.path.join(ov_dir, name), "wb") as f:
            f.write(data)
    for stale in sorted(set(os.listdir(ov_dir)) - set(wanted)):
        os.remove(os.path.join(ov_dir, stale))

    # ---------- openvpn.zip — ONE merged package, no per-source folders ------
    for legacy in cfg.LEGACY_ZIP_FILES:            # drop the old branded zips
        p = os.path.join(ROOT, legacy)
        if os.path.exists(p):
            os.remove(p)
    if wanted:                                     # zero configs -> keep old zip
        main_files = dict(wanted)
        main_files[cfg.OPENVPN_JSON_FILE] = json_bytes
        main_files["README.txt"] = OPENVPN_README.encode("utf-8")
        main_path = os.path.join(ROOT, cfg.OPENVPN_ZIP_FILE)
        manifest_main = {k: sha_hex(v.decode("utf-8", "replace"))
                         for k, v in main_files.items()}
        if state.get("manifest") != manifest_main or not os.path.exists(main_path):
            build_zip(main_path, main_files)
            state["manifest"] = manifest_main
            run_meta["main_zip_rebuilt"] = True
    # if nothing valid was found: previous zip stays untouched (spec rule)

    # ---------- last_update + state ----------
    with open(os.path.join(ROOT, cfg.OPENVPN_LASTUPD_FILE), "w",
              encoding="utf-8") as f:
        f.write(f"OpenVPN: {iso(now)} UTC\n")
    state["runs"] = (state.get("runs", []) + [run_meta["summary"]])[-10:]
    prune_registry(state)
    save_state(state)


# ------------------------------------------------------------------ texts

OPENVPN_README = """MSN Collector — OpenVPN package
================================
Every .ovpn file in this package is standalone: wherever a login is
required, the username and password are already embedded inside the file
itself (<auth-user-pass> block, OpenVPN 2.4+). Just import and connect —
no manual login is needed.

Files are also available individually (openvpn/<name>.ovpn), and the
metadata of all servers lives in openvpn.json.

Shared credentials rotate every 1-2 weeks — re-download the package when
connections stop working.
"""

AUTH_REQUIRED = """AUTH REQUIRED
=============
Credentials could not be fetched automatically this run.
The affected configs need a username/password on connect, or you can
create a file next to the .ovpn file:
    line 1: username
    line 2: password
and set `auth-user-pass that-file` in the .ovpn file.
"""


# -------------------------------------------------------------------- main

def main():
    t0 = time.time()
    print("=" * 60)
    print("MSN OpenVPN Collector started")
    try:
        geoip.geo()
    except Exception as e:
        print(f"[geoip] unavailable: {e}")

    state = load_state()
    col = Collector(state)
    now = now_utc()
    cutoff = now - timedelta(hours=cfg.FRESHNESS_HOURS)
    run_meta = {"sources": [], "summary": {}, "run_start_iso": iso(now)}

    # ---------------- 1) VPNBook (web) ----------------
    creds = None
    try:
        servers, err = vpnbook_fetch_servers()
        page_html = ""
        try:
            page_html = http_get(cfg.VPNBOOK_PAGE_URLS[0])
        except Exception:
            pass
        creds = vpnbook_credentials(page_html) if page_html else None
        src_info = {"name": "vpnbook.com", "type": "web", "status": "ok",
                    "servers": len(servers), "downloads_ok": 0,
                    "configs_collected": 0, "credentials": "not_found",
                    "password_last_changed": "", "error": err or ""}
        if creds:
            src_info["credentials"] = ("embedded" if cfg.VPNBOOK_EMBED_CREDS
                                       else "found-not-embedded")
            src_info["password_last_changed"] = creds.get("changed", "")
            state["vpnbook"]["username"] = creds["username"]
            state["vpnbook"]["password_last_changed"] = creds.get("changed", "")
            state["vpnbook"]["creds_found"] = True
        if err:
            src_info["status"] = "unavailable"
            print(f"[x] VPNBook unavailable: {err}")
        else:
            ok = fail = 0
            for srv in servers:
                for proto_key, (tr, port) in cfg.VPNBOOK_PROTOCOLS.items():
                    try:
                        text = vpnbook_download_config(srv, proto_key)
                        r = col.add(text, "vpnbook.com", now,
                                    vpnbook_id=srv["id"], vpnbook_server=srv,
                                    vpnbook_creds=creds)
                        ok += 1
                    except Exception:
                        fail += 1
                    time.sleep(cfg.VPNBOOK_DL_DELAY)
            src_info["downloads_ok"] = ok
            src_info["configs_collected"] = col.stats["by_source"].get(
                "vpnbook.com", {}).get("added", 0)
            print(f"[+] VPNBook: {len(servers)} servers, {ok} configs downloaded"
                  f" ({fail} failed), credentials: {src_info['credentials']}")
        run_meta["sources"].append(src_info)
    except Exception as e:
        run_meta["sources"].append({"name": "vpnbook.com", "type": "web",
                                    "status": "unavailable",
                                    "error": f"{type(e).__name__}: {e}"})
        print(f"[x] VPNBook block failed: {e}")

    # ---------------- 2) Telegram channels ----------------
    channels = load_channels()
    print(f"[i] {len(channels)} OpenVPN Telegram channels loaded")
    have_creds = bool(cfg.TG_API_ID and cfg.TG_API_HASH and cfg.TG_SESSION)

    def tg_add(content, source, dt):
        return col.add(content, source, dt)

    for name in channels:
        src_info = {"name": name, "type": "telegram", "status": "ok",
                    "attachments": 0, "new_messages": 0, "new_configs": 0,
                    "last_msg_id": state["channels"].get(name, {}).get("last_msg_id", 0),
                    "error": ""}
        try:
            pages = fetch_preview(name, state, cutoff)
            if not pages:
                raise RuntimeError("no preview pages fetched")
            msgs = parse_messages(name, pages)
            fresh = [m for m in msgs if m["date"] and m["date"] >= cutoff
                     and m["id"] > max(int(state["channels"].get(name, {})
                                            .get("last_msg_id", 0)) - REWIND, 0)]
            src_info["attachments"] = sum(
                1 for m in msgs for t in m["docs"] if t.lower().endswith(".ovpn"))
            src_info["new_messages"] = len(fresh)
            preview_max = max((m["id"] for m in msgs), default=0)
            for m in fresh:
                for blk in extract_ovpn_blocks(m["text"]):
                    tg_add(blk, name, m["date"])
            src_info["new_configs"] = col.stats["by_source"].get(name, {}).get("added", 0)
            src_info["last_msg_id"] = state["channels"].get(name, {}) \
                .get("last_msg_id", preview_max)
            state.setdefault("_preview_max", {})[name] = preview_max
            print(f"    [+] @{name}: {len(fresh)} new posts, "
                  f"{src_info['attachments']} .ovpn attachments seen, "
                  f"{src_info['new_configs']} text configs")
        except Exception as e:
            src_info["status"] = "unavailable"
            src_info["error"] = f"{type(e).__name__}: {e}"
            print(f"    [x] @{name}: {src_info['error']}")
        run_meta["sources"].append(src_info)

    # ---------------- 3) MTProto attachments (official API) ----------------
    mt_status = mtproto_collect(channels, state, cutoff, tg_add)
    print(f"[i] MTProto attachments: {mt_status}")
    preview_maxes = state.pop("_preview_max", {}) or {}
    if have_creds:
        # advance per-channel state to the newest id actually seen
        for name in channels:
            pm = int(preview_maxes.get(name, 0))
            st = state["channels"].setdefault(name, {})
            st["last_msg_id"] = max(int(st.get("last_msg_id", 0)), pm)
            st["updated"] = iso(now)
    else:
        for s in run_meta["sources"]:
            if s.get("type") == "telegram" and s["status"] == "ok":
                s["status"] = "unavailable"
                s["error"] = mt_status
        print("[!] attachments need MTProto credentials — see README-OPENVPN.md")

    # ---------------- 4) outputs ----------------
    n_new = col.stats["added"]
    n_dup = col.stats["duplicate"]
    n_inv = col.stats["invalid"]
    n_vb = col.stats["by_source"].get("vpnbook.com", {}).get("added", 0)
    run_meta["summary"] = {
        "ts": iso(now), "new_configs": n_new, "duplicates": n_dup,
        "invalid": n_inv, "vpnbook_new": n_vb,
        "duration_sec": round(time.time() - t0, 1),
    }
    write_outputs(state, creds, run_meta)

    dur = round(time.time() - t0, 1)
    print(f"[✓] done in {dur}s — new: {n_new} (vpnbook {n_vb}), "
          f"duplicates: {n_dup}, invalid: {n_inv}")
    print(f"[✓] outputs: {cfg.OPENVPN_JSON_FILE}, {cfg.OPENVPN_ZIP_FILE}, "
          f"{cfg.OPENVPN_DIR}/<name>.ovpn")
    return 0


if __name__ == "__main__":
    sys.exit(main())
