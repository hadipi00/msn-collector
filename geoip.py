#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GeoIP country lookup — pure stdlib, no external dependencies.

Source: sapics/ip-location-db "dbip-country" CSVs (DB-IP data, CC-BY 4.0).
Downloads ipv4+ipv6 range CSVs on first use (refreshed monthly), parses them
once into compact arrays and pickles the result for fast subsequent loads.

    geo()          -> True when a database is loaded (else False)
    country(ip)    -> ISO-3166 alpha-2 code or None
    flag(cc)       -> regional-indicator emoji for a country code
    resolve(host)  -> best-effort IP for a hostname
"""
import bisect
import gzip
import ipaddress
import os
import pickle
import socket
import time
import urllib.request
from array import array

ROOT = os.path.dirname(os.path.abspath(__file__))
V4_CSV = os.path.join(ROOT, "dbip-country-ipv4.csv")
V6_CSV = os.path.join(ROOT, "dbip-country-ipv6.csv")
V4_BIN = V4_CSV + ".pkl"
V6_BIN = V6_CSV + ".pkl"
SRC = "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-{fam}.csv"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
MAX_AGE = 40 * 86400          # monthly updates -> refresh after 40 days


# ------------------------------------------------------------ download/parse

def _download(path, fam):
    url = SRC.format(fam=fam)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()
        if data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
        print(f"[geoip] {os.path.basename(path)} updated ({len(data) // 1024} KB)")
        return True
    except Exception as e:
        print(f"[geoip] download failed ({fam}): {e}")
        return False


def _ipv4_int(s):
    a, b, c, d = s.split(".")
    return (int(a) << 24) | (int(b) << 16) | (int(c) << 8) | int(d)


def _parse_csv(path, v6):
    if v6:
        starts, ends = [], []          # 128-bit ints -> plain lists
    else:
        starts, ends = array("Q"), array("Q")
    ccs = []
    ip2int = (lambda s: int(ipaddress.IPv6Address(s))) if v6 else _ipv4_int
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\n").split(",")
            if len(parts) < 3:
                continue
            cc = parts[2].strip()
            if len(cc) != 2 or not cc.isalpha():
                continue
            try:
                s = ip2int(parts[0])
                e = ip2int(parts[1])
            except Exception:
                continue
            if e < s:
                continue
            starts.append(s)
            ends.append(e)
            ccs.append(cc.upper())
    return starts, ends, "".join(ccs)


def _load_db(path, binpath, fam, v6):
    need = True
    if os.path.exists(path):
        need = (time.time() - os.path.getmtime(path)) > MAX_AGE
    if need and not _download(path, fam) and not os.path.exists(path):
        return None
    if os.path.exists(binpath) and \
            os.path.getmtime(binpath) >= os.path.getmtime(path):
        try:
            with open(binpath, "rb") as f:
                return pickle.load(f)
        except Exception:
            pass
    try:
        db = _parse_csv(path, v6)
    except Exception as e:
        print(f"[geoip] parse failed ({fam}): {e}")
        return None
    try:
        tmp = binpath + ".tmp"
        with open(tmp, "wb") as f:
            pickle.dump(db, f, protocol=pickle.HIGHEST_PROTOCOL)
        os.replace(tmp, binpath)
    except Exception:
        pass
    return db


_DBS = None
_INITED = False


def geo():
    """Load (and cache) the databases. Returns True when at least v4 is ready."""
    global _DBS, _INITED
    if not _INITED:
        v4 = _load_db(V4_CSV, V4_BIN, "ipv4", v6=False)
        v6 = _load_db(V6_CSV, V6_BIN, "ipv6", v6=True)
        _DBS = {4: v4, 6: v6}
        _INITED = True
        if not v4:
            print("[geoip] no country database — configs will be named without country")
        else:
            print(f"[geoip] ready: {len(v4[0])} v4 ranges"
                  + (f", {len(v6[0])} v6 ranges" if v6 else ""))
    return bool(_DBS[4] or _DBS[6])


def country(ip):
    """ISO alpha-2 country code for an IP string, or None."""
    if not _INITED:
        geo()
    if not ip:
        return None
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.version == 6:
        m = a.ipv4_mapped
        if m:
            a = m            # ::ffff:x.x.x.x -> lookup the embedded IPv4
    db = _DBS.get(a.version)
    if not db:
        return None
    starts, ends, ccs = db
    n = int(a)
    i = bisect.bisect_right(starts, n) - 1
    if i < 0 or n > ends[i]:
        return None
    return ccs[i * 2:i * 2 + 2]


def flag(cc):
    """🇩🇪-style emoji for a 2-letter country code."""
    if not cc or len(cc) != 2:
        return ""
    out = []
    for c in cc.upper():
        if "A" <= c <= "Z":
            out.append(chr(0x1F1E6 + ord(c) - 65))
        else:
            return ""
    return "".join(out)


def resolve(host):
    """Best-effort IP resolution for a hostname (returns None on failure)."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            return socket.getaddrinfo(host, None, fam)[0][4][0]
        except Exception:
            continue
    return None
