#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MSN OpenVPN Collector — configuration module
=============================================
Settings and constants for openvpn_collector.py.  This module is fully
additive: nothing here is imported by (or modifies) the existing
collector.py / mtproto_collector.py pipeline.

Environment overrides (all optional):
    OPENVPN_FRESHNESS_HOURS   max age of a post to count as "new"   (default 24)
    OPENVPN_RETENTION_HOURS   how long a config stays in the ZIP     (default 72)
    OPENVPN_TG_API_ID         Telegram MTProto api_id  (enables .ovpn attachment
    OPENVPN_TG_API_HASH       downloads; falls back to TG_API_ID / TG_API_HASH)
    OPENVPN_TG_SESSION        Telethon StringSession value
    VPNBOOK_EMBED_CREDS       1 = inject <auth-user-pass> into VPNBook .ovpn
                              0 = ship AUTH-REQUIRED.txt instead     (default 1)
    OPENVPN_MAX_REGISTRY      max configs kept in openvpn.json/state (default 3000)
"""
import os

ROOT = os.path.dirname(os.path.abspath(__file__))

# ------------------------------------------------------------------ sources
# Telegram channels that post OpenVPN configs (one @channel per line).
# VPNBook is the only web source and is handled in code (official API).
TELEGRAM_CHANNELS_FILE = os.path.join(ROOT, "openvpn_channels.txt")
VPNBOOK_PAGE_URLS = [
    "https://www.vpnbook.com/freevpn/openvpn",
    "https://www.vpnbook.com/freevpn",
]
VPNBOOK_API_URL = "https://www.vpnbook.com/api/openvpn"
# protocol keys as offered by the VPNBook download UI -> (transport, port)
VPNBOOK_PROTOCOLS = {
    "tcp443":   ("TCP", 443),
    "tcp80":    ("TCP", 80),
    "udp53":    ("UDP", 53),
    "udp25000": ("UDP", 25000),
}
VPNBOOK_DL_DELAY = 0.3          # polite delay between API downloads
VPNBOOK_TIMEOUT = 30            # seconds per HTTP request

# ------------------------------------------------------------------ outputs
# All names are openvpn-prefixed so they can never collide with the
# existing outputs (all.txt, stats.json, wireguard*.txt, ...).
OPENVPN_JSON_FILE   = "openvpn.json"
OPENVPN_ZIP_FILE    = "openvpn.zip"          # single merged package (no source branding)
OPENVPN_DIR         = "openvpn"              # per-file downloads: openvpn/<name>.ovpn
OPENVPN_STATE_FILE  = "openvpn_state.json"
OPENVPN_LASTUPD_FILE = "openvpn_last_update.txt"
VPNBOOK_ZIP_FILE    = "mehdisedighinasab-vpnbook.zip"   # legacy — deleted on run
VPNBOOK_DIR_IN_ZIP  = "VPNBook"   # legacy — no longer used
CREDENTIALS_FILE    = "vpnbook_credentials.txt"   # legacy — no longer used
LEGACY_ZIP_FILES    = ("mehdisedighinasab-openvpn.zip",
                       "mehdisedighinasab-vpnbook.zip")  # removed by the collector

# ------------------------------------------------------------------ policy
FRESHNESS_HOURS = float(os.environ.get("OPENVPN_FRESHNESS_HOURS", "24"))
RETENTION_HOURS = float(os.environ.get("OPENVPN_RETENTION_HOURS", "72"))
MAX_REGISTRY    = int(os.environ.get("OPENVPN_MAX_REGISTRY", "3000"))

# Telegram MTProto (official API) — needed to download .ovpn attachments.
# t.me/s/ previews can not serve files, so attachments require credentials.
TG_API_ID   = int(os.environ.get("OPENVPN_TG_API_ID",
                                 os.environ.get("TG_API_ID", "0")) or 0)
TG_API_HASH = os.environ.get("OPENVPN_TG_API_HASH",
                             os.environ.get("TG_API_HASH", ""))
TG_SESSION  = os.environ.get("OPENVPN_TG_SESSION",
                             os.environ.get("TG_SESSION", ""))
TG_PAGES_MAX        = 3      # preview pages scanned per channel (~20 posts each)
TG_FETCH_TIMEOUT    = 20
TG_FETCH_DELAY      = 0.4
TG_ITER_LIMIT       = 500    # safety cap per channel for MTProto iteration

# inject <auth-user-pass> username/password into VPNBook .ovpn files?
VPNBOOK_EMBED_CREDS = os.environ.get("VPNBOOK_EMBED_CREDS", "1") not in ("0", "false", "no")

# ------------------------------------------------------------------ naming
NAMING_PREFIX    = "mehdisedighinasab"
UNKNOWN_COUNTRY  = "Unknown"
# filename pattern: PREFIX-COUNTRY-NUMBER-TCP|UDP-PORT.ovpn  (no spaces)
FILENAME_RE = r"^mehdisedighinasab-[A-Za-z-]+-\d+-(TCP|UDP)-\d+\.ovpn$"

# ISO-3166 alpha-2 -> English country name (used when only the CC is known,
# e.g. from GeoIP).  Unknown codes fall back to UNKNOWN_COUNTRY — nothing is
# ever guessed.
COUNTRY_NAMES = {
    "AE": "United-Arab-Emirates", "AL": "Albania", "AM": "Armenia", "AR": "Argentina",
    "AT": "Austria", "AU": "Australia", "AZ": "Azerbaijan", "BA": "Bosnia-Herzegovina",
    "BD": "Bangladesh", "BE": "Belgium", "BG": "Bulgaria", "BR": "Brazil",
    "BY": "Belarus", "CA": "Canada", "CH": "Switzerland", "CL": "Chile",
    "CN": "China", "CY": "Cyprus", "CZ": "Czechia", "DE": "Germany", "DK": "Denmark",
    "EE": "Estonia", "EG": "Egypt", "ES": "Spain", "FI": "Finland", "FR": "France",
    "GB": "United-Kingdom", "GE": "Georgia", "GR": "Greece", "HK": "Hong-Kong",
    "HR": "Croatia", "HU": "Hungary", "ID": "Indonesia", "IE": "Ireland",
    "IL": "Israel", "IN": "India", "IQ": "Iraq", "IS": "Iceland", "IT": "Italy",
    "JP": "Japan", "KE": "Kenya", "KG": "Kyrgyzstan", "KH": "Cambodia", "KR": "South-Korea",
    "KZ": "Kazakhstan", "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia",
    "MD": "Moldova", "MK": "North-Macedonia", "MN": "Mongolia", "MT": "Malta",
    "MX": "Mexico", "MY": "Malaysia", "NG": "Nigeria", "NL": "Netherlands",
    "NO": "Norway", "NP": "Nepal", "NZ": "New-Zealand", "PH": "Philippines",
    "PK": "Pakistan", "PL": "Poland", "PT": "Portugal", "RO": "Romania",
    "RS": "Serbia", "RU": "Russia", "SA": "Saudi-Arabia", "SE": "Sweden",
    "SG": "Singapore", "SI": "Slovenia", "SK": "Slovakia", "TH": "Thailand",
    "TJ": "Tajikistan", "TM": "Turkmenistan", "TR": "Turkey", "TW": "Taiwan",
    "UA": "Ukraine", "US": "United-States", "UZ": "Uzbekistan", "VN": "Vietnam",
    "ZA": "South-Africa",
}

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
