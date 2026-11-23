#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""One-time full harvester for outlinekeys.com key pages -> outlinekeys_cache.json
Resumable, checkpointed, flock-protected (shares the cache with collector.py).
Cache format: {url: uri-or-null}. null = page confirmed empty (404 / no key).
Fetch failures are NOT cached, so they get retried on the next run.
Lives inside the repo so ensure.sh can relaunch it after a sandbox reset."""
import fcntl
import gzip
import json
import os
import re
import ssl
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(ROOT, "outlinekeys_cache.json")
LOCK = CACHE + ".lock"
HARVEST_SENTINEL = os.path.join(ROOT, "outlinekeys_harvest.lock")
SITEMAP = "https://outlinekeys.com/sitemap.xml"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
WORKERS = 16
TIMEOUT = 60
CTX = ssl.create_default_context()

TA_RE = re.compile(r'<textarea[^>]*id="accessKey"[^>]*>(.*?)</textarea>', re.S)
URI_RE = re.compile(r'(?:ss|vless|trojan|vmess|hy2|hysteria2?|tuic|ssr)://[^\s<>"\']+')
LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>")


def cache_lock():
    f = open(LOCK, "w")
    fcntl.flock(f, fcntl.LOCK_EX)
    return f


def load_cache():
    with cache_lock():
        try:
            with open(CACHE, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {}


def merge_save(new_entries):
    """Merge new_entries into the on-disk cache atomically (flock)."""
    if not new_entries:
        return 0
    with cache_lock():
        try:
            with open(CACHE, encoding="utf-8") as fh:
                disk = json.load(fh)
        except Exception:
            disk = {}
        disk.update(new_entries)
        tmp = CACHE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(disk, fh, ensure_ascii=False)
        os.replace(tmp, CACHE)
        return len(disk)


def fetch_page(url):
    """Returns (status, text). text=None on error. Raises nothing."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "gzip"})
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=CTX) as r:
            data = r.read()
            if data[:2] == b"\x1f\x8b":
                data = gzip.decompress(data)
            return r.status, data.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return 0, None


def extract_uri(html):
    m = TA_RE.search(html)
    if m:
        u = m.group(1).strip()
        if "://" in u:
            return u.split()[0]
    m = URI_RE.search(html)
    if m:
        return m.group(0)
    return None


def key_pages():
    st, xml = fetch_page(SITEMAP)
    if st != 200 or not xml:
        print("[!] sitemap fetch failed", file=sys.stderr)
        sys.exit(1)
    return [u for u in LOC_RE.findall(xml) if "/key/" in u]


def harvest(pages):
    _harvest_inner(pages)


def _harvest_inner(pages):
    cache = load_cache()
    todo = [u for u in pages if u not in cache]
    print(f"[i] cache has {len(cache)} entries; {len(todo)} pages to harvest", flush=True)
    if not todo:
        return
    t0 = time.time()
    done = errs = found = 0
    recent = []          # sliding window of transient errors (cooldown input)
    batch = {}

    def work(url):
        st, html = fetch_page(url)
        return url, st, html

    with ThreadPoolExecutor(WORKERS) as ex:
        futs = [ex.submit(work, u) for u in todo]
        for fut in as_completed(futs):
            url, st, html = fut.result()
            done += 1
            err = not (st == 200 and html is not None)
            recent.append(err)
            recent[:] = recent[-200:]
            if st == 200 and html is not None:
                uri = extract_uri(html)
                batch[url] = uri
                if uri:
                    found += 1
            elif st == 404 or st == 410:
                batch[url] = None          # confirmed gone -> remember
            else:
                errs += 1                  # transient -> not cached, retried later
            if done % 50 == 0 or done == len(todo):
                merge_save(batch)
                batch = {}
                el = time.time() - t0
                rate = done / el
                eta = (len(todo) - done) / max(rate, 0.01)
                err_rate = sum(recent) / max(len(recent), 1)
                print(f"    {done}/{len(todo)}  ok={done-errs} err={errs} "
                      f"with_key={found}  {rate:.1f}/s  eta {eta/60:.0f}m  "
                      f"err_rate={err_rate:.0%}", flush=True)
                if err_rate > 0.5 and len(recent) >= 100:
                    print("[!] high error rate -> cooldown 120s", flush=True)
                    time.sleep(120)

    print(f"[i] pass done: {done} processed, {errs} transient errors, {found} keys found", flush=True)

    # retry transient failures up to 2 more passes
    for p in range(2):
        cache = load_cache()
        todo = [u for u in pages if u not in cache]
        if not todo:
            break
        print(f"[i] retry pass {p+1}: {len(todo)} pages, workers=8", flush=True)
        batch = {}
        with ThreadPoolExecutor(8) as ex:
            futs = [ex.submit(work, u) for u in todo]
            for fut in as_completed(futs):
                url, st, html = fut.result()
                if st == 200 and html is not None:
                    batch[url] = extract_uri(html)
                elif st in (404, 410):
                    batch[url] = None
        merge_save(batch)
    cache = load_cache()
    miss = sum(1 for u in pages if u not in cache)
    print(f"[✓] cache: {len(cache)} entries; still-missing pages: {miss}", flush=True)


if __name__ == "__main__":
    import traceback
    try:
        # sentinel FIRST (before the slow sitemap fetch) so a concurrently
        # starting collector cycle skips new-page fetching (no double hammering)
        with open(HARVEST_SENTINEL, "w") as f:
            f.write(str(os.getpid()))
        pages = key_pages()
        print(f"[i] sitemap lists {len(pages)} key pages", flush=True)
        harvest(pages)
    except Exception:
        traceback.print_exc()
        sys.exit(1)
    finally:
        try:
            os.remove(HARVEST_SENTINEL)
        except OSError:
            pass
