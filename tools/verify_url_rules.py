#!/usr/bin/env python3
"""Observe how AI web services appear in THIS machine's browser profiles.

Run it on a laptop where you actually use ChatGPT, Claude, Gemini and similar sites.
The output is used to promote rules in catalog/vendor/url_usage_rules.seed.yaml from
'unverified' to 'verified'.

Privacy guarantees (read the code; it is short):
  * Read-only. Each browser database is copied to a temp dir and the copy is read.
  * No network access of any kind.
  * URL paths are reduced to SHAPES: a segment is printed only if it is one of the
    STRUCTURAL words below; every other segment becomes {x}. Query strings and
    fragments are dropped. Conversation IDs, slugs and page titles are never output.
  * Cookies: only cookie NAMES for the listed AI hosts. Values are never read.
  * Downloads: only the source HOST and a count. File names and paths are not read.

Usage:  python3 tools/verify_url_rules.py > ai-url-observations.json
Supports Chrome, Edge, Brave, Chromium, Arc, Vivaldi, Opera and Firefox on
Windows, macOS and Linux. Python 3.8+ standard library only.
"""
import glob
import json
import os
import platform
import shutil
import sqlite3
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

AI_HOSTS = [
    "chatgpt.com", "chat.openai.com", "claude.ai", "gemini.google.com", "perplexity.ai",
    "copilot.microsoft.com", "chat.deepseek.com", "grok.com", "poe.com", "chat.mistral.ai",
    "notebooklm.google.com", "aistudio.google.com", "huggingface.co", "character.ai",
]
# googleusercontent.com is deliberately absent: obs-2026-11-05-win showed it carries Google Docs,
# Slides and Gmail attachment downloads, not AI output.
DOWNLOAD_HOST_SUFFIXES = ["oaiusercontent.com", "claude.ai", "anthropic.com",
                          "perplexity.ai", "deepseek.com", "x.ai", "grok.com", "mistral.ai"]
# --reveal-route-words: also print the FIRST path segment when it is a plain lowercase word
# (letters only, 2-24 chars). Route names like /chat or /project are this shape; IDs and
# question slugs (digits, hyphens) are not. Off by default.
ROUTE_WORD = __import__("re").compile(r"^[a-z]{2,24}$")
REVEAL_ROUTE_WORDS = "--reveal-route-words" in sys.argv
STRUCTURAL = {
    "c", "g", "chat", "chats", "app", "share", "search", "project", "projects", "gpts", "gem", "gems",
    "a", "s", "new", "library", "discover", "spaces", "notebook", "notebooks", "settings", "auth",
    "login", "signin", "logout", "api", "backend-api", "organizations", "conversation", "conversations",
    "files", "upload", "uploads", "recents", "codex", "canvas", "artifacts", "images", "explore",
    "prompts", "models", "spaces", "datasets", "u", "p", "page", "pages", "home", "account", "billing",
}
MAX_SEGMENTS = 5


def match_host(host, hosts):
    host = (host or "").lower().lstrip(".")
    for h in hosts:
        if host == h or host.endswith("." + h):
            return h
    return None


def char_classes(s):
    kinds = []
    for name, test in (("lower", str.islower), ("upper", str.isupper), ("digit", str.isdigit)):
        if any(test(ch) for ch in s):
            kinds.append(name)
    if "-" in s:
        kinds.append("hyphen")
    if "_" in s:
        kinds.append("underscore")
    if any(not (ch.isalnum() or ch in "-_") for ch in s):
        kinds.append("other")
    return "+".join(kinds) + f",len{len(s)}"


def shape(path):
    segs = [s for s in path.split("/") if s][:MAX_SEGMENTS]
    out = []
    for i, s in enumerate(segs):
        if s.lower() in STRUCTURAL or (REVEAL_ROUTE_WORDS and i == 0 and ROUTE_WORD.match(s)):
            out.append(s.lower())
        elif REVEAL_ROUTE_WORDS and i == 0:
            out.append("{x:" + char_classes(s) + "}")  # character types and length only, never content
        else:
            out.append("{x}")
    return "/" + "/".join(out) if out else "/"


def chrome_time(us):
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(us))).date().isoformat() if us else None
    except Exception:
        return None


def unix_us_time(us):
    try:
        return datetime.fromtimestamp(int(us) / 1e6, tz=timezone.utc).date().isoformat() if us else None
    except Exception:
        return None


def roots():
    home = os.path.expanduser("~")
    sysname = platform.system()
    if sysname == "Windows":
        la = os.environ.get("LOCALAPPDATA", "")
        ra = os.environ.get("APPDATA", "")
        chromium = {
            "chrome": os.path.join(la, "Google", "Chrome", "User Data"),
            "edge": os.path.join(la, "Microsoft", "Edge", "User Data"),
            "brave": os.path.join(la, "BraveSoftware", "Brave-Browser", "User Data"),
            "chromium": os.path.join(la, "Chromium", "User Data"),
            "vivaldi": os.path.join(la, "Vivaldi", "User Data"),
            "opera": os.path.join(ra, "Opera Software", "Opera Stable"),
            "arc": os.path.join(la, "Packages"),  # Arc on Windows lives under a package dir; best effort
        }
        firefox = os.path.join(ra, "Mozilla", "Firefox", "Profiles")
    elif sysname == "Darwin":
        base = os.path.join(home, "Library", "Application Support")
        chromium = {
            "chrome": os.path.join(base, "Google", "Chrome"),
            "edge": os.path.join(base, "Microsoft Edge"),
            "brave": os.path.join(base, "BraveSoftware", "Brave-Browser"),
            "chromium": os.path.join(base, "Chromium"),
            "vivaldi": os.path.join(base, "Vivaldi"),
            "arc": os.path.join(base, "Arc", "User Data"),
            "opera": os.path.join(base, "com.operasoftware.Opera"),
        }
        firefox = os.path.join(base, "Firefox", "Profiles")
    else:
        cfg = os.path.join(home, ".config")
        chromium = {
            "chrome": os.path.join(cfg, "google-chrome"),
            "edge": os.path.join(cfg, "microsoft-edge"),
            "brave": os.path.join(cfg, "BraveSoftware", "Brave-Browser"),
            "chromium": os.path.join(cfg, "chromium"),
            "vivaldi": os.path.join(cfg, "vivaldi"),
            "opera": os.path.join(cfg, "opera"),
        }
        firefox = os.path.join(home, ".mozilla", "firefox")
        if not os.path.isdir(firefox):
            firefox = os.path.join(home, "snap", "firefox", "common", ".mozilla", "firefox")
    return chromium, firefox


def copy_db(path, tmp):
    if not os.path.isfile(path):
        return None
    dst = os.path.join(tmp, f"{abs(hash(path))}.sqlite")
    try:
        shutil.copy2(path, dst)
    except PermissionError:
        # Windows: a running browser can hold the file locked (seen with Edge cookies).
        raise PermissionError(f"locked by a running browser; close that browser and rerun ({os.path.basename(path)})")
    for ext in ("-wal", "-journal"):
        if os.path.isfile(path + ext):
            shutil.copy2(path + ext, dst + ext)
    return dst


def query(db, sql):
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


class Acc:
    def __init__(self):
        self.paths = defaultdict(lambda: {"urls": 0, "visits": 0, "last_seen": None})
        self.cookies = defaultdict(set)
        self.downloads = defaultdict(int)
        self.profiles = []
        self.errors = []

    def path(self, host, url, visits, last):
        s = urlsplit(url)
        k = (host, shape(s.path))
        p = self.paths[k]
        p["urls"] += 1
        p["visits"] += int(visits or 0)
        if last and (p["last_seen"] is None or last > p["last_seen"]):
            p["last_seen"] = last


def scan_chromium(name, root, acc, tmp):
    for hist in glob.glob(os.path.join(root, "*", "History")) + glob.glob(os.path.join(root, "History")):
        prof = os.path.dirname(hist)
        label = f"{name}:{os.path.basename(prof)}"
        acc.profiles.append(label)
        try:
            db = copy_db(hist, tmp)
            for url, visits, last in query(db, "SELECT url, visit_count, last_visit_time FROM urls"):
                h = match_host(urlsplit(url).hostname, AI_HOSTS)
                if h:
                    acc.path(h, url, visits, chrome_time(last))
            try:
                for (u,) in query(db, "SELECT url FROM downloads_url_chains"):
                    dh = (urlsplit(u).hostname or "").lower()
                    if match_host(dh, DOWNLOAD_HOST_SUFFIXES):
                        acc.downloads[dh] += 1
            except sqlite3.Error:
                pass
        except Exception as e:
            acc.errors.append(f"{label} history: {type(e).__name__}: {e}")
        for cpath in (os.path.join(prof, "Network", "Cookies"), os.path.join(prof, "Cookies")):
            try:
                db = copy_db(cpath, tmp)
                if not db:
                    continue
                for host_key, cname in query(db, "SELECT host_key, name FROM cookies"):
                    h = match_host(host_key, AI_HOSTS)
                    if h:
                        acc.cookies[h].add(cname)
                break
            except Exception as e:
                acc.errors.append(f"{label} cookies: {type(e).__name__}: {e}")


def scan_firefox(root, acc, tmp):
    for places in glob.glob(os.path.join(root, "*", "places.sqlite")):
        prof = os.path.dirname(places)
        label = f"firefox:{os.path.basename(prof)}"
        acc.profiles.append(label)
        try:
            db = copy_db(places, tmp)
            for url, visits, last in query(db, "SELECT url, visit_count, last_visit_date FROM moz_places"):
                h = match_host(urlsplit(url).hostname, AI_HOSTS)
                if h:
                    acc.path(h, url, visits, unix_us_time(last))
            try:
                rows = query(db, "SELECT p.url FROM moz_annos a JOIN moz_places p ON p.id=a.place_id "
                                 "JOIN moz_anno_attributes t ON t.id=a.anno_attribute_id WHERE t.name='downloads/destinationFileURI'")
                for (u,) in rows:
                    dh = (urlsplit(u).hostname or "").lower()
                    if match_host(dh, DOWNLOAD_HOST_SUFFIXES):
                        acc.downloads[dh] += 1
            except sqlite3.Error:
                pass
        except Exception as e:
            acc.errors.append(f"{label} history: {type(e).__name__}: {e}")
        try:
            db = copy_db(os.path.join(prof, "cookies.sqlite"), tmp)
            if db:
                for host, cname in query(db, "SELECT host, name FROM moz_cookies"):
                    h = match_host(host, AI_HOSTS)
                    if h:
                        acc.cookies[h].add(cname)
        except Exception as e:
            acc.errors.append(f"{label} cookies: {type(e).__name__}: {e}")


def main():
    acc = Acc()
    chromium, firefox = roots()
    with tempfile.TemporaryDirectory(prefix="ai-url-verify-") as tmp:
        for name, root in chromium.items():
            if os.path.isdir(root):
                scan_chromium(name, root, acc, tmp)
        if os.path.isdir(firefox):
            scan_firefox(firefox, acc, tmp)

    by_host = defaultdict(list)
    for (host, shp), v in sorted(acc.paths.items(), key=lambda kv: (-kv[1]["visits"])):
        by_host[host].append({"path_shape": shp, **v})
    out = {
        "tool": "tools/verify_url_rules.py",
        "tool_version": 3,
        "options": {"reveal_route_words": REVEAL_ROUTE_WORDS},
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "os": platform.system(),
        "profiles_scanned": acc.profiles,
        "path_shapes_by_host": {h: v[:25] for h, v in sorted(by_host.items())},
        "cookie_names_by_host": {h: sorted(n) for h, n in sorted(acc.cookies.items())},
        "download_source_hosts": dict(sorted(acc.downloads.items())),
        "errors": acc.errors,
        "privacy": "Path shapes, counts, dates, cookie NAMES and download host names only. No IDs, titles, query strings, cookie values or file names.",
    }
    json.dump(out, sys.stdout, indent=1)
    print()
    if not acc.profiles:
        print("No browser profiles found for this OS user. Run it as the user who uses the browser.", file=sys.stderr)


if __name__ == "__main__":
    main()
