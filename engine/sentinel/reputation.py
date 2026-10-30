"""Reputation lookups — the ONLY network calls Sentinel makes.

* VirusTotal v3: file-hash lookup (GET /files/{sha256}) and URL lookup
  (GET /urls/{id}). Lookups only: Sentinel never submits URLs for scanning and
  never uploads file contents unless `reputation.allow_file_upload` is turned on
  AND the user runs `sentinel vt-upload <file>` and confirms.
* Google Safe Browsing v4 Lookup API (threatMatches:find) for URLs.

API keys are read from the Keychain at call time and never logged. Results are
cached locally (keyed by a hash of the value, so the cache is not a plaintext
browsing history).
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Callable, Dict, List, Optional

from . import __version__, keychain, paths

VT_BASE = "https://www.virustotal.com/api/v3"
GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
VT_FREE_PER_MINUTE = 4
VT_MAX_UPLOAD = 32 * 1024 * 1024
USER_AGENT = "Sentinel/%s (personal, local-first)" % __version__


class HttpResult:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self.body = body

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8") or "{}")
        except ValueError:
            return {}


def _default_http(method: str, url: str, headers: Dict[str, str], body: Optional[bytes] = None,
                  timeout: int = 15) -> HttpResult:
    req = urllib.request.Request(url, data=body, method=method, headers=dict(headers, **{"User-Agent": USER_AGENT}))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return HttpResult(r.status, r.read())
    except urllib.error.HTTPError as e:
        return HttpResult(e.code, e.read() if hasattr(e, "read") else b"")
    except (urllib.error.URLError, OSError, ValueError) as e:
        # Deliberately do not include the request URL (it can contain an API key).
        return HttpResult(0, json.dumps({"error": type(e).__name__}).encode())


# Tests replace this to run fully offline.
http = _default_http  # type: Callable[..., HttpResult]


# --- local cache ---------------------------------------------------------------

def _cache_file() -> Path:
    return paths.state_dir() / "reputation-cache.json"


def _cache_key(kind: str, value: str) -> str:
    return hashlib.sha256(("%s:%s" % (kind, value)).encode("utf-8")).hexdigest()


def _cache_load() -> dict:
    try:
        return json.loads(_cache_file().read_text())
    except (OSError, ValueError):
        return {}


def cache_get(kind: str, value: str, max_age_hours: float) -> Optional[dict]:
    entry = _cache_load().get(_cache_key(kind, value))
    if entry and time.time() - entry.get("t", 0) < max_age_hours * 3600:
        return entry.get("r")
    return None


def cache_put(kind: str, value: str, result: dict) -> None:
    if result.get("status") in ("error", "rate_limited", "no_key", "disabled"):
        return
    data = _cache_load()
    data[_cache_key(kind, value)] = {"t": time.time(), "r": result}
    if len(data) > 5000:  # keep it bounded
        for k, _ in sorted(data.items(), key=lambda kv: kv[1].get("t", 0))[: len(data) - 4000]:
            data.pop(k, None)
    try:
        paths.write_json_atomic(_cache_file(), data)
    except OSError:
        pass


# --- VirusTotal rate limiting (free tier: 4 requests/minute) ---------------------

def _vt_slot(wait: bool) -> bool:
    f = paths.state_dir() / "vt-rate.json"
    try:
        stamps = [t for t in json.loads(f.read_text()) if time.time() - t < 60]
    except (OSError, ValueError):
        stamps = []
    if len(stamps) >= VT_FREE_PER_MINUTE:
        if not wait:
            return False
        time.sleep(max(0.0, 60 - (time.time() - min(stamps))) + 0.5)
        stamps = [t for t in stamps if time.time() - t < 60]
    stamps.append(time.time())
    try:
        paths.write_json_atomic(f, stamps)
    except OSError:
        pass
    return True


def _cfg() -> dict:
    return paths.load_config().get("reputation", {})


# --- VirusTotal ---------------------------------------------------------------

def _vt_summary(attrs: dict) -> dict:
    stats = attrs.get("last_analysis_stats") or {}
    total = sum(v for v in stats.values() if isinstance(v, int))
    label = ((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label") or "")
    return {"malicious": int(stats.get("malicious", 0)), "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)), "undetected": int(stats.get("undetected", 0)),
            "total": total, "label": label}


def vt_file(sha256: str, wait: bool = True) -> dict:
    link = "https://www.virustotal.com/gui/file/%s" % sha256
    base = {"service": "virustotal", "kind": "file", "link": link}
    if not _cfg().get("virustotal_enabled", True):
        return dict(base, status="disabled")
    cached = cache_get("vt-file", sha256, _cfg().get("cache_hours", 24))
    if cached:
        return dict(cached, cached=True)
    key = keychain.get("virustotal-api-key")
    if not key:
        return dict(base, status="no_key")
    if not _vt_slot(wait):
        return dict(base, status="rate_limited")
    r = http("GET", "%s/files/%s" % (VT_BASE, sha256), {"x-apikey": key, "Accept": "application/json"})
    if r.status == 404:
        res = dict(base, status="not_found")
    elif r.status == 200:
        attrs = (r.json().get("data") or {}).get("attributes") or {}
        res = dict(base, status="found", **_vt_summary(attrs))
    elif r.status == 429:
        return dict(base, status="rate_limited")
    else:
        return dict(base, status="error", http_status=r.status)
    cache_put("vt-file", sha256, res)
    return res


def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def vt_url(url: str, wait: bool = False) -> dict:
    uid = vt_url_id(url)
    base = {"service": "virustotal", "kind": "url",
            "link": "https://www.virustotal.com/gui/url/%s" % hashlib.sha256(url.encode()).hexdigest()}
    if not _cfg().get("virustotal_enabled", True):
        return dict(base, status="disabled")
    cached = cache_get("vt-url", url, _cfg().get("cache_hours", 24))
    if cached:
        return dict(cached, cached=True)
    key = keychain.get("virustotal-api-key")
    if not key:
        return dict(base, status="no_key")
    if not _vt_slot(wait):
        return dict(base, status="rate_limited")
    r = http("GET", "%s/urls/%s" % (VT_BASE, uid), {"x-apikey": key, "Accept": "application/json"})
    if r.status == 404:
        res = dict(base, status="not_found")
    elif r.status == 200:
        attrs = (r.json().get("data") or {}).get("attributes") or {}
        res = dict(base, status="found", **_vt_summary(attrs))
    elif r.status == 429:
        return dict(base, status="rate_limited")
    else:
        return dict(base, status="error", http_status=r.status)
    cache_put("vt-url", url, res)
    return res


def vt_upload(path: Path, confirmed: bool) -> dict:
    """Upload file CONTENTS to VirusTotal. Double-gated: config toggle + explicit confirmation."""
    if not _cfg().get("allow_file_upload", False):
        return {"service": "virustotal", "status": "blocked",
                "detail": "File upload is OFF. Turn on reputation.allow_file_upload in Settings first."}
    if not confirmed:
        return {"service": "virustotal", "status": "blocked", "detail": "Upload needs explicit confirmation."}
    key = keychain.get("virustotal-api-key")
    if not key:
        return {"service": "virustotal", "status": "no_key"}
    data = Path(path).read_bytes()
    if len(data) > VT_MAX_UPLOAD:
        return {"service": "virustotal", "status": "error", "detail": "File is larger than 32 MB."}
    boundary = uuid.uuid4().hex
    body = b"".join([
        b"--" + boundary.encode() + b"\r\n",
        b'Content-Disposition: form-data; name="file"; filename="sample"\r\n',
        b"Content-Type: application/octet-stream\r\n\r\n", data, b"\r\n",
        b"--" + boundary.encode() + b"--\r\n"])
    _vt_slot(True)
    r = http("POST", "%s/files" % VT_BASE, {"x-apikey": key, "Content-Type": "multipart/form-data; boundary=" + boundary},
             body, timeout=120)
    if r.status == 200:
        aid = (r.json().get("data") or {}).get("id", "")
        return {"service": "virustotal", "status": "submitted", "analysis_id": aid,
                "link": "https://www.virustotal.com/gui/file/%s" % hashlib.sha256(data).hexdigest()}
    return {"service": "virustotal", "status": "error", "http_status": r.status}


# --- Google Safe Browsing -----------------------------------------------------

GSB_THREAT_TEXT = {
    "MALWARE": "known to spread malware",
    "SOCIAL_ENGINEERING": "a known phishing / deceptive site",
    "UNWANTED_SOFTWARE": "known to push unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "known to distribute harmful apps",
}


def safe_browsing(urls: List[str]) -> Dict[str, dict]:
    """Look up many URLs in one request. Returns {url: result}."""
    out = {}  # type: Dict[str, dict]
    base = {"service": "safebrowsing"}
    if not _cfg().get("safebrowsing_enabled", True):
        return {u: dict(base, status="disabled") for u in urls}
    todo = []
    for u in urls:
        c = cache_get("gsb", u, min(_cfg().get("cache_hours", 24), 6))
        if c:
            out[u] = dict(c, cached=True)
        else:
            todo.append(u)
    if not todo:
        return out
    key = keychain.get("safebrowsing-api-key")
    if not key:
        for u in todo:
            out[u] = dict(base, status="no_key")
        return out
    payload = {
        "client": {"clientId": "sentinel-personal", "clientVersion": __version__},
        "threatInfo": {
            "threatTypes": list(GSB_THREAT_TEXT.keys()),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in todo[:500]],
        },
    }
    r = http("POST", "%s?key=%s" % (GSB_ENDPOINT, key), {"Content-Type": "application/json"},
             json.dumps(payload).encode("utf-8"))
    if r.status != 200:
        for u in todo:
            out[u] = dict(base, status="error", http_status=r.status)
        return out
    matches = {}  # type: Dict[str, List[str]]
    for m in r.json().get("matches", []) or []:
        u = (m.get("threat") or {}).get("url", "")
        matches.setdefault(u, []).append(m.get("threatType", "UNKNOWN"))
    for u in todo[:500]:
        if u in matches:
            res = dict(base, status="flagged", threats=sorted(set(matches[u])))
        else:
            res = dict(base, status="clean")
        cache_put("gsb", u, res)
        out[u] = res
    return out
