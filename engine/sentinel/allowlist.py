"""False positives are expected: Allow once / Always allow this source.

Always-allow entries (allowlist.json):
  {"type": "sha256" | "domain" | "sender" | "team_id", "value": "...", "added": "...", "note": "..."}

"Allow once" is stored per event (state/allow-once.json) and only silences that
exact file (path + SHA-256).

An allowlisted *source* (domain / sender / signing team) never silences hard
evidence — a VirusTotal malicious verdict, a ClamAV hit, a known-bad hash, or
EICAR. Only an exact SHA-256 entry does that, because the user chose that exact file.
"""
from __future__ import annotations

import datetime as dt
import json
from typing import List, Optional

from . import paths, actionlog

TYPES = ("sha256", "domain", "sender", "team_id")
HARD_EVIDENCE = {"eicar", "known_bad_hash", "vt_malicious", "clamav", "gsb_origin", "gsb_link", "vt_url_malicious"}


def is_hard_evidence(code: str) -> bool:
    return code in HARD_EVIDENCE or (code.startswith("att_") and code[4:] in HARD_EVIDENCE)


def _load() -> List[dict]:
    try:
        data = json.loads(paths.allowlist_path().read_text())
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def entries() -> List[dict]:
    return _load()


def add(kind: str, value: str, note: str = "") -> dict:
    if kind not in TYPES:
        raise ValueError("allowlist type must be one of %s" % ", ".join(TYPES))
    value = value.strip().lower() if kind != "team_id" else value.strip()
    if not value:
        raise ValueError("empty allowlist value")
    data = _load()
    for e in data:
        if e.get("type") == kind and e.get("value") == value:
            return e
    entry = {"type": kind, "value": value, "added": dt.datetime.now().isoformat(timespec="seconds"), "note": note}
    data.append(entry)
    paths.write_json_atomic(paths.allowlist_path(), data)
    actionlog.log("allowlist_add", type=kind, value=value, note=note)
    return entry


def remove(kind: str, value: str) -> bool:
    data = _load()
    v = value.strip().lower() if kind != "team_id" else value.strip()
    kept = [e for e in data if not (e.get("type") == kind and e.get("value") == v)]
    if len(kept) == len(data):
        return False
    paths.write_json_atomic(paths.allowlist_path(), kept)
    actionlog.log("allowlist_remove", type=kind, value=v)
    return True


def _domain_match(host: str, allowed: str) -> bool:
    host = host.lower()
    return host == allowed or host.endswith("." + allowed)


def match(sha256: str = "", host: str = "", sender: str = "", team_id: str = "") -> Optional[dict]:
    for e in _load():
        t, v = e.get("type"), e.get("value", "")
        if t == "sha256" and sha256 and sha256.lower() == v:
            return e
        if t == "domain" and host and _domain_match(host, v):
            return e
        if t == "sender" and sender and (sender.lower() == v or sender.lower().endswith("@" + v.lstrip("@"))):
            return e
        if t == "team_id" and team_id and team_id == v:
            return e
    return None


# --- allow once ----------------------------------------------------------------

def _once_path():
    return paths.state_dir() / "allow-once.json"


def allow_once(event_id: str, path: str, sha256: str) -> None:
    try:
        data = json.loads(_once_path().read_text())
    except (OSError, ValueError):
        data = []
    data.append({"event_id": event_id, "path": path, "sha256": sha256,
                 "at": dt.datetime.now().isoformat(timespec="seconds")})
    paths.write_json_atomic(_once_path(), data[-2000:])
    actionlog.log("allow_once", event_id=event_id, path=path, sha256=sha256)


def allowed_once(path: str, sha256: str) -> bool:
    try:
        data = json.loads(_once_path().read_text())
    except (OSError, ValueError):
        return False
    return any(d.get("path") == path and d.get("sha256") == sha256 for d in data)
