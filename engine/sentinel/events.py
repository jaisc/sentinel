"""Event store: full records in ~/.Sentinel/events/<id>.json plus a one-line feed."""
from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import List, Optional

from . import paths

_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,120}$")


def new_id(kind: str, digest: str) -> str:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return "%s-%s-%s" % (stamp, kind, (digest or "0" * 8)[:8])


def valid_id(event_id: str) -> bool:
    return bool(_SAFE_ID.match(event_id or "")) and ".." not in event_id


def save(record: dict) -> None:
    paths.ensure_dirs()
    if not valid_id(record["id"]):
        raise ValueError("bad event id")
    paths.write_json_atomic(paths.events_dir() / ("%s.json" % record["id"]), record)


def append_feed(record: dict) -> None:
    line = {
        "id": record["id"], "kind": record.get("kind"), "verdict": record.get("verdict"),
        "title": record.get("title"), "summary": record.get("summary"), "at": record.get("first_seen"),
        "report": record.get("report_path", ""), "plan": record.get("plan_path", ""),
        "path": record.get("path", ""), "allowlisted": bool(record.get("allowlisted")),
    }
    paths.ensure_dirs()
    with open(paths.events_feed(), "a", encoding="utf-8") as f:
        f.write(json.dumps(line) + "\n")


def load(event_id: str) -> Optional[dict]:
    if not valid_id(event_id):
        return None
    p = paths.events_dir() / ("%s.json" % event_id)
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def recent(limit: int = 50) -> List[dict]:
    try:
        lines = paths.events_feed().read_text().splitlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
        if len(out) >= limit:
            break
    return out


def find_by_path(path: str) -> Optional[dict]:
    for e in recent(500):
        if e.get("path") == path:
            return load(e["id"])
    return None


def update(event_id: str, **changes) -> Optional[dict]:
    rec = load(event_id)
    if rec is None:
        return None
    rec.update(changes)
    save(rec)
    return rec


def event_file(event_id: str) -> Path:
    return paths.events_dir() / ("%s.json" % event_id)
