"""Append-only action log (~/.Sentinel/logs/actions.log, one JSON object per line).

Every remove / restore / delete / allow decision is recorded here. Values passed
in are paths, hashes and IDs — never secrets.
"""
from __future__ import annotations

import datetime as dt
import json
import os

from . import paths


def log(action: str, **fields) -> None:
    paths.logs_dir().mkdir(parents=True, exist_ok=True)
    rec = {"at": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "action": action,
           "user": os.environ.get("USER", "")}
    rec.update(fields)
    with open(paths.logs_dir() / "actions.log", "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, default=str) + "\n")
