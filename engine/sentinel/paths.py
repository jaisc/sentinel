"""Filesystem locations and the user config.

Everything Sentinel writes stays under the user's home directory:

  ~/Sentinel/Reports/            human-readable reports + removal-plan JSON
  ~/.Sentinel/config.json        settings (no secrets — those live in the Keychain)
  ~/.Sentinel/allowlist.json     "Always allow this source" entries
  ~/.Sentinel/events/<id>.json   full analysis record per event
  ~/.Sentinel/events.jsonl       one-line-per-event feed (menu-bar app reads this)
  ~/.Sentinel/Quarantine/<id>/   reversible quarantine (items + manifest.json)
  ~/.Sentinel/logs/actions.log   every remove / restore / delete / allow action
  ~/.Sentinel/state/             watcher + mail-poll state, persistence baseline, caches

SENTINEL_HOME overrides the home directory (used by tests).
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path


def home() -> Path:
    return Path(os.environ.get("SENTINEL_HOME") or os.path.expanduser("~"))


def reports_dir() -> Path:
    return home() / "Sentinel" / "Reports"


def data_dir() -> Path:
    return home() / ".Sentinel"


def quarantine_dir() -> Path:
    return data_dir() / "Quarantine"


def events_dir() -> Path:
    return data_dir() / "events"


def events_feed() -> Path:
    return data_dir() / "events.jsonl"


def logs_dir() -> Path:
    return data_dir() / "logs"


def state_dir() -> Path:
    return data_dir() / "state"


def config_path() -> Path:
    return data_dir() / "config.json"


def allowlist_path() -> Path:
    return data_dir() / "allowlist.json"


def ensure_dirs() -> None:
    for d in (reports_dir(), quarantine_dir(), events_dir(), logs_dir(), state_dir()):
        d.mkdir(parents=True, exist_ok=True)
    # Private data: owner-only.
    try:
        os.chmod(data_dir(), 0o700)
    except OSError:
        pass


DEFAULT_CONFIG = {
    # Folders the download watcher scans. "~" is expanded at load time.
    "watch_folders": [
        "~/Downloads",
        "~/Desktop",
        "~/Library/Mail Downloads",
        "~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads",
    ],
    # Persistence locations watched for new startup items (BlockBlock-lite).
    "persistence_folders": [
        "~/Library/LaunchAgents",
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
    ],
    "reputation": {
        "virustotal_enabled": True,
        "safebrowsing_enabled": True,
        # OFF by default. When OFF, file contents never leave the Mac — only hashes.
        "allow_file_upload": False,
        "cache_hours": 24,
    },
    "notifications": {
        "enabled": True,
        # Minimum verdict that triggers a macOS notification: "caution" or "dangerous".
        "min_verdict": "caution",
        "sound": True,
    },
    "mail": {
        "gmail_enabled": False,
        "gmail_account": "",
        # Optional read-only IMAP accounts (e.g. Yahoo with an app password in the Keychain):
        # [{"name": "yahoo", "host": "imap.mail.yahoo.com", "user": "you@yahoo.com"}]
        "imap_accounts": [],
        "lookback_hours": 24,
    },
    "watcher": {
        "settle_seconds": 2.0,
        "poll_interval_seconds": 2.0,
    },
}


def expand_path(p: str) -> Path:
    """Expand a leading "~" against home() (so SENTINEL_HOME redirects it in tests)."""
    if p == "~":
        return home()
    if p.startswith("~/"):
        return home() / p[2:]
    return Path(p)


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config() -> dict:
    p = config_path()
    user = {}
    if p.exists():
        try:
            user = json.loads(p.read_text())
        except (OSError, ValueError):
            user = {}
    return _deep_merge(DEFAULT_CONFIG, user)


def save_config(cfg: dict) -> None:
    ensure_dirs()
    write_json_atomic(config_path(), cfg)


def write_json_atomic(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=False, default=str))
    os.replace(tmp, path)
