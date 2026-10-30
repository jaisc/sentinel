"""Where did this file come from? (macOS quarantine metadata)

Three sources, combined:

1. The `com.apple.quarantine` extended attribute, set by browsers/Mail/AirDrop on
   every downloaded file. Format: "flags;hex-unix-time;agent-name;event-UUID",
   e.g. "0083;6720a1b2;Brave Browser;5A1C...". It carries the downloading app and
   the time — but NOT the URL itself.
2. The LaunchServices QuarantineEventsV2 database
   (~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2), keyed by
   that event UUID, which records the download URL, the page it came from, and
   (for Mail) the sender.
3. The `com.apple.metadata:kMDItemWhereFroms` attribute — a binary plist array,
   usually [download URL, referring page] (Mail stores the sender/message instead).
"""
from __future__ import annotations

import datetime as dt
import os
import plistlib
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional

QUARANTINE_XATTR = "com.apple.quarantine"
WHEREFROMS_XATTR = "com.apple.metadata:kMDItemWhereFroms"
COCOA_EPOCH = dt.datetime(2001, 1, 1, tzinfo=dt.timezone.utc)

# Bits in the quarantine flags field (from LaunchServices headers / observed values).
QTN_FLAG_DOWNLOAD = 0x0001
QTN_FLAG_SANDBOX = 0x0002
QTN_FLAG_HARD = 0x0004
QTN_FLAG_USER_APPROVED = 0x0040


@dataclass
class QuarantineInfo:
    present: bool = False
    raw: str = ""
    flags: int = 0
    timestamp: Optional[str] = None          # ISO 8601 UTC
    agent: str = ""                          # e.g. "Brave Browser", "Mail", "sharingd" (AirDrop)
    event_id: str = ""
    user_approved: bool = False              # Gatekeeper already approved an open
    data_url: str = ""                       # the URL the bytes were downloaded from
    origin_url: str = ""                     # the page that linked to it
    sender_name: str = ""
    sender_address: str = ""
    where_froms: List[str] = field(default_factory=list)

    def best_origin(self) -> str:
        return self.data_url or (self.where_froms[0] if self.where_froms else "") or self.origin_url

    def to_dict(self) -> dict:
        return asdict(self)


def parse_quarantine_value(raw: str) -> QuarantineInfo:
    """Parse the com.apple.quarantine attribute string."""
    info = QuarantineInfo(present=True, raw=raw.strip())
    parts = info.raw.split(";")
    if parts and parts[0]:
        try:
            info.flags = int(parts[0], 16)
        except ValueError:
            pass
    if len(parts) > 1 and parts[1]:
        try:
            ts = int(parts[1], 16)
            info.timestamp = dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            pass
    if len(parts) > 2:
        info.agent = parts[2]
    if len(parts) > 3:
        info.event_id = parts[3]
    info.user_approved = bool(info.flags & QTN_FLAG_USER_APPROVED)
    return info


def parse_where_froms(data: bytes) -> List[str]:
    """Decode the kMDItemWhereFroms binary (or XML) plist into a list of strings."""
    try:
        val = plistlib.loads(data)
    except Exception:
        return []
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return [v for v in val if isinstance(v, str) and v]
    return []


def lookup_quarantine_event(event_id: str, db_path: Optional[Path] = None) -> dict:
    """Read the download URL etc. for a quarantine event UUID (read-only)."""
    if not event_id:
        return {}
    db_path = db_path or Path(os.path.expanduser(
        "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"))
    if not db_path.exists():
        return {}
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=2)
        try:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM LSQuarantineEvent WHERE LSQuarantineEventIdentifier = ? COLLATE NOCASE",
                (event_id,)).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return {}
    if not row:
        return {}
    keys = row.keys()
    out = {}
    for k in ("LSQuarantineDataURLString", "LSQuarantineOriginURLString", "LSQuarantineSenderName",
              "LSQuarantineSenderAddress", "LSQuarantineAgentName", "LSQuarantineAgentBundleIdentifier"):
        if k in keys and row[k]:
            out[k] = str(row[k])
    if "LSQuarantineTimeStamp" in keys and row["LSQuarantineTimeStamp"] is not None:
        try:
            out["timestamp"] = (COCOA_EPOCH + dt.timedelta(seconds=float(row["LSQuarantineTimeStamp"]))).isoformat()
        except (TypeError, ValueError, OverflowError):
            pass
    return out


def read_xattr(path: Path, name: str) -> Optional[bytes]:
    """Read an extended attribute. macOS: via /usr/bin/xattr (Python's os has no xattr API there)."""
    if hasattr(os, "getxattr"):  # Linux
        for candidate in (name, "user." + name):
            try:
                return os.getxattr(str(path), candidate)
            except OSError:
                continue
        return None
    if not shutil.which("xattr"):
        return None
    try:
        out = subprocess.run(["xattr", "-px", name, str(path)], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    try:
        return bytes.fromhex("".join(out.stdout.split()))
    except ValueError:
        return None


def read_quarantine(path: Path, db_path: Optional[Path] = None) -> QuarantineInfo:
    raw = read_xattr(path, QUARANTINE_XATTR)
    info = parse_quarantine_value(raw.decode("utf-8", "replace")) if raw else QuarantineInfo()
    wf = read_xattr(path, WHEREFROMS_XATTR)
    if wf:
        info.where_froms = parse_where_froms(wf)
    if info.event_id:
        ev = lookup_quarantine_event(info.event_id, db_path)
        info.data_url = ev.get("LSQuarantineDataURLString", "")
        info.origin_url = ev.get("LSQuarantineOriginURLString", "")
        info.sender_name = ev.get("LSQuarantineSenderName", "")
        info.sender_address = ev.get("LSQuarantineSenderAddress", "")
        if not info.agent:
            info.agent = ev.get("LSQuarantineAgentName", "")
    return info
