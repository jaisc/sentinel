"""Persistence scan (KnockKnock-style, lightweight) and new-startup-item alerts (BlockBlock-lite).

Malware wants to survive a reboot, so it installs something that starts
automatically. Sentinel snapshots the common places and diffs them:

  * LaunchAgents / LaunchDaemons (user + system folders)   — plist contents
  * the user's crontab
  * shell startup files (~/.zshrc, ~/.zprofile, ~/.bash_profile, ...)
  * configuration profiles (`profiles list`, best-effort)
  * Login Items (via System Events, OFF by default because it triggers a macOS
    automation prompt; see config persistence.login_items)

If BlockBlock / KnockKnock are installed, the report points to them for a deeper look.
"""
from __future__ import annotations

import hashlib
import json
import os
import plistlib
from pathlib import Path
from typing import Dict, List, Optional

from . import macos, paths

SHELL_STARTUP = ["~/.zshrc", "~/.zprofile", "~/.zshenv", "~/.zlogin", "~/.bash_profile", "~/.bashrc", "~/.profile"]
SUSPICIOUS_PROGRAM_DIRS = ("/tmp/", "/private/tmp/", "/var/tmp/", "/Users/Shared/", "/Downloads/", "/.Trash/")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _launch_items(folder: Path) -> Dict[str, dict]:
    out = {}
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return out
    for n in names:
        if not n.endswith(".plist"):
            continue
        p = folder / n
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        entry = {"kind": "launch_item", "path": str(p), "sha256": _sha(raw), "label": "", "program": "",
                 "arguments": [], "run_at_load": False, "keep_alive": False, "mtime": _mtime(p)}
        try:
            pl = plistlib.loads(raw)
            entry["label"] = str(pl.get("Label", ""))
            args = pl.get("ProgramArguments") or []
            entry["program"] = str(pl.get("Program") or (args[0] if args else ""))
            entry["arguments"] = [str(a) for a in args][:20]
            entry["run_at_load"] = bool(pl.get("RunAtLoad"))
            entry["keep_alive"] = bool(pl.get("KeepAlive"))
        except Exception:
            entry["label"] = "(unreadable plist)"
        out["launch_item:%s" % p] = entry
    return out


def _mtime(p: Path) -> float:
    try:
        return p.stat().st_mtime
    except OSError:
        return 0.0


def snapshot(cfg: Optional[dict] = None) -> Dict[str, dict]:
    cfg = cfg or paths.load_config()
    snap = {}  # type: Dict[str, dict]
    for folder in cfg.get("persistence_folders", []):
        snap.update(_launch_items(paths.expand_path(folder)))
    if macos.IS_MACOS:
        rc, out, _ = macos.run(["crontab", "-l"])
        if rc == 0:
            for line in out.splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    snap["cron:%s" % _sha(s.encode())[:16]] = {"kind": "cron", "path": "crontab", "label": s[:200],
                                                               "program": s, "sha256": _sha(s.encode())}
        rc, out, _ = macos.run(["profiles", "list"])
        if rc == 0:
            for line in out.splitlines():
                if "profileIdentifier" in line:
                    ident = line.split(":", 1)[-1].strip()
                    snap["profile:%s" % ident] = {"kind": "profile", "path": "profiles", "label": ident, "program": "",
                                                  "sha256": _sha(ident.encode())}
        if cfg.get("persistence", {}).get("login_items"):
            rc, out, _ = macos.run(["osascript", "-e",
                                    'tell application "System Events" to get the path of every login item'])
            if rc == 0:
                for item in [i.strip() for i in out.split(",") if i.strip()]:
                    snap["login_item:%s" % item] = {"kind": "login_item", "path": item, "label": Path(item).name,
                                                    "program": item, "sha256": _sha(item.encode())}
    for f in SHELL_STARTUP:
        p = paths.expand_path(f)
        try:
            data = p.read_bytes()
        except OSError:
            continue
        snap["shell:%s" % p] = {"kind": "shell_startup", "path": str(p), "label": p.name, "program": "",
                                "sha256": _sha(data), "mtime": _mtime(p)}
    return snap


def baseline_path() -> Path:
    return paths.state_dir() / "persistence-baseline.json"


def load_baseline() -> Optional[Dict[str, dict]]:
    try:
        return json.loads(baseline_path().read_text())
    except (OSError, ValueError):
        return None


def save_baseline(snap: Dict[str, dict]) -> None:
    paths.write_json_atomic(baseline_path(), snap)


def diff(old: Dict[str, dict], new: Dict[str, dict]) -> Dict[str, List[dict]]:
    added = [new[k] for k in new if k not in old]
    removed = [old[k] for k in old if k not in new]
    changed = [new[k] for k in new if k in old and new[k].get("sha256") != old[k].get("sha256")]
    return {"added": added, "removed": removed, "changed": changed}


def related_to(entry: dict, file_path: str) -> bool:
    """Does a persistence entry point at (or into) the given file/bundle?"""
    if not file_path:
        return False
    hay = " ".join([entry.get("program", "")] + entry.get("arguments", []))
    fp = file_path.rstrip("/")
    return fp in hay or (Path(fp).stem and len(Path(fp).stem) >= 5 and Path(fp).stem in entry.get("label", ""))


def entry_risk(entry: dict) -> List[tuple]:
    """(points, title, why) tuples for a new/changed persistence entry."""
    out = []
    kind = entry.get("kind")
    prog = entry.get("program", "")
    if kind == "launch_item":
        out.append((45, "A new background item was set to start automatically: %s" % (entry.get("label") or Path(entry["path"]).name),
                    "Programs that add themselves to startup keep running every time you log in. Make sure you recognise it."))
        if any(d in prog for d in SUSPICIOUS_PROGRAM_DIRS) or "/." in prog:
            out.append((70, "It runs a program from an unusual or hidden location (%s)" % prog,
                        "Legitimate apps run from /Applications or /Library, not from temp, Downloads or hidden folders."))
        if entry.get("label", "").startswith("com.apple.") and "/Users/" in entry.get("path", ""):
            out.append((60, "It claims to be an Apple item but lives in your personal LaunchAgents folder",
                        "Apple never installs items there; this is a common disguise."))
        if prog and os.path.exists(prog):
            sig = macos.check_signature(Path(prog), "executable")
            if sig.status == "unsigned":
                out.append((40, "The program it starts is unsigned", "Nobody vouches for what it does."))
            elif sig.notarized:
                out.append((-20, "The program it starts is notarized by Apple (%s)" % sig.signer, "A good sign."))
    elif kind == "cron":
        out.append((50, "A new scheduled task (cron job) was added: %s" % entry.get("label", "")[:120],
                    "Cron jobs run commands on a timer; most people never use them."))
    elif kind == "profile":
        out.append((60, "A new configuration profile was installed: %s" % entry.get("label"),
                    "Profiles can change browser, network and security settings."))
    elif kind == "login_item":
        out.append((30, "A new login item was added: %s" % entry.get("label"), "It will open every time you log in."))
    elif kind == "shell_startup":
        out.append((25, "Your shell startup file %s changed" % entry.get("label"),
                    "Malware sometimes adds commands here; if you didn't edit it, take a look."))
    return out
