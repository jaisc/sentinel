"""Removal assistant — approval-gated, quarantine-first, reversible.

remove   -> moves the file + its startup items to ~/.Sentinel/Quarantine/<id>/items/
            with a manifest.json (original path, SHA-256, permissions). Executable
            bits are stripped while quarantined.
restore  -> moves everything back exactly where it was.
delete   -> permanent; only for items already in quarantine, and only after a
            second, separate confirmation.

These functions assume the caller has ALREADY obtained the user's approval for
this specific item (the CLI and menu-bar app do that). They never act on
anything that is not listed in the event's removal plan, and they refuse to
move a file whose SHA-256 changed since the report was written.
"""
from __future__ import annotations

import datetime as dt
import errno
import json
import os
import shutil
import stat
from pathlib import Path
from typing import List, Optional

from . import actionlog, analyzer, events, filetype as ft, macos, paths, report


class RemovalError(RuntimeError):
    pass


def _now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def manifest_path(event_id: str) -> Path:
    return paths.quarantine_dir() / event_id / "manifest.json"


def load_manifest(event_id: str) -> Optional[dict]:
    try:
        return json.loads(manifest_path(event_id).read_text())
    except (OSError, ValueError):
        return None


def load_plan(rec: dict) -> dict:
    p = rec.get("plan_path")
    if p and Path(p).exists():
        try:
            return json.loads(Path(p).read_text())
        except ValueError:
            pass
    return report.build_removal_plan(rec)


def _current_sha(path: Path) -> str:
    if path.is_dir():
        exe = ft.bundle_executable(path)
        return analyzer.sha256_file(exe) if exe else ""
    return analyzer.sha256_file(path) if path.is_file() else ""


def _move(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.rename(src, dst)          # same volume: atomic, keeps xattrs (incl. quarantine tag)
    except OSError as e:
        if e.errno != errno.EXDEV:
            raise
        shutil.move(str(src), str(dst))


def _strip_exec(p: Path) -> Optional[int]:
    try:
        st = p.lstat()
    except OSError:
        return None
    if stat.S_ISREG(st.st_mode):
        os.chmod(p, st.st_mode & ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    return stat.S_IMODE(st.st_mode)


def plan_summary(rec: dict, include_optional: bool = False) -> List[dict]:
    plan = load_plan(rec)
    return [it for it in plan["items"] if include_optional or not it.get("optional")]


def remove(event_id: str, include_optional: bool = False, stop_processes: bool = False) -> dict:
    """Quarantine the items in an event's removal plan. Caller must have the user's approval."""
    rec = events.load(event_id)
    if rec is None:
        raise RemovalError("No such event: %s" % event_id)
    existing = load_manifest(event_id)
    if existing and existing.get("status") == "quarantined":
        raise RemovalError("Already quarantined (see %s). Use `sentinel restore %s` to undo." % (manifest_path(event_id), event_id))
    plan = load_plan(rec)
    qdir = paths.quarantine_dir() / event_id
    qdir.mkdir(parents=True, exist_ok=True)
    os.chmod(qdir, 0o700)

    results = []
    if stop_processes:
        for p in plan.get("running_processes", []):
            try:
                os.kill(int(p["pid"]), 15)
                results.append({"action": "stopped_process", "pid": p["pid"], "ok": True})
            except (OSError, ValueError) as e:
                results.append({"action": "stopped_process", "pid": p.get("pid"), "ok": False, "error": str(e)})

    moved = []
    for it in plan["items"]:
        if it.get("optional") and not include_optional:
            results.append({"n": it["n"], "path": it["path"], "ok": False, "skipped": "optional (not included)"})
            continue
        src = Path(it["path"])
        if not os.path.lexists(src):
            results.append({"n": it["n"], "path": it["path"], "ok": False, "skipped": "no longer exists"})
            continue
        if it.get("sha256") and it["kind"] in ("file", "app_bundle"):
            cur = _current_sha(src)
            if cur and cur != it["sha256"]:
                results.append({"n": it["n"], "path": it["path"], "ok": False,
                                "skipped": "file changed since the report (SHA-256 differs) — re-scan it first"})
                continue
        was_loaded = False
        if it["kind"] == "launch_item" and macos.IS_MACOS:
            for step in it.get("pre_steps", []):
                parts = step.split()
                if parts[:2] == ["launchctl", "bootout"]:
                    rc, _, err = macos.run(["launchctl", "bootout", parts[2], str(src)])
                    was_loaded = rc == 0
        dst = Path(it["quarantine_to"])
        try:
            _move(src, dst)
        except OSError as e:
            hint = (" This item is in a system folder; run the manual command from the report with sudo."
                    if e.errno in (errno.EACCES, errno.EPERM) else "")
            results.append({"n": it["n"], "path": it["path"], "ok": False, "error": e.strerror + hint})
            continue
        mode = _strip_exec(dst)
        entry = {"n": it["n"], "kind": it["kind"], "original_path": str(src), "quarantined_path": str(dst),
                 "sha256": it.get("sha256", ""), "mode": mode, "label": it.get("label", ""),
                 "was_loaded": was_loaded, "moved_at": _now()}
        moved.append(entry)
        results.append({"n": it["n"], "path": it["path"], "ok": True, "to": str(dst)})

    manifest = {
        "event_id": event_id, "created": _now(), "status": "quarantined" if moved else "nothing_moved",
        "verdict": rec.get("verdict"), "title": rec.get("title"), "items": moved,
        "restore_command": "sentinel restore %s" % event_id,
        "delete_command": "sentinel delete %s" % event_id,
    }
    paths.write_json_atomic(manifest_path(event_id), manifest)
    (qdir / "README.txt").write_text(
        "Sentinel quarantine for event %s\n\nThese items were moved here with your approval.\n"
        "Restore:  sentinel restore %s\nDelete permanently (asks again):  sentinel delete %s\n" % (event_id, event_id, event_id))
    actionlog.log("remove", event_id=event_id, results=results)
    if moved:
        events.update(event_id, status="quarantined", quarantined_at=_now())
        _set_plan_status(rec, "quarantined")
    return {"event_id": event_id, "status": manifest["status"], "results": results, "manifest": str(manifest_path(event_id))}


def restore(event_id: str) -> dict:
    m = load_manifest(event_id)
    if not m or m.get("status") != "quarantined":
        raise RemovalError("Nothing in quarantine for %s." % event_id)
    results, remaining = [], []
    for e in m["items"]:
        src, dst = Path(e["quarantined_path"]), Path(e["original_path"])
        if os.path.lexists(dst):
            results.append({"path": str(dst), "ok": False, "error": "something already exists at the original path"})
            remaining.append(e)
            continue
        try:
            _move(src, dst)
            if e.get("mode") is not None and dst.is_file():
                os.chmod(dst, e["mode"])
        except OSError as err:
            results.append({"path": str(dst), "ok": False, "error": err.strerror})
            remaining.append(e)
            continue
        r = {"path": str(dst), "ok": True}
        if e["kind"] == "launch_item":
            domain = "system" if str(dst).startswith("/Library/LaunchDaemons") else "gui/%d" % os.getuid()
            r["note"] = "Startup item restored but not re-loaded. To re-enable now: launchctl bootstrap %s %s" % (domain, dst)
        results.append(r)
    m["items"] = remaining
    m["status"] = "restored" if not remaining else "quarantined"
    m["restored_at"] = _now()
    paths.write_json_atomic(manifest_path(event_id), m)
    actionlog.log("restore", event_id=event_id, results=results)
    if not remaining:
        events.update(event_id, status="restored")
        rec = events.load(event_id)
        if rec:
            _set_plan_status(rec, "restored")
    return {"event_id": event_id, "status": m["status"], "results": results}


def delete(event_id: str) -> dict:
    """Permanently delete quarantined items. Caller must have a SECOND explicit confirmation."""
    m = load_manifest(event_id)
    if not m or m.get("status") != "quarantined":
        raise RemovalError("Only items already in quarantine can be deleted (nothing quarantined for %s)." % event_id)
    results = []
    qroot = (paths.quarantine_dir() / event_id).resolve()
    for e in m["items"]:
        p = Path(e["quarantined_path"])
        # Safety: only ever delete inside this event's quarantine folder.
        try:
            p.resolve().relative_to(qroot)
        except ValueError:
            results.append({"path": str(p), "ok": False, "error": "outside quarantine folder — refused"})
            continue
        try:
            if p.is_dir() and not p.is_symlink():
                shutil.rmtree(p)
            else:
                p.unlink()
            results.append({"path": str(p), "ok": True, "original_path": e["original_path"]})
        except OSError as err:
            results.append({"path": str(p), "ok": False, "error": err.strerror})
    m["status"] = "deleted"
    m["deleted_at"] = _now()
    m["deleted_items"] = m.pop("items")
    paths.write_json_atomic(manifest_path(event_id), m)
    actionlog.log("delete_permanently", event_id=event_id, results=results)
    events.update(event_id, status="deleted")
    return {"event_id": event_id, "status": "deleted", "results": results}


def _set_plan_status(rec: dict, status: str) -> None:
    p = rec.get("plan_path")
    if not p or not Path(p).exists():
        return
    try:
        plan = json.loads(Path(p).read_text())
        plan["status"] = status
        plan["status_changed"] = _now()
        paths.write_json_atomic(Path(p), plan)
    except (OSError, ValueError):
        pass


def list_quarantine() -> List[dict]:
    out = []
    root = paths.quarantine_dir()
    if not root.exists():
        return out
    for d in sorted(root.iterdir()):
        m = load_manifest(d.name)
        if m:
            out.append({"event_id": d.name, "status": m.get("status"), "title": m.get("title"),
                        "items": [e["original_path"] for e in m.get("items", m.get("deleted_items", []))]})
    return out
