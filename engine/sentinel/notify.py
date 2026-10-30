"""macOS notifications for the standalone engine.

When the Swift SentinelAgent runs a scan it passes --no-notify and posts a richer
UserNotifications alert itself (with Open report / Allow once / Always allow /
Remove… buttons). When the engine runs on its own (CLI, mail poller, polling
watcher) it uses `terminal-notifier` if installed, else AppleScript.
"""
from __future__ import annotations

import shutil

from . import macos, paths
from .scoring import at_least


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def notify(rec: dict, force: bool = False) -> bool:
    cfg = paths.load_config().get("notifications", {})
    if not force:
        if not cfg.get("enabled", True) or rec.get("allowlisted"):
            return False
        if not at_least(rec.get("verdict", "clean"), cfg.get("min_verdict", "caution")):
            return False
    title = "Sentinel — %s" % rec.get("title", "alert")
    body = (rec.get("summary") or "")[:180]
    subtitle = "Report: %s" % rec.get("report_path", "")[-60:] if rec.get("report_path") else ""
    if not macos.IS_MACOS:
        print("[notification] %s: %s" % (title, body))
        return True
    tn = shutil.which("terminal-notifier")
    if tn:
        cmd = [tn, "-title", title, "-message", body, "-group", "sentinel-" + rec.get("id", "")]
        if rec.get("report_path"):
            cmd += ["-open", "file://" + rec["report_path"]]
        if cfg.get("sound", True):
            cmd += ["-sound", "Basso"]
        rc, _, _ = macos.run(cmd)
        return rc == 0
    script = 'display notification "%s" with title "%s" subtitle "%s"%s' % (
        _esc(body), _esc(title), _esc(subtitle), ' sound name "Basso"' if cfg.get("sound", True) else "")
    rc, _, _ = macos.run(["osascript", "-e", script])
    return rc == 0
