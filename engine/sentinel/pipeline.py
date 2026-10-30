"""Glue: analyse -> store -> report -> notify. Used by the CLI, watchers and agent."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import List, Optional

from . import analyzer, behaviour, events, notify as notifier, paths, persistence, report
from .scoring import Reason, verdict_for, score, VERDICT_LABEL, CLEAN, at_least, CAUTION


def finish(rec: dict, do_notify: bool = True) -> dict:
    """Store an analysed event; write a report for Caution/Dangerous; notify."""
    if at_least(rec["verdict"], CAUTION):
        report.write(rec)
    events.save(rec)
    events.append_feed(rec)
    if do_notify and rec["verdict"] != CLEAN:
        notifier.notify(rec)
    return rec


def process_file(path, source: str = "watcher", do_notify: bool = True, use_network: bool = True,
                 mail_context: Optional[dict] = None) -> dict:
    rec = analyzer.analyze_file(Path(path), source=source, use_network=use_network, mail_context=mail_context)
    if at_least(rec["verdict"], CAUTION):
        try:
            rec["behaviour"] = behaviour.snapshot(rec)
        except Exception as e:  # a snapshot failure must never lose the alert
            rec["behaviour"] = {"observed": [], "inferred": [], "not_seen": ["Snapshot failed: %s" % e],
                                "persistence_changes": [], "processes": [], "connections": [], "manual_checks": []}
    return finish(rec, do_notify)


def resnapshot(event_id: str) -> Optional[dict]:
    rec = events.load(event_id)
    if rec is None:
        return None
    rec["behaviour"] = behaviour.snapshot(rec)
    report.write(rec)
    events.save(rec)
    return rec


def persistence_check(do_notify: bool = True) -> Optional[dict]:
    """Diff startup items against the baseline; alert on new/changed ones (BlockBlock-lite)."""
    base = persistence.load_baseline()
    current = persistence.snapshot()
    persistence.save_baseline(current)
    if base is None:
        return None
    changes = persistence.diff(base, current)
    new = changes["added"] + changes["changed"]
    if not new:
        return None
    reasons = []  # type: List[Reason]
    recent = [e for e in events.recent(100) if e.get("kind") == "file" and e.get("verdict") != CLEAN]
    for e in new:
        for pts, title, why in persistence.entry_risk(e):
            reasons.append(Reason("persistence_" + e["kind"], pts, title, why))
        for ev in recent:
            if ev.get("path") and persistence.related_to(e, ev["path"]):
                e["related_event"] = "%s (%s)" % (ev["id"], ev.get("title"))
                reasons.append(Reason("persistence_from_flagged", 60, "It points at a file Sentinel already flagged: %s" % ev.get("path"),
                                      "The suspicious download appears to have installed itself to run at startup."))
    sha = new[0].get("sha256", "")
    first = new[0]
    rec = {
        "id": events.new_id("persist", sha), "kind": "persistence",
        "name": Path(first.get("path", "startup-item")).name, "path": first.get("path", ""),
        "first_seen": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "entries": new, "removed_entries": changes["removed"],
        "reasons": [r.to_dict() for r in sorted(reasons, key=lambda r: -r.points)],
        "score": score(reasons), "verdict": verdict_for(reasons), "allowlisted": None, "sha256": sha,
    }
    rec["title"] = "%s: new startup item %s" % (VERDICT_LABEL[rec["verdict"]], first.get("label") or rec["name"])
    rec["summary"] = reasons[0].title if reasons else "Startup items changed."
    return finish(rec, do_notify)
