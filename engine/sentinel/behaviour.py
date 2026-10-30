""""What is this file doing?" — a point-in-time behaviour snapshot for a flagged file.

Sentinel is not an EDR: it does not trace every system call. It reports, and
labels honestly:

  OBSERVED  — things Sentinel saw directly right now (a running process whose
              command line points at the file, its open network connections via
              lsof, a persistence entry that references the file).
  INFERRED  — things that are likely related by timing or naming but not proven
              (e.g. a new LaunchAgent that appeared shortly after the download).
  NOT SEEN  — gaps (past connections are only visible if LuLu logged them).
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import List

from . import macos, persistence


def processes_for(target: str) -> List[dict]:
    rc, out, _ = macos.run(["ps", "-axww", "-o", "pid=,ppid=,user=,lstart=,command="])
    if rc != 0:
        return []
    found = []
    for line in out.splitlines():
        if target not in line or "sentinel" in line.lower():
            continue
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        found.append({"pid": int(parts[0]), "ppid": int(parts[1]), "user": parts[2],
                      "started": " ".join(parts[3:8]), "command": parts[8][:400]})
    return found


def connections_for(pids: List[int]) -> List[str]:
    if not pids:
        return []
    rc, out, _ = macos.run(["lsof", "-nP", "-a", "-i", "-p", ",".join(str(p) for p in pids)])
    if rc not in (0, 1):
        return []
    return [l for l in out.splitlines()[1:] if l.strip()][:50]


def lulu_rules_mentioning(target: str) -> List[str]:
    """LuLu (if installed) stores per-program rules; a rule means the program tried to connect."""
    hits = []
    for rules in ("/Library/Objective-See/LuLu/rules.plist", "/Library/Objective-See/LuLu/rules.json"):
        p = Path(rules)
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if target.encode() in data:
            hits.append("LuLu has a firewall rule for this program (%s) — it attempted an outbound connection." % rules)
    return hits


def snapshot(rec: dict) -> dict:
    target = rec.get("path", "")
    tools = macos.objective_see_tools() if macos.IS_MACOS else {}
    observed, inferred, not_seen = [], [], []

    # Persistence: diff the current state against the baseline taken before/at the event.
    base = persistence.load_baseline()
    current = persistence.snapshot()
    changes = persistence.diff(base, current) if base is not None else {"added": [], "removed": [], "changed": []}
    persist = []
    first_seen = _ts(rec.get("first_seen"))
    for kind in ("added", "changed"):
        for e in changes[kind]:
            item = dict(e, change=kind)
            if persistence.related_to(e, target) or (rec.get("sha256_of") and persistence.related_to(e, rec["sha256_of"])):
                item["attribution"] = "observed"
                observed.append("Persistence entry %s points at this file: %s" % (kind, e.get("path")))
            elif first_seen and e.get("mtime") and e["mtime"] >= first_seen - 60:
                item["attribution"] = "inferred"
                inferred.append("Persistence entry %s after this file arrived (timing only): %s" % (kind, e.get("path")))
            else:
                item["attribution"] = "unrelated"
            persist.append(item)
    if base is None:
        not_seen.append("No persistence baseline existed yet, so new startup items can't be attributed. One has now been recorded.")
        persistence.save_baseline(current)

    procs = processes_for(target) if target else []
    if procs:
        observed.append("%d running process(es) launched from this file" % len(procs))
    else:
        observed.append("No running process launched from this file right now")
    conns = connections_for([p["pid"] for p in procs])
    if conns:
        observed.append("%d open network connection(s) from those processes" % len(conns))
    lulu = lulu_rules_mentioning(target) if tools.get("LuLu") else []
    observed.extend(lulu)
    if not tools.get("LuLu"):
        not_seen.append("Past network connections are not visible: LuLu is not installed. A process snapshot only shows connections open right now.")

    return {
        "taken_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "persistence_changes": persist,
        "processes": procs,
        "connections": conns,
        "lulu": lulu,
        "observed": observed,
        "inferred": inferred,
        "not_seen": not_seen,
        "objective_see": tools,
        "manual_checks": [
            "Live network view for a process:  nettop -p <PID>   (or)   lsof -nP -i -p <PID>",
            "Deeper persistence scan: open KnockKnock (objective-see.org) and look for unsigned/unknown items.",
            "Background items list: System Settings > General > Login Items & Extensions.",
        ],
    }


def _ts(iso):
    if not iso:
        return 0.0
    try:
        return dt.datetime.fromisoformat(iso).timestamp()
    except ValueError:
        return 0.0
