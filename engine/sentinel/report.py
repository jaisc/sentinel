"""Report generator: ~/Sentinel/Reports/<date>-<name>.md + <...>.removal-plan.json"""
from __future__ import annotations

import datetime as dt
import os
import re
import shlex
from pathlib import Path
from typing import List, Optional

from . import paths
from .scoring import VERDICT_LABEL, DANGEROUS, CAUTION

PLAN_SCHEMA = "sentinel.removal-plan/1"


def _slug(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-.")
    return (s or "item")[:60]


def report_paths(rec: dict):
    day = (rec.get("first_seen") or dt.datetime.now().isoformat())[:10]
    base = "%s-%s-%s" % (day, _slug(rec.get("name") or rec.get("title") or rec["id"]), rec["id"][-8:])
    d = paths.reports_dir()
    return d / (base + ".md"), d / (base + ".removal-plan.json")


def _uid() -> int:
    try:
        return os.getuid()
    except AttributeError:
        return 501


def _q(p: str) -> str:
    return shlex.quote(p)


def build_removal_plan(rec: dict) -> dict:
    qdir = paths.quarantine_dir() / rec["id"]
    items = []
    if rec.get("kind") == "file" and rec.get("path"):
        items.append({"kind": "app_bundle" if rec.get("type", {}).get("real_category") == "app_bundle" else "file",
                      "path": rec["path"], "sha256": rec.get("sha256", ""),
                      "reason": rec.get("summary", ""), "attribution": "observed", "optional": False})
    beh = rec.get("behaviour") or {}
    for e in beh.get("persistence_changes", []):
        if e.get("attribution") not in ("observed", "inferred"):
            continue
        if e.get("kind") != "launch_item":
            continue  # cron/profile/login items need manual removal; listed under manual_steps
        items.append({"kind": "launch_item", "path": e["path"], "sha256": e.get("sha256", ""),
                      "label": e.get("label", ""), "reason": "Startup item %s" % e.get("change", "added"),
                      "attribution": e["attribution"], "optional": e["attribution"] != "observed"})
    if rec.get("kind") == "persistence":
        for e in rec.get("entries", []):
            if e.get("kind") == "launch_item":
                items.append({"kind": "launch_item", "path": e["path"], "sha256": e.get("sha256", ""),
                              "label": e.get("label", ""), "reason": "New startup item", "attribution": "observed",
                              "optional": False})
    manual = []
    for n, it in enumerate(items, 1):
        dest = qdir / "items" / ("%d-%s" % (n, Path(it["path"]).name))
        it["n"] = n
        it["quarantine_to"] = str(dest)
        it["requires_admin"] = not it["path"].startswith(str(paths.home()))
        it["pre_steps"] = []
        if it["kind"] == "launch_item":
            domain = "system" if it["path"].startswith("/Library/LaunchDaemons") else "gui/%d" % _uid()
            it["pre_steps"].append("launchctl bootout %s %s" % (domain, _q(it["path"])))
        sudo = "sudo " if it["requires_admin"] else ""
        manual.extend(["%s%s" % (sudo, s) for s in it["pre_steps"]])
        manual.append("mkdir -p %s && %smv %s %s" % (_q(str(dest.parent)), sudo, _q(it["path"]), _q(str(dest))))
    for p in beh.get("processes", []):
        manual.insert(0, "kill -TERM %d   # stop: %s" % (p["pid"], p["command"][:80]))
    other = []
    for e in beh.get("persistence_changes", []) + rec.get("entries", []):
        if e.get("attribution", "observed") in ("observed", "inferred") and e.get("kind") == "cron":
            other.append("Remove this line with `crontab -e`: %s" % e.get("label"))
        if e.get("attribution", "observed") in ("observed", "inferred") and e.get("kind") == "profile":
            other.append("Remove profile %s in System Settings > Privacy & Security > Profiles" % e.get("label"))
        if e.get("attribution", "observed") in ("observed", "inferred") and e.get("kind") == "login_item":
            other.append("Remove login item %s in System Settings > General > Login Items" % e.get("label"))
        if e.get("kind") == "shell_startup":
            other.append("Review recent changes in %s and delete lines you didn't add" % e.get("path"))
    return {
        "schema": PLAN_SCHEMA,
        "event_id": rec["id"],
        "created": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "verdict": rec.get("verdict"),
        "status": "awaiting_user_approval",
        "approval_required": True,
        "instructions_for_assistants": (
            "Do NOT execute any step without the user's explicit approval for THIS item. "
            "Preferred: run `sentinel remove %s` (moves items to a reversible quarantine with a manifest). "
            "Never delete permanently unless the user confirms a second time (`sentinel delete %s`). "
            "Items marked optional are only inferred to be related; ask before including them." % (rec["id"], rec["id"])),
        "quarantine_dir": str(qdir),
        "items": items,
        "running_processes": beh.get("processes", []),
        "commands": {
            "remove": "sentinel remove %s" % rec["id"],
            "remove_including_optional": "sentinel remove %s --include-optional" % rec["id"],
            "restore": "sentinel restore %s" % rec["id"],
            "delete_permanently_after_quarantine": "sentinel delete %s" % rec["id"],
            "manual_equivalent": manual,
        },
        "manual_steps": other,
        "antivirus_handoff": {
            "sha256": rec.get("sha256", ""), "path": rec.get("path", ""),
            "virustotal": (rec.get("reputation", {}).get("virustotal") or {}).get("link", ""),
        },
    }


def _what_to_do(rec: dict) -> List[str]:
    v = rec.get("verdict")
    if rec.get("kind") == "email":
        return (["Don't click the flagged link(s) or open the flagged attachment(s).",
                 "If the message claims to be from a company, go to their site by typing the address yourself.",
                 "If you already clicked and typed a password, change it now (and turn on 2-step verification).",
                 "Mark it as phishing/spam in Gmail if you agree. Sentinel never changes or deletes your mail."]
                if v in (DANGEROUS, CAUTION) else ["Nothing to do."])
    if rec.get("kind") == "url":
        return ["If you didn't mean to go there, click Go back on the warning page.",
                "If you already entered a password on that site, change it now and turn on 2-step verification.",
                "False alarm? Click \"Always allow this site\" on the warning page (or `sentinel allow %s`)." % rec["id"]]
    steps = []
    if v == DANGEROUS:
        steps.append("Do not open it. If you already opened it, keep reading — the behaviour section shows what it did.")
        steps.append("Approve removal: `sentinel remove %s` (or click Remove in the menu bar). It moves the item to a "
                     "reversible quarantine — nothing is deleted." % rec["id"])
    elif v == CAUTION:
        steps.append("Only open it if you were expecting it and trust where it came from.")
        steps.append("If you don't recognise it, approve removal: `sentinel remove %s`. You can restore it later." % rec["id"])
    steps.append("If this is a false alarm, choose Allow once (`sentinel allow-once %s`) or Always allow this source "
                 "(`sentinel allow %s`)." % (rec["id"], rec["id"]))
    steps.append("To get a second opinion, hand the SHA-256 or the removal-plan JSON to your antivirus.")
    return steps


def _rep_line(r: Optional[dict]) -> str:
    if not r:
        return "not checked"
    s = r.get("status")
    if s == "found":
        return "%d malicious / %d suspicious of %d engines%s — %s" % (
            r.get("malicious", 0), r.get("suspicious", 0), r.get("total", 0),
            (" (%s)" % r["label"]) if r.get("label") else "", r.get("link", ""))
    return {"not_found": "never seen by VirusTotal (hash only was sent; the file was not uploaded)",
            "no_key": "not checked — no VirusTotal API key in the Keychain (run `sentinel keys set virustotal`)",
            "disabled": "disabled in settings", "rate_limited": "skipped — free-tier rate limit reached; retry later",
            "flagged": "FLAGGED: %s" % ", ".join(r.get("threats", [])), "clean": "no match",
            }.get(s, "lookup failed (%s)" % s)


def render_markdown(rec: dict, plan: dict) -> str:
    v = rec.get("verdict", "clean")
    L = []
    L.append("# %s — %s" % (VERDICT_LABEL.get(v, v).upper(), rec.get("name") or rec.get("title")))
    L.append("")
    L.append("*Sentinel report · event `%s` · %s*" % (rec["id"], rec.get("first_seen")))
    L.append("")
    if rec.get("allowlisted"):
        a = rec["allowlisted"]
        L.append("> Allowlisted (%s: %s) — no notification was shown." % (a.get("type"), a.get("value")))
        L.append("")
    L.append("## In plain English")
    L.append("")
    L.append("**What happened:** %s" % _what_happened(rec))
    L.append("")
    reasons = [r for r in rec.get("reasons", []) if r["points"] > 0]
    L.append("**Why it matters:** %s" % (reasons[0]["why"] if reasons else "Nothing suspicious was found."))
    L.append("")
    L.append("**What to do:**")
    L.append("")
    for i, s in enumerate(_what_to_do(rec), 1):
        L.append("%d. %s" % (i, s))
    L.append("")
    L.append("## Risk score: %s (%d points)" % (VERDICT_LABEL.get(v, v), rec.get("score", 0)))
    L.append("")
    L.append("| Points | Finding | Basis |")
    L.append("|---:|---|---|")
    for r in rec.get("reasons", []):
        L.append("| %+d | %s — %s | %s |" % (r["points"], _md(r["title"]), _md(r["why"]), "observed" if r.get("observed", True) else "inferred (heuristic)"))
    L.append("")
    if rec.get("kind") == "email":
        L.extend(_email_section(rec))
    elif rec.get("kind") == "persistence":
        L.extend(_persistence_section(rec))
    elif rec.get("kind") == "url":
        L.extend(_url_section(rec))
    else:
        L.extend(_file_section(rec))
    L.extend(_behaviour_section(rec))
    L.append("## Removal plan (needs your approval)")
    L.append("")
    if plan["items"]:
        L.append("Nothing has been moved or deleted. Approving moves these to `%s` (reversible):" % plan["quarantine_dir"])
        L.append("")
        for it in plan["items"]:
            L.append("%d. `%s`%s%s" % (it["n"], it["path"], " — *optional, only inferred to be related*" if it.get("optional") else "",
                                        " — *needs admin password*" if it.get("requires_admin") else ""))
        L.append("")
        L.append("Approve with: `%s`  ·  Undo with: `%s`" % (plan["commands"]["remove"], plan["commands"]["restore"]))
        L.append("")
        L.append("Exact manual equivalent (what Sentinel will do):")
        L.append("")
        L.append("```sh")
        L.extend(plan["commands"]["manual_equivalent"] or ["# nothing to move"])
        L.append("```")
    else:
        L.append("No files to remove." if rec.get("kind") != "email" else "Sentinel never modifies or deletes email. Delete or report the message in Gmail yourself.")
    for s in plan.get("manual_steps", []):
        L.append("- %s" % s)
    L.append("")
    L.append("Machine-readable plan: `%s`" % rec.get("plan_path", ""))
    L.append("")
    return "\n".join(L)


def _md(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def _what_happened(rec: dict) -> str:
    if rec.get("kind") == "email":
        return "An email from %s (\"%s\") arrived %s with %s." % (
            rec.get("from", "?"), rec.get("subject", ""), rec.get("received", "recently"), rec.get("summary", "").lower() or "something suspicious")
    if rec.get("kind") == "persistence":
        return rec.get("summary", "A new startup item appeared.")
    if rec.get("kind") == "url":
        return "Brave was about to open %s and Sentinel showed a warning page first. %s" % (rec.get("url"), rec.get("summary", ""))
    o = rec.get("origin", {})
    summary = rec.get("summary", "").rstrip(".")
    return "A %s named \"%s\" appeared in %s. Origin: %s. Main concern: %s." % (
        rec.get("type", {}).get("real_label", "file"), rec.get("name"), str(Path(rec.get("path", "")).parent),
        o.get("summary", "unknown"), summary[0].lower() + summary[1:] if summary else "none")


def _file_section(rec: dict) -> List[str]:
    t, o, s = rec.get("type", {}), rec.get("origin", {}), rec.get("signature", {})
    L = ["## The file", "",
         "| | |", "|---|---|",
         "| Name | `%s` |" % _md(rec.get("name")),
         "| Full path | `%s` |" % _md(rec.get("path")),
         "| Size | %s bytes |" % rec.get("size", "?"),
         "| First seen by Sentinel | %s |" % rec.get("first_seen"),
         "| Real type (by content) | %s |" % _md(t.get("real_label")),
         "| Claimed by extension | %s |" % (".%s (%s)" % (t.get("claimed_extension"), t.get("claimed_category")) if t.get("claimed_extension") else "no extension"),
         "| `file` says | %s |" % _md(t.get("file_command") or "n/a"),
         "| SHA-256 | `%s`%s |" % (rec.get("sha256", ""), " (of %s)" % rec["sha256_of"] if rec.get("sha256_of") else ""),
         "| Code signature | %s |" % _sig_line(s),
         "| Gatekeeper | %s |" % ("%s %s" % (s.get("gatekeeper"), ("(%s)" % s["gatekeeper_source"]) if s.get("gatekeeper_source") else "")),
         "| VirusTotal | %s |" % _md(_rep_line(rec.get("reputation", {}).get("virustotal"))),
         ]
    if rec.get("clamav"):
        L.append("| ClamAV | %s |" % _md(rec["clamav"].get("detail")))
    if t.get("archive_runnable_members"):
        L.append("| Programs inside archive | %s |" % _md(", ".join(t["archive_runnable_members"][:10])))
    L += ["", "## Where it came from", "",
          "| | |", "|---|---|",
          "| Summary | %s |" % _md(o.get("summary")),
          "| Download URL | %s |" % _md(o.get("download_url") or "—"),
          "| Referring page | %s |" % _md(o.get("referrer") or "—"),
          "| Downloaded by | %s |" % _md(o.get("downloaded_by") or "—"),
          "| Download time | %s |" % (o.get("downloaded_at") or "—"),
          "| Email sender | %s |" % _md(o.get("email_sender") or "—"),
          "| Email subject | %s |" % _md(o.get("email_subject") or "—"),
          "| Safe Browsing (download site) | %s |" % _md(_rep_line(rec.get("reputation", {}).get("safebrowsing_origin"))),
          ""]
    return L


def _sig_line(s: dict) -> str:
    st = s.get("status", "not_applicable")
    text = {"signed_valid": "valid signature", "signed_invalid": "INVALID signature",
            "signed_detritus": "valid signature (stray file attributes)", "adhoc": "ad-hoc (no identity)",
            "unsigned": "not signed", "unavailable": "not checked (needs macOS)", "not_applicable": "n/a (not a program)"}.get(st, st)
    if s.get("signer"):
        text += " — %s" % s["signer"]
    if s.get("team_id"):
        text += " (Team %s)" % s["team_id"]
    if s.get("notarized"):
        text += ", notarized"
    return _md(text)


def _email_section(rec: dict) -> List[str]:
    L = ["## The email", "", "| | |", "|---|---|",
         "| From | %s |" % _md(rec.get("from")), "| Reply-To | %s |" % _md(rec.get("reply_to") or "—"),
         "| Subject | %s |" % _md(rec.get("subject")), "| Received | %s |" % rec.get("received"),
         "| Account | %s |" % _md(rec.get("account")), "| Message-ID | `%s` |" % _md(rec.get("message_id")),
         "| Authentication | %s |" % _md(rec.get("auth_summary") or "—"), "",
         "### Links", ""]
    if not rec.get("links"):
        L.append("No links.")
    for l in rec.get("links", []):
        flag = "**FLAGGED**" if l.get("flagged") else "ok"
        L.append("- %s `%s`%s" % (flag, l["url"][:300], (" — shown as \"%s\"" % l["text"][:80]) if l.get("text") else ""))
        for r in l.get("reasons", []):
            L.append("  - %s" % r["title"])
        for k in ("safebrowsing", "virustotal"):
            if l.get(k) and l[k].get("status") not in (None, "clean", "not_found", "no_key", "disabled"):
                L.append("  - %s: %s" % (k, _rep_line(l[k])))
    L += ["", "### Attachments", ""]
    if not rec.get("attachments"):
        L.append("No attachments.")
    for a in rec.get("attachments", []):
        L.append("- `%s` — %s, %s, SHA-256 `%s`%s" % (a["filename"], a.get("real_label", a.get("content_type")), a.get("verdict", ""),
                                                   a.get("sha256", ""), "" if not a.get("reasons") else ""))
        for r in a.get("reasons", []):
            if r["points"] > 0:
                L.append("  - %s" % r["title"])
    L.append("")
    return L


def _url_section(rec: dict) -> List[str]:
    rep = rec.get("reputation", {})
    return ["## The link", "", "| | |", "|---|---|",
            "| URL | `%s` |" % _md(rec.get("url")),
            "| Seen | %s (Brave link guard) |" % rec.get("first_seen"),
            "| Safe Browsing | %s |" % _md(_rep_line(rep.get("safebrowsing"))),
            "| VirusTotal | %s |" % _md(_rep_line(rep.get("virustotal"))), ""]


def _persistence_section(rec: dict) -> List[str]:
    L = ["## New startup items", ""]
    for e in rec.get("entries", []):
        L.append("- **%s** `%s`" % (e.get("kind"), e.get("path")))
        if e.get("label"):
            L.append("  - Label: `%s`" % e["label"])
        if e.get("program"):
            L.append("  - Runs: `%s`" % " ".join(e.get("arguments") or [e["program"]])[:300])
        if e.get("related_event"):
            L.append("  - Related download: %s" % e["related_event"])
    L.append("")
    return L


def _behaviour_section(rec: dict) -> List[str]:
    b = rec.get("behaviour")
    L = ["## What it is doing (behaviour snapshot)", ""]
    if not b:
        L.append("Not collected yet. Run `sentinel snapshot %s` after the item has been opened (or anytime) to check "
                 "for startup items, running processes and network connections." % rec["id"])
        L.append("")
        return L
    L.append("*Taken %s. Observed = seen directly; inferred = likely related by timing only.*" % b.get("taken_at"))
    L.append("")
    for k, title in (("observed", "Observed"), ("inferred", "Inferred"), ("not_seen", "Not visible to Sentinel")):
        if b.get(k):
            L.append("**%s:**" % title)
            L.extend("- %s" % x for x in b[k])
            L.append("")
    if b.get("connections"):
        L.append("```")
        L.extend(b["connections"][:20])
        L.append("```")
    L.append("Manual follow-ups:")
    L.extend("- %s" % x for x in b.get("manual_checks", []))
    L.append("")
    return L


def write(rec: dict) -> dict:
    """Write the markdown report + removal-plan JSON; returns rec with paths filled in."""
    paths.ensure_dirs()
    md_path, plan_path = report_paths(rec)
    rec["report_path"], rec["plan_path"] = str(md_path), str(plan_path)
    plan = build_removal_plan(rec)
    paths.write_json_atomic(plan_path, plan)
    md_path.write_text(render_markdown(rec, plan), encoding="utf-8")
    return rec
