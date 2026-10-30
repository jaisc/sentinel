"""sentinel — command-line interface (works with or without the menu-bar app)."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import sys
from pathlib import Path

from . import (__version__, actionlog, allowlist, events, keychain, macos, paths, pipeline,
               removal, reputation, urlcheck, watcher)
from .scoring import VERDICT_LABEL, CLEAN

KEY_ACCOUNTS = {
    "virustotal": ["virustotal-api-key"],
    "safebrowsing": ["safebrowsing-api-key"],
    "gmail-client": ["gmail-oauth-client-id", "gmail-oauth-client-secret"],
}


def _print_rec(rec: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(rec, default=str))
        return
    v = rec["verdict"]
    print("%s  %s" % (VERDICT_LABEL[v].upper().ljust(9), rec.get("path") or rec.get("url") or rec.get("subject", "")))
    for r in rec.get("reasons", []):
        if r["points"] != 0:
            print("   %+4d  %s" % (r["points"], r["title"]))
    if rec.get("allowlisted"):
        print("   (allowlisted: %s %s)" % (rec["allowlisted"].get("type"), rec["allowlisted"].get("value")))
    if rec.get("report_path"):
        print("   report: %s" % rec["report_path"])
        print("   event:  %s" % rec["id"])


def _confirm(prompt: str, expected: str) -> bool:
    if not sys.stdin.isatty():
        print("Refusing: approval must be typed interactively (or pass --yes after the user approved).", file=sys.stderr)
        return False
    try:
        return input(prompt).strip() == expected
    except EOFError:
        return False


def _resolve_event(ref: str) -> dict:
    rec = events.load(ref)
    if rec:
        return rec
    p = os.path.abspath(os.path.expanduser(ref))
    if os.path.lexists(p):
        rec = events.find_by_path(p)
        if rec:
            return rec
        # Not seen before: analyse now so there is a plan to approve.
        return pipeline.process_file(p, source="cli", do_notify=False)
    sys.exit("No event or file found for %r. See `sentinel events`." % ref)


# --- commands --------------------------------------------------------------------

def cmd_scan(a):
    seen = watcher.load_seen() if a.if_new else None
    worst = 0
    for p in a.paths:
        path = Path(os.path.abspath(os.path.expanduser(p)))
        if not os.path.lexists(path):
            print("not found: %s" % path, file=sys.stderr)
            continue
        if seen is not None:
            if not watcher.is_new(path, seen):
                continue
            watcher.mark_seen(path, seen)
        rec = pipeline.process_file(path, source=a.source, do_notify=not a.no_notify, use_network=not a.no_network)
        _print_rec(rec, a.json)
        worst = max(worst, {"clean": 0, "caution": 1, "dangerous": 2}[rec["verdict"]])
    if seen is not None:
        watcher.save_seen(seen)
    return 0 if worst == 0 else 10 + worst  # 11 = caution, 12 = dangerous


def cmd_watch(a):
    def on_ready(p):
        try:
            _print_rec(pipeline.process_file(p, source="watcher"), False)
        except Exception as e:  # keep watching
            print("scan failed for %s: %s" % (p, e), file=sys.stderr)

    def on_persist():
        try:
            rec = pipeline.persistence_check()
            if rec:
                _print_rec(rec, False)
        except Exception as e:
            print("persistence check failed: %s" % e, file=sys.stderr)

    if persistence_baseline_missing():
        pipeline.persistence_check(do_notify=False)
    watcher.run_polling(on_ready, scan_existing=a.scan_existing, on_persistence=on_persist)


def persistence_baseline_missing() -> bool:
    from . import persistence
    return persistence.load_baseline() is None


def cmd_check_url(a):
    from . import nmhost
    res = nmhost.check_url(a.url, deep=a.deep, use_network=not a.no_network)
    if a.json:
        print(json.dumps(res))
    else:
        print("%s  %s" % (VERDICT_LABEL[res["verdict"]].upper().ljust(9), a.url))
        for r in res["reasons"]:
            print("   %+4d  %s" % (r["points"], r["title"]))
        for k, v in res["reputation"].items():
            print("   %s: %s" % (k, v.get("status")))
    return 0 if res["verdict"] == CLEAN else 11


def cmd_mail_poll(a):
    from .mail import poller
    recs = poller.poll_all(do_notify=not a.no_notify, verbose=a.verbose)
    if a.verbose:
        print("%d new message(s) checked." % len(recs))
    return 0


def cmd_mail_check(a):
    from .mail import emailscan
    raw = Path(a.eml).read_bytes()
    rec = emailscan.analyze_message(raw, account="file:%s" % a.eml, use_network=not a.no_network)
    pipeline.finish(rec, do_notify=not a.no_notify)
    if a.json:
        print(json.dumps(rec, default=str))
    else:
        _print_rec(rec, False)
    return 0 if rec["verdict"] == CLEAN else 11


def cmd_mail_setup(a):
    cfg = paths.load_config()
    if a.provider == "gmail":
        from .mail import gmail
        print(__doc_gmail__)
        if not keychain.has("gmail-oauth-client-id") or a.reset_client:
            cid = input("OAuth client ID: ").strip()
            secret = getpass.getpass("OAuth client secret (hidden): ").strip()
            keychain.set("gmail-oauth-client-id", cid)
            keychain.set("gmail-oauth-client-secret", secret)
            print("Stored client ID/secret in the Keychain (service \"Sentinel\").")
        gmail.authorize()
        cfg["mail"]["gmail_enabled"] = True
        cfg["mail"]["gmail_account"] = a.account or cfg["mail"].get("gmail_account", "")
        paths.save_config(cfg)
        print("Gmail connected read-only. Test it with: sentinel mail-poll -v")
    else:
        name = a.name or "yahoo"
        host = a.host or ("imap.mail.yahoo.com" if name == "yahoo" else "")
        user = a.user or input("IMAP username (email address): ").strip()
        if not host:
            host = input("IMAP server (e.g. imap.mail.yahoo.com): ").strip()
        pw = getpass.getpass("App password for %s (hidden; Yahoo: Account security > Generate app password): " % user)
        from .mail import imap
        keychain.set(imap.password_account(name), pw)
        accts = [x for x in cfg["mail"].get("imap_accounts", []) if x.get("name") != name]
        accts.append({"name": name, "host": host, "user": user})
        cfg["mail"]["imap_accounts"] = accts
        paths.save_config(cfg)
        print("IMAP account %r added (read-only). Test it with: sentinel mail-poll -v" % name)
    return 0


__doc_gmail__ = """Gmail setup (read-only)
  1. https://console.cloud.google.com/ > new project "Sentinel" > APIs & Services > Library > enable "Gmail API".
  2. OAuth consent screen: External, add yourself as a test user, then PUBLISH the app ("In production")
     — apps left in "Testing" get refresh tokens that expire after 7 days.
  3. Credentials > Create credentials > OAuth client ID > Application type "Desktop app".
  4. Paste the client ID and secret below (they go straight into the Keychain).
"""


def cmd_events(a):
    for e in events.recent(a.limit):
        if a.all or e.get("verdict") != CLEAN:
            print("%s  %-9s %s%s" % (e["id"], (e.get("verdict") or "").upper(), e.get("title", ""),
                                     "  [allowlisted]" if e.get("allowlisted") else ""))
    return 0


def cmd_report(a):
    rec = _resolve_event(a.ref)
    rp = rec.get("report_path")
    if not rp:
        print("No report (verdict %s). Full record: %s" % (rec["verdict"], events.event_file(rec["id"])))
        return 0
    print(rp)
    if a.open and macos.IS_MACOS:
        subprocess.run(["open", rp])
    return 0


def cmd_snapshot(a):
    rec = pipeline.resnapshot(a.event_id)
    if not rec:
        sys.exit("No such event.")
    b = rec["behaviour"]
    for k in ("observed", "inferred", "not_seen"):
        for x in b.get(k, []):
            print("%-9s %s" % (k.upper(), x))
    print("report: %s" % rec.get("report_path"))
    return 0


def cmd_remove(a):
    rec = _resolve_event(a.ref)
    items = removal.plan_summary(rec, a.include_optional)
    plan = removal.load_plan(rec)
    if not items:
        print("Nothing to remove for %s." % rec["id"])
        return 0
    print("%s\n" % rec.get("title"))
    print("Sentinel will MOVE these item(s) to %s (reversible — nothing is deleted):" % plan["quarantine_dir"])
    for it in items:
        print("  %d. %s%s" % (it["n"], it["path"], "  (optional)" if it.get("optional") else ""))
    skipped_optional = [it for it in plan["items"] if it.get("optional") and not a.include_optional]
    if skipped_optional:
        print("  (+%d optional item(s) only inferred to be related; add --include-optional to include them)" % len(skipped_optional))
    if plan.get("running_processes"):
        print("  Running processes from this item: %s%s" % (", ".join(str(p["pid"]) for p in plan["running_processes"]),
                                                         " (will be stopped)" if a.stop_processes else " (add --stop-processes to stop them)"))
    if not a.yes and not _confirm("\nType REMOVE to approve: ", "REMOVE"):
        print("Not approved. Nothing changed.")
        actionlog.log("remove_declined", event_id=rec["id"])
        return 1
    res = removal.remove(rec["id"], include_optional=a.include_optional, stop_processes=a.stop_processes)
    for r in res["results"]:
        print("  %s %s%s" % ("moved  " if r.get("ok") else "SKIPPED", r.get("path", r.get("pid", "")),
                             "" if r.get("ok") else "  — %s" % (r.get("skipped") or r.get("error"))))
    print("Undo any time: sentinel restore %s" % rec["id"])
    return 0 if res["status"] == "quarantined" else 1


def cmd_restore(a):
    m = removal.load_manifest(a.event_id)
    if not m or m.get("status") != "quarantined":
        sys.exit("Nothing in quarantine for %s." % a.event_id)
    for e in m["items"]:
        print("  restore %s" % e["original_path"])
    if not a.yes and not _confirm("Type RESTORE to put these back: ", "RESTORE"):
        print("Not approved. Nothing changed.")
        return 1
    res = removal.restore(a.event_id)
    for r in res["results"]:
        print("  %s %s%s" % ("restored" if r["ok"] else "FAILED  ", r["path"], ("  — " + r.get("error", "")) if not r["ok"] else ""))
        if r.get("note"):
            print("     %s" % r["note"])
    return 0


def cmd_delete(a):
    m = removal.load_manifest(a.event_id)
    if not m or m.get("status") != "quarantined":
        sys.exit("Only quarantined items can be deleted; nothing quarantined for %s." % a.event_id)
    print("PERMANENTLY delete these quarantined item(s)? This cannot be undone:")
    for e in m["items"]:
        print("  %s  (was %s)" % (e["quarantined_path"], e["original_path"]))
    code = a.event_id[-8:]
    if not a.yes_permanently:
        if not _confirm("Type DELETE to continue: ", "DELETE"):
            print("Not approved. Nothing deleted.")
            return 1
        if not _confirm("Second confirmation — type %s: " % code, code):
            print("Not approved. Nothing deleted.")
            return 1
    res = removal.delete(a.event_id)
    for r in res["results"]:
        print("  %s %s" % ("deleted" if r["ok"] else "FAILED ", r["path"]))
    return 0


def cmd_quarantine(a):
    for q in removal.list_quarantine():
        print("%s  %-11s %s" % (q["event_id"], q["status"], q.get("title") or ""))
        for p in q["items"]:
            print("      %s" % p)
    return 0


def cmd_allow(a):
    if a.ref:
        rec = _resolve_event(a.ref)
        kind, value = a.type, a.value
        if not kind:
            if rec.get("kind") == "email":
                kind, value = "sender", rec.get("from_address", "")
            elif rec.get("kind") == "url":
                kind, value = "domain", urlcheck.registrable_domain(urlcheck.hostname(rec.get("url", "")))
            elif (rec.get("signature") or {}).get("team_id"):
                kind, value = "team_id", rec["signature"]["team_id"]
            elif (rec.get("origin") or {}).get("download_url"):
                kind, value = "domain", urlcheck.registrable_domain(urlcheck.hostname(rec["origin"]["download_url"]))
            else:
                kind, value = "sha256", rec.get("sha256", "")
        elif not value:
            value = {"sha256": rec.get("sha256", ""), "sender": rec.get("from_address", ""),
                     "team_id": (rec.get("signature") or {}).get("team_id", ""),
                     "domain": urlcheck.registrable_domain(urlcheck.hostname(
                         (rec.get("origin") or {}).get("download_url") or rec.get("url", "")))}[kind]
        if not value:
            sys.exit("Could not determine a source to allow for this event; use --type/--value.")
    else:
        if not (a.type and a.value):
            sys.exit("Give an event id, or --type and --value.")
        kind, value = a.type, a.value
    e = allowlist.add(kind, value, note=a.note or "")
    print("Always allowed: %s %s" % (e["type"], e["value"]))
    print("(A known-malicious verdict from VirusTotal/ClamAV/Safe Browsing is still reported unless you allow the exact SHA-256.)")
    return 0


def cmd_allow_once(a):
    rec = _resolve_event(a.ref)
    allowlist.allow_once(rec["id"], rec.get("path", ""), rec.get("sha256", ""))
    events.update(rec["id"], status="allowed_once")
    print("Allowed once: %s" % (rec.get("path") or rec["id"]))
    return 0


def cmd_allowlist(a):
    if a.action == "remove":
        ok = allowlist.remove(a.type, a.value)
        print("removed" if ok else "not found")
        return 0 if ok else 1
    for e in allowlist.entries():
        print("%-8s %-40s %s  %s" % (e["type"], e["value"], e.get("added", ""), e.get("note", "")))
    return 0


def cmd_keys(a):
    if a.action == "status":
        for name in ("virustotal-api-key", "safebrowsing-api-key", "gmail-oauth-client-id", "gmail-oauth-client-secret", "gmail-refresh-token"):
            print("%-28s %s" % (name, "stored in Keychain" if keychain.has(name) else "not set"))
        for acct in paths.load_config()["mail"].get("imap_accounts", []):
            n = "imap-%s-password" % acct["name"]
            print("%-28s %s" % (n, "stored in Keychain" if keychain.has(n) else "not set"))
        return 0
    if not a.service:
        sys.exit("Which key? virustotal | safebrowsing | gmail-client | imap NAME")
    accounts = ["imap-%s-password" % (a.name or "yahoo")] if a.service == "imap" else KEY_ACCOUNTS[a.service]
    if a.action == "delete":
        for acct in accounts:
            print("%s: %s" % (acct, "deleted" if keychain.delete(acct) else "not found"))
        return 0
    for acct in accounts:
        secret = getpass.getpass("%s (hidden, stored only in the Keychain): " % acct).strip()
        if not secret:
            print("skipped %s" % acct)
            continue
        keychain.set(acct, secret)
        print("stored %s" % acct)
    return 0


def cmd_persistence(a):
    from . import persistence
    if a.action == "baseline":
        persistence.save_baseline(persistence.snapshot())
        print("Baseline recorded: %s" % persistence.baseline_path())
        return 0
    if a.action == "list":
        for k, e in sorted(persistence.snapshot().items()):
            print("%-13s %s  %s" % (e["kind"], e.get("path"), e.get("program", "")[:80]))
        return 0
    rec = pipeline.persistence_check(do_notify=not a.no_notify)
    if rec:
        _print_rec(rec, a.json)
        return 11
    if not a.json:
        print("No new startup items.")
    return 0


def cmd_vt_upload(a):
    cfg = paths.load_config()
    if not cfg["reputation"].get("allow_file_upload"):
        sys.exit("File upload is OFF (the default). Turn it on in Settings or with:\n"
                 "  sentinel config set reputation.allow_file_upload true")
    p = Path(a.path)
    print("This will upload the CONTENTS of %s to VirusTotal, where it becomes visible to security researchers." % p)
    ok = a.yes or _confirm("Type UPLOAD to continue: ", "UPLOAD")
    if not ok:
        print("Not uploaded.")
        return 1
    actionlog.log("vt_upload", path=str(p))
    print(json.dumps(reputation.vt_upload(p, confirmed=True)))
    return 0


def cmd_config(a):
    cfg = paths.load_config()
    if a.action == "show":
        print(json.dumps(cfg, indent=2))
        return 0
    if a.action == "path":
        print(paths.config_path())
        return 0
    if a.action == "init":
        if not paths.config_path().exists():
            paths.save_config(cfg)
        print(paths.config_path())
        return 0
    keys = a.key.split(".")
    node = cfg
    for k in keys[:-1]:
        node = node.setdefault(k, {})
    try:
        val = json.loads(a.value)
    except ValueError:
        val = a.value
    node[keys[-1]] = val
    paths.save_config(cfg)
    actionlog.log("config_set", key=a.key, value=val if "key" not in a.key.lower() else "(hidden)")
    print("%s = %s" % (a.key, json.dumps(val)))
    return 0


def cmd_status(a):
    cfg = paths.load_config()
    print("Sentinel %s" % __version__)
    print("  macOS:          %s" % ("yes" if macos.IS_MACOS else "no (analysis works, macOS-only checks are skipped)"))
    print("  Gatekeeper:     %s" % {True: "enabled", False: "DISABLED — turn it back on: sudo spctl --master-enable", None: "n/a"}[macos.gatekeeper_enabled()])
    print("  SIP:            %s" % {True: "enabled", False: "DISABLED", None: "n/a"}[macos.sip_enabled()])
    print("  Watch folders:")
    for f in cfg["watch_folders"]:
        p = paths.expand_path(f)
        print("    %s %s" % ("ok     " if p.is_dir() else "missing", p))
    print("  Keys:           VirusTotal %s, Safe Browsing %s" % (
        "set" if keychain.has("virustotal-api-key") else "not set", "set" if keychain.has("safebrowsing-api-key") else "not set"))
    print("  File upload:    %s" % ("ON" if cfg["reputation"]["allow_file_upload"] else "off (hash-only)"))
    print("  Mail:           Gmail %s, IMAP accounts: %d" % ("on" if cfg["mail"]["gmail_enabled"] else "off", len(cfg["mail"]["imap_accounts"])))
    tools = macos.objective_see_tools() if macos.IS_MACOS else {}
    if tools:
        print("  Objective-See:  %s" % ", ".join("%s %s" % (k, "installed" if v else "not installed") for k, v in tools.items()))
    if macos.IS_MACOS:
        for label in ("com.sentinel.agent", "com.sentinel.mail"):
            rc, _, _ = macos.run(["launchctl", "print", "gui/%d/%s" % (os.getuid(), label)])
            print("  %-15s %s" % (label + ":", "loaded" if rc == 0 else "not loaded"))
    print("  Reports:        %s" % paths.reports_dir())
    print("  Quarantine:     %s" % paths.quarantine_dir())
    return 0


def cmd_nm_host(a):
    from . import nmhost
    return nmhost.main()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description="Sentinel — local-first Mac security guard")
    p.add_argument("--version", action="version", version="sentinel %s" % __version__)
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="analyse files now")
    s.add_argument("paths", nargs="+")
    s.add_argument("--json", action="store_true")
    s.add_argument("--no-notify", action="store_true")
    s.add_argument("--no-network", action="store_true", help="skip VirusTotal/Safe Browsing lookups")
    s.add_argument("--if-new", action="store_true", help="skip files already scanned (used by the agent)")
    s.add_argument("--source", default="cli")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("watch", help="polling download watcher (fallback when the Swift agent isn't installed)")
    s.add_argument("--scan-existing", action="store_true")
    s.set_defaults(fn=cmd_watch)

    s = sub.add_parser("check-url", help="check one link")
    s.add_argument("url")
    s.add_argument("--deep", action="store_true", help="also ask VirusTotal")
    s.add_argument("--json", action="store_true")
    s.add_argument("--no-network", action="store_true")
    s.set_defaults(fn=cmd_check_url)

    s = sub.add_parser("mail-poll", help="check new mail once (launchd runs this every 2 min)")
    s.add_argument("-v", "--verbose", action="store_true")
    s.add_argument("--no-notify", action="store_true")
    s.set_defaults(fn=cmd_mail_poll)

    s = sub.add_parser("mail-check", help="analyse a saved .eml file")
    s.add_argument("eml")
    s.add_argument("--json", action="store_true")
    s.add_argument("--no-notify", action="store_true")
    s.add_argument("--no-network", action="store_true")
    s.set_defaults(fn=cmd_mail_check)

    s = sub.add_parser("mail-setup", help="connect Gmail (OAuth, read-only) or an IMAP account (e.g. Yahoo)")
    s.add_argument("provider", choices=["gmail", "imap"])
    s.add_argument("--account", help="Gmail address (label only)")
    s.add_argument("--reset-client", action="store_true")
    s.add_argument("--name"), s.add_argument("--host"), s.add_argument("--user")
    s.set_defaults(fn=cmd_mail_setup)

    s = sub.add_parser("events", help="recent alerts")
    s.add_argument("--limit", type=int, default=30)
    s.add_argument("--all", action="store_true", help="include clean events")
    s.set_defaults(fn=cmd_events)

    s = sub.add_parser("report", help="print (or --open) the report for an event or file")
    s.add_argument("ref")
    s.add_argument("--open", action="store_true")
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("snapshot", help="re-check what a flagged file is doing (startup items, processes, network)")
    s.add_argument("event_id")
    s.set_defaults(fn=cmd_snapshot)

    s = sub.add_parser("remove", help="move an item + its startup entries to quarantine (asks for approval)")
    s.add_argument("ref", help="event id or file path")
    s.add_argument("--include-optional", action="store_true")
    s.add_argument("--stop-processes", action="store_true")
    s.add_argument("--yes", action="store_true", help="the user already approved THIS item (menu-bar app uses this)")
    s.set_defaults(fn=cmd_remove)

    s = sub.add_parser("restore", help="undo a removal")
    s.add_argument("event_id")
    s.add_argument("--yes", action="store_true")
    s.set_defaults(fn=cmd_restore)

    s = sub.add_parser("delete", help="permanently delete quarantined items (asks twice)")
    s.add_argument("event_id")
    s.add_argument("--yes-permanently", action="store_true", help="the user confirmed twice in the menu-bar app")
    s.set_defaults(fn=cmd_delete)

    s = sub.add_parser("quarantine", help="list quarantined items")
    s.set_defaults(fn=cmd_quarantine)

    s = sub.add_parser("allow", help="Always allow this source (sender / domain / signing team / exact file)")
    s.add_argument("ref", nargs="?")
    s.add_argument("--type", choices=allowlist.TYPES)
    s.add_argument("--value")
    s.add_argument("--note")
    s.set_defaults(fn=cmd_allow)

    s = sub.add_parser("allow-once", help="silence this one file")
    s.add_argument("ref")
    s.set_defaults(fn=cmd_allow_once)

    s = sub.add_parser("allowlist", help="show or edit the allowlist")
    s.add_argument("action", nargs="?", default="list", choices=["list", "remove"])
    s.add_argument("--type", choices=allowlist.TYPES)
    s.add_argument("--value")
    s.set_defaults(fn=cmd_allowlist)

    s = sub.add_parser("keys", help="manage API keys in the Keychain (never printed)")
    s.add_argument("action", choices=["set", "status", "delete"])
    s.add_argument("service", nargs="?", choices=["virustotal", "safebrowsing", "gmail-client", "imap"])
    s.add_argument("name", nargs="?", help="IMAP account name (default yahoo)")
    s.set_defaults(fn=cmd_keys)

    s = sub.add_parser("persistence", help="startup-item check (BlockBlock-lite)")
    s.add_argument("action", nargs="?", default="check", choices=["check", "baseline", "list"])
    s.add_argument("--json", action="store_true")
    s.add_argument("--no-notify", action="store_true")
    s.set_defaults(fn=cmd_persistence)

    s = sub.add_parser("vt-upload", help="upload a file's CONTENTS to VirusTotal (opt-in only)")
    s.add_argument("path")
    s.add_argument("--yes", action="store_true")
    s.set_defaults(fn=cmd_vt_upload)

    s = sub.add_parser("config", help="show / set settings")
    s.add_argument("action", choices=["show", "set", "path", "init"])
    s.add_argument("key", nargs="?")
    s.add_argument("value", nargs="?")
    s.set_defaults(fn=cmd_config)

    s = sub.add_parser("status", help="health check")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("nm-host", help=argparse.SUPPRESS)
    s.set_defaults(fn=cmd_nm_host)
    return p


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # Brave/Chrome launch native hosts with the caller origin as the first argument.
    if argv and argv[0].startswith("chrome-extension://"):
        from . import nmhost
        return nmhost.main()
    parser = build_parser()
    a = parser.parse_args(argv)
    if not getattr(a, "fn", None):
        parser.print_help()
        return 0
    if a.cmd == "config" and a.action == "set" and (not a.key or a.value is None):
        parser.error("config set needs KEY VALUE")
    paths.ensure_dirs()
    return a.fn(a) or 0


if __name__ == "__main__":
    sys.exit(main())
