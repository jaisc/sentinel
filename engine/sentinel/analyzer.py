"""File analysis: what is it, where did it come from, is it dangerous?"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
from pathlib import Path
from typing import Callable, List, Optional

from . import allowlist, events, filetype as ft, macos, paths, quarantine, reputation, urlcheck
from .scoring import Reason, verdict_for, score, VERDICT_LABEL, DANGEROUS

# EICAR standard antivirus test string (harmless). Split so this source file itself
# is not flagged by antivirus products.
EICAR = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE!$H+H*").encode("ascii")

# Local known-bad hashes: EICAR variants + anything the user lists in ~/.Sentinel/known-bad.txt
BUILTIN_BAD_HASHES = {
    hashlib.sha256(EICAR).hexdigest(): "EICAR test file",
    hashlib.sha256(EICAR + b"\n").hexdigest(): "EICAR test file",
    hashlib.sha256(EICAR + b"\r\n").hexdigest(): "EICAR test file",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def is_eicar(path: Path) -> bool:
    """The EICAR spec: the file starts with the 68-byte string, optionally followed by whitespace (<=128 bytes total)."""
    try:
        if path.stat().st_size > 128:
            return False
        data = path.read_bytes()
    except OSError:
        return False
    return data.startswith(EICAR) and not data[len(EICAR):].strip()


def known_bad_hashes() -> dict:
    out = dict(BUILTIN_BAD_HASHES)
    f = paths.data_dir() / "known-bad.txt"
    try:
        for line in f.read_text().splitlines():
            parts = line.strip().split(None, 1)
            if parts and len(parts[0]) == 64 and not parts[0].startswith("#"):
                out[parts[0].lower()] = parts[1] if len(parts) > 1 else "listed in known-bad.txt"
    except OSError:
        pass
    return out


SigChecker = Callable[[Path, str], macos.SignatureInfo]


def _origin_summary(q: quarantine.QuarantineInfo, source: str, mail_context: Optional[dict]) -> dict:
    o = {"download_url": q.data_url or (q.where_froms[0] if q.where_froms else ""),
         "referrer": q.origin_url or (q.where_froms[1] if len(q.where_froms) > 1 else ""),
         "downloaded_by": q.agent, "downloaded_at": q.timestamp, "where_froms": q.where_froms,
         "email_sender": "", "email_subject": "", "source": source}
    if q.sender_name or q.sender_address:
        o["email_sender"] = ("%s <%s>" % (q.sender_name, q.sender_address)).strip()
    if mail_context:
        o["email_sender"] = mail_context.get("from", o["email_sender"])
        o["email_subject"] = mail_context.get("subject", "")
    if q.agent == "Mail" and q.where_froms and not o["email_sender"]:
        # Apple Mail stores the sender (and sometimes the message link) in WhereFroms.
        o["email_sender"] = q.where_froms[0]
        o["download_url"] = ""
    parts = []
    if o["email_sender"]:
        parts.append("email from %s" % o["email_sender"] + (" (\"%s\")" % o["email_subject"] if o["email_subject"] else ""))
    if o["download_url"]:
        parts.append("downloaded from %s" % o["download_url"])
    if q.agent and not o["email_sender"]:
        parts.append("by %s" % q.agent)
    o["summary"] = ", ".join(parts) if parts else ("no download record (not tagged by a browser or Mail)" if not q.present else "downloaded by %s" % (q.agent or "an unknown app"))
    return o


def analyze_file(path, source: str = "watcher", sig_checker: Optional[SigChecker] = None,
                 use_network: bool = True, mail_context: Optional[dict] = None,
                 quarantine_db: Optional[Path] = None) -> dict:
    """Analyse one file or bundle. Pure read-only: never moves, opens, or runs it."""
    path = Path(path)
    now = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    reasons = []  # type: List[Reason]
    info = ft.sniff(path)

    # Hash: the file itself, or the main executable of an .app bundle.
    hash_target = path
    if path.is_dir():
        hash_target = ft.bundle_executable(path) or path
    sha = sha256_file(hash_target) if hash_target.is_file() else ""
    size = path.stat().st_size if path.is_file() else _dir_size(path)

    # --- hard evidence --------------------------------------------------------
    if path.is_file() and is_eicar(path):
        reasons.append(Reason("eicar", 150, "This is the EICAR antivirus test file",
                              "EICAR is a harmless, industry-standard test file. Sentinel treats it exactly like "
                              "malware so you can see what a real alert and removal look like."))
    bad = known_bad_hashes().get(sha)
    if bad and not any(r.code == "eicar" for r in reasons):
        reasons.append(Reason("known_bad_hash", 150, "Its fingerprint matches a known-bad file (%s)" % bad,
                              "This exact file has been identified as malicious before."))

    # --- name tricks ------------------------------------------------------------
    for t in ft.name_tricks(path.name):
        reasons.append(Reason("name_" + t.kind, 100, "Disguised file name", t.detail))

    # --- real type vs claimed extension -------------------------------------------
    claimed, real = info.claimed_category, info.category
    if claimed and claimed != ft.UNKNOWN and claimed != real and real != ft.UNKNOWN:
        if real in ft.RUNNABLE and claimed in ft.HARMLESS_LOOKING | {ft.MACRO_DOCUMENT, ft.HTML, ft.ARCHIVE}:
            reasons.append(Reason("ext_type_mismatch", 100,
                                  "\"%s\" is named like a .%s but is really a %s" % (path.name, info.claimed_ext, info.label),
                                  "A program pretending to be a document is a classic malware trick: opening it runs code."))
        elif real in (ft.DISK_IMAGE, ft.ARCHIVE, ft.INSTALLER) and claimed in ft.HARMLESS_LOOKING:
            reasons.append(Reason("ext_type_mismatch", 60,
                                  "\"%s\" is named like a .%s but is really a %s" % (path.name, info.claimed_ext, info.label),
                                  "Files whose name lies about their type are often hiding something."))
        elif real == ft.HTML and claimed == ft.IMAGE:
            reasons.append(Reason("svg_script", 40, "This image contains web code (script)",
                                  "Images that run scripts can open fake login pages when previewed in a browser."))
        elif not (claimed in ft.RUNNABLE and real == ft.TEXT) and not (claimed == ft.TEXT and real in (ft.HTML, ft.TEXT)) and not (claimed in (ft.SCRIPT, ft.HTML) and real == ft.TEXT) \
                and not (claimed == ft.ARCHIVE and real in (ft.ARCHIVE, ft.DOCUMENT, ft.JAVA)) \
                and not (claimed == ft.DOCUMENT and real == ft.TEXT and info.claimed_ext in ("csv",)):
            reasons.append(Reason("ext_type_mismatch_minor", 20,
                                  "\"%s\" is named like a .%s but its contents are %s" % (path.name, info.claimed_ext, info.label),
                                  "Not necessarily harmful, but the name doesn't match what the file really is."))

    # --- what kind of thing is it ------------------------------------------------
    checker = sig_checker or macos.check_signature
    sig = checker(path, real)
    if real in (ft.EXECUTABLE, ft.APP_BUNDLE):
        if sig.status == "unsigned":
            reasons.append(Reason("unsigned_executable", 60, "This is a program with no developer signature",
                                  "macOS can't tell who made it. Legitimate Mac apps are almost always signed and notarized by Apple."))
        elif sig.status == "signed_invalid":
            reasons.append(Reason("bad_signature", 80, "This program's signature is broken or has been tampered with",
                                  "A broken signature can mean the app was modified after the developer signed it."))
        elif sig.status == "signed_detritus":
            reasons.append(Reason("signature_detritus", 5, "This program's signature is intact, but it carries stray file attributes",
                                  "Finder, Spotlight and backup tools leave these behind on ordinary apps. The developer seal itself verifies; this is housekeeping, not tampering. `xattr -cr` on the app clears it."))
        elif sig.status == "adhoc":
            reasons.append(Reason("adhoc_signature", 45, "This program is only 'ad-hoc' signed (no identified developer)",
                                  "Ad-hoc signatures prove nothing about who made the program."))
        elif sig.status == "unavailable":
            reasons.append(Reason("signature_unchecked", 30, "This is a program; its signature could not be checked here",
                                  "Run Sentinel on the Mac itself to verify the developer signature.", observed=False))
        if sig.gatekeeper == "rejected" and sig.status in ("signed_valid", "signed_detritus"):
            reasons.append(Reason("gatekeeper_rejected", 40, "Gatekeeper would block this program (%s)" % (sig.gatekeeper_source or "not notarized"),
                                  "Apple's own check does not trust it to run."))
        if sig.notarized:
            reasons.append(Reason("notarized", -15, "Notarized by Apple (%s)" % (sig.signer or "identified developer"),
                                  "Apple scanned this program for known malware before it was published."))
    elif real == ft.INSTALLER:
        reasons.append(Reason("installer", 25, "This is an installer package",
                              "Installers can put files anywhere on your Mac, including hidden background items. Only run ones you expected."))
        if sig.status in ("unsigned", "signed_invalid"):
            reasons.append(Reason("unsigned_installer", 45, "The installer is %s" % ("unsigned" if sig.status == "unsigned" else "badly signed"),
                                  "Nobody vouches for what this installer will do."))
        elif sig.status == "unavailable":
            reasons.append(Reason("signature_unchecked", 10, "Installer signature not checked here", "Verify on the Mac.", observed=False))
    elif real == ft.DISK_IMAGE:
        reasons.append(Reason("disk_image", 10, "This is a disk image (.dmg/.iso)",
                              "Disk images are how most Mac apps arrive — and most Mac malware too. Check the app inside before running it."))
    elif real == ft.SCRIPT:
        pts = 45 if info.claimed_ext in ("command", "tool", "terminal") else 35
        reasons.append(Reason("script", pts, "This is a script (%s)" % info.label,
                              "Scripts run commands with your full permissions and macOS does not vet them."))
    elif real == ft.JAVA:
        reasons.append(Reason("java", 30, "This is a Java program", "Java programs run code; they're rarely needed for everyday use."))
    if real == ft.MACRO_DOCUMENT or info.has_macros or claimed == ft.MACRO_DOCUMENT:
        reasons.append(Reason("macros", 45, "This document contains (or is a type that allows) macros",
                              "Macros are small programs inside Office files. Never click 'Enable content' unless you expected it."))
    if info.archive_members:
        shown = ", ".join(info.archive_members[:5])
        reasons.append(Reason("archive_executables", 35, "The archive contains programs or scripts: %s" % shown,
                              "Archives are used to sneak programs past email and browser filters."))
        for member in info.archive_members:
            for t in ft.name_tricks(member.rstrip("/").split("/")[-1]):
                reasons.append(Reason("archive_name_trick", 100, "A file inside the archive has a disguised name", t.detail))
                break
    if real == ft.HTML and source.startswith("mail"):
        reasons.append(Reason("html_attachment", 30, "This is a web page sent as an attachment",
                              "HTML attachments are a common way to show a fake login page that runs on your own computer."))
    if real == ft.WEB_SHORTCUT:
        reasons.append(Reason("web_shortcut", 20, "This is a web shortcut", "Opening it sends you to a website — check where first."))

    # --- origin -------------------------------------------------------------------
    q = quarantine.read_quarantine(path, quarantine_db)
    origin = _origin_summary(q, source, mail_context)
    origin_host = urlcheck.hostname(origin["download_url"]) if origin["download_url"] else ""
    if origin["download_url"]:
        for r in urlcheck.analyze_url(origin["download_url"]):
            if r.code == "url_download":
                continue
            r.title = "Download source: " + r.title[0].lower() + r.title[1:]
            reasons.append(r)
    if not q.present and real in (ft.EXECUTABLE, ft.APP_BUNDLE, ft.INSTALLER, ft.SCRIPT) and source == "watcher":
        reasons.append(Reason("no_quarantine", 25, "This program has no download tag",
                              "Files saved by browsers and Mail are tagged so Gatekeeper checks them on first open. "
                              "This one isn't — it may have been fetched by a script or tool (common for malware droppers).",
                              observed=True))

    # --- reputation (hash only by default) -------------------------------------------
    rep = {}
    if use_network and sha:
        rep["virustotal"] = reputation.vt_file(sha)
        vt = rep["virustotal"]
        if vt.get("status") == "found":
            mal, sus = vt.get("malicious", 0), vt.get("suspicious", 0)
            if mal >= 3:
                reasons.append(Reason("vt_malicious", 150, "%d antivirus engines on VirusTotal flag this file as malicious%s" % (
                    mal, (" (%s)" % vt["label"]) if vt.get("label") else ""), "Multiple independent engines agree this is malware."))
            elif mal >= 1 or sus >= 3:
                reasons.append(Reason("vt_some", 40, "%d engine(s) on VirusTotal flag this file (%d suspicious)" % (mal, sus),
                                      "A few detections can be false positives, but treat it with care."))
            elif real in ft.RUNNABLE:
                reasons.append(Reason("vt_clean", -10, "VirusTotal knows this file and no engine flags it",
                                      "Good sign, though brand-new malware can go undetected for a while."))
        elif vt.get("status") == "not_found" and real in ft.RUNNABLE | {ft.DISK_IMAGE}:
            reasons.append(Reason("vt_unknown", 10, "VirusTotal has never seen this file",
                                  "Brand-new or rare programs are riskier simply because nobody has checked them yet.", observed=True))
        if origin["download_url"]:
            g = reputation.safe_browsing([origin["download_url"]]).get(origin["download_url"], {})
            rep["safebrowsing_origin"] = g
            if g.get("status") == "flagged":
                reasons.append(Reason("gsb_origin", 100, "Google Safe Browsing lists the download site as %s" % (
                    ", ".join(reputation.GSB_THREAT_TEXT.get(t, t) for t in g.get("threats", []))),
                                      "The website this came from is known to be dangerous."))
    cav = macos.clamscan(path) if path.is_file() else None
    if cav and cav.get("infected"):
        reasons.append(Reason("clamav", 150, "ClamAV detected: %s" % cav["detail"], "Your local antivirus recognizes this file as malicious."))

    verdict = verdict_for(reasons)

    # --- allowlist ---------------------------------------------------------------------
    allowed_by = allowlist.match(sha256=sha, host=origin_host,
                                 sender=_addr(origin.get("email_sender", "")), team_id=sig.team_id)
    if allowed_by and allowed_by["type"] != "sha256" and any(allowlist.is_hard_evidence(r.code) for r in reasons):
        allowed_by = None  # an allowed source never hides hard evidence
    if not allowed_by and sha and allowlist.allowed_once(str(path), sha):
        allowed_by = {"type": "once", "value": str(path)}

    rec = {
        "id": events.new_id("file", sha),
        "kind": "file",
        "path": str(path),
        "name": path.name,
        "first_seen": now,
        "source": source,
        "size": size,
        "sha256": sha,
        "sha256_of": str(hash_target) if hash_target != path else "",
        "type": {"real_category": real, "real_label": info.label, "claimed_extension": info.claimed_ext,
                 "claimed_category": claimed, "file_command": info.file_description,
                 "archive_runnable_members": info.archive_members, "has_macros": info.has_macros},
        "quarantine": q.to_dict(),
        "origin": origin,
        "signature": sig.to_dict(),
        "reputation": rep,
        "clamav": cav,
        "reasons": [r.to_dict() for r in sorted(reasons, key=lambda r: -r.points)],
        "score": score(reasons),
        "verdict": verdict,
        "allowlisted": allowed_by,
    }
    rec["title"] = "%s: %s" % (VERDICT_LABEL[verdict], path.name)
    top = [r for r in reasons if r.points > 0]
    top.sort(key=lambda r: -r.points)
    rec["summary"] = top[0].title if top else "Nothing suspicious found."
    return rec


def _addr(sender: str) -> str:
    if "<" in sender and ">" in sender:
        return sender.split("<", 1)[1].split(">", 1)[0].strip()
    return sender.strip()


def _dir_size(p: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(p):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


def is_dangerous(rec: dict) -> bool:
    return rec.get("verdict") == DANGEROUS
