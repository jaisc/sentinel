"""Analyse one RFC 822 message: links, attachments, sender. Never modifies mail."""
from __future__ import annotations

import datetime as dt
import email
import email.policy
import email.utils
import hashlib
import os
import re
import shutil
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .. import allowlist, analyzer, events, paths, reputation, urlcheck
from ..scoring import Reason, verdict_for, score, VERDICT_LABEL

MAX_LINKS = 150
MAX_ATTACHMENT_BYTES = 40 * 1024 * 1024

# Mail-tracking / click-redirect services: link text and href legitimately differ.
TRACKING_DOMAINS = {
    "sendgrid.net", "list-manage.com", "mailchimp.com", "mandrillapp.com", "hubspotlinks.com", "hs-sites.com",
    "rs6.net", "constantcontact.com", "exacttarget.com", "sailthru.com", "klaviyo.com", "klclick.com",
    "awstrack.me", "mailgun.org", "mailgun.net", "sparkpostmail.com", "mcusercontent.com", "ct.sendgrid.net",
    "safelinks.protection.outlook.com", "protection.outlook.com", "linkedin.com", "mailjet.com", "cmail19.com",
    "cmail20.com", "createsend.com", "emltrk.com", "mkt.com", "marketo.com", "mktoweb.com", "substack.com",
    "beehiiv.com", "convertkit-mail.com", "ck.page", "postmarkapp.com", "pstmrk.it", "urldefense.com",
    "mimecast.com", "e.customeriomail.com", "customeriomail.com", "click.e.amazon.com",
}


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []  # type: List[Tuple[str, str]]
        self._href = None  # type: Optional[str]
        self._text = []  # type: List[str]

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._finish()
            self._href, self._text = a["href"].strip(), []
        elif tag == "form" and a.get("action"):
            self.links.append((a["action"].strip(), "[form submits to]"))
        elif tag == "area" and a.get("href"):
            self.links.append((a["href"].strip(), ""))
        elif tag == "img" and self._href is not None and a.get("alt"):
            self._text.append(a["alt"])

    def handle_endtag(self, tag):
        if tag == "a":
            self._finish()

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def _finish(self):
        if self._href is not None:
            self.links.append((self._href, " ".join("".join(self._text).split())))
        self._href, self._text = None, []

    def close(self):
        super().close()
        self._finish()


_URL_RE = re.compile(r"""\bhttps?://[^\s<>"'\)\]]+""", re.I)


def extract_links(msg) -> List[Dict[str, str]]:
    seen, out = set(), []

    def add(url, text=""):
        url = url.strip().rstrip(".,;:!?")
        low = url.lower()
        if not low.startswith(("http://", "https://", "javascript:", "data:")):
            return
        key = (url, text)
        if key in seen or len(out) >= MAX_LINKS:
            return
        seen.add(key)
        out.append({"url": url, "text": text})

    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/html", "text/plain"):
            continue
        try:
            body = part.get_content()
        except (LookupError, ValueError, AssertionError):
            payload = part.get_payload(decode=True) or b""
            body = payload.decode("utf-8", "replace")
        if ctype == "text/html":
            p = _LinkParser()
            try:
                p.feed(body)
                p.close()
            except Exception:
                pass
            for href, text in p.links:
                add(href, text)
        else:
            for m in _URL_RE.finditer(body):
                add(m.group(0))
    return out


def attachments(msg) -> List[dict]:
    out = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fn = part.get_filename()
        disp = part.get_content_disposition()
        if not fn and disp != "attachment":
            continue
        payload = part.get_payload(decode=True) or b""
        out.append({"filename": fn or "unnamed", "content_type": part.get_content_type(), "data": payload[:MAX_ATTACHMENT_BYTES],
                    "size": len(payload)})
    return out


def _addr_domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def sender_reasons(msg) -> Tuple[List[Reason], dict]:
    reasons = []  # type: List[Reason]
    from_raw = str(msg.get("From", ""))
    name, addr = email.utils.parseaddr(from_raw)
    reply_raw = str(msg.get("Reply-To", ""))
    _, reply = email.utils.parseaddr(reply_raw)
    fdom = _addr_domain(addr)
    info = {"from": from_raw, "from_address": addr, "from_name": name, "reply_to": reply_raw}

    if fdom:
        look = urlcheck.lookalike_of(fdom)
        if look:
            reasons.append(Reason("sender_lookalike", max(70, look[2]), "The sender's address (%s) %s" % (addr, look[1]),
                                  "Scammers register addresses that look like real companies.", observed=False))
    # Display name claims a brand / shows another address, but the real address is elsewhere.
    m = re.search(r"[\w.+-]+@([\w-]+\.)+[a-z]{2,}", name or "", re.I)
    if m and _addr_domain(m.group(0)) != fdom:
        reasons.append(Reason("sender_name_spoof", 60, "The sender's name shows %s but the real address is %s" % (m.group(0), addr),
                              "Putting a different address in the display name is a common impersonation trick."))
    else:
        nm = re.sub(r"[^a-z]", "", (name or "").lower())
        for brand, legit in urlcheck.PROTECTED_BRANDS.items():
            if len(brand) >= 5 and brand in nm and fdom and urlcheck.registrable_domain(fdom) not in legit:
                reasons.append(Reason("sender_brand_mismatch", 45,
                                      "The sender calls themselves \"%s\" but writes from %s" % (name, fdom),
                                      "Real %s emails come from %s." % (brand.capitalize(), legit[0]), observed=False))
                break
    if reply and _addr_domain(reply) and fdom and urlcheck.registrable_domain(_addr_domain(reply)) != urlcheck.registrable_domain(fdom):
        reasons.append(Reason("reply_to_differs", 20, "Replies would go to a different address (%s)" % reply,
                              "Scammers often set a different reply address to receive your answer."))
    auth = " ".join(str(h) for h in msg.get_all("Authentication-Results", []) or [])
    info["auth_summary"] = _auth_summary(auth)
    if re.search(r"dmarc=fail", auth, re.I):
        reasons.append(Reason("dmarc_fail", 45, "The sender failed email authentication (DMARC)",
                              "The message may not really come from %s." % (fdom or "the domain it claims")))
    elif re.search(r"spf=fail", auth, re.I) and re.search(r"dkim=(fail|none)", auth, re.I):
        reasons.append(Reason("spf_dkim_fail", 30, "The sender failed email authentication (SPF and DKIM)",
                              "The message may be forged."))
    return reasons, info


def _auth_summary(auth: str) -> str:
    parts = []
    for k in ("spf", "dkim", "dmarc"):
        m = re.search(r"\b%s=(\w+)" % k, auth, re.I)
        if m:
            parts.append("%s=%s" % (k.upper(), m.group(1).lower()))
    return ", ".join(parts)


def _received(msg, internal_ms: Optional[int]) -> Tuple[str, str]:
    when = None
    if internal_ms:
        when = dt.datetime.fromtimestamp(internal_ms / 1000, tz=dt.timezone.utc)
    else:
        try:
            when = email.utils.parsedate_to_datetime(str(msg.get("Date", "")))
        except (TypeError, ValueError):
            when = None
    if when is None:
        return "", "recently"
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    mins = int((dt.datetime.now(dt.timezone.utc) - when).total_seconds() // 60)
    rel = "just now" if mins < 1 else ("%d min ago" % mins if mins < 120 else "%d hours ago" % (mins // 60) if mins < 48 * 60 else "on %s" % when.date())
    return when.astimezone().isoformat(timespec="seconds"), rel


def analyze_message(raw: bytes, account: str = "", internal_ms: Optional[int] = None,
                    use_network: bool = True, mail_id: str = "") -> dict:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    reasons, info = sender_reasons(msg)
    subject = str(msg.get("Subject", ""))
    received_iso, received_rel = _received(msg, internal_ms)

    # --- links -------------------------------------------------------------------
    links = extract_links(msg)
    gsb = reputation.safe_browsing([l["url"] for l in links if l["url"].lower().startswith("http")]) if (use_network and links) else {}
    best = {}  # type: Dict[str, Reason]  # one reason per code across all links (avoid inflating)
    flagged_links = 0
    for l in links:
        lr = urlcheck.analyze_url(l["url"])
        mm = urlcheck.display_mismatch(l["text"], l["url"])
        if mm:
            dom = urlcheck.registrable_domain(urlcheck.hostname(l["url"]))
            if dom in TRACKING_DOMAINS or urlcheck.hostname(l["url"]) in TRACKING_DOMAINS:
                mm = Reason("link_via_tracker", 5, "A link goes through a mail-tracking service (%s)" % dom,
                            "Normal for newsletters; the final destination isn't visible until clicked.")
            lr.append(mm)
        g = gsb.get(l["url"])
        if g:
            l["safebrowsing"] = g
            if g.get("status") == "flagged":
                lr.append(Reason("gsb_link", 120, "Google Safe Browsing lists a link as %s: %s" % (
                    ", ".join(reputation.GSB_THREAT_TEXT.get(t, t) for t in g.get("threats", [])), urlcheck.hostname(l["url"])),
                                 "Opening it is known to be dangerous."))
        if use_network and any(r.points >= 25 for r in lr):
            v = reputation.vt_url(l["url"], wait=False)
            l["virustotal"] = v
            if v.get("status") == "found" and v.get("malicious", 0) >= 2:
                lr.append(Reason("vt_url_malicious", 100, "%d VirusTotal engines flag a link (%s)" % (v["malicious"], urlcheck.hostname(l["url"])),
                                 "Independent security vendors consider this site malicious."))
        l["reasons"] = [r.to_dict() for r in lr]
        l["flagged"] = sum(r.points for r in lr) >= 20
        flagged_links += l["flagged"]
        for r in lr:
            if r.code not in best or r.points > best[r.code].points:
                best[r.code] = r
    reasons.extend(best.values())

    # --- attachments ----------------------------------------------------------------
    atts = []
    tmp_root = paths.state_dir() / "mail-tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    os.chmod(tmp_root, 0o700)
    for a in attachments(msg):
        d = Path(tempfile.mkdtemp(dir=str(tmp_root)))
        safe_name = Path(a["filename"]).name.replace("/", "_") or "attachment"
        p = d / safe_name
        try:
            with open(p, "wb") as f:
                f.write(a["data"])
            os.chmod(p, 0o600)  # never executable
            arec = analyzer.analyze_file(p, source="mail-attachment", use_network=use_network)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        entry = {"filename": a["filename"], "content_type": a["content_type"], "size": a["size"],
                 "sha256": hashlib.sha256(a["data"]).hexdigest(), "real_label": arec["type"]["real_label"],
                 "real_category": arec["type"]["real_category"], "verdict": arec["verdict"],
                 "reasons": arec["reasons"], "virustotal": arec["reputation"].get("virustotal")}
        atts.append(entry)
        for r in arec["reasons"]:
            if r["points"] <= 0 or r["code"] == "signature_unchecked":
                continue
            reasons.append(Reason("att_" + r["code"], r["points"], "Attachment \"%s\": %s" % (a["filename"], r["title"][0].lower() + r["title"][1:]),
                                  r["why"], r.get("observed", True)))

    verdict = verdict_for(reasons)
    digest = hashlib.sha256((str(msg.get("Message-ID", "")) + subject + info["from"]).encode()).hexdigest()
    rec = {
        "id": events.new_id("mail", digest), "kind": "email", "account": account, "mail_id": mail_id,
        "message_id": str(msg.get("Message-ID", "")), "from": info["from"], "from_address": info["from_address"],
        "reply_to": info["reply_to"], "subject": subject, "received": received_iso or received_rel,
        "received_relative": received_rel, "auth_summary": info.get("auth_summary", ""),
        "first_seen": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "name": "email-" + (re.sub(r"\s+", "-", subject)[:40] or "no-subject"),
        "links": links, "attachments": atts,
        "reasons": [r.to_dict() for r in sorted(reasons, key=lambda r: -r.points)],
        "score": score(reasons), "verdict": verdict,
    }
    allowed = allowlist.match(sender=info["from_address"])
    if allowed and any(allowlist.is_hard_evidence(r.code) for r in reasons):
        allowed = None
    rec["allowlisted"] = allowed
    flagged_att = [a for a in atts if a["verdict"] != "clean"]
    what = []
    if flagged_links:
        what.append("%d flagged link%s" % (flagged_links, "s" if flagged_links > 1 else ""))
    if flagged_att:
        what.append("a flagged attachment (%s)" % flagged_att[0]["filename"])
    if not what and verdict != "clean":
        what.append("a suspicious sender")
    rec["title"] = "%s email: %s" % (VERDICT_LABEL[verdict], subject[:60] or "(no subject)")
    rec["summary"] = ("This email arrived %s with %s — from %s" % (received_rel, " and ".join(what), info["from_address"] or info["from"])
                      if what else "No problems found.")
    return rec
