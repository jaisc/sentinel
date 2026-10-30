"""Email analysis: links, sender tricks, attachments, allowlisting. Mail is only read."""
import io
import zipfile
from pathlib import Path
from email.message import EmailMessage

from helpers import SentinelTestCase, EICAR

from sentinel import allowlist, pipeline, reputation
from sentinel.mail import emailscan


def make_mail(html, text=None, attachments=(), sender="PayPal Service <service@paypa1-billing.com>", reply_to=None,
              subject="Your account is on hold", auth=None):
    m = EmailMessage()
    m["From"] = sender
    m["To"] = "me@gmail.com"
    m["Subject"] = subject
    m["Message-ID"] = "<abc123@example>"
    m["Date"] = "Thu, 29 Oct 2026 17:00:00 -0600"
    if reply_to:
        m["Reply-To"] = reply_to
    if auth:
        m["Authentication-Results"] = auth
    m.set_content(text or "plain body")
    m.add_alternative(html, subtype="html")
    for name, data, ctype in attachments:
        maintype, subtype = ctype.split("/")
        m.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return m.as_bytes()


class EmailTests(SentinelTestCase):
    def test_phishing_email(self):
        raw = make_mail('<p>Hi</p><a href="https://paypal.com.secure-check.xyz/login">https://www.paypal.com/signin</a>'
                        '<a href="https://bit.ly/3abc">Unlock account</a>',
                        reply_to="refunds@gmail.com", auth="mx.google.com; spf=fail; dkim=none; dmarc=fail")
        rec = emailscan.analyze_message(raw, account="gmail:me", use_network=False)
        codes = self.codes(rec)
        self.assertEqual(rec["verdict"], "dangerous")
        for c in ("link_text_mismatch", "url_lookalike", "url_shortener", "sender_lookalike", "dmarc_fail", "reply_to_differs"):
            self.assertIn(c, codes)
        self.assertIn("flagged link", rec["summary"])
        self.assertIn("This email arrived", rec["summary"])

    def test_attachment_checks(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("Invoice.pdf.app/Contents/MacOS/run", "x")
        raw = make_mail("<p>see attached</p>", sender="Accounts <ap@vendor.example>", attachments=[
            ("invoice.zip", buf.getvalue(), "application/zip"),
            ("budget.xlsm", b"PK\x03\x04", "application/vnd.ms-excel.sheet.macroEnabled.12"),
            ("login.html", b"<html><form action='https://evil.example/p'>", "text/html"),
            ("eicar.com", EICAR, "application/octet-stream"),
        ])
        rec = emailscan.analyze_message(raw, use_network=False)
        codes = self.codes(rec)
        self.assertIn("att_archive_executables", codes)
        self.assertIn("att_macros", codes)
        self.assertIn("att_html_attachment", codes)
        self.assertIn("att_eicar", codes)
        self.assertEqual(rec["verdict"], "dangerous")
        self.assertEqual(len(rec["attachments"]), 4)
        # Temporary attachment copies are removed after analysis.
        self.assertEqual(list((self.home / ".Sentinel" / "state" / "mail-tmp").iterdir()), [])

    def test_newsletter_tracker_not_flagged_as_phishing(self):
        raw = make_mail('<a href="https://u123.ct.sendgrid.net/ls/click?x=1">www.shopify.com</a>',
                        sender="Shopify <news@shopify.com>", subject="News")
        rec = emailscan.analyze_message(raw, use_network=False)
        self.assertNotIn("link_text_mismatch", self.codes(rec))
        self.assertEqual(rec["verdict"], "clean")

    def test_clean_email(self):
        raw = make_mail('<a href="https://www.google.com/">Google</a>', sender="Friend <friend@gmail.com>", subject="Lunch?")
        rec = emailscan.analyze_message(raw, use_network=False)
        self.assertEqual(rec["verdict"], "clean")

    def test_safe_browsing_flag(self):
        self.keys["safebrowsing-api-key"] = "PLACEHOLDER-NOT-A-KEY-test"
        # PLACEHOLDER values are treated as "not set" by the real keychain; the test store returns raw values.
        self.http.add("POST", reputation.GSB_ENDPOINT, 200,
                      {"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "https://evil.example/x"}}]})
        raw = make_mail('<a href="https://evil.example/x">Click</a>', sender="A <a@b.example>", subject="hi")
        rec = emailscan.analyze_message(raw, use_network=True)
        self.assertIn("gsb_link", self.codes(rec))
        self.assertEqual(rec["verdict"], "dangerous")
        # Allowlisting the sender must NOT hide Safe Browsing evidence.
        allowlist.add("sender", "a@b.example")
        rec = emailscan.analyze_message(raw, use_network=True)
        self.assertIsNone(rec["allowlisted"])

    def test_allowlisted_sender_suppresses_heuristics(self):
        raw = make_mail('<a href="https://bit.ly/x">deal</a>', sender="Shop <deals@shop.example>", subject="Sale")
        allowlist.add("sender", "shop.example")
        rec = emailscan.analyze_message(raw, use_network=False)
        self.assertEqual(rec["allowlisted"]["type"], "sender")
        pipeline.finish(rec, do_notify=False)

    def test_report_written_and_mail_untouched(self):
        raw = make_mail('<a href="https://paypal.com.secure-check.xyz/">https://paypal.com</a>')
        before = bytes(raw)
        rec = pipeline.finish(emailscan.analyze_message(raw, use_network=False), do_notify=False)
        self.assertEqual(raw, before)
        text = Path(rec["report_path"]).read_text()
        self.assertIn("never modifies or deletes email", text)
        self.assertIn("The email", text)
