"""Quarantine-origin parsing: xattr string, kMDItemWhereFroms plist, QuarantineEventsV2 DB."""
import datetime as dt
import plistlib
import sqlite3
from unittest import mock

from helpers import SentinelTestCase, MACHO_ARM64, unsigned_checker

from sentinel import analyzer, quarantine

UUID = "5A1C2B3D-1111-2222-3333-444455556666"


class QuarantineTests(SentinelTestCase):
    def test_parse_xattr_value(self):
        ts = int(dt.datetime(2026, 10, 29, 17, 0, tzinfo=dt.timezone.utc).timestamp())
        q = quarantine.parse_quarantine_value("0083;%x;Brave Browser;%s" % (ts, UUID))
        self.assertTrue(q.present)
        self.assertEqual(q.flags, 0x83)
        self.assertEqual(q.agent, "Brave Browser")
        self.assertEqual(q.event_id, UUID)
        self.assertTrue(q.timestamp.startswith("2026-10-29T17:00:00"))
        self.assertFalse(q.user_approved)
        self.assertTrue(quarantine.parse_quarantine_value("00c3;%x;Safari;" % ts).user_approved)

    def test_parse_malformed_values_do_not_crash(self):
        for raw in ("", ";;;", "zz;yy;", "0081", "0081;notahex;Chrome"):
            q = quarantine.parse_quarantine_value(raw)
            self.assertTrue(q.present)

    def test_parse_where_froms_binary_plist(self):
        data = plistlib.dumps(["https://dl.example.net/setup.dmg", "https://example.net/download"], fmt=plistlib.FMT_BINARY)
        self.assertEqual(quarantine.parse_where_froms(data),
                         ["https://dl.example.net/setup.dmg", "https://example.net/download"])
        self.assertEqual(quarantine.parse_where_froms(b"garbage"), [])

    def _make_db(self):
        db = self.home / "QuarantineEventsV2"
        c = sqlite3.connect(db)
        c.execute("""CREATE TABLE LSQuarantineEvent (ID INTEGER PRIMARY KEY, LSQuarantineEventIdentifier TEXT,
                     LSQuarantineTimeStamp REAL, LSQuarantineAgentBundleIdentifier TEXT, LSQuarantineAgentName TEXT,
                     LSQuarantineDataURLString TEXT, LSQuarantineSenderName TEXT, LSQuarantineSenderAddress TEXT,
                     LSQuarantineTypeNumber INTEGER, LSQuarantineOriginTitle TEXT, LSQuarantineOriginURLString TEXT,
                     LSQuarantineOriginAlias BLOB)""")
        c.execute("INSERT INTO LSQuarantineEvent (LSQuarantineEventIdentifier, LSQuarantineTimeStamp, LSQuarantineAgentName,"
                  " LSQuarantineDataURLString, LSQuarantineOriginURLString) VALUES (?,?,?,?,?)",
                  (UUID, 783450000.0, "Brave Browser", "http://paypal.com.account-verify.xyz/Invoice.pdf",
                   "http://paypal.com.account-verify.xyz/"))
        c.commit()
        c.close()
        return db

    def test_lookup_event_db(self):
        row = quarantine.lookup_quarantine_event(UUID.lower(), self._make_db())
        self.assertEqual(row["LSQuarantineDataURLString"], "http://paypal.com.account-verify.xyz/Invoice.pdf")
        self.assertTrue(row["timestamp"].startswith("2025-"))  # Cocoa epoch (2001) + 783450000 s
        self.assertEqual(quarantine.lookup_quarantine_event("missing", self.home / "nope"), {})

    def test_full_origin_flows_into_analysis(self):
        db = self._make_db()
        p = self.write("Invoice.pdf", MACHO_ARM64)
        attrs = {quarantine.QUARANTINE_XATTR: ("0083;6720a1b2;Brave Browser;%s" % UUID).encode(),
                 quarantine.WHEREFROMS_XATTR: plistlib.dumps(["http://paypal.com.account-verify.xyz/Invoice.pdf"], fmt=plistlib.FMT_BINARY)}
        with mock.patch.object(quarantine, "read_xattr", lambda path, name: attrs.get(name)):
            rec = analyzer.analyze_file(p, use_network=False, sig_checker=unsigned_checker, quarantine_db=db)
        o = rec["origin"]
        self.assertEqual(o["download_url"], "http://paypal.com.account-verify.xyz/Invoice.pdf")
        self.assertEqual(o["downloaded_by"], "Brave Browser")
        self.assertIn("downloaded from http://paypal.com.account-verify.xyz", o["summary"])
        self.assertIn("url_lookalike", self.codes(rec))           # origin heuristics applied
        self.assertNotIn("no_quarantine", self.codes(rec))
        self.assertEqual(rec["verdict"], "dangerous")

    def test_mail_attachment_origin(self):
        p = self.write("statement.zip", b"PK\x05\x06" + b"\x00" * 18)
        attrs = {quarantine.QUARANTINE_XATTR: b"0083;6720a1b2;Mail;",
                 quarantine.WHEREFROMS_XATTR: plistlib.dumps(["Billing <billing@pay-pal-support.com>", "message:%3Cabc@x%3E"])}
        with mock.patch.object(quarantine, "read_xattr", lambda path, name: attrs.get(name)):
            rec = analyzer.analyze_file(p, use_network=False)
        self.assertEqual(rec["origin"]["email_sender"], "Billing <billing@pay-pal-support.com>")
        self.assertIn("email from", rec["origin"]["summary"])

    def test_no_quarantine_attribute(self):
        p = self.write("notes.txt", b"hello")
        with mock.patch.object(quarantine, "read_xattr", lambda path, name: None):
            q = quarantine.read_quarantine(p)
        self.assertFalse(q.present)
        self.assertEqual(q.best_origin(), "")
