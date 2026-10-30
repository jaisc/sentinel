"""EICAR test-file detection (the harmless industry-standard test string — never real malware)."""
import hashlib
import json
from pathlib import Path

from helpers import SentinelTestCase, EICAR

from sentinel import analyzer, pipeline


class EicarTests(SentinelTestCase):
    def test_eicar_is_dangerous_with_reason(self):
        p = self.write("eicar.com", EICAR)
        rec = analyzer.analyze_file(p, use_network=False)
        self.assertEqual(rec["verdict"], "dangerous")
        self.assertIn("eicar", self.codes(rec))
        self.assertEqual(rec["sha256"], hashlib.sha256(EICAR).hexdigest())
        self.assertEqual(rec["sha256"], "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")

    def test_eicar_with_trailing_whitespace(self):
        p = self.write("eicar.txt", EICAR + b"\r\n  ")
        self.assertTrue(analyzer.is_eicar(p))
        self.assertEqual(analyzer.analyze_file(p, use_network=False)["verdict"], "dangerous")

    def test_eicar_embedded_in_larger_file_is_not_the_test_file(self):
        p = self.write("notes.txt", b"prefix " + EICAR + b" suffix")
        self.assertFalse(analyzer.is_eicar(p))

    def test_eicar_produces_report_plan_and_notification_feed(self):
        p = self.write("eicar.com", EICAR)
        rec = pipeline.process_file(p, use_network=False, do_notify=False)
        md, plan = Path(rec["report_path"]), Path(rec["plan_path"])
        self.assertTrue(md.exists() and plan.exists())
        self.assertTrue(md.name.endswith(".md") and str(md.parent).endswith("Sentinel/Reports"))
        text = md.read_text()
        for field in ("Full path", "SHA-256", "Real type", "Code signature", "VirusTotal", "Where it came from",
                      "Risk score", "Removal plan", "What to do"):
            self.assertIn(field, text)
        pj = json.loads(plan.read_text())
        self.assertEqual(pj["schema"], "sentinel.removal-plan/1")
        self.assertEqual(pj["status"], "awaiting_user_approval")
        self.assertTrue(pj["approval_required"])
        self.assertEqual(pj["items"][0]["path"], str(p))
        self.assertTrue(p.exists(), "analysis must never move or delete anything")

    def test_clean_text_file_no_report(self):
        p = self.write("notes.txt", b"just some notes\n")
        rec = pipeline.process_file(p, use_network=False, do_notify=False)
        self.assertEqual(rec["verdict"], "clean")
        self.assertNotIn("report_path", rec)
