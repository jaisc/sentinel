"""Removal assistant: quarantine-first, reversible, approval-gated, logged."""
import json
from pathlib import Path
import os
import stat

from helpers import SentinelTestCase, EICAR, MACHO_ARM64, unsigned_checker

from sentinel import cli, events, paths, pipeline, removal, analyzer


class RemovalTests(SentinelTestCase):
    def _flag(self, name="eicar.com", data=EICAR, mode=0o755):
        p = self.write(name, data, mode=mode)
        return p, pipeline.process_file(p, use_network=False, do_notify=False)

    def test_remove_restore_roundtrip(self):
        p, rec = self._flag()
        res = removal.remove(rec["id"])
        self.assertEqual(res["status"], "quarantined")
        self.assertFalse(p.exists())
        m = removal.load_manifest(rec["id"])
        q = m["items"][0]
        self.assertEqual(q["original_path"], str(p))
        self.assertTrue(q["quarantined_path"].startswith(str(paths.quarantine_dir() / rec["id"])))
        qmode = os.stat(q["quarantined_path"]).st_mode
        self.assertFalse(qmode & stat.S_IXUSR, "exec bits stripped while quarantined")
        self.assertEqual(json.loads(Path(rec["plan_path"]).read_text())["status"], "quarantined")
        self.assertEqual(events.load(rec["id"])["status"], "quarantined")

        res = removal.restore(rec["id"])
        self.assertEqual(res["status"], "restored")
        self.assertTrue(p.exists())
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o755)
        self.assertEqual(p.read_bytes(), EICAR)

    def test_every_action_logged(self):
        _, rec = self._flag()
        removal.remove(rec["id"])
        removal.restore(rec["id"])
        removal.remove(rec["id"])
        removal.delete(rec["id"])
        actions = [json.loads(l)["action"] for l in (paths.logs_dir() / "actions.log").read_text().splitlines()]
        self.assertEqual(actions, ["remove", "restore", "remove", "delete_permanently"])

    def test_delete_requires_quarantine_first(self):
        p, rec = self._flag()
        with self.assertRaises(removal.RemovalError):
            removal.delete(rec["id"])
        self.assertTrue(p.exists())

    def test_delete_only_inside_quarantine(self):
        p, rec = self._flag()
        removal.remove(rec["id"])
        m = removal.load_manifest(rec["id"])
        outside = self.home / "precious.txt"
        outside.write_text("keep me")
        m["items"].append({"n": 9, "kind": "file", "original_path": str(outside), "quarantined_path": str(outside)})
        paths.write_json_atomic(removal.manifest_path(rec["id"]), m)
        res = removal.delete(rec["id"])
        self.assertTrue(outside.exists(), "must refuse to delete outside the quarantine folder")
        self.assertTrue(any(not r["ok"] and "refused" in r["error"] for r in res["results"]))

    def test_refuses_changed_file(self):
        p, rec = self._flag()
        p.write_bytes(b"different content now")
        res = removal.remove(rec["id"])
        self.assertTrue(p.exists())
        self.assertIn("SHA-256 differs", res["results"][0]["skipped"])

    def test_restore_does_not_overwrite(self):
        p, rec = self._flag()
        removal.remove(rec["id"])
        p.write_text("new file with same name")
        res = removal.restore(rec["id"])
        self.assertFalse(res["results"][0]["ok"])
        self.assertEqual(p.read_text(), "new file with same name")

    def test_cli_remove_needs_approval_non_interactive(self):
        p, rec = self._flag()
        rc = cli.main(["remove", rec["id"]])  # stdin is not a TTY under the test runner, no --yes
        self.assertEqual(rc, 1)
        self.assertTrue(p.exists())
        rc = cli.main(["remove", rec["id"], "--yes"])
        self.assertEqual(rc, 0)
        self.assertFalse(p.exists())
        rc = cli.main(["delete", rec["id"]])  # second confirmation can't be typed -> refused
        self.assertEqual(rc, 1)
        self.assertEqual(removal.load_manifest(rec["id"])["status"], "quarantined")

    def test_plan_lists_exact_commands(self):
        p = self.write("invoice.pdf", MACHO_ARM64)
        rec = analyzer.analyze_file(p, use_network=False, sig_checker=unsigned_checker)
        rec = pipeline.finish(rec, do_notify=False)
        plan = json.loads(Path(rec["plan_path"]).read_text())
        self.assertEqual(plan["commands"]["remove"], "sentinel remove %s" % rec["id"])
        self.assertTrue(any("mv" in c and str(p) in c for c in plan["commands"]["manual_equivalent"]))
        self.assertEqual(plan["antivirus_handoff"]["sha256"], rec["sha256"])
