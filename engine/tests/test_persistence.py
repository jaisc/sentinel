"""Persistence scan / new-startup-item alerts and behaviour snapshot attribution."""
import json
from pathlib import Path
import plistlib

from helpers import SentinelTestCase, EICAR

from sentinel import paths, persistence, pipeline, removal


class PersistenceTests(SentinelTestCase):
    def setUp(self):
        super().setUp()
        self.agents = self.home / "Library" / "LaunchAgents"
        self.agents.mkdir(parents=True)
        cfg = paths.load_config()
        cfg["persistence_folders"] = ["~/Library/LaunchAgents"]
        paths.save_config(cfg)

    def _agent(self, label, program):
        p = self.agents / ("%s.plist" % label)
        p.write_bytes(plistlib.dumps({"Label": label, "ProgramArguments": [program, "--daemon"], "RunAtLoad": True}))
        return p

    def test_new_launch_agent_from_tmp_is_dangerous(self):
        self._agent("com.legit.updater", "/Applications/Legit.app/Contents/MacOS/updater")
        self.assertIsNone(pipeline.persistence_check(do_notify=False))  # first run = baseline
        plist = self._agent("com.apple.softwareupdate.helper", "/tmp/.hidden/helper")
        rec = pipeline.persistence_check(do_notify=False)
        self.assertEqual(rec["kind"], "persistence")
        self.assertEqual(rec["verdict"], "dangerous")
        self.assertEqual(rec["entries"][0]["path"], str(plist))
        plan = json.loads(Path(rec["plan_path"]).read_text())
        self.assertEqual(plan["items"][0]["kind"], "launch_item")
        self.assertTrue(any("launchctl bootout" in s for s in plan["items"][0]["pre_steps"]))
        # Approved removal quarantines the plist and restore puts it back.
        removal.remove(rec["id"])
        self.assertFalse(plist.exists())
        removal.restore(rec["id"])
        self.assertTrue(plist.exists())
        # No change -> no alert.
        self.assertIsNone(pipeline.persistence_check(do_notify=False))

    def test_flagged_download_attribution(self):
        pipeline.persistence_check(do_notify=False)  # baseline
        f = self.write("eicar.com", EICAR)
        rec = pipeline.process_file(f, use_network=False, do_notify=False)
        self._agent("com.evil.agent", str(f))
        snap = pipeline.resnapshot(rec["id"])["behaviour"]
        attributed = [e for e in snap["persistence_changes"] if e["attribution"] == "observed"]
        self.assertEqual(len(attributed), 1)
        plan = json.loads(Path(pipeline.events.load(rec["id"])["plan_path"]).read_text())
        kinds = [i["kind"] for i in plan["items"]]
        self.assertEqual(kinds, ["file", "launch_item"])
        alert = pipeline.persistence_check(do_notify=False)
        self.assertIn("persistence_from_flagged", self.codes(alert))

    def test_diff(self):
        a = {"x": {"sha256": "1"}, "y": {"sha256": "2"}}
        b = {"x": {"sha256": "1"}, "y": {"sha256": "3"}, "z": {"sha256": "4"}}
        d = persistence.diff(a, b)
        self.assertEqual(len(d["added"]), 1)
        self.assertEqual(len(d["changed"]), 1)
        self.assertEqual(d["removed"], [])
