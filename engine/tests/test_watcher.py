"""Debounced download watching (polling fallback + logic shared with the Swift agent)."""
from helpers import SentinelTestCase

from sentinel import watcher


class WatcherTests(SentinelTestCase):
    def test_stability_tracker(self):
        t = watcher.StabilityTracker(2.0)
        self.assertFalse(t.observe("a", (10, 1.0), now=100))
        self.assertFalse(t.observe("a", (20, 2.0), now=101))   # still growing
        self.assertFalse(t.observe("a", (20, 2.0), now=102))   # stable 1s
        self.assertTrue(t.observe("a", (20, 2.0), now=103.5))  # stable >= 2s

    def test_poll_once_waits_and_skips_partials(self):
        seen, ready = {}, []
        t = watcher.StabilityTracker(1.0)
        self.write("setup.dmg.crdownload", b"partial")
        self.write("report.pdf", b"%PDF-1.4")
        watcher.poll_once(t, seen, [self.downloads], ready.append, now=0)
        self.assertEqual(ready, [])
        watcher.poll_once(t, seen, [self.downloads], ready.append, now=2)
        self.assertEqual([p.name for p in ready], ["report.pdf"])
        # Seen once -> not reported again.
        watcher.poll_once(t, seen, [self.downloads], ready.append, now=4)
        self.assertEqual(len(ready), 1)

    def test_file_with_crdownload_sibling_waits(self):
        seen, ready = {}, []
        t = watcher.StabilityTracker(0.0)
        self.write("big.zip", b"PK")
        self.write("big.zip.crdownload", b"...")
        watcher.poll_once(t, seen, [self.downloads], ready.append, now=0)
        watcher.poll_once(t, seen, [self.downloads], ready.append, now=1)
        self.assertEqual(ready, [])

    def test_baseline_existing_does_not_alert(self):
        self.write("old.pdf", b"%PDF")
        seen = {}
        self.assertEqual(watcher.baseline_existing([self.downloads], seen), 1)
        ready = []
        t = watcher.StabilityTracker(0.0)
        watcher.poll_once(t, seen, [self.downloads], ready.append, now=0)
        watcher.poll_once(t, seen, [self.downloads], ready.append, now=1)
        self.assertEqual(ready, [])

    def test_mail_downloads_subfolders_and_bundles(self):
        (self.downloads / "Mail" / "ABC-UUID").mkdir(parents=True)
        self.write("Mail/ABC-UUID/invoice.pdf", b"%PDF")
        (self.downloads / "Thing.app" / "Contents").mkdir(parents=True)
        names = sorted(p.name for p in watcher.candidates(self.downloads, depth=3))
        self.assertEqual(names, ["Thing.app", "invoice.pdf"])
