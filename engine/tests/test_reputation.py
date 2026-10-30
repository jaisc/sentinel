"""Reputation: hash-only by default, keys from Keychain only, never written to disk."""
import json

from helpers import SentinelTestCase, MACHO_ARM64, unsigned_checker

from sentinel import analyzer, paths, reputation

FAKE_KEY = "test-key-0000-not-real"


class ReputationTests(SentinelTestCase):
    def test_no_key_means_no_request(self):
        p = self.write("tool", MACHO_ARM64, 0o755)
        rec = analyzer.analyze_file(p, sig_checker=unsigned_checker)
        self.assertEqual(rec["reputation"]["virustotal"]["status"], "no_key")
        self.assertEqual(self.http.calls, [])

    def test_vt_malicious_hash(self):
        self.keys["virustotal-api-key"] = FAKE_KEY
        p = self.write("tool", MACHO_ARM64, 0o755)
        sha = analyzer.sha256_file(p)
        self.http.add("GET", "%s/files/%s" % (reputation.VT_BASE, sha), 200, {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 41, "suspicious": 0, "harmless": 0, "undetected": 20},
            "popular_threat_classification": {"suggested_threat_label": "trojan.amos/stealer"}}}})
        rec = analyzer.analyze_file(p, sig_checker=unsigned_checker)
        self.assertIn("vt_malicious", self.codes(rec))
        self.assertEqual(rec["verdict"], "dangerous")
        call = self.http.calls[0]
        self.assertEqual(call["method"], "GET")          # a lookup, not an upload
        self.assertIsNone(call["body"])                  # no file contents sent
        self.assertNotIn(MACHO_ARM64[:16].hex(), call["url"])
        # Second analysis is served from the local cache.
        analyzer.analyze_file(p, sig_checker=unsigned_checker)
        self.assertEqual(len(self.http.calls), 1)

    def test_upload_blocked_by_default(self):
        self.keys["virustotal-api-key"] = FAKE_KEY
        p = self.write("sample.bin", b"data")
        self.assertEqual(reputation.vt_upload(p, confirmed=True)["status"], "blocked")
        cfg = paths.load_config()
        cfg["reputation"]["allow_file_upload"] = True
        paths.save_config(cfg)
        self.assertEqual(reputation.vt_upload(p, confirmed=False)["status"], "blocked")
        self.assertEqual(self.http.calls, [])

    def test_keys_never_written_to_disk(self):
        self.keys["virustotal-api-key"] = FAKE_KEY
        self.keys["safebrowsing-api-key"] = FAKE_KEY + "-gsb"
        self.http.add("GET", reputation.VT_BASE, 404, {})
        self.http.add("POST", reputation.GSB_ENDPOINT, 200, {})
        p = self.write("tool", MACHO_ARM64, 0o755)
        from sentinel import pipeline
        rec = pipeline.process_file(p, do_notify=False)
        reputation.safe_browsing(["https://example.com/"])
        for f in self.home.rglob("*"):
            if f.is_file():
                self.assertNotIn(FAKE_KEY, f.read_text(errors="ignore"), "API key leaked into %s" % f)

    def test_cache_does_not_store_plain_urls(self):
        self.keys["safebrowsing-api-key"] = FAKE_KEY
        self.http.add("POST", reputation.GSB_ENDPOINT, 200, {})
        reputation.safe_browsing(["https://private-site.example/secret-path"])
        cache = (paths.state_dir() / "reputation-cache.json").read_text()
        self.assertNotIn("private-site.example", cache)
        self.assertTrue(json.loads(cache))
