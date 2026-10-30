"""Unsigned-binary detection.

On Linux the code-signature checker is injected (codesign doesn't exist here);
on macOS the real `codesign` is exercised against a copy of /usr/bin/true with
its signature stripped.
"""
import platform
import shutil
import subprocess
import unittest

from helpers import SentinelTestCase, MACHO_ARM64, unsigned_checker, notarized_checker

from sentinel import analyzer, macos, filetype as ft


class UnsignedTests(SentinelTestCase):
    def test_unsigned_macho_is_flagged(self):
        p = self.write("tool", MACHO_ARM64, mode=0o755)
        rec = analyzer.analyze_file(p, use_network=False, sig_checker=unsigned_checker)
        self.assertIn("unsigned_executable", self.codes(rec))
        self.assertEqual(rec["signature"]["status"], "unsigned")
        self.assertIn(rec["verdict"], ("caution", "dangerous"))
        # No download tag + runnable => extra reason (fetched by a script/tool).
        self.assertIn("no_quarantine", self.codes(rec))

    def test_notarized_binary_scores_lower(self):
        p = self.write("goodtool", MACHO_ARM64, mode=0o755)
        bad = analyzer.analyze_file(p, use_network=False, sig_checker=unsigned_checker)
        good = analyzer.analyze_file(p, use_network=False, sig_checker=notarized_checker)
        self.assertLess(good["score"], bad["score"])
        self.assertIn("notarized", self.codes(good))
        self.assertNotIn("unsigned_executable", self.codes(good))

    def test_app_bundle_hashes_main_executable(self):
        app = self.downloads / "Fake.app" / "Contents" / "MacOS"
        app.mkdir(parents=True)
        (app / "Fake").write_bytes(MACHO_ARM64)
        (app / "Fake").chmod(0o755)
        (app.parent / "Info.plist").write_bytes(
            b'<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>Fake</string></dict></plist>')
        rec = analyzer.analyze_file(self.downloads / "Fake.app", use_network=False, sig_checker=unsigned_checker)
        self.assertEqual(rec["type"]["real_category"], ft.APP_BUNDLE)
        self.assertTrue(rec["sha256_of"].endswith("Contents/MacOS/Fake"))
        self.assertIn("unsigned_executable", self.codes(rec))

    def test_without_macos_signature_is_reported_unchecked_not_clean(self):
        if macos.IS_MACOS:
            self.skipTest("Linux-only behaviour")
        p = self.write("tool", MACHO_ARM64, mode=0o755)
        rec = analyzer.analyze_file(p, use_network=False)
        self.assertEqual(rec["signature"]["status"], "unavailable")
        self.assertIn("signature_unchecked", self.codes(rec))

    @unittest.skipUnless(platform.system() == "Darwin" and shutil.which("codesign"), "needs macOS codesign")
    def test_real_codesign_on_mac(self):
        signed = macos.check_signature(__import__("pathlib").Path("/usr/bin/true"), ft.EXECUTABLE)
        self.assertEqual(signed.status, "signed_valid")
        p = self.downloads / "true-unsigned"
        shutil.copy("/usr/bin/true", p)
        subprocess.run(["codesign", "--remove-signature", str(p)], check=True)
        info = macos.check_signature(p, ft.EXECUTABLE)
        self.assertEqual(info.status, "unsigned")
        rec = analyzer.analyze_file(p, use_network=False)
        self.assertIn("unsigned_executable", self.codes(rec))
