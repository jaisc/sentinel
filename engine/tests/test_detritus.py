"""Stray extended attributes must not be reported as tampering.

`codesign --verify --strict` rejects resource forks and Finder information that Finder,
Spotlight and backup tools routinely leave on ordinary apps. The developer seal is still
intact. Before this was separated out, /Applications/Brave Browser.app scored +80
"signature is broken or has been tampered with" while Gatekeeper accepted it as notarized.
"""
import platform
import shutil
import subprocess
import unittest
from pathlib import Path

from helpers import SentinelTestCase, MACHO_ARM64

from sentinel import analyzer, macos, filetype as ft

DETRITUS = ("/Applications/Example.app: resource fork, Finder information, or similar "
            "detritus not allowed\nIn subcomponent: /Applications/Example.app/Contents/Frameworks/X")
REAL_BREAK = "/Applications/Example.app: main executable failed strict validation"


def detritus_checker(path, category):
    if category in ("executable", "app_bundle"):
        return macos.SignatureInfo(status="signed_detritus",
                                   authorities=["Developer ID Application: Good Dev (ABCDE12345)"],
                                   team_id="ABCDE12345", notarized=True, gatekeeper="accepted",
                                   gatekeeper_source="Notarized Developer ID")
    return macos.SignatureInfo()


def broken_checker(path, category):
    if category in ("executable", "app_bundle"):
        return macos.SignatureInfo(status="signed_invalid", gatekeeper="rejected")
    return macos.SignatureInfo()


def detritus_but_gatekeeper_rejects(path, category):
    if category in ("executable", "app_bundle"):
        return macos.SignatureInfo(status="signed_detritus", gatekeeper="rejected",
                                   gatekeeper_source="Unnotarized Developer ID")
    return macos.SignatureInfo()


class DetritusClassificationTests(SentinelTestCase):
    """_is_detritus_only asks codesign again without --strict; it never trusts the text alone."""

    def _with_relaxed_exit(self, code):
        calls = []

        def fake_run(cmd, timeout=30):
            calls.append(list(cmd))
            return code, "", ""

        return fake_run, calls

    def test_detritus_message_plus_relaxed_pass_is_detritus(self):
        fake_run, calls = self._with_relaxed_exit(0)
        old = macos.run
        macos.run = fake_run
        try:
            self.assertTrue(macos._is_detritus_only(Path("/Applications/Example.app"), DETRITUS))
        finally:
            macos.run = old
        self.assertEqual(len(calls), 1)
        self.assertNotIn("--strict", calls[0])

    def test_detritus_message_but_relaxed_also_fails_is_not_detritus(self):
        fake_run, _ = self._with_relaxed_exit(1)
        old = macos.run
        macos.run = fake_run
        try:
            self.assertFalse(macos._is_detritus_only(Path("/Applications/Example.app"), DETRITUS))
        finally:
            macos.run = old

    def test_other_failure_is_never_detritus_and_runs_nothing(self):
        fake_run, calls = self._with_relaxed_exit(0)
        old = macos.run
        macos.run = fake_run
        try:
            self.assertFalse(macos._is_detritus_only(Path("/Applications/Example.app"), REAL_BREAK))
        finally:
            macos.run = old
        self.assertEqual(calls, [])


class DetritusScoringTests(SentinelTestCase):
    def test_detritus_is_not_reported_as_tampering(self):
        p = self.write("tool", MACHO_ARM64, mode=0o755)
        rec = analyzer.analyze_file(p, use_network=False, sig_checker=detritus_checker)
        codes = self.codes(rec)
        self.assertIn("signature_detritus", codes)
        self.assertNotIn("bad_signature", codes)
        self.assertNotIn("unsigned_executable", codes)

    def test_detritus_scores_far_below_a_broken_signature(self):
        p = self.write("tool", MACHO_ARM64, mode=0o755)
        ok = analyzer.analyze_file(p, use_network=False, sig_checker=detritus_checker)
        bad = analyzer.analyze_file(p, use_network=False, sig_checker=broken_checker)
        self.assertLess(ok["score"], bad["score"])

    def test_gatekeeper_rejection_still_bites_through_detritus(self):
        p = self.write("tool", MACHO_ARM64, mode=0o755)
        rec = analyzer.analyze_file(p, use_network=False, sig_checker=detritus_but_gatekeeper_rejects)
        self.assertIn("gatekeeper_rejected", self.codes(rec))

    def test_a_genuinely_broken_signature_is_still_tampering(self):
        p = self.write("tool", MACHO_ARM64, mode=0o755)
        rec = analyzer.analyze_file(p, use_network=False, sig_checker=broken_checker)
        self.assertIn("bad_signature", self.codes(rec))


class RealCodesignDetritusTests(SentinelTestCase):
    @unittest.skipUnless(platform.system() == "Darwin" and shutil.which("codesign")
                         and shutil.which("xattr"), "needs macOS codesign + xattr")
    def test_real_binary_with_finder_info_is_detritus_not_invalid(self):
        p = self.downloads / "true-detritus"
        shutil.copy("/usr/bin/true", p)
        # 32 bytes of Finder information: exactly the "detritus" --strict refuses.
        subprocess.run(["xattr", "-wx", "com.apple.FinderInfo",
                        "00" * 32, str(p)], check=True)
        strict = macos.run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(p)])
        if strict[0] == 0:
            self.skipTest("this macOS build does not treat FinderInfo as strict detritus")
        info = macos.check_signature(p, ft.EXECUTABLE)
        self.assertEqual(info.status, "signed_detritus")
        rec = analyzer.analyze_file(p, use_network=False)
        self.assertNotIn("bad_signature", self.codes(rec))


if __name__ == "__main__":
    unittest.main()
