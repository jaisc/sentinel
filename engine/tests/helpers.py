"""Shared test fixtures: isolated SENTINEL_HOME, in-memory Keychain, offline HTTP."""
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel import keychain, reputation, macos  # noqa: E402

# Built from pieces so this test source is not itself detected as EICAR.
EICAR = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE!$H+H*").encode("ascii")

# Minimal 64-bit arm64 Mach-O header (magic 0xfeedfacf little-endian, cputype arm64, MH_EXECUTE).
MACHO_ARM64 = struct.pack("<IiiIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0) + b"\x00" * 64


class FakeHttp:
    """Records requests; answers from a routing table of (method, url-prefix) -> (status, json)."""

    def __init__(self):
        self.routes = []
        self.calls = []

    def add(self, method, prefix, status, body):
        self.routes.append((method, prefix, status, body))

    def __call__(self, method, url, headers, body=None, timeout=15):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        for m, prefix, status, resp in self.routes:
            if m == method and url.startswith(prefix):
                return reputation.HttpResult(status, json.dumps(resp).encode())
        return reputation.HttpResult(404, b"{}")


def unsigned_checker(path, category):
    if category in ("executable", "app_bundle"):
        return macos.SignatureInfo(status="unsigned", gatekeeper="rejected")
    return macos.SignatureInfo()


def notarized_checker(path, category):
    if category in ("executable", "app_bundle"):
        return macos.SignatureInfo(status="signed_valid", authorities=["Developer ID Application: Good Dev (ABCDE12345)"],
                                   team_id="ABCDE12345", notarized=True, gatekeeper="accepted",
                                   gatekeeper_source="Notarized Developer ID")
    return macos.SignatureInfo()


class SentinelTestCase(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="sentinel-test-"))
        self._old_home = os.environ.get("SENTINEL_HOME")
        os.environ["SENTINEL_HOME"] = str(self.home)
        self.keys = {}
        keychain.use_test_store(self.keys)
        self.http = FakeHttp()
        self._old_http = reputation.http
        reputation.http = self.http
        self.downloads = self.home / "Downloads"
        self.downloads.mkdir()

    def tearDown(self):
        reputation.http = self._old_http
        keychain.use_test_store(None)
        if self._old_home is None:
            os.environ.pop("SENTINEL_HOME", None)
        else:
            os.environ["SENTINEL_HOME"] = self._old_home
        shutil.rmtree(self.home, ignore_errors=True)

    def write(self, name, data, mode=0o644):
        p = self.downloads / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        os.chmod(p, mode)
        return p

    def codes(self, rec):
        return {r["code"] for r in rec["reasons"]}
