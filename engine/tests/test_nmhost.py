"""Native-messaging host used by the Brave extension."""
import io
import json
import struct
import subprocess
import sys
from pathlib import Path

from helpers import SentinelTestCase

from sentinel import allowlist, events, nmhost

BIN = Path(__file__).resolve().parents[1] / "bin" / "sentinel"


class NativeHostTests(SentinelTestCase):
    def test_framing_roundtrip(self):
        buf = io.BytesIO()
        nmhost.write_message(buf, {"type": "ping"})
        buf.seek(0)
        self.assertEqual(nmhost.read_message(buf), {"type": "ping"})
        self.assertIsNone(nmhost.read_message(io.BytesIO(b"")))

    def test_check_flags_and_records_event(self):
        res = nmhost.handle({"type": "check", "url": "https://paypal.com.secure-verify.xyz/login", "navigation": True})
        self.assertEqual(res["verdict"], "dangerous")
        self.assertIn("event_id", res)
        rec = events.load(res["event_id"])
        self.assertEqual(rec["kind"], "url")
        self.assertTrue(Path(rec["report_path"]).exists())
        self.assertFalse(res["keys"]["safebrowsing"])

    def test_allow_site(self):
        nmhost.handle({"type": "allow", "host": "login.example-bank.xyz"})
        self.assertTrue(allowlist.match(host="www.example-bank.xyz"))
        res = nmhost.handle({"type": "check", "url": "https://bit.ly/zz"})
        self.assertEqual(res["verdict"], "caution")

    def test_stdio_process(self):
        """Run the real host the way Brave does (origin as argv[1])."""
        def frame(o):
            d = json.dumps(o).encode()
            return struct.pack("=I", len(d)) + d
        inp = frame({"type": "ping"}) + frame({"type": "check", "url": "https://www.google.com/"})
        env = dict(__import__("os").environ)
        p = subprocess.run([sys.executable, str(BIN), "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"],
                           input=inp, capture_output=True, env=env, timeout=30)
        out = io.BytesIO(p.stdout)
        first, second = nmhost.read_message(out), nmhost.read_message(out)
        self.assertTrue(first["ok"])
        self.assertEqual(second["verdict"], "clean")
