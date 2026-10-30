"""Project hygiene: Python 3.9 syntax (macOS CLT python), no embedded secrets."""
import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SECRET_PATTERNS = [
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),                     # Google API key
    re.compile(r"GOCSPX-[0-9A-Za-z_\-]{20,}"),                  # Google OAuth client secret
    re.compile(r"\b1//0[0-9A-Za-z_\-]{30,}"),                   # Google refresh token
    re.compile(r"ya29\.[0-9A-Za-z_\-]{20,}"),                   # Google access token
    re.compile(r"x-apikey['\"]?\s*[:=]\s*['\"][0-9a-f]{64}"),   # hard-coded VirusTotal key
]


class HygieneTests(unittest.TestCase):
    def test_python39_syntax(self):
        for f in (ROOT / "engine").rglob("*.py"):
            ast.parse(f.read_text(), filename=str(f), feature_version=(3, 9))

    def test_no_secrets_in_repo(self):
        for f in ROOT.rglob("*"):
            if not f.is_file() or f.suffix in (".png", ".icns") or "__pycache__" in f.parts:
                continue
            text = f.read_text(errors="ignore")
            for pat in SECRET_PATTERNS:
                self.assertIsNone(pat.search(text), "possible secret in %s" % f)
