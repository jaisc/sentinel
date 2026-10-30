"""Offline URL heuristics used by the email watcher and the Brave link guard."""
import unittest

import helpers  # noqa: F401 - sets sys.path

from sentinel import urlcheck
from sentinel.scoring import verdict_for


def verdict(url):
    return verdict_for(urlcheck.analyze_url(url))


class UrlTests(unittest.TestCase):
    def test_legit_sites_clean(self):
        for u in ("https://www.google.com/", "https://accounts.google.com/signin", "https://www.paypal.com/ca/home",
                  "https://github.com/x/y", "https://www.rbcroyalbank.com/", "https://brave.com/download/",
                  "https://www.canada.ca/en/revenue-agency.html", "https://grave.com/"):
            self.assertEqual(verdict(u), "clean", u)

    def test_brand_subdomain_trick_dangerous(self):
        self.assertEqual(verdict("https://paypal.com.secure-verify.xyz/login"), "dangerous")
        self.assertEqual(verdict("https://rbcroyalbank.com.signin.io/"), "dangerous")

    def test_userinfo_trick(self):
        self.assertEqual(verdict("https://www.google.com@evil.example/"), "dangerous")

    def test_homoglyph_punycode(self):
        self.assertEqual(verdict("https://xn--pple-43d.com/"), "dangerous")   # Cyrillic 'а' + "pple"

    def test_typosquats(self):
        for u in ("https://paypa1.com/", "https://amaz0n.ca/", "https://micros0ft.com/", "https://gooogle.com/"):
            self.assertNotEqual(verdict(u), "clean", u)

    def test_brand_plus_account_word(self):
        for u in ("https://appleid-verify.com/", "https://interac-refund.ca/", "https://mypaypal.com/"):
            self.assertNotEqual(verdict(u), "clean", u)

    def test_shortener_ip_and_schemes(self):
        self.assertEqual(verdict("https://bit.ly/abc"), "caution")
        self.assertEqual(verdict("http://45.12.9.8/login.php"), "caution")
        self.assertEqual(verdict("javascript:alert(1)"), "caution")
        self.assertEqual(urlcheck.analyze_url("http://192.168.1.1/"), [])  # private IPs are fine

    def test_display_mismatch(self):
        self.assertIsNotNone(urlcheck.display_mismatch("www.paypal.com", "https://evil.example/"))
        self.assertIsNone(urlcheck.display_mismatch("www.paypal.com", "https://www.paypal.com/x"))
        self.assertIsNone(urlcheck.display_mismatch("youtube.com", "https://www.google.com/"))  # same owner
        self.assertIsNone(urlcheck.display_mismatch("Read more", "https://example.com/"))
        self.assertIsNotNone(urlcheck.display_mismatch("Sign in to PayPal", "https://evil.example/"))

    def test_registrable_domain(self):
        self.assertEqual(urlcheck.registrable_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(urlcheck.registrable_domain("www.cra-arc.gc.ca"), "cra-arc.gc.ca")
        self.assertEqual(urlcheck.registrable_domain("mail.google.com"), "google.com")
