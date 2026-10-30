"""Offline URL heuristics shared by the email watcher and the Brave link guard.

These never touch the network. Reputation services (Safe Browsing, VirusTotal)
are layered on top in reputation.py.
"""
from __future__ import annotations

import ipaddress
import re
from typing import List, Optional, Tuple
from urllib.parse import urlsplit, unquote

from .scoring import Reason

# Link shorteners hide the real destination.
SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "lnkd.in", "s.id", "v.gd", "bl.ink",
    "short.io", "shorte.st", "adf.ly", "qrco.de", "urlz.fr", "clck.ru", "x.gd", "tr.im", "soo.gd",
    "1url.com", "trib.al", "dlvr.it", "surl.li", "u.to", "linktr.ee",
}

# Brands commonly impersonated, plus ones relevant to a Canadian (Saskatchewan) user.
# Map: brand label -> legitimate registrable domains.
PROTECTED_BRANDS = {
    "google": ["google.com", "google.ca", "gmail.com", "youtube.com", "goo.gl", "googleusercontent.com", "gstatic.com"],
    "gmail": ["gmail.com", "google.com"],
    "yahoo": ["yahoo.com", "yahoo.ca", "yimg.com"],
    "apple": ["apple.com", "icloud.com", "me.com", "apple.ca"],
    "icloud": ["icloud.com", "apple.com"],
    "paypal": ["paypal.com", "paypal.ca", "paypal.me", "paypalobjects.com"],
    "amazon": ["amazon.com", "amazon.ca", "amazonaws.com", "a2z.com", "amazon.co.uk"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "office365.com", "sharepoint.com"],
    "outlook": ["outlook.com", "live.com", "microsoft.com", "office.com"],
    "office365": ["office.com", "microsoft.com", "office365.com"],
    "facebook": ["facebook.com", "fb.com", "fb.me", "meta.com", "facebookmail.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com", "lnkd.in"],
    "dropbox": ["dropbox.com", "dropboxusercontent.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "github": ["github.com", "githubusercontent.com", "github.io"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "brave": ["brave.com"],
    "interac": ["interac.ca"],
    "canadapost": ["canadapost.ca", "canadapost-postescanada.ca", "postescanada.ca"],
    "royalbank": ["rbc.com", "royalbank.com", "rbcroyalbank.com"],
    "rbcroyalbank": ["rbcroyalbank.com", "rbc.com"],
    "scotiabank": ["scotiabank.com"],
    "desjardins": ["desjardins.com"],
    "tdbank": ["td.com", "tdbank.com", "tdcanadatrust.com"],
    "cibc": ["cibc.com"],
    "bmo": ["bmo.com"],
    "wellsfargo": ["wellsfargo.com"],
    "chase": ["chase.com"],
    "bankofamerica": ["bankofamerica.com"],
    "sasktel": ["sasktel.com", "sasktel.net"],
    "saskpower": ["saskpower.com"],
    "servicecanada": ["canada.ca", "gc.ca"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com", "dhl.ca"],
    "ups": ["ups.com"],
    "usps": ["usps.com"],
    "wise": ["wise.com"],
    "adobe": ["adobe.com"],
}

# Two-label public suffixes that matter in practice (lightweight eTLD+1).
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.in",
    "com.br", "com.mx", "gc.ca", "ab.ca", "bc.ca", "sk.ca", "mb.ca", "on.ca", "qc.ca", "com.cn",
    "co.za", "com.sg", "com.tr", "github.io", "herokuapp.com", "web.app", "firebaseapp.com",
    "pages.dev", "netlify.app", "vercel.app", "blogspot.com", "azurewebsites.net", "cloudfront.net",
    "amazonaws.com", "appspot.com", "glitch.me", "ngrok.io", "ngrok-free.app", "workers.dev",
}

# TLDs heavily used by throwaway phishing domains (informational only).
RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work",
              "rest", "fit", "cam", "surf", "monster", "quest", "cyou", "sbs", "lol", "icu", "buzz"}

DOWNLOAD_EXTS = {"exe", "dmg", "pkg", "mpkg", "app", "zip", "rar", "7z", "iso", "img", "scr", "js",
                 "jar", "command", "sh", "msi", "bat", "vbs", "ps1", "docm", "xlsm", "apk", "hta"}

# Characters commonly swapped to imitate brand names.
CONFUSABLES = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"),
               ("4", "a"), ("7", "t"), ("$", "s"), ("@", "a"), ("!", "i"), ("|", "l")]
UNICODE_SKELETON = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u", "ѕ": "s", "ԝ": "w", "ɑ": "a",
    "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "α": "a", "ε": "e",
    "ı": "i", "ł": "l", "ø": "o", "ö": "o", "ó": "o", "ò": "o", "é": "e", "è": "e", "á": "a",
    "à": "a", "ä": "a", "í": "i", "ü": "u", "ú": "u", "ç": "c", "ñ": "n",
}


def hostname(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def registrable_domain(host: str) -> str:
    host = host.lower().rstrip(".")
    if not host or _is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last2 = ".".join(labels[-2:])
    if last2 in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return last2


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"0x[0-9a-f]+|\d{8,10}", host))  # hex / dword-encoded IPs


def is_private_host(host: str) -> bool:
    if host in ("localhost",) or host.endswith((".local", ".localhost", ".internal", ".lan", ".home.arpa")):
        return True
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _decode_idna(host: str) -> str:
    out = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                out.append(label[4:].encode("ascii").decode("punycode"))
                continue
            except (UnicodeError, ValueError):
                pass
        out.append(label)
    return ".".join(out)


def skeleton(label: str) -> str:
    s = "".join(UNICODE_SKELETON.get(c, c) for c in label.lower())
    for a, b in CONFUSABLES:
        s = s.replace(a, b)
    return s


def _edit_distance(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _brand_owner(domain: str) -> Optional[str]:
    for brand, domains in PROTECTED_BRANDS.items():
        if domain in domains:
            return brand
    return None


def is_legit_brand_domain(domain: str) -> bool:
    return _brand_owner(domain) is not None


ACCOUNT_WORDS = {"login", "logon", "signin", "secure", "security", "verify", "verification", "account",
                 "accounts", "support", "update", "id", "billing", "help", "service", "services", "alert",
                 "wallet", "auth", "pay", "payment", "online", "bank", "confirm", "center", "centre", "team",
                 "recovery", "unlock", "refund", "invoice", "notice", "customer", "my", "web", "mail", "app",
                 "store", "delivery", "track", "tracking", "gift", "prize", "reward", "rewards", "claim"}


def _is_account_word(token: str) -> bool:
    if token in ACCOUNT_WORDS:
        return True
    # "secure-login" glued together: "securelogin", "verifyaccount".
    return any(token.startswith(w) and token[len(w):] in ACCOUNT_WORDS for w in ACCOUNT_WORDS if len(w) >= 4)


def lookalike_of(host: str) -> Optional[Tuple[str, str, int]]:
    """If host imitates a protected brand, return (brand, how, points)."""
    domain = registrable_domain(host)
    if not domain or _is_ip(domain) or is_legit_brand_domain(domain):
        return None
    decoded = _decode_idna(domain)
    core = decoded.split(".")[0]
    sk = skeleton(core)
    for brand, legit in PROTECTED_BRANDS.items():
        if len(brand) < 4:
            continue
        if sk == brand and core != brand:
            return brand, "uses look-alike characters to imitate %s" % legit[0], 90
        if decoded != domain and sk == brand:
            return brand, "uses international characters to imitate %s" % legit[0], 90
        if len(brand) >= 6 and core != brand and _edit_distance(sk, brand) == 1:
            return brand, "is one letter away from %s" % legit[0], 70
    # Brand name + account-ish word in an unrelated domain: "paypal-secure-login.com", "appleid-verify.net".
    tokens = [t for t in re.split(r"[-_]", sk) if t]
    for brand, legit in PROTECTED_BRANDS.items():
        if len(brand) < 4:
            continue
        rest = []  # type: List[str]
        if brand in tokens and len(tokens) > 1:
            rest = [t for t in tokens if t != brand]
        elif sk.startswith(brand) and sk != brand:
            rest = [sk[len(brand):].strip("-_")]
        elif sk.endswith(brand) and sk != brand:
            rest = [sk[: -len(brand)].strip("-_")]
        rest = [w for t in rest for w in re.split(r"[-_]", t) if w]
        if any(_is_account_word(t) for t in rest):
            return brand, "contains the name '%s' but is not an official %s domain" % (brand, legit[0]), 60
    # Brand domain used as a subdomain: "paypal.com.account-check.xyz".
    sub = host[: -len(domain)].rstrip(".") if host.endswith(domain) else ""
    for brand, legit in PROTECTED_BRANDS.items():
        for d in legit:
            if sub and (sub == d or sub.endswith("." + d) or sub.startswith(d + ".") or ("." + d + ".") in ("." + sub + ".")):
                return brand, "puts '%s' at the front, but the real site is %s" % (d, domain), 100
        if len(brand) >= 5 and sub and brand in sub.split("."):
            return brand, "puts '%s' in the address, but the real site is %s" % (brand, domain), 60
    return None


def analyze_url(url: str) -> List[Reason]:
    """Offline heuristics for a single URL. Returns reasons (may be empty)."""
    reasons = []  # type: List[Reason]
    url = url.strip()
    lower = url.lower()
    if lower.startswith("javascript:"):
        return [Reason("url_javascript", 60, "The link runs JavaScript instead of opening a page",
                       "Legitimate emails and sites rarely use javascript: links; they can run code when clicked.")]
    if lower.startswith("data:"):
        return [Reason("url_data", 60, "The link opens embedded data (data: URL) instead of a website",
                       "data: links can hide a whole fake login page inside the link itself.")]
    if not lower.startswith(("http://", "https://")):
        return reasons
    try:
        parts = urlsplit(url)
    except ValueError:
        return [Reason("url_malformed", 25, "The link is malformed", "Malformed links are sometimes used to confuse filters.")]
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return reasons
    if parts.username is not None:
        shown = parts.username
        reasons.append(Reason("url_userinfo", 100, "The link hides its real destination behind an '@' (%s@%s)" % (shown, host),
                              "Everything before '@' is ignored by the browser. The real site is %s." % host))
    if _is_ip(host) and not is_private_host(host):
        reasons.append(Reason("url_ip_host", 35, "The link goes to a raw IP address (%s), not a named website" % host,
                              "Real companies use domain names; raw IPs are common in phishing and malware links."))
    domain = registrable_domain(host)
    if host in SHORTENERS or domain in SHORTENERS:
        reasons.append(Reason("url_shortener", 25, "The link uses a URL shortener (%s)" % domain,
                              "Shorteners hide where the link really goes. Sentinel can only judge the final site after you expand it."))
    if "xn--" in host:
        reasons.append(Reason("url_punycode", 30, "The address uses international characters (%s)" % _decode_idna(host),
                              "Some letters from other alphabets look identical to English ones and can imitate real sites.", observed=False))
    look = lookalike_of(host)
    if look:
        brand, how, pts = look
        reasons.append(Reason("url_lookalike", pts, "The address %s %s" % (domain, how),
                              "Look-alike addresses are the #1 trick in phishing: the page will look real but steal what you type.",
                              observed=False))
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    if tld in RISKY_TLDS:
        reasons.append(Reason("url_risky_tld", 10, "The site uses a .%s address" % tld,
                              "This ending is cheap and frequently used for throwaway scam sites (not proof by itself).", observed=False))
    if host.count(".") >= 5:
        reasons.append(Reason("url_deep_subdomains", 10, "The address has an unusually long chain of sub-domains",
                              "Long chains are used to push the real domain out of view on phones.", observed=False))
    path_ext = unquote(parts.path).rsplit("/", 1)[-1]
    if "." in path_ext and path_ext.rsplit(".", 1)[1].lower() in DOWNLOAD_EXTS:
        reasons.append(Reason("url_download", 20, "The link downloads a file directly (%s)" % path_ext[:80],
                              "Files you didn't ask for — especially apps, installers and archives — are a common way malware arrives."))
    if parts.scheme == "http" and re.search(r"log.?in|sign.?in|verify|account|password|secure|bank|wallet", lower):
        reasons.append(Reason("url_insecure_login", 15, "A login-style page that isn't using a secure (https) connection",
                              "Anything typed there can be read in transit.", observed=False))
    return reasons


_DOMAINISH = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.I)


def display_mismatch(display_text: str, href: str) -> Optional[Reason]:
    """Link text says one site, the actual link goes to another."""
    text = (display_text or "").strip()
    if not text or not href.lower().startswith(("http://", "https://")):
        return None
    m = _DOMAINISH.search(text)
    real = registrable_domain(hostname(href))
    if not real:
        return None
    if m:
        shown_host = m.group(1).lower()
        if shown_host.rsplit(".", 1)[-1] in ("png", "jpg", "gif", "pdf", "html", "php", "aspx", "js", "css"):
            return None
        shown = registrable_domain(shown_host)
        if shown and shown != real and not (_brand_owner(shown) and _brand_owner(shown) == _brand_owner(real)):
            return Reason("link_text_mismatch", 100,
                          "The link text says \"%s\" but it actually goes to %s" % (text[:80], real),
                          "Showing one address and linking to another is a classic phishing trick.")
        return None
    # Text names a brand ("Sign in to PayPal") but the link is not that brand's site.
    t = re.sub(r"[^a-z]", "", text.lower())
    for brand, legit in PROTECTED_BRANDS.items():
        if len(brand) >= 5 and brand in t and real not in legit and not is_legit_brand_domain(real):
            if re.search(r"log.?in|sign.?in|verify|confirm|account|password|update|unlock|secure", text.lower()):
                return Reason("link_brand_mismatch", 45,
                              "The link mentions %s but goes to %s" % (brand.capitalize(), real),
                              "The button looks like it belongs to %s, but the site it opens does not." % legit[0],
                              observed=False)
    return None
