"""Native-messaging host for the Brave/Chrome link guard (com.sentinel.host).

The extension never holds API keys: it asks this local process, which reads the
keys from the Keychain. Protocol: 4-byte native-endian length + UTF-8 JSON, both ways.

Requests:
  {"type": "ping"}
  {"type": "check", "url": "...", "deep": false, "navigation": true}
  {"type": "allow", "host": "example.com"}           # "Always allow this site"
  {"type": "proceeded", "url": "..."}                # user clicked Proceed on a warning
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import struct
import sys
from typing import BinaryIO, Optional

from . import __version__, allowlist, actionlog, events, keychain, pipeline, reputation, urlcheck
from .scoring import Reason, verdict_for, score, VERDICT_LABEL, CLEAN

MAX_MSG = 1024 * 1024


def read_message(stream: BinaryIO) -> Optional[dict]:
    head = stream.read(4)
    if len(head) < 4:
        return None
    (n,) = struct.unpack("=I", head)
    if n > MAX_MSG:
        raise ValueError("message too large")
    return json.loads(stream.read(n).decode("utf-8"))


def write_message(stream: BinaryIO, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8")
    stream.write(struct.pack("=I", len(data)))
    stream.write(data)
    stream.flush()


def check_url(url: str, deep: bool = False, use_network: bool = True) -> dict:
    host = urlcheck.hostname(url)
    reasons = urlcheck.analyze_url(url)
    rep = {}
    if use_network and url.lower().startswith(("http://", "https://")) and not urlcheck.is_private_host(host):
        rep["safebrowsing"] = reputation.safe_browsing([url]).get(url, {})
        if rep["safebrowsing"].get("status") == "flagged":
            reasons.append(Reason("gsb_link", 120, "Google Safe Browsing lists this site as %s" % ", ".join(
                reputation.GSB_THREAT_TEXT.get(t, t) for t in rep["safebrowsing"].get("threats", [])),
                "Google has confirmed this site is dangerous."))
        if deep or any(r.points >= 25 for r in reasons):
            rep["virustotal"] = reputation.vt_url(url, wait=False)
            v = rep["virustotal"]
            if v.get("status") == "found":
                if v.get("malicious", 0) >= 2:
                    reasons.append(Reason("vt_url_malicious", 100, "%d VirusTotal engines flag this site" % v["malicious"],
                                          "Independent security vendors consider it malicious."))
                elif v.get("malicious", 0) == 1 or v.get("suspicious", 0) >= 2:
                    reasons.append(Reason("vt_url_some", 30, "VirusTotal: %d engine(s) flag this site" % (v.get("malicious", 0) + v.get("suspicious", 0)),
                                          "Could be a false positive; be careful what you type there."))
    verdict = verdict_for(reasons)
    allowed = allowlist.match(host=host)
    if allowed and any(allowlist.is_hard_evidence(r.code) for r in reasons):
        allowed = None
    if allowed:
        verdict = CLEAN
    return {"url": url, "host": host, "verdict": verdict, "score": score(reasons),
            "reasons": [r.to_dict() for r in sorted(reasons, key=lambda r: -r.points)],
            "reputation": rep, "allowlisted": allowed,
            "keys": {"safebrowsing": keychain.has("safebrowsing-api-key"), "virustotal": keychain.has("virustotal-api-key")}}


def record_url_event(res: dict) -> dict:
    rec = {
        "id": events.new_id("url", hashlib.sha256(res["url"].encode("utf-8")).hexdigest()), "kind": "url",
        "name": res["host"] or "link", "url": res["url"], "path": "",
        "first_seen": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "reasons": res["reasons"], "score": res["score"], "verdict": res["verdict"],
        "reputation": res["reputation"], "allowlisted": res.get("allowlisted"), "source": "brave-link-guard",
    }
    rec["title"] = "%s link: %s" % (VERDICT_LABEL[res["verdict"]], res["host"])
    rec["summary"] = res["reasons"][0]["title"] if res["reasons"] else "No problems found."
    # The browser already shows the warning page, so no extra notification.
    return pipeline.finish(rec, do_notify=False)


def handle(req: dict) -> dict:
    t = req.get("type")
    if t == "ping":
        return {"ok": True, "version": __version__,
                "keys": {"safebrowsing": keychain.has("safebrowsing-api-key"), "virustotal": keychain.has("virustotal-api-key")}}
    if t == "check":
        url = str(req.get("url", ""))[:4096]
        res = check_url(url, deep=bool(req.get("deep")))
        if req.get("navigation") and res["verdict"] != CLEAN:
            res["event_id"] = record_url_event(res)["id"]
        return res
    if t == "allow":
        host = str(req.get("host", "")).lower()
        if not host:
            return {"ok": False, "error": "no host"}
        allowlist.add("domain", urlcheck.registrable_domain(host), note="Always allow (Brave link guard)")
        return {"ok": True}
    if t == "proceeded":
        actionlog.log("link_proceeded", url=str(req.get("url", ""))[:2048])
        return {"ok": True}
    return {"ok": False, "error": "unknown request type"}


def main() -> int:  # pragma: no cover - stdio loop exercised in tests via handle()
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    while True:
        try:
            req = read_message(stdin)
        except (ValueError, json.JSONDecodeError) as e:
            write_message(stdout, {"ok": False, "error": str(e)})
            return 1
        if req is None:
            return 0
        try:
            write_message(stdout, handle(req))
        except Exception as e:
            write_message(stdout, {"ok": False, "error": type(e).__name__})
