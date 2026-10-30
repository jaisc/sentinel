"""Gmail API watcher — read-only scope, OAuth installed-app flow with PKCE.

Setup (once): create a Google Cloud OAuth client of type "Desktop app", then
`sentinel mail-setup gmail`. The client ID/secret and the refresh token are
stored in the Keychain; the short-lived access token is kept in memory only.
Scope is gmail.readonly: Sentinel cannot modify, label, move or delete mail.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import secrets
import socket
import threading
import time
import urllib.parse
import webbrowser
from typing import Iterable, List, Optional, Tuple

from .. import keychain, paths, reputation

SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
API = "https://gmail.googleapis.com/gmail/v1/users/me"


class GmailError(RuntimeError):
    pass


def _client() -> Tuple[str, str]:
    cid, secret = keychain.get("gmail-oauth-client-id"), keychain.get("gmail-oauth-client-secret")
    if not cid or not secret:
        raise GmailError("Gmail OAuth client not configured. Run `sentinel mail-setup gmail`.")
    return cid, secret


def _post_form(url: str, fields: dict) -> dict:
    r = reputation.http("POST", url, {"Content-Type": "application/x-www-form-urlencoded"},
                        urllib.parse.urlencode(fields).encode())
    data = r.json()
    if r.status != 200:
        # Google's error codes are safe to show; never echo the request.
        raise GmailError("Google token endpoint error: %s" % data.get("error", r.status))
    return data


def authorize(open_browser: bool = True, timeout: int = 300) -> None:
    """Interactive consent in the browser; stores the refresh token in the Keychain."""
    cid, secret = _client()
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state = secrets.token_urlsafe(24)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    redirect = "http://127.0.0.1:%d" % port
    result = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            if q.get("state", [""])[0] == state:
                result["code"] = q.get("code", [""])[0]
                result["error"] = q.get("error", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<h2>Sentinel: Gmail connected (read-only). You can close this tab.</h2>"
                             if result.get("code") else b"<h2>Sentinel: authorization failed. Close this tab and retry.</h2>")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=srv.handle_request, daemon=True)
    t.start()
    url = AUTH_URL + "?" + urllib.parse.urlencode({
        "client_id": cid, "redirect_uri": redirect, "response_type": "code", "scope": SCOPE,
        "access_type": "offline", "prompt": "consent", "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256"})
    print("Opening your browser to grant Sentinel READ-ONLY access to Gmail...")
    print("If it doesn't open, visit:\n  %s" % url)
    if open_browser:
        webbrowser.open(url)
    t.join(timeout)
    srv.server_close()
    if not result.get("code"):
        raise GmailError("No authorization received (%s)." % (result.get("error") or "timed out"))
    tok = _post_form(TOKEN_URL, {"code": result["code"], "client_id": cid, "client_secret": secret,
                                 "redirect_uri": redirect, "grant_type": "authorization_code", "code_verifier": verifier})
    if not tok.get("refresh_token"):
        raise GmailError("Google did not return a refresh token; remove Sentinel's access at "
                         "myaccount.google.com/permissions and retry.")
    keychain.set("gmail-refresh-token", tok["refresh_token"])


_ACCESS = {"token": None, "exp": 0.0}


def access_token() -> str:
    if _ACCESS["token"] and time.time() < _ACCESS["exp"] - 60:
        return _ACCESS["token"]
    cid, secret = _client()
    rt = keychain.get("gmail-refresh-token")
    if not rt:
        raise GmailError("Gmail not authorized. Run `sentinel mail-setup gmail`.")
    tok = _post_form(TOKEN_URL, {"client_id": cid, "client_secret": secret, "refresh_token": rt,
                                 "grant_type": "refresh_token"})
    _ACCESS["token"], _ACCESS["exp"] = tok["access_token"], time.time() + float(tok.get("expires_in", 3600))
    return _ACCESS["token"]


def _get(path: str, params: Optional[dict] = None) -> dict:
    url = API + path + ("?" + urllib.parse.urlencode(params, doseq=True) if params else "")
    r = reputation.http("GET", url, {"Authorization": "Bearer " + access_token(), "Accept": "application/json"})
    if r.status != 200:
        raise GmailError("Gmail API error HTTP %s" % r.status)
    return r.json()


def list_new_ids(since_epoch: int) -> List[str]:
    ids, token = [], None
    for _ in range(5):  # at most 5 pages per poll
        params = {"q": "after:%d -in:sent -in:drafts" % since_epoch, "maxResults": 100}
        if token:
            params["pageToken"] = token
        data = _get("/messages", params)
        ids.extend(m["id"] for m in data.get("messages", []))
        token = data.get("nextPageToken")
        if not token:
            break
    return ids


def fetch_raw(msg_id: str) -> Tuple[bytes, Optional[int]]:
    data = _get("/messages/%s" % urllib.parse.quote(msg_id), {"format": "raw"})
    raw = base64.urlsafe_b64decode(data["raw"] + "=" * (-len(data["raw"]) % 4))
    return raw, int(data["internalDate"]) if data.get("internalDate") else None


def poll(state: dict, lookback_hours: int = 24) -> Iterable[Tuple[str, bytes, Optional[int]]]:
    """Yield (gmail_id, raw_message, internal_ms) for messages not seen before."""
    seen = set(state.get("gmail_seen", []))
    since = int(state.get("gmail_since") or (time.time() - lookback_hours * 3600)) - 300
    started = int(time.time())
    for mid in list_new_ids(since):
        if mid in seen:
            continue
        raw, internal = fetch_raw(mid)
        seen.add(mid)
        state["gmail_seen"] = list(seen)[-3000:]
        yield mid, raw, internal
    state["gmail_since"] = started
