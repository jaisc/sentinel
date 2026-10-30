"""Read-only IMAP watcher (e.g. Yahoo Mail with an app password in the Keychain).

The mailbox is opened with EXAMINE (read-only) and messages are fetched with
BODY.PEEK[], so Sentinel never marks mail as read, moves, flags or deletes it.
"""
from __future__ import annotations

import datetime as dt
import imaplib
import re
import time
from typing import Iterable, Optional, Tuple

from .. import keychain


class ImapError(RuntimeError):
    pass


def password_account(name: str) -> str:
    return "imap-%s-password" % name


def poll(acct: dict, state: dict, lookback_hours: int = 24) -> Iterable[Tuple[str, bytes, Optional[int]]]:
    name, host, user = acct["name"], acct["host"], acct["user"]
    pw = keychain.get(password_account(name))
    if not pw:
        raise ImapError("No app password for IMAP account %r in the Keychain. Run `sentinel keys set imap %s`." % (name, name))
    st = state.setdefault("imap", {}).setdefault(name, {})
    conn = imaplib.IMAP4_SSL(host, int(acct.get("port", 993)))
    try:
        conn.login(user, pw)
        typ, data = conn.select(acct.get("mailbox", "INBOX"), readonly=True)
        if typ != "OK":
            raise ImapError("Could not open mailbox read-only")
        uidvalidity = _uidvalidity(conn)
        if st.get("uidvalidity") != uidvalidity:
            st.clear()
            st["uidvalidity"] = uidvalidity
        last = int(st.get("last_uid", 0))
        if last:
            typ, data = conn.uid("SEARCH", None, "UID", "%d:*" % (last + 1))
        else:
            since = (dt.date.today() - dt.timedelta(hours=lookback_hours)).strftime("%d-%b-%Y")
            typ, data = conn.uid("SEARCH", None, "SINCE", since)
        uids = [int(u) for u in (data[0] or b"").split()] if typ == "OK" else []
        for uid in sorted(u for u in uids if u > last)[-200:]:
            typ, msg = conn.uid("FETCH", str(uid), "(BODY.PEEK[] INTERNALDATE)")
            if typ != "OK" or not msg or not isinstance(msg[0], tuple):
                continue
            meta, raw = msg[0]
            internal = None
            m = re.search(rb'INTERNALDATE "([^"]+)"', meta)
            if m:
                t = imaplib.Internaldate2tuple(b'INTERNALDATE "' + m.group(1) + b'"')
                if t:
                    internal = int(time.mktime(t) * 1000)
            st["last_uid"] = max(int(st.get("last_uid", 0)), uid)
            yield "%s:%d" % (name, uid), raw, internal
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _uidvalidity(conn) -> str:
    typ, data = conn.response("UIDVALIDITY")
    return (data[0].decode() if data and data[0] else "") if typ else ""
