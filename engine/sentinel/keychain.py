"""Secrets live only in the macOS login Keychain (service "Sentinel").

Reads use `security find-generic-password -w`. Writes go through `security -i`
with the command on *stdin*, so the secret never appears in a process argument
list (which other local processes could read via `ps`). Nothing here ever logs
or prints a secret value.

Accounts used:
  virustotal-api-key, safebrowsing-api-key,
  gmail-oauth-client-id, gmail-oauth-client-secret, gmail-refresh-token,
  imap-<name>-password
"""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional

SERVICE = "Sentinel"
SECURITY = "/usr/bin/security"

PLACEHOLDER_PREFIX = "PLACEHOLDER"


class KeychainUnavailable(RuntimeError):
    pass


def available() -> bool:
    return os.path.exists(SECURITY) or bool(shutil.which("security"))


def _test_store() -> Optional[dict]:
    # Tests inject an in-memory store; never used in normal operation.
    return _TEST_STORE


_TEST_STORE = None  # type: Optional[dict]


def use_test_store(store: Optional[dict]) -> None:
    global _TEST_STORE
    _TEST_STORE = store


def get(account: str) -> Optional[str]:
    store = _test_store()
    if store is not None:
        return store.get(account)
    if not available():
        return None
    try:
        p = subprocess.run([SECURITY, "find-generic-password", "-s", SERVICE, "-a", account, "-w"],
                           capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    val = p.stdout.rstrip("\n")
    if not val or val.startswith(PLACEHOLDER_PREFIX):
        return None
    return val


def _quote(s: str) -> str:
    if any(c in s for c in "\n\r\0"):
        raise ValueError("secret contains a newline or NUL; refusing to store")
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def set(account: str, secret: str) -> None:  # noqa: A001 - mirrors Keychain verb
    store = _test_store()
    if store is not None:
        store[account] = secret
        return
    if not available():
        raise KeychainUnavailable("macOS Keychain (`security`) is not available on this system")
    cmd = "add-generic-password -U -s %s -a %s -l %s -w %s\n" % (
        _quote(SERVICE), _quote(account), _quote("Sentinel: " + account), _quote(secret))
    p = subprocess.run([SECURITY, "-i"], input=cmd, capture_output=True, text=True, timeout=20)
    if p.returncode != 0 or "error" in (p.stderr or "").lower():
        # Do not echo stderr verbatim: keep any accidental secret echo out of logs.
        raise KeychainUnavailable("Keychain write failed for account %r (exit %s)" % (account, p.returncode))


def delete(account: str) -> bool:
    store = _test_store()
    if store is not None:
        return store.pop(account, None) is not None
    if not available():
        return False
    p = subprocess.run([SECURITY, "delete-generic-password", "-s", SERVICE, "-a", account],
                       capture_output=True, text=True, timeout=20)
    return p.returncode == 0


def has(account: str) -> bool:
    return get(account) is not None
