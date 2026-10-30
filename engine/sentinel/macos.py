"""Thin, read-only wrappers around built-in macOS tools.

Sentinel layers on top of macOS protections — it only *asks* Gatekeeper and
codesign for their opinion; it never changes their settings.
"""
from __future__ import annotations

import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Sequence

from . import filetype as ft

IS_MACOS = platform.system() == "Darwin"


def run(cmd: Sequence[str], timeout: int = 30):
    """Run a command; returns (exit_code, stdout, stderr). Never raises for tool failures."""
    try:
        p = subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "%s: not found" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except OSError as e:
        return 126, "", str(e)



DETRITUS_RE = re.compile(r"resource fork, Finder information, or similar detritus not allowed")


def _is_detritus_only(path: Path, strict_text: str) -> bool:
    """True when --strict failed *only* over stray extended attributes.

    Decided by re-running the same verification without --strict rather than by reading the
    message alone: if the seal is genuinely broken, the relaxed run fails too.
    """
    if not DETRITUS_RE.search(strict_text):
        return False
    rc, out, err = run(["codesign", "--verify", "--deep", "--verbose=2", str(path)])
    return rc == 0


@dataclass
class SignatureInfo:
    # signed_valid | signed_detritus | signed_invalid | adhoc | unsigned | unavailable | not_applicable
    status: str = "not_applicable"
    authorities: List[str] = field(default_factory=list)
    team_id: str = ""
    identifier: str = ""
    notarized: Optional[bool] = None
    gatekeeper: str = "not_checked"          # accepted | rejected | not_checked | unavailable
    gatekeeper_source: str = ""              # e.g. "Notarized Developer ID"
    detail: str = ""

    @property
    def signer(self) -> str:
        return self.authorities[0] if self.authorities else ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["signer"] = self.signer
        return d


def _parse_codesign_display(text: str, info: SignatureInfo) -> None:
    for line in text.splitlines():
        if line.startswith("Authority="):
            info.authorities.append(line.split("=", 1)[1].strip())
        elif line.startswith("TeamIdentifier="):
            v = line.split("=", 1)[1].strip()
            info.team_id = "" if v == "not set" else v
        elif line.startswith("Identifier="):
            info.identifier = line.split("=", 1)[1].strip()
        elif line.startswith("Signature=adhoc"):
            info.status = "adhoc"


def check_signature(path: Path, category: str) -> SignatureInfo:
    """Code-signature + Gatekeeper assessment for runnable things. Read-only."""
    info = SignatureInfo()
    if category not in (ft.EXECUTABLE, ft.APP_BUNDLE, ft.INSTALLER, ft.DISK_IMAGE, ft.JAVA, ft.SCRIPT):
        return info
    if not IS_MACOS or not shutil.which("codesign"):
        info.status, info.gatekeeper = "unavailable", "unavailable"
        info.detail = "codesign/spctl are only available on macOS."
        return info

    if category == ft.INSTALLER:
        rc, out, err = run(["pkgutil", "--check-signature", str(path)])
        text = out + err
        if "no signature" in text.lower():
            info.status = "unsigned"
        elif rc == 0 and "signed" in text.lower():
            info.status = "signed_valid"
            for m in re.finditer(r"^\s*\d+\.\s*(.+)$", text, re.M):
                info.authorities.append(m.group(1).strip())
            m = re.search(r"\(([A-Z0-9]{10})\)", text)
            info.team_id = m.group(1) if m else ""
        else:
            info.status = "signed_invalid"
        info.detail = text.strip()[:500]
        rc, out, err = run(["spctl", "--assess", "--type", "install", "-vv", str(path)])
    else:
        if category == ft.SCRIPT:
            # Plain scripts are almost never signed; record that without treating it as a failure.
            info.status = "unsigned"
            info.detail = "Scripts are not code-signed; macOS will not vet this before it runs."
            return info
        rc, out, err = run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(path)])
        verify_text = (out + err).strip()
        if "not signed at all" in verify_text:
            info.status = "unsigned"
        elif rc == 0:
            info.status = "signed_valid"
        elif _is_detritus_only(path, verify_text):
            # --strict also rejects stray extended attributes (resource forks, Finder info) that
            # Finder, Spotlight and backup tools leave on perfectly good apps. The seal itself is
            # intact: the same verification passes without --strict. Housekeeping, not tampering.
            info.status = "signed_detritus"
        else:
            info.status = "signed_invalid"
        info.detail = verify_text[:500]
        rc2, out2, err2 = run(["codesign", "-dv", "--verbose=4", str(path)])
        _parse_codesign_display(out2 + err2, info)
        if category == ft.DISK_IMAGE:
            rc, out, err = run(["spctl", "--assess", "--type", "open", "--context",
                                "context:primary-signature", "-vv", str(path)])
        else:
            rc, out, err = run(["spctl", "--assess", "--type", "execute", "-vv", str(path)])

    gk_text = (out + err).strip()
    info.gatekeeper = "accepted" if rc == 0 else "rejected"
    m = re.search(r"source=(.+)", gk_text)
    info.gatekeeper_source = m.group(1).strip() if m else ""
    if info.gatekeeper_source:
        info.notarized = "Notarized" in info.gatekeeper_source
    return info


def gatekeeper_enabled() -> Optional[bool]:
    if not IS_MACOS:
        return None
    rc, out, err = run(["spctl", "--status"])
    return "enabled" in (out + err)


def sip_enabled() -> Optional[bool]:
    if not IS_MACOS:
        return None
    rc, out, err = run(["csrutil", "status"])
    return "enabled" in (out + err).lower()


def clamscan(path: Path) -> Optional[dict]:
    """Optional ClamAV scan if the user installed it (e.g. `brew install clamav`)."""
    exe = shutil.which("clamdscan") or shutil.which("clamscan")
    if not exe:
        return None
    rc, out, err = run([exe, "--no-summary", str(path)], timeout=300)
    if rc == 0:
        return {"engine": Path(exe).name, "infected": False, "detail": "OK"}
    if rc == 1:
        m = re.search(r":\s*(.+)\s+FOUND", out)
        return {"engine": Path(exe).name, "infected": True, "detail": m.group(1) if m else out.strip()[:200]}
    return {"engine": Path(exe).name, "infected": None, "detail": (err or out).strip()[:200]}


def objective_see_tools() -> dict:
    """Which free Objective-See tools are installed (Sentinel integrates, never clones)."""
    apps = {"BlockBlock": "/Applications/BlockBlock Helper.app", "LuLu": "/Applications/LuLu.app",
            "KnockKnock": "/Applications/KnockKnock.app"}
    found = {}
    for name, p in apps.items():
        alt = "/Applications/%s.app" % name
        found[name] = Path(p).exists() or Path(alt).exists()
    return found
