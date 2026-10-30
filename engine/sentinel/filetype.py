"""Real file-type sniffing (by content, not by name) and name-trick detection.

The `file` command is also consulted for a human-readable description, but the
verdict-driving classification is done here from magic bytes so it is
deterministic and testable on any OS.
"""
from __future__ import annotations

import os
import struct
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# Category names used everywhere in Sentinel.
EXECUTABLE = "executable"        # Mach-O / PE / ELF binary
APP_BUNDLE = "app_bundle"        # Something.app directory
INSTALLER = "installer"          # .pkg / .mpkg (xar)
DISK_IMAGE = "disk_image"        # .dmg / .iso / .img
SCRIPT = "script"                # shebang scripts, AppleScript, .command, ...
ARCHIVE = "archive"              # zip / gz / bz2 / xz / 7z / rar / tar
DOCUMENT = "document"            # pdf / rtf / office
MACRO_DOCUMENT = "macro_document"
IMAGE = "image"
MEDIA = "media"
TEXT = "text"
HTML = "html"
WEB_SHORTCUT = "web_shortcut"    # .webloc / .url / .inetloc
JAVA = "java"
UNKNOWN = "unknown"

RUNNABLE = {EXECUTABLE, APP_BUNDLE, INSTALLER, SCRIPT, JAVA}
HARMLESS_LOOKING = {DOCUMENT, IMAGE, MEDIA, TEXT}

# What a file *claims* to be, from its extension.
EXT_CATEGORY = {
    # documents
    "pdf": DOCUMENT, "rtf": DOCUMENT, "doc": DOCUMENT, "docx": DOCUMENT, "xls": DOCUMENT,
    "xlsx": DOCUMENT, "ppt": DOCUMENT, "pptx": DOCUMENT, "pages": DOCUMENT,
    "numbers": DOCUMENT, "key": DOCUMENT, "odt": DOCUMENT, "ods": DOCUMENT, "epub": DOCUMENT,
    "csv": TEXT, "txt": TEXT, "md": TEXT, "json": TEXT, "xml": TEXT, "log": TEXT,
    "docm": MACRO_DOCUMENT, "xlsm": MACRO_DOCUMENT, "pptm": MACRO_DOCUMENT,
    "dotm": MACRO_DOCUMENT, "xltm": MACRO_DOCUMENT, "xlam": MACRO_DOCUMENT, "ppsm": MACRO_DOCUMENT,
    # images / media
    "jpg": IMAGE, "jpeg": IMAGE, "png": IMAGE, "gif": IMAGE, "heic": IMAGE, "webp": IMAGE,
    "tif": IMAGE, "tiff": IMAGE, "bmp": IMAGE, "svg": IMAGE, "ico": IMAGE,
    "mp3": MEDIA, "m4a": MEDIA, "wav": MEDIA, "aac": MEDIA, "flac": MEDIA, "mp4": MEDIA,
    "mov": MEDIA, "m4v": MEDIA, "avi": MEDIA, "mkv": MEDIA, "webm": MEDIA,
    # web
    "html": HTML, "htm": HTML, "shtml": HTML, "xhtml": HTML, "mht": HTML, "mhtml": HTML,
    "webloc": WEB_SHORTCUT, "url": WEB_SHORTCUT, "inetloc": WEB_SHORTCUT,
    # archives
    "zip": ARCHIVE, "gz": ARCHIVE, "tgz": ARCHIVE, "bz2": ARCHIVE, "xz": ARCHIVE,
    "7z": ARCHIVE, "rar": ARCHIVE, "tar": ARCHIVE, "cpio": ARCHIVE,
    # disk images / installers
    "dmg": DISK_IMAGE, "iso": DISK_IMAGE, "img": DISK_IMAGE, "sparseimage": DISK_IMAGE,
    "pkg": INSTALLER, "mpkg": INSTALLER,
    # runnable
    "app": APP_BUNDLE, "exe": EXECUTABLE, "com": EXECUTABLE, "dll": EXECUTABLE, "scr": EXECUTABLE,
    "msi": INSTALLER, "dylib": EXECUTABLE, "so": EXECUTABLE, "bin": EXECUTABLE,
    "elf": EXECUTABLE, "out": EXECUTABLE,
    "sh": SCRIPT, "bash": SCRIPT, "zsh": SCRIPT, "command": SCRIPT, "tool": SCRIPT,
    "py": SCRIPT, "pl": SCRIPT, "rb": SCRIPT, "js": SCRIPT, "jxa": SCRIPT,
    "applescript": SCRIPT, "scpt": SCRIPT, "scptd": SCRIPT, "workflow": SCRIPT,
    "terminal": SCRIPT, "ps1": SCRIPT, "bat": SCRIPT, "cmd": SCRIPT, "vbs": SCRIPT,
    "vbe": SCRIPT, "wsf": SCRIPT, "hta": SCRIPT, "lnk": SCRIPT, "jse": SCRIPT,
    "jar": JAVA, "class": JAVA,
}

# Extensions that make a file runnable when double-clicked (used for double-extension tricks).
RUNNABLE_EXTS = {e for e, c in EXT_CATEGORY.items() if c in RUNNABLE} | {"dmg", "iso", "img"}
DECOY_EXTS = {e for e, c in EXT_CATEGORY.items() if c in HARMLESS_LOOKING | {MACRO_DOCUMENT, HTML}}

# Unicode bidirectional controls used to disguise names ("invoice‮fdp.app" shows as "invoiceppa.pdf").
BIDI_CONTROLS = {"‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩", "‏", "‎"}

PARTIAL_DOWNLOAD_SUFFIXES = (".crdownload", ".download", ".part", ".partial", ".opdownload", ".tmp")


@dataclass
class TypeInfo:
    category: str
    label: str                       # short human label, e.g. "Mach-O executable (arm64)"
    claimed_ext: str = ""
    claimed_category: str = ""
    archive_members: List[str] = field(default_factory=list)   # runnable members found in archives
    has_macros: bool = False
    file_description: str = ""       # output of `file -b`, when available


def claimed_extension(name: str) -> str:
    base = name.rstrip(" .")
    if "." not in base:
        return ""
    return base.rsplit(".", 1)[1].strip().lower()


def _read_head(path: Path, n: int = 8192) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def _read_tail(path: Path, n: int = 512) -> bytes:
    size = path.stat().st_size
    with open(path, "rb") as f:
        f.seek(max(0, size - n))
        return f.read(n)


def _macho_label(head: bytes) -> Optional[str]:
    if len(head) < 8:
        return None
    magic_be = struct.unpack(">I", head[:4])[0]
    if magic_be in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE):
        little = magic_be in (0xCEFAEDFE, 0xCFFAEDFE)
        cputype = struct.unpack("<i" if little else ">i", head[4:8])[0]
        arch = {0x0100000C: "arm64", 0x01000007: "x86_64", 7: "i386", 12: "arm"}.get(cputype, "unknown arch")
        return "Mach-O executable (%s)" % arch
    if magic_be in (0xCAFEBABE, 0xCAFEBABF):
        nfat = struct.unpack(">I", head[4:8])[0]
        # Java class files share CAFEBABE, but their next word is a version (>= 45 major).
        if 0 < nfat < 40:
            return "Mach-O universal binary"
    return None


def _zip_inspect(path: Path, info: TypeInfo) -> str:
    """Return a refined label for zip-based formats and note runnable members."""
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return "ZIP archive (unreadable)"
    lower = [n.lower() for n in names]
    if "[content_types].xml" in lower:
        if any(n.endswith("vbaproject.bin") for n in lower):
            info.has_macros = True
        return "Office document (OOXML)"
    if "meta-inf/manifest.mf" in lower or any(n.endswith(".class") for n in lower):
        info.category = JAVA
        return "Java archive (JAR)"
    if "mimetype" in lower and any(n.startswith("meta-inf/") for n in lower):
        return "OpenDocument/EPUB document"
    runnable = []
    for n in names:
        parts = n.split("/")
        if any(p.lower().endswith(".app") for p in parts[:-1]) and "/Contents/MacOS/" in n:
            app = "/".join(parts[: next(i for i, p in enumerate(parts) if p.lower().endswith(".app")) + 1])
            if app not in runnable:
                runnable.append(app)
            continue
        ext = claimed_extension(parts[-1])
        if ext in RUNNABLE_EXTS and ext != "app":
            runnable.append(n)
    info.archive_members = runnable[:25]
    return "ZIP archive"


def _ole_has_macros(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            data = f.read(4 * 1024 * 1024)
    except OSError:
        return False
    return "_VBA_PROJECT".encode("utf-16-le") in data or b"_VBA_PROJECT" in data or "Macros".encode("utf-16-le") in data


def sniff(path: Path) -> TypeInfo:
    """Classify a file by its content."""
    path = Path(path)
    ext = claimed_extension(path.name)
    claimed_cat = EXT_CATEGORY.get(ext, UNKNOWN if ext else "")
    info = TypeInfo(category=UNKNOWN, label="Unknown data", claimed_ext=ext, claimed_category=claimed_cat)

    if path.is_dir():
        if path.suffix.lower() == ".app" or (path / "Contents" / "Info.plist").exists():
            info.category, info.label = APP_BUNDLE, "macOS application bundle"
        elif path.suffix.lower() in (".pkg", ".mpkg"):
            info.category, info.label = INSTALLER, "macOS installer package (bundle)"
        else:
            info.category, info.label = UNKNOWN, "Folder"
        return info

    try:
        size = path.stat().st_size
        head = _read_head(path)
    except OSError as e:
        info.label = "Unreadable (%s)" % e.strerror
        return info

    macho = _macho_label(head)
    if macho:
        info.category, info.label = EXECUTABLE, macho
    elif head.startswith(b"MZ"):
        info.category, info.label = EXECUTABLE, "Windows executable (PE)"
    elif head.startswith(b"\x7fELF"):
        info.category, info.label = EXECUTABLE, "Linux executable (ELF)"
    elif head.startswith(b"xar!"):
        info.category, info.label = INSTALLER, "macOS installer package (xar)"
    elif head.startswith(b"#!"):
        interp = head[2:120].split(b"\n", 1)[0].strip().decode("utf-8", "replace")
        info.category, info.label = SCRIPT, "Script (%s)" % (interp or "shebang")
    elif head.startswith(b"FasdUAS"):
        info.category, info.label = SCRIPT, "Compiled AppleScript"
    elif head.startswith(b"%PDF"):
        info.category, info.label = DOCUMENT, "PDF document"
    elif head.startswith(b"{\\rtf"):
        info.category, info.label = DOCUMENT, "RTF document"
    elif head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        info.category, info.label = DOCUMENT, "Legacy Office document (OLE)"
        if _ole_has_macros(path):
            info.has_macros = True
    elif head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        info.category = ARCHIVE
        info.label = _zip_inspect(path, info)
        if info.label.startswith(("Office", "OpenDocument")):
            info.category = DOCUMENT
    elif head.startswith(b"\x1f\x8b"):
        info.category, info.label = ARCHIVE, "gzip archive"
    elif head.startswith(b"BZh"):
        info.category, info.label = ARCHIVE, "bzip2 archive"
    elif head.startswith(b"\xfd7zXZ\x00"):
        info.category, info.label = ARCHIVE, "xz archive"
    elif head.startswith(b"7z\xbc\xaf\x27\x1c"):
        info.category, info.label = ARCHIVE, "7-Zip archive"
    elif head.startswith(b"Rar!\x1a\x07"):
        info.category, info.label = ARCHIVE, "RAR archive"
    elif len(head) > 262 and head[257:262] == b"ustar":
        info.category, info.label = ARCHIVE, "tar archive"
    elif head.startswith(b"\x89PNG"):
        info.category, info.label = IMAGE, "PNG image"
    elif head.startswith(b"\xff\xd8\xff"):
        info.category, info.label = IMAGE, "JPEG image"
    elif head.startswith((b"GIF87a", b"GIF89a")):
        info.category, info.label = IMAGE, "GIF image"
    elif head[4:12] in (b"ftypheic", b"ftypheix", b"ftypmif1"):
        info.category, info.label = IMAGE, "HEIC image"
    elif head[4:8] == b"ftyp":
        info.category, info.label = MEDIA, "MP4/QuickTime media"
    elif head.startswith(b"RIFF") and head[8:12] in (b"WEBP",):
        info.category, info.label = IMAGE, "WebP image"
    elif head.startswith(b"RIFF") or head.startswith(b"ID3") or head.startswith(b"fLaC"):
        info.category, info.label = MEDIA, "Audio/video media"
    elif head.startswith(b"bplist00") or head.lstrip().startswith(b"<?xml") and b"<plist" in head:
        if ext in ("webloc", "inetloc"):
            info.category, info.label = WEB_SHORTCUT, "Web location shortcut"
        elif ext == "terminal":
            info.category, info.label = SCRIPT, "Terminal settings file (can run commands)"
        else:
            info.category, info.label = TEXT, "Property list"
    else:
        lowered = head[:2048].lower()
        if size >= 512 and _read_tail(path)[:4] == b"koly":
            info.category, info.label = DISK_IMAGE, "macOS disk image (UDIF .dmg)"
        elif size > 0x8006 and _read_at(path, 0x8001, 5) == b"CD001":
            info.category, info.label = DISK_IMAGE, "ISO disk image"
        elif size > 1026 and _read_at(path, 1024, 2) in (b"H+", b"HX"):
            info.category, info.label = DISK_IMAGE, "Raw HFS+ disk image"
        elif b"<html" in lowered or b"<!doctype html" in lowered or b"<script" in lowered:
            info.category, info.label = HTML, "HTML document"
        elif lowered.startswith(b"[internetshortcut]"):
            info.category, info.label = WEB_SHORTCUT, "Internet shortcut (.url)"
        elif lowered.lstrip().startswith(b"<svg") or (b"<svg" in lowered and lowered.lstrip().startswith(b"<?xml")):
            info.category, info.label = IMAGE, "SVG image"
            if b"<script" in head.lower() or b"onload=" in head.lower():
                info.category, info.label = HTML, "SVG image containing script"
        elif _looks_text(head):
            info.category, info.label = TEXT, "Text"
            if ext in ("sh", "command", "tool", "py", "js", "ps1", "bat", "cmd", "vbs", "applescript"):
                info.category, info.label = SCRIPT, "Script (%s, no shebang)" % ext
    info.file_description = describe_with_file_cmd(path)
    return info


def _read_at(path: Path, offset: int, n: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(n)


def _looks_text(head: bytes) -> bool:
    if not head:
        return True
    if b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
        return True
    except UnicodeDecodeError:
        # A multibyte char may be cut at the buffer edge.
        try:
            head[:-4].decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False


def describe_with_file_cmd(path: Path) -> str:
    try:
        out = subprocess.run(["file", "-b", str(path)], capture_output=True, text=True, timeout=10)
        return out.stdout.strip()[:200]
    except (OSError, subprocess.SubprocessError):
        return ""


# --- name tricks -------------------------------------------------------------

@dataclass
class NameTrick:
    kind: str       # "bidi", "double_extension", "padded_extension"
    detail: str


def name_tricks(name: str) -> List[NameTrick]:
    tricks = []
    if any(c in BIDI_CONTROLS for c in name):
        shown = "".join(c for c in name if c not in BIDI_CONTROLS)
        tricks.append(NameTrick("bidi", "The name contains hidden right-to-left control characters, "
                                        "so Finder may display it differently from its real name (%r)." % shown))
    stripped = name.rstrip()
    parts = stripped.split(".")
    if len(parts) >= 3:
        last = parts[-1].strip().lower()
        prev = parts[-2].strip().lower()
        if last in RUNNABLE_EXTS and prev in DECOY_EXTS:
            tricks.append(NameTrick("double_extension",
                                    "The name looks like a .%s but really ends in .%s, which macOS can run." % (prev, last)))
    # "invoice.pdf          .app": lots of spaces hiding the real extension.
    if len(parts) >= 2 and "   " in parts[-2] and parts[-1].strip().lower() in RUNNABLE_EXTS:
        tricks.append(NameTrick("padded_extension", "The name is padded with spaces to push the real extension (.%s) out of view." % parts[-1].strip()))
    return tricks


def is_partial_download(name: str) -> bool:
    return name.lower().endswith(PARTIAL_DOWNLOAD_SUFFIXES)


def is_ignorable(name: str) -> bool:
    return name.startswith(".") or name in ("Icon\r",) or is_partial_download(name)


def bundle_executable(app: Path) -> Optional[Path]:
    """Main executable of an .app bundle (for signature/process checks)."""
    macos_dir = app / "Contents" / "MacOS"
    try:
        import plistlib
        with open(app / "Contents" / "Info.plist", "rb") as f:
            name = plistlib.load(f).get("CFBundleExecutable")
        if name and (macos_dir / name).exists():
            return macos_dir / name
    except Exception:
        pass
    if macos_dir.is_dir():
        for p in sorted(macos_dir.iterdir()):
            if p.is_file() and os.access(p, os.X_OK):
                return p
    return None
