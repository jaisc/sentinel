"""Download watcher logic shared by the Swift FSEvents agent and the polling fallback.

* Debounce: a file is only scanned once its size and modification time have
  been stable for `settle_seconds` and it is no longer a partial download
  (.crdownload / .download / .part ...).
* Seen-state: each (path, size, mtime) is scanned once, so restarts don't re-alert.
* The polling watcher (`sentinel watch`) is the no-Swift fallback; the native
  agent uses FSEvents and calls `sentinel scan --if-new` for settled paths.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from . import filetype as ft, paths

BUNDLE_SUFFIXES = (".app", ".pkg", ".mpkg", ".bundle", ".plugin", ".framework", ".kext", ".scptd", ".workflow")


class StabilityTracker:
    """Reports a path as ready once (size, mtime) stayed unchanged for settle_seconds."""

    def __init__(self, settle_seconds: float = 2.0):
        self.settle = settle_seconds
        self._last = {}  # type: Dict[str, Tuple[Tuple[int, float], float]]

    def observe(self, path: str, signature: Tuple[int, float], now: float) -> bool:
        prev = self._last.get(path)
        if prev is None or prev[0] != signature:
            self._last[path] = (signature, now)
            return False
        return now - prev[1] >= self.settle

    def forget(self, path: str) -> None:
        self._last.pop(path, None)


def file_signature(p: Path) -> Optional[Tuple[int, float]]:
    try:
        if p.is_dir():
            # For bundles, use the newest mtime + total size of the tree (cheap enough for apps).
            size, newest = 0, p.stat().st_mtime
            for root, _d, files in os.walk(p):
                for f in files:
                    try:
                        st = os.lstat(os.path.join(root, f))
                    except OSError:
                        continue
                    size += st.st_size
                    newest = max(newest, st.st_mtime)
            return size, newest
        st = p.stat()
        return st.st_size, st.st_mtime
    except OSError:
        return None


def candidates(folder: Path, depth: int = 2) -> Iterable[Path]:
    """Files and bundles under a watch folder (bundles are not descended into)."""
    try:
        entries = list(os.scandir(folder))
    except OSError:
        return
    for e in entries:
        if ft.is_ignorable(e.name):
            continue
        p = Path(e.path)
        try:
            is_dir = e.is_dir(follow_symlinks=False)
        except OSError:
            continue
        if is_dir:
            if e.name.lower().endswith(BUNDLE_SUFFIXES):
                yield p
            elif depth > 1:
                for sub in candidates(p, depth - 1):
                    yield sub
        elif e.is_file(follow_symlinks=False):
            yield p


def any_partial_sibling(p: Path) -> bool:
    """Brave/Chrome write 'name.crdownload' then rename; Safari uses a 'name.download' folder."""
    for suffix in (".crdownload", ".download", ".part"):
        if Path(str(p) + suffix).exists():
            return True
    return False


# --- seen-state ----------------------------------------------------------------

def _seen_path() -> Path:
    return paths.state_dir() / "seen.json"


def load_seen() -> Dict[str, list]:
    try:
        return json.loads(_seen_path().read_text())
    except (OSError, ValueError):
        return {}


def save_seen(seen: Dict[str, list]) -> None:
    if len(seen) > 20000:
        for k in list(seen)[: len(seen) - 15000]:
            seen.pop(k, None)
    paths.write_json_atomic(_seen_path(), seen)


def is_new(p: Path, seen: Dict[str, list]) -> bool:
    sig = file_signature(p)
    return sig is not None and seen.get(str(p)) != [sig[0], sig[1]]


def mark_seen(p: Path, seen: Dict[str, list]) -> None:
    sig = file_signature(p)
    if sig is not None:
        seen[str(p)] = [sig[0], sig[1]]


def watch_folders(cfg: dict) -> List[Path]:
    out = []
    for f in cfg.get("watch_folders", []):
        p = paths.expand_path(f)
        if p.is_dir():
            out.append(p)
    return out


def poll_once(tracker: StabilityTracker, seen: Dict[str, list], folders: List[Path],
              on_ready: Callable[[Path], None], now: Optional[float] = None) -> List[Path]:
    """One polling pass; calls on_ready(path) for each new, settled file. Returns those paths."""
    now = time.time() if now is None else now
    ready = []
    for folder in folders:
        for p in candidates(folder):
            key = str(p)
            if not is_new(p, seen):
                tracker.forget(key)
                continue
            sig = file_signature(p)
            if sig is None or any_partial_sibling(p):
                continue
            if tracker.observe(key, sig, now):
                tracker.forget(key)
                mark_seen(p, seen)
                ready.append(p)
                on_ready(p)
    return ready


def baseline_existing(folders: List[Path], seen: Dict[str, list]) -> int:
    n = 0
    for folder in folders:
        for p in candidates(folder):
            if is_new(p, seen):
                mark_seen(p, seen)
                n += 1
    return n


def run_polling(on_ready: Callable[[Path], None], scan_existing: bool = False,
                on_persistence: Optional[Callable[[], None]] = None) -> None:  # pragma: no cover - loop
    cfg = paths.load_config()
    interval = float(cfg.get("watcher", {}).get("poll_interval_seconds", 2.0))
    tracker = StabilityTracker(float(cfg.get("watcher", {}).get("settle_seconds", 2.0)))
    seen = load_seen()
    folders = watch_folders(cfg)
    if not scan_existing:
        baseline_existing(folders, seen)
        save_seen(seen)
    print("Sentinel polling watcher: %s" % ", ".join(str(f) for f in folders), flush=True)
    last_persist = 0.0
    while True:
        if poll_once(tracker, seen, folders, on_ready):
            save_seen(seen)
        if on_persistence and time.time() - last_persist > 30:
            last_persist = time.time()
            on_persistence()
        time.sleep(interval)
