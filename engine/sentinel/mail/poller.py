"""One mail-poll pass over every enabled account (run every 2 minutes by launchd)."""
from __future__ import annotations

import json
import traceback
from typing import List

from .. import paths, pipeline
from . import emailscan, gmail, imap


def _state_path():
    return paths.state_dir() / "mail-state.json"


def _load_state() -> dict:
    try:
        return json.loads(_state_path().read_text())
    except (OSError, ValueError):
        return {}


def poll_all(do_notify: bool = True, verbose: bool = False) -> List[dict]:
    cfg = paths.load_config()
    mcfg = cfg.get("mail", {})
    state = _load_state()
    out, errors = [], []
    sources = []
    if mcfg.get("gmail_enabled"):
        sources.append(("gmail:%s" % (mcfg.get("gmail_account") or "me"), lambda: gmail.poll(state, mcfg.get("lookback_hours", 24))))
    for acct in mcfg.get("imap_accounts", []):
        sources.append(("imap:%s" % acct.get("name"), (lambda a=acct: imap.poll(a, state, mcfg.get("lookback_hours", 24)))))
    for account, gen in sources:
        try:
            for mid, raw, internal in gen():
                rec = emailscan.analyze_message(raw, account=account, internal_ms=internal, mail_id=mid)
                pipeline.finish(rec, do_notify)
                out.append(rec)
                if verbose:
                    print("%-9s %s  %s" % (rec["verdict"].upper(), account, rec["subject"][:70]))
        except Exception as e:  # keep polling other accounts
            errors.append("%s: %s" % (account, e))
            if verbose:
                traceback.print_exc()
        finally:
            paths.write_json_atomic(_state_path(), state)
    if errors:
        with (paths.logs_dir() / "mail-errors.log").open("a") as f:
            f.write("\n".join(errors) + "\n")
        if verbose:
            for e in errors:
                print("error:", e)
    if not sources and verbose:
        print("No mail accounts enabled. Run `sentinel mail-setup gmail` (and/or imap).")
    return out
