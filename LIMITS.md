# LIMITS — what was not verified in the build VM, and how to verify it on the Mac

Sentinel was built in a **Linux VM**. Some things can't be run there: macOS frameworks
(FSEvents, launchd, UserNotifications, Keychain, codesign/spctl, xattr), the Swift toolchain, and
Brave on macOS. This file says honestly what *was* verified, what *wasn't*, and the exact on-Mac
steps for each gap.

## What was verified in the VM

| Area | How | Result |
|---|---|---|
| Engine: type sniffing, mismatch, name tricks, EICAR, scoring, reports, removal plans, quarantine / restore / delete, allowlist, persistence diff, email parsing and phishing heuristics, URL heuristics, native-messaging protocol | `python3 -m unittest` (Python 3.12; the code also passes a Python 3.9 grammar check) | 73 tests, **all pass**. 1 skipped: the real-`codesign` test, which is macOS-only |
| Reputation logic (VirusTotal / Safe Browsing) | Mocked HTTP: hash-only, no key → no request, upload double-gated, keys never on disk, cache holds no plaintext URLs | pass. **No real API call was made**; no keys exist here |
| Brave/Chromium extension | `scripts/test-extension.mjs`: real Chrome for Testing 156 (Chromium), unpacked extension, native host wired to the engine | **7/7 pass**: loads with the pinned ID, service worker runs, native host connects, look-alike URL → interstitial with engine reasons, normal site not interrupted |
| setup.sh / uninstall.sh | `bash -n`; launchd templates rendered and parsed with `plistlib`, including paths with spaces and `&` | pass. **Not executed** (they need macOS) |
| CLI end to end | `sentinel scan`, `check-url`, `events`, `remove --yes`, `restore`, `delete` refusal without a TTY | pass (Linux paths) |

## Verified on this Mac — 2026-10-30

Run on the real machine (macOS 27.0.1, build 26A434, arm64), not in the build VM. This section records what
is now closed. The numbered list below it is kept as written, so the original gaps stay readable;
check here first for current status.

**Closed**

| # | Gap | Result on this Mac |
|---|---|---|
| 1 | Swift compilation | **Closed.** `swift build -c release` in `macos/` → `Build complete!`. The loaded `com.sentinel.agent` (pid 10380) runs `~/Applications/Sentinel/Sentinel Agent.app/Contents/MacOS/SentinelAgent`, i.e. the Swift binary, not the Python fallback. This was the file's highest-risk item. |
| 6 | Real `codesign` test | **Closed.** `test_real_codesign_on_mac` runs and passes here; the single remaining skip is now `test_without_macos_signature_…`, correctly skipped as Linux-only. `QuarantineEventsV2` is readable (767 rows). |
| 7 | Extension, automated run | **Closed for the automated path.** `scripts/test-extension.mjs` against the real `/Applications/Brave Browser.app` binary: **7/7**, including native-host connect and the look-alike interstitial. It used an isolated temp profile and cleaned it up. |

**Partly closed**

| # | Gap | What was and was not shown |
|---|---|---|
| 2 | FSEvents watching | An EICAR file written to `~/Downloads` raised a `DANGEROUS` event in **under 12 seconds**, and the file was left in place — flagged, never silently deleted. **Debounce is still untested:** nobody has downloaded a large file in Brave to confirm exactly one event and none for `*.crdownload`. |
| 4 | launchd agents | `agent` and `menubar` both load and report `state = running`. `mail` does not load, because no mail account is configured. **Logout/login persistence is still untested.** |
| 7 | Extension, manual install | Steps 1–4 (loading the unpacked extension into the everyday Brave profile and clicking through the interstitial) have **not** been done. Only the optional automated run in step 5 has. |

**Still open, unchanged:** 3 (UserNotifications action buttons and the removal confirmation dialog
— these need a human to click), 5 (Keychain), 8 (Gmail / Yahoo), 9 (persistence watching: an
earlier `Caution: new startup item com.sentinel.menubar` event from 2026-10-29 suggests it fires,
but it was not tested on 2026-10-30), 10 (behaviour snapshot accuracy), 11 (out of scope for v1).

Full suite on this Mac: `Ran 73 tests ... OK (skipped=1)` — **72 pass, 1 platform skip** — plus
clean `node --check` on every extension script.

### Reputation lookups are live as of 2026-10-30

The VM table above records that reputation logic was only ever exercised against mocked HTTP, with
no keys present. Both keys are now in the Keychain (`sentinel keys status`: `virustotal-api-key`
and `safebrowsing-api-key` both **stored**), and both were confirmed with real calls:

- `sentinel scan <eicar>` → `+150 66 antivirus engines on VirusTotal flag this file as malicious`
- `sentinel check-url http://testsafebrowsing.appspot.com/s/malware.html` →
  `+120 Google Safe Browsing lists this site as known to spread malware`, `+100 9 VirusTotal
  engines flag this site`, with `safebrowsing: flagged` and `virustotal: found`

The Safe Browsing key is restricted to the Safe Browsing API on its own Google Cloud project, so a leak of it cannot reach any other Google service. Detection is no
longer heuristics-only.

### Defect found while verifying §6 — legitimate apps are called "tampered with"

`sentinel scan "/Applications/Brave Browser.app"` is documented below as expecting
*valid signature, Brave Software, notarized → Clean*. **It returns `CAUTION` instead**, with
`+80 This program's signature is broken or has been tampered with`.

Brave is fine. Checked directly:

- `codesign --verify --deep --strict` fails only with
  `resource fork, Finder information, or similar detritus not allowed` — stray extended
  attributes on a subcomponent, which Finder, Spotlight and backup tools routinely leave behind.
- `spctl -a -vv` returns `accepted`, `source=Notarized Developer ID`,
  `origin=Developer ID Application: Brave Software, Inc. (KL8N8XSYF4)`.

Cause: `sentinel/macos.py:100` runs `codesign --verify --deep --strict` and maps **any** non-zero
exit that is not `not signed at all` to `signed_invalid`; `sentinel/analyzer.py:144` then applies
the full 80-point `bad_signature` reason. The detritus case is not separated from real tampering,
and the `spctl` verdict the same function already collects (`gatekeeper = accepted`,
`notarized = True`) does not temper it.

Why it matters: this fires on ordinary, notarized, Gatekeeper-accepted apps, and the wording tells
the user they have been tampered with. A personal security tool that cries wolf on Brave gets
ignored when it is right.

**Fixed the same day.** A new `signed_detritus` status sits between valid and invalid. It is not
decided from the message text: when `--strict` fails with the detritus wording, `_is_detritus_only`
re-runs the *same* verification **without** `--strict`, and only a clean pass there earns the new
status — a genuinely broken seal fails both ways. `analyzer.py` scores it `+5`
("signature is intact, but it carries stray file attributes") instead of `+80`, and a Gatekeeper
rejection still applies its own 40 points through the detritus status, so a rejected app cannot
slip through on this path.

Confirmed on this Mac after the change:

- `sentinel scan "/Applications/Brave Browser.app"` → **`CLEAN`**, `+5` detritus, `-15` notarized,
  which is what this section always said to expect.
- A real tamper check — 8 bytes overwritten inside a signed copy of `/usr/bin/true`, so `codesign`
  reports `CSSMERR_TP_NOT_TRUSTED` — still scores **`+80` "broken or has been tampered with"**.
- Suite: **`Ran 81 tests ... OK (skipped=2)`**, up from 73. `tests/test_detritus.py` adds 8 covering
  the relaxed-rerun logic, the scoring split, Gatekeeper still biting, and real tampering staying
  tampering. Its one skip is a real-binary case this macOS build does not reproduce.
- Changed: `sentinel/macos.py`, `sentinel/analyzer.py`, `sentinel/report.py`.
  **The installed engine was synced too** (`~/Library/Application Support/Sentinel/engine`), since
  the `sentinel` command and the Swift agent run that copy, not this source tree — editing the
  source alone changes nothing about what is actually protecting the Mac. `./setup.sh` is still the
  supported way to reinstall everything.

**Testing residue in the event log** (all from this verification, not real threats): a `DANGEROUS`
`eicar-test.com` and a `DANGEROUS` `paypal.com.secure-verify.xyz` on 2026-10-30, plus the
`CAUTION` Brave scan above. Reports for each are in `Reports/`. The EICAR file itself was deleted
from `~/Downloads`.

## What could NOT be verified, and the exact on-Mac steps

Run these from the project folder after `./setup.sh`. Each one says what to look for.

### 1. Swift compilation (agent + menu-bar app). *Highest risk: the code was written without a compiler.*

```sh
cd macos && swift build -c release 2>&1 | tail -20
```

Expect `Build complete!`. If it fails, the error is almost certainly a small API typo. Two ways
forward: paste the error to Claude Code to fix, or keep using Sentinel through the fallback
(`./setup.sh --no-swift`), which uses the tested Python watcher. The areas I'd check first if it
fails:

- the `FSEventStreamCreate` callback signature and `FSEventStreamCreateFlags` casting (`main.swift`)
- the `Window` scene / `openWindow` (macOS 13 APIs, `SentinelMenuBarApp.swift`)

### 2. FSEvents download watching + debounce

```sh
launchctl print gui/$(id -u)/com.sentinel.agent | grep -E 'state|pid'   # expect: state = running
tail -f ~/.Sentinel/logs/agent.log &                                      # "Sentinel: watching …"
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-' 'ANTIVIRUS-TEST-FILE!$H+H*' > ~/Downloads/eicar-test.com
sleep 6; sentinel events                                                  # a DANGEROUS eicar-test.com event
```

Then download any large file in Brave and confirm exactly **one** event appears, after the download
finishes (no event for `*.crdownload`). macOS will ask "Sentinel Agent would like to access files
in your Downloads folder": click **Allow**.

Note: XProtect or another antivirus may grab the EICAR file first. That's fine and expected.
Sentinel layers on top of them.

### 3. UserNotifications with action buttons

1. On first launch, allow notifications for **Sentinel Agent**. In System Settings → Notifications
   → Sentinel Agent, set the style to **Alerts** so the buttons stay visible.
2. Trigger the EICAR test above. Hover the notification and expand **Options**. Expect *Open
   report*, *Remove…*, *Allow once*, *Always allow this source*.
3. Click **Remove…**. A confirmation dialog must appear *before* anything moves. Confirm, then
   check `ls ~/.Sentinel/Quarantine/` and `sentinel quarantine`.
4. If notifications never appear, the agent falls back to `osascript` banners (no buttons). Use
   the menu-bar app or the CLI for actions instead.

Unverified assumption: an ad-hoc-signed `LSUIElement` app started by launchd is allowed to use
UserNotifications. If it isn't, the fallback above applies.

### 4. launchd agents

```sh
for l in agent menubar mail; do launchctl print gui/$(id -u)/com.sentinel.$l >/dev/null 2>&1 && echo "$l loaded" || echo "$l not loaded"; done
```

Log out and back in, and confirm the shield icon returns to the menu bar and `agent` is still
running. `mail` only loads once a mail account is configured.

### 5. Keychain (writes via `security -i` stdin)

```sh
sentinel keys set virustotal       # paste key (hidden)
sentinel keys status               # "stored in Keychain" (the key itself is never printed)
security find-generic-password -s Sentinel -a virustotal-api-key   # item exists (prints metadata, not the key)
```

Unverified assumption: `security -i` parses the quoted `add-generic-password … -w "<secret>"`
command line correctly for every key format. VirusTotal and Google keys are alphanumeric with
`-`/`_`, so this should be safe. If a save fails, use `security add-generic-password -s Sentinel
-a virustotal-api-key -U -w` (no value after `-w`), which prompts for the key itself.

Also try saving a key from the menu-bar app's **Settings** and confirm `sentinel keys status`
sees it with no extra Keychain prompt.

### 6. codesign / spctl / pkgutil / xattr / QuarantineEventsV2 (real macOS data)

```sh
cd engine && python3 -m unittest tests.test_unsigned -v      # the real-codesign test now runs (not skipped)
sentinel scan "/Applications/Brave Browser.app"              # expect: valid signature, Brave Software, notarized → Clean
# Download any small PDF in Brave, then:
xattr -p com.apple.quarantine ~/Downloads/<file>.pdf          # e.g. 0083;…;Brave Browser;<UUID>
sentinel scan --json ~/Downloads/<file>.pdf | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["origin"], indent=2))'
```

The `origin` block must show the `download_url` and `"downloaded_by": "Brave Browser"`. Clean
files get no Markdown report; flagged ones show the same data under **Where it came from**. If the URL is empty but the agent is known, check that the database path is readable:

```sh
sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 'select count(*) from LSQuarantineEvent'
```

Unverified assumptions:

- Brave writes `kMDItemWhereFroms` the way Chrome does.
- Apple Mail's WhereFroms contains the sender, which is what the parser assumes.

### 7. Brave extension on macOS + native messaging to the installed engine

1. `brave://extensions` → Developer mode → Load unpacked →
   `~/Library/Application Support/Sentinel/extension`. The ID must be
   `hkjkodcckmeegnfhjjmcajmnadcgnmbm`.
2. Click the toolbar icon. Expect *Local engine connected (v1.0.0)* and the key status.
3. Visit `https://paypal.com.secure-verify.xyz/login`. The interstitial appears with reasons. Try
   **Go back** (returns to the previous page, never the flagged one), **Proceed anyway**, and
   **Always allow this site** (then `sentinel allowlist` shows it).
4. Right-click any link → **Check this link with Sentinel**. A result tab opens.
5. Optional automated run:
   `CHROME="/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" node scripts/test-extension.mjs`.
   It uses a throwaway profile; if Brave ignores `<profile>/NativeMessagingHosts`, test 2 may
   fail there while manual step 2 passes.

Known limitation (by design in MV3): the extension can't block a navigation synchronously. It
redirects the tab to the warning page as soon as the check returns (instant for offline
heuristics, roughly 100–400 ms for Safe Browsing). A malicious page may start loading for that
moment. Brave Shields and Brave's own Safe Browsing stay on and are the first line of defence.

### 8. Gmail API and Yahoo IMAP (needs your accounts; no tokens were used here)

```sh
sentinel mail-setup gmail     # browser consent → "Gmail connected (read-only)"
sentinel mail-poll -v         # lists new messages with verdicts
```

Send yourself a test email from another account. Use HTML with link text `https://www.paypal.com`
pointing at `https://paypal.com.example-check.xyz/` (a harmless non-existent domain). Within 2
minutes you should get *"This email arrived N min ago with 1 flagged link"*, and the message must
be **unchanged** in Gmail: still unread, no labels. For Yahoo, `sentinel mail-setup imap --name
yahoo`, then the same test, and check the message stays **unread**.

Unverified: the Gmail OAuth loopback flow, refresh-token behaviour, and the IMAP UIDVALIDITY
handling were written to the documented APIs but not run against live servers.

### 9. Persistence watching (BlockBlock-lite)

```sh
cat > ~/Library/LaunchAgents/com.example.sentinel-test.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Label</key><string>com.example.sentinel-test</string>
<key>ProgramArguments</key><array><string>/tmp/sentinel-test-binary</string></array></dict></plist>
EOF
sleep 6; sentinel events | head -3          # Dangerous: new startup item … (runs from /tmp)
sentinel remove <that-id>                    # quarantines the plist (it was never loaded, so bootout is a no-op)
```

Not covered at all: Login Items (the macOS 13+ Background Task Management database needs root to
read). Opt in with `sentinel config set persistence.login_items true`, which uses System Events
and triggers an Automation prompt, or check System Settings → General → Login Items. KnockKnock
covers these fully.

### 10. Behaviour snapshot accuracy

`ps`/`lsof` matching works by command-line path. A program that copies itself elsewhere, then
runs, won't be linked to the original download: Sentinel will say *"No running process launched
from this file"*. That's why reports separate **observed** from **inferred** and point to
LuLu/KnockKnock. To verify: open a flagged (harmless) app, then run `sentinel snapshot <id>`. Its
PID and open connections should be listed.

### 11. Other things that are deliberately not done in v1

- No real-time kernel scanning. No Endpoint Security, no kernel extension: by design.
- XProtect can't be queried directly. Sentinel relies on Gatekeeper's `spctl` assessment, and on
  XProtect itself when you open the file.
- No automatic deletion or quarantine, ever. No email modification. No Safari extension (v2).
- The VirusTotal free tier allows 4 lookups/minute. A burst of downloads waits for the rate limit
  (results are cached for 24 h). Link checks don't wait: they show *rate_limited* and rely on
  Safe Browsing plus the heuristics.
- Heuristics will produce false positives, e.g. a legitimate site whose name contains a bank's
  name plus "online". Every alert offers Allow once / Always allow.
