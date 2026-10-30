# Sentinel — a personal Mac security guard

Sentinel watches what arrives from the internet (downloads, email links and attachments, link
clicks in Brave) and tells you in plain English **what it is, where it came from, what it's
doing, and how to remove it**. You approve every removal yourself. Removal means a reversible
quarantine, never a silent delete.

It's for one person on one Mac. Everything runs locally. There's no server, no account, and no
telemetry. The only network calls are reputation lookups: a file's SHA-256 to VirusTotal, and
link addresses to Google Safe Browsing / VirusTotal. File contents never leave the Mac unless you
turn on the upload option, and even then each upload needs its own confirmation.

> **Status:** the engine, CLI, reports, removal and email analysis are tested (73 unit tests).
> The Brave extension was load-tested in real Chromium with the native host. The Swift agent and
> menu-bar app couldn't be compiled in the Linux build VM. See [LIMITS.md](LIMITS.md) for what
> still needs verifying on the Mac and exactly how to do it.

---

## Architecture

```
                            ┌────────────────────────── your Mac (everything below is local) ──────────────────────────┐
                            │                                                                                           │
 internet ─ download ──────►│  ~/Downloads ~/Desktop Mail Downloads …                                                   │
                            │        │ FSEvents                                                                         │
                            │        ▼                                                                                  │
                            │  SentinelAgent.app  (launchd: com.sentinel.agent, Swift)                                  │
                            │   • debounce until the download settles (.crdownload gone, size stable)                   │
                            │   • watches LaunchAgents/Daemons for new startup items (BlockBlock-lite)                  │
                            │   • posts notifications: Open report · Remove… · Allow once · Always allow                │
                            │        │ runs: sentinel scan --if-new --json --no-notify <path>                           │
                            │        ▼                                                                                  │
                            │  ┌──────────────── Sentinel engine (Python 3.9+, stdlib only) ─────────────────┐          │
                            │  │ filetype   real type by magic bytes · ext-vs-type mismatch · .pdf.app ·     │          │
                            │  │            RTLO names · zips containing apps · macro docs                   │          │
                            │  │ quarantine com.apple.quarantine + QuarantineEventsV2 + kMDItemWhereFroms    │          │
                            │  │            → download URL, referrer, app, time, Mail sender                 │          │
                            │  │ macos      codesign --verify · spctl --assess · pkgutil · (ClamAV if any)   │          │
                            │  │ reputation VirusTotal hash/URL lookup · Safe Browsing ── HTTPS ─────────────┼──► VT / Google
                            │  │ urlcheck   look-alike domains · shorteners · @-tricks · text≠href           │          │  (hash / URL only)
                            │  │ scoring    Clean / Caution / Dangerous + every reason                       │          │
                            │  │ behaviour  startup-item diff · processes · lsof · LuLu rules                │          │
                            │  │ report     ~/Sentinel/Reports/<date>-<name>.md + .removal-plan.json         │          │
                            │  │ removal    quarantine → restore → (2nd confirm) delete, all logged          │          │
                            │  │ keychain   secrets only in the login Keychain (service "Sentinel")          │          │
                            │  └───────▲───────────────────────▲──────────────────────────▲───────────────────┘          │
                            │          │ CLI                   │ native messaging         │ launchd every 2 min         │
                            │   `sentinel …` / Sentinel.app    │ (stdio JSON)             │ sentinel mail-poll          │
                            │   (menu bar, SwiftUI)            │                          │                             │
                            │                          Brave + Sentinel Link Guard   Gmail API (gmail.readonly,        │
 internet ─ link click ────►│                          (MV3: check → interstitial)   OAuth+PKCE) · IMAP EXAMINE (Yahoo)│◄── mail (read-only)
                            └───────────────────────────────────────────────────────────────────────────────────────────┘
```

| Component | Where | Language |
|---|---|---|
| Analysis engine + CLI | `engine/sentinel/` | Python 3.9+, stdlib only (runs on the macOS Command Line Tools' `/usr/bin/python3`) |
| Download/persistence watcher agent | `macos/Sources/SentinelAgent/` | Swift (FSEvents, UserNotifications, AppKit) |
| Menu-bar app + settings | `macos/Sources/SentinelMenuBar/` | SwiftUI (`MenuBarExtra`, macOS 13+) |
| Link-click guard | `extension/` | MV3 JavaScript (Brave / Chrome) |
| launchd templates | `launchd/` | plist |
| Tests | `engine/tests/`, `scripts/test-extension.mjs` | unittest, Node + DevTools protocol |

**Why Python for the engine?** The brief allows helpers in Python where simpler. Keeping all the
analysis in one stdlib-only engine means it's testable anywhere and needs nothing from pip. It
also means the agent, the menu bar, the CLI, the mail poller and the browser host all apply the
same rules. The Swift side covers the parts that must be native: FSEvents, notifications with
action buttons, and the menu bar.

**Fallback:** if Swift can't build (no Command Line Tools, or a build error), `setup.sh` installs
the polling watcher (`sentinel watch`) as the launchd agent. It applies the same checks and
sends AppleScript notifications. The menu-bar app is optional too: everything works from the CLI.

---

## Install

Requirements: macOS 13+, the Xcode Command Line Tools (`xcode-select --install`), and Brave for the
link guard.

```sh
cd ~/workspace/mac-security-guard/build
./setup.sh            # interactive; ./setup.sh --yes for defaults, --no-swift for the polling watcher
```

`setup.sh` installs the engine and a `sentinel` command, runs the self-tests, builds and ad-hoc
signs the two apps into `~/Applications/Sentinel/`, and loads the launchd agents. It also
registers the Brave/Chrome native-messaging host. It offers, optionally, to:

- store API keys in the Keychain (typed hidden),
- connect Gmail and/or Yahoo,
- drop the harmless **EICAR** test file in Downloads so you can see a full alert.

It never needs `sudo` and never changes SIP, Gatekeeper or XProtect.

### API keys (optional; Sentinel works offline without them)

| Key | Get it | Store it |
|---|---|---|
| VirusTotal | virustotal.com → profile → **API Key** (free: 4 lookups/min, 500/day) | `sentinel keys set virustotal` or Settings |
| Google Safe Browsing | console.cloud.google.com → enable **Safe Browsing API** → Credentials → API key | `sentinel keys set safebrowsing` or Settings |

Keys are written with `security -i` reading from stdin, so they never show up in a process list,
and they're never written to a file or log. `sentinel keys status` shows *whether* each key is
set, never the key itself.

### Email

- **Gmail (primary):** `sentinel mail-setup gmail`. You'll need a free Google Cloud OAuth client
  of type *Desktop app*; the command walks you through it. The scope is `gmail.readonly`, so
  Sentinel can't change, move, label or delete mail. Publish the OAuth app ("In production"):
  apps left in *Testing* get refresh tokens that expire after 7 days.
- **Yahoo:** `sentinel mail-setup imap --name yahoo` with a Yahoo app password. Sentinel opens
  the mailbox read-only (`EXAMINE`, `BODY.PEEK`), so it never marks anything as read.
- **Apple Mail fallback:** attachments you save or open from Mail land in Mail's *Mail Downloads*
  folder, which the agent watches. That needs Full Disk Access for *Sentinel Agent*.

### Brave extension

`brave://extensions` → **Developer mode** → **Load unpacked** →
`~/Library/Application Support/Sentinel/extension`. The ID is pinned to
`hkjkodcckmeegnfhjjmcajmnadcgnmbm` so the native host trusts it. The popup should say *Local
engine connected*.

---

## Everyday use

When something is flagged you get a notification. Each alert offers four actions:

- **Open report** for the full story.
- **Remove…** asks you to confirm, then quarantines the item.
- **Allow once** silences this exact file.
- **Always allow this source** allows the sender, website or signing developer.

```sh
sentinel events                    # recent alerts
sentinel report <id> --open        # open the report
sentinel snapshot <id>             # re-check what it is doing (startup items, processes, connections)
sentinel remove <id>               # shows the plan; type REMOVE to approve → ~/.Sentinel/Quarantine/<id>/
sentinel restore <id>              # undo
sentinel delete <id>               # permanent; only after quarantine; asks twice
sentinel allow <id> | allow-once <id> | allowlist
sentinel scan <file>               # check any file now
sentinel check-url <url> --deep    # check a link (Safe Browsing + VirusTotal)
sentinel mail-check message.eml    # analyse a saved email
sentinel persistence list          # every startup item Sentinel knows about
sentinel status                    # health check (Gatekeeper, SIP, keys set?, agents loaded?)
```

### What a report contains

`~/Sentinel/Reports/<date>-<name>-<id>.md` starts with a plain-English summary: what happened,
why it matters, what to do. Then:

- **The file:** full path, real type vs the extension it claims, `file` output, SHA-256, code
  signature and Gatekeeper status, VirusTotal verdict and link.
- **Where it came from:** the download URL, referring page, the app that downloaded it,
  download time, or the email sender and subject.
- **Risk score:** every reason, with its points and whether it's *observed* or *inferred*.
- **Behaviour snapshot:** startup-item changes, processes and network connections, split into
  observed, inferred, and what Sentinel can't see.
- **Removal plan:** exact paths and exact shell commands, quarantine first.

Next to it, `<…>.removal-plan.json` (schema `sentinel.removal-plan/1`) is the machine-readable
version for an assistant or antivirus. It has `status: awaiting_user_approval`, an explicit
instruction not to act without your approval, per-item SHA-256s, `launchctl bootout` pre-steps,
and the restore command.

### How scoring works

Each finding adds points. A single *danger* finding is ≥100 points and makes the item
**Dangerous** on its own. Examples: EICAR, a VirusTotal hit from 3+ engines, a program disguised
as a PDF, a `paypal.com.evil.xyz` link, a startup item running from `/tmp`. **Caution** starts at
20 points: unsigned apps, installers, scripts, macro documents, shorteners, and so on. Good
signals subtract points: Apple notarization, or a file VirusTotal knows and nobody flags.

Allowlisting a *source* never hides hard evidence: VirusTotal/ClamAV/Safe Browsing hits, known-bad
hashes, EICAR. Only allowlisting that exact file's SHA-256 does.

### Files and folders

```
~/Sentinel/Reports/            reports + removal plans (yours to read/share)
~/.Sentinel/config.json        settings (no secrets)          ~/.Sentinel/allowlist.json
~/.Sentinel/events/            full JSON per event             ~/.Sentinel/events.jsonl  (feed)
~/.Sentinel/Quarantine/<id>/   items/ + manifest.json          ~/.Sentinel/logs/actions.log
~/Library/Application Support/Sentinel/   engine, extension, bin/sentinel, bin/sentinel-nm-host
~/Applications/Sentinel/       Sentinel Agent.app, Sentinel.app
~/Library/LaunchAgents/com.sentinel.{agent,menubar,mail}.plist
```

### Objective-See tools (recommended, free)

Sentinel detects them if they're installed and refers to them in reports. It doesn't clone them.
**LuLu** (outbound firewall) means Sentinel can report that a flagged program tried to connect.
**BlockBlock** gives real-time persistence alerts. **KnockKnock** does a deep persistence scan.
Without them, Sentinel's own lighter versions run: the startup-item diff, and `lsof` snapshots.

---

## Tests

```sh
./scripts/run-tests.sh                 # engine tests + JS syntax (+ extension runtime if CHROME is set, + swift build on macOS)
cd engine && python3 -m unittest -v    # just the engine
CHROME="/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" node scripts/test-extension.mjs
```

The tests the brief asked for, all in `engine/tests/`:

- `test_eicar.py`: EICAR detection, from the standard test string written at runtime. No real
  malware is involved.
- `test_mismatch.py`: extension-vs-type mismatch. Covers a Mach-O named `.pdf`, a PE named
  `.jpg`, a script named `.docx`, a DMG named `.pdf`, double extensions, RTLO names, and zips
  hiding apps.
- `test_unsigned.py`: unsigned binaries. On a Mac it also runs real `codesign` against a
  signature-stripped copy of `/usr/bin/true`.
- `test_quarantine.py`: quarantine-origin parsing: the xattr string, the binary WhereFroms
  plist, and a QuarantineEventsV2 SQLite fixture, flowing through into the analysis.

Further tests cover removal and restore, email phishing and attachments, URL heuristics,
reputation (no key → no request; hash-only; upload gated; keys never written to disk), the
watcher debounce, the native-messaging host, persistence alerts, Python 3.9 syntax, and a scan
for committed secrets.

## Uninstall

```sh
./uninstall.sh          # removes agents, apps, engine, host registration; keeps reports + quarantine
./uninstall.sh --purge  # also deletes ~/.Sentinel and ~/Sentinel/Reports (asks twice)
```
