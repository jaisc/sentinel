#!/bin/bash
# Sentinel setup for macOS (Apple Silicon or Intel), per-user, no sudo required.
#
#   ./setup.sh             interactive install
#   ./setup.sh --yes       non-interactive (no API keys, no mail, defaults everywhere)
#   ./setup.sh --no-swift  skip the native FSEvents agent/menu-bar app; use the polling watcher
#
# What it does (and does not do):
#   * installs the engine to ~/Library/Application Support/Sentinel and a `sentinel` command
#   * builds SentinelAgent.app + Sentinel.app (menu bar) with Swift, ad-hoc signed, into ~/Applications/Sentinel
#   * loads launchd agents: com.sentinel.agent (watcher), com.sentinel.menubar, and (if mail is set up) com.sentinel.mail
#   * registers the Brave/Chrome native-messaging host for the Link Guard extension
#   * offers to store API keys in the Keychain (typed hidden; never written to files)
#   * NEVER touches SIP, Gatekeeper, XProtect or kernel extensions, and never deletes anything.
set -euo pipefail

YES=0; NO_SWIFT=0
for arg in "$@"; do
  case "$arg" in
    --yes|-y) YES=1 ;;
    --no-swift) NO_SWIFT=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg"; exit 2 ;;
  esac
done

SRC="$(cd "$(dirname "$0")" && pwd)"
APPSUPPORT="$HOME/Library/Application Support/Sentinel"
APPS="$HOME/Applications/Sentinel"
LA="$HOME/Library/LaunchAgents"
LOGS="$HOME/.Sentinel/logs"
PY=/usr/bin/python3
UID_NUM="$(id -u)"
EXT_ID="hkjkodcckmeegnfhjjmcajmnadcgnmbm"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { printf '\n\033[1;34m==>\033[0m \033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m!! %s\033[0m\n' "$*"; }
ask() {  # ask "question" -> 0 for yes
  [ "$YES" = 1 ] && return 1
  read -r -p "$1 [y/N] " a; [[ "$a" =~ ^[Yy] ]]
}

[ "$(uname)" = "Darwin" ] || { echo "Sentinel installs on macOS only (this is $(uname))."; exit 1; }

step "Checking prerequisites"
if ! xcode-select -p >/dev/null 2>&1; then
  warn "The Xcode Command Line Tools are required (they provide python3 and swift)."
  echo "Run:  xcode-select --install   then re-run ./setup.sh"
  exit 1
fi
"$PY" -c 'import sys; assert sys.version_info >= (3, 9), sys.version' || { echo "python3 >= 3.9 required"; exit 1; }
echo "python3: $("$PY" --version 2>&1)   arch: $(uname -m)   macOS: $(sw_vers -productVersion)"
echo "Gatekeeper: $(spctl --status 2>&1)   SIP: $(csrutil status 2>&1 | sed 's/System Integrity Protection status: //')"
spctl --status 2>&1 | grep -q enabled || warn "Gatekeeper is OFF. Sentinel won't change it, but you should turn it on: sudo spctl --master-enable"

step "Installing the engine"
mkdir -p "$APPSUPPORT/bin" "$LOGS" "$HOME/.local/bin"
rm -rf "$APPSUPPORT/engine"
mkdir -p "$APPSUPPORT/engine"
cp -R "$SRC/engine/sentinel" "$SRC/engine/bin" "$APPSUPPORT/engine/"
find "$APPSUPPORT/engine" -name '__pycache__' -prune -exec rm -rf {} +
cat > "$APPSUPPORT/bin/sentinel" <<EOF
#!/bin/sh
# Sentinel CLI wrapper (absolute interpreter; -I ignores PYTHON* environment variables).
exec $PY -I "$APPSUPPORT/engine/bin/sentinel" "\$@"
EOF
chmod 755 "$APPSUPPORT/bin/sentinel"
ln -sf "$APPSUPPORT/bin/sentinel" "$HOME/.local/bin/sentinel"
SENTINEL="$APPSUPPORT/bin/sentinel"
"$SENTINEL" config init >/dev/null
chmod 700 "$HOME/.Sentinel"
echo "CLI: $SENTINEL  (linked as ~/.local/bin/sentinel)"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) warn "Add ~/.local/bin to your PATH:  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc" ;; esac

step "Running the engine self-tests"
if (cd "$SRC/engine" && "$PY" -m unittest discover -s tests >"$LOGS/selftest.log" 2>&1); then
  echo "engine tests: $(grep -E '^Ran ' "$LOGS/selftest.log")  OK"
else
  warn "Some engine tests failed — see $LOGS/selftest.log (continuing)."
fi

NATIVE=0
if [ "$NO_SWIFT" = 0 ] && command -v swift >/dev/null 2>&1; then
  step "Building the native agent and menu-bar app (swift build -c release)"
  (cd "$SRC/macos" && swift build -c release 2>&1 | tee "$LOGS/swift-build.log" | tail -n 5) || warn "Swift build had failures (see $LOGS/swift-build.log); installing whatever built."
  BIN="$(cd "$SRC/macos" && swift build -c release --show-bin-path)"
  mkdir -p "$APPS"
  for pair in "SentinelAgent:Sentinel Agent" "SentinelMenuBar:Sentinel"; do
    exe="${pair%%:*}"; name="${pair#*:}"
    if [ -x "$BIN/$exe" ]; then
      app="$APPS/$name.app"
      rm -rf "$app"
      mkdir -p "$app/Contents/MacOS"
      cp "$BIN/$exe" "$app/Contents/MacOS/$exe"
      cp "$SRC/macos/Resources/$exe-Info.plist" "$app/Contents/Info.plist"
      # Ad-hoc signature: required on Apple Silicon to run, and gives notifications a stable identity.
      codesign --force --sign - --timestamp=none "$app" >/dev/null 2>&1 || warn "ad-hoc signing failed for $app"
      echo "Built: $app"
    else
      warn "Skipping $name (build product missing)"
    fi
  done
  if [ -x "$APPS/Sentinel Agent.app/Contents/MacOS/SentinelAgent" ]; then
    NATIVE=1
  else
    warn "Swift build failed (see $LOGS/swift-build.log). Falling back to the polling watcher."
  fi
else
  [ "$NO_SWIFT" = 1 ] || warn "swift not found; using the polling watcher (works the same, slightly slower to react)."
fi

step "Installing launchd agents"
mkdir -p "$LA"
render() {  # render TEMPLATE OUT key=value...
  "$PY" - "$@" <<'PYEOF'
import sys
from xml.sax.saxutils import escape
src, out, pairs = sys.argv[1], sys.argv[2], sys.argv[3:]
text = open(src).read()
for p in pairs:
    k, v = p.split("=", 1)
    if k == "PROGRAM_ARGUMENTS":
        v = "\n".join("\t\t<string>%s</string>" % escape(x) for x in v.split("\x1f"))
    else:
        v = escape(v)
    text = text.replace("@%s@" % k, v)
open(out, "w").write(text)
PYEOF
}
load_agent() {  # load_agent LABEL
  local plist="$LA/$1.plist"
  launchctl bootout "gui/$UID_NUM/$1" 2>/dev/null || true
  plutil -lint "$plist" >/dev/null
  launchctl bootstrap "gui/$UID_NUM" "$plist"
}
if [ "$NATIVE" = 1 ]; then
  ARGS="$APPS/Sentinel Agent.app/Contents/MacOS/SentinelAgent"
else
  ARGS="$SENTINEL"$'\x1f'"watch"
fi
render "$SRC/launchd/com.sentinel.agent.plist" "$LA/com.sentinel.agent.plist" "PROGRAM_ARGUMENTS=$ARGS" "LOG_DIR=$LOGS"
load_agent com.sentinel.agent
echo "com.sentinel.agent loaded ($([ "$NATIVE" = 1 ] && echo 'native FSEvents agent' || echo 'polling watcher'))"
if [ "$NATIVE" = 1 ] && [ -x "$APPS/Sentinel.app/Contents/MacOS/SentinelMenuBar" ]; then
  render "$SRC/launchd/com.sentinel.menubar.plist" "$LA/com.sentinel.menubar.plist" \
    "MENUBAR_EXE=$APPS/Sentinel.app/Contents/MacOS/SentinelMenuBar"
  load_agent com.sentinel.menubar
  echo "com.sentinel.menubar loaded (look for the shield in the menu bar)"
fi

step "Brave / Chrome Link Guard extension"
rm -rf "$APPSUPPORT/extension"
cp -R "$SRC/extension" "$APPSUPPORT/extension"
cat > "$APPSUPPORT/bin/sentinel-nm-host" <<EOF
#!/bin/sh
# Native-messaging host for the Sentinel Link Guard extension (Brave/Chrome start it on demand).
exec $PY -I "$APPSUPPORT/engine/bin/sentinel" "\$@"
EOF
chmod 755 "$APPSUPPORT/bin/sentinel-nm-host"
for dir in "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts" \
           "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"; do
  if [ -d "$(dirname "$dir")" ]; then
    mkdir -p "$dir"
    "$PY" - "$dir/com.sentinel.host.json" "$APPSUPPORT/bin/sentinel-nm-host" "$EXT_ID" <<'PYEOF'
import json, sys
out, path, ext = sys.argv[1:4]
json.dump({"name": "com.sentinel.host", "description": "Sentinel local engine (URL checks; keys stay in the Keychain)",
           "path": path, "type": "stdio", "allowed_origins": ["chrome-extension://%s/" % ext]}, open(out, "w"), indent=2)
PYEOF
    echo "native host registered: $dir"
  fi
done
bold "To load the extension in Brave:"
echo "  1. Open brave://extensions   2. Turn on Developer mode (top right)"
echo "  3. Click 'Load unpacked' and choose:  $APPSUPPORT/extension"
echo "  The extension ID should be $EXT_ID (it's pinned, so the native host trusts it)."

step "API keys (optional — Sentinel works offline without them)"
echo "Keys are typed hidden and stored ONLY in your login Keychain (service \"Sentinel\")."
if ask "Add a VirusTotal API key now? (free: virustotal.com > your profile > API Key)"; then "$SENTINEL" keys set virustotal; fi
if ask "Add a Google Safe Browsing API key now? (console.cloud.google.com > enable Safe Browsing API > Credentials)"; then "$SENTINEL" keys set safebrowsing; fi

step "Email watcher (optional)"
MAIL=0
if ask "Connect Gmail now (read-only)?"; then "$SENTINEL" mail-setup gmail && MAIL=1; fi
if ask "Connect Yahoo Mail now (read-only IMAP, needs a Yahoo app password)?"; then "$SENTINEL" mail-setup imap --name yahoo && MAIL=1; fi
if [ "$MAIL" = 1 ] || "$SENTINEL" config show | grep -q '"gmail_enabled": true'; then
  render "$SRC/launchd/com.sentinel.mail.plist" "$LA/com.sentinel.mail.plist" "SENTINEL_CLI=$SENTINEL" "LOG_DIR=$LOGS"
  load_agent com.sentinel.mail
  echo "com.sentinel.mail loaded (checks every 2 minutes)"
else
  echo "Skipped. Later: sentinel mail-setup gmail  then re-run ./setup.sh"
fi

step "macOS permissions you may be asked for"
cat <<EOF
  * "Sentinel Agent would like to access files in your Downloads/Desktop folder" -> Allow.
  * Notifications for "Sentinel Agent" -> Allow (System Settings > Notifications), style "Alerts" recommended.
  * Apple Mail attachments live in a protected folder: to watch them, add
      $APPS/Sentinel Agent.app
    to System Settings > Privacy & Security > Full Disk Access. (Optional; Gmail API covers Gmail.)
EOF

step "Status"
"$SENTINEL" status || true

if ask "Drop the harmless EICAR antivirus test file into ~/Downloads to see a real alert?"; then
  printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-' 'ANTIVIRUS-TEST-FILE!$H+H*' > "$HOME/Downloads/sentinel-eicar-test.com"
  echo "Created ~/Downloads/sentinel-eicar-test.com — an alert should appear within a few seconds."
  echo "Then try:  sentinel events   and   sentinel remove <event-id>"
fi

bold $'\nSentinel is installed. Reports: ~/Sentinel/Reports   Uninstall: ./uninstall.sh'
