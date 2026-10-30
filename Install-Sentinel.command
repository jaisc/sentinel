#!/bin/bash
# Sentinel one-click installer — double-click this file to install and run Sentinel.
# It downloads the project, installs with defaults (no API keys, no mail setup),
# builds the menu-bar apps, and loads the watchers. No sudo, no system changes.
set -u
cd "$(dirname "$0")"
echo "== Sentinel installer =="
if ! xcode-select -p >/dev/null 2>&1; then
  echo "Xcode Command Line Tools are missing. Installing them now — when that finishes, double-click this file again."
  xcode-select --install
  read -p "Press Enter to close..."
  exit 0
fi
echo "Downloading Sentinel..."
curl -L -o /tmp/sentinel-build.zip "https://muse.ai/files/1310435255488605/1429887815965778/yxdjiz5a4a3wfw3ybwze3eju/sentinel-build-v2.zip"
echo "Unpacking into $PWD..."
unzip -o -q /tmp/sentinel-build.zip -d "$PWD"
echo "Installing (defaults — API keys and mail can be added later)..."
bash setup.sh --yes
echo
echo "Done. Final step: load the Brave extension from ~/Library/Application Support/Sentinel/extension in brave://extensions (Developer mode -> Load unpacked)."
read -p "Press Enter to close..."
