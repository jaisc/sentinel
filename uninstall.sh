#!/bin/bash
# Sentinel uninstall. Removes the agents, apps, engine and browser host registration.
# Your reports, settings and QUARANTINE are kept unless you pass --purge (asks first).
#
#   ./uninstall.sh            remove the program, keep ~/Sentinel/Reports and ~/.Sentinel
#   ./uninstall.sh --purge    also delete reports, settings, logs and quarantine (asks twice)
set -uo pipefail

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
UID_NUM="$(id -u)"
APPSUPPORT="$HOME/Library/Application Support/Sentinel"

echo "==> Stopping launchd agents"
for label in com.sentinel.agent com.sentinel.menubar com.sentinel.mail; do
  launchctl bootout "gui/$UID_NUM/$label" 2>/dev/null && echo "stopped $label"
  rm -f "$HOME/Library/LaunchAgents/$label.plist"
done

echo "==> Removing apps, engine and browser host registration"
rm -rf "$HOME/Applications/Sentinel" "$APPSUPPORT"
[ -L "$HOME/.local/bin/sentinel" ] && rm -f "$HOME/.local/bin/sentinel"
rm -f "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/com.sentinel.host.json" \
      "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.sentinel.host.json"
echo "Remove the 'Sentinel Link Guard' extension yourself at brave://extensions."

read -r -p "Delete Sentinel's API keys / Gmail token from the Keychain? [y/N] " a
if [[ "$a" =~ ^[Yy] ]]; then
  for acct in virustotal-api-key safebrowsing-api-key gmail-oauth-client-id gmail-oauth-client-secret gmail-refresh-token; do
    security delete-generic-password -s Sentinel -a "$acct" >/dev/null 2>&1 && echo "deleted $acct"
  done
  # IMAP app passwords (imap-<name>-password)
  while acct=$(security find-generic-password -s Sentinel 2>/dev/null | sed -n 's/.*"acct"<blob>="\(imap-[^"]*\)".*/\1/p' | head -1) && [ -n "$acct" ]; do
    security delete-generic-password -s Sentinel -a "$acct" >/dev/null 2>&1 && echo "deleted $acct" || break
  done
  echo "If you connected Gmail, also revoke access at https://myaccount.google.com/permissions"
fi

QUARANTINED=$(ls "$HOME/.Sentinel/Quarantine" 2>/dev/null | wc -l | tr -d ' ')
if [ "$PURGE" = 1 ]; then
  echo "This deletes ~/Sentinel/Reports and ~/.Sentinel (settings, logs, and $QUARANTINED quarantine folder(s))."
  [ "$QUARANTINED" != 0 ] && echo "Quarantined items will be PERMANENTLY deleted. Restore anything you want first: sentinel restore <id>"
  read -r -p "Type PURGE to continue: " a
  if [ "$a" = "PURGE" ]; then
    read -r -p "Second confirmation — type DELETE: " b
    if [ "$b" = "DELETE" ]; then
      rm -rf "$HOME/.Sentinel" "$HOME/Sentinel/Reports"
      rmdir "$HOME/Sentinel" 2>/dev/null
      echo "Purged."
    fi
  fi
else
  echo "Kept: ~/Sentinel/Reports and ~/.Sentinel ($QUARANTINED quarantine folder(s)). Use --purge to remove them."
fi
echo "Sentinel uninstalled."
