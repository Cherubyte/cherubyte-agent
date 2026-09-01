#!/usr/bin/env bash
# Removes the Cherubyte agent daemon. Keeps the enrolment key unless --purge:
# losing it means needing a fresh token, since tokens are single use.
set -euo pipefail
LABEL="pt.qqc.cherubyte-agent"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
DATA="/Library/Application Support/Cherubyte Agent"

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }

launchctl bootout system "$PLIST" 2>/dev/null || true
rm -f "$PLIST" /usr/local/bin/cherubyte-agent
echo "Daemon removed."

if [ "${1:-}" = "--purge" ]; then
  rm -rf "$DATA"
  echo "Configuration and state removed — a new enrolment token will be needed."
else
  echo "State kept at $DATA (pass --purge to remove it)."
fi
