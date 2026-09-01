#!/usr/bin/env bash
# Removes the Cherubyte agent service. Keeps the enrolment key unless --purge:
# losing it means needing a fresh token, since tokens are single use.
set -euo pipefail
UNIT=cherubyte-agent.service
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }

systemctl disable --now "$UNIT" 2>/dev/null || true
rm -f "/etc/systemd/system/$UNIT" /usr/local/bin/cherubyte-agent
systemctl daemon-reload
echo "Service removed."

if [ "${1:-}" = "--purge" ]; then
  rm -rf /etc/cherubyte-agent /var/lib/cherubyte-agent
  echo "Configuration and state removed — a new enrolment token will be needed."
else
  echo "State kept at /var/lib/cherubyte-agent (pass --purge to remove it)."
fi
