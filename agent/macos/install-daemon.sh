#!/usr/bin/env bash
# Installs the Cherubyte agent as a launchd daemon.
#
#   sudo ./install-daemon.sh --panel http://192.168.1.9:1001 --token <token> [--name sala]
#
# Self-contained — the plist is written inline, so it also works piped:
#
#   curl -fsSL http://panel:1001/api/agents/installer/macos \
#     | sudo bash -s -- --panel http://panel:1001 --token <token> --binary ./cherubyte-agent
#
# Needs root: the ARP sweep uses raw sockets, and a LaunchDaemon is registered
# machine-wide rather than per login session.
set -euo pipefail

LABEL="pt.qqc.cherubyte-agent"
BIN=/usr/local/bin/cherubyte-agent
DATA="/Library/Application Support/Cherubyte Agent"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
HERE="$(cd "$(dirname "$0")" 2>/dev/null && pwd || pwd)"

PANEL=""; TOKEN=""; NAME="$(scutil --get ComputerName 2>/dev/null || hostname -s)"; SRC="$HERE/cherubyte-agent"
while [ $# -gt 0 ]; do
  case "$1" in
    --panel) PANEL="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --name)  NAME="$2";  shift 2 ;;
    --binary) SRC="$2";  shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }
[ -n "$PANEL" ] || { echo "--panel is required (the URL of your Cherubyte panel)." >&2; exit 2; }
[ -n "$TOKEN" ] || { echo "--token is required (mint one in the panel, Config > Agents)." >&2; exit 2; }
[ -f "$SRC" ] || { echo "cherubyte-agent binary not found at $SRC — pass --binary." >&2; exit 1; }

echo ">> Installing $SRC -> $BIN"
install -m 0755 "$SRC" "$BIN"

mkdir -p "$DATA"
# Configuration in a file rather than the environment: launchd gives a daemon
# no shell environment, and the token should not sit in a plist that any user
# can read.
cat > "$DATA/agent.env" <<CONF
CHERUBYTE_AGENT_PANEL_URL=$PANEL
CHERUBYTE_AGENT_ENROL_TOKEN=$TOKEN
CHERUBYTE_AGENT_NAME=$NAME
CONF
chmod 600 "$DATA/agent.env"
chown root:wheel "$DATA/agent.env"

# The plist, written inline rather than copied from a sibling — so this script
# is the only thing an install needs. Keep in sync with
# agent/macos/pt.qqc.cherubyte-agent.plist (a test checks they match).
cat > "$PLIST" <<'PLISTFILE'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>pt.qqc.cherubyte-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/cherubyte-agent</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>StandardOutPath</key>
  <string>/var/log/cherubyte-agent.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/cherubyte-agent.log</string>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
PLISTFILE
chown root:wheel "$PLIST"

# bootout first so re-running this upgrades cleanly instead of erroring
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl enable "system/$LABEL"

echo
echo "Cherubyte agent installed as '$NAME'."
echo "  Panel:  $PANEL"
echo "  Config: $DATA/agent.env"
echo "  Log:    /var/log/cherubyte-agent.log"
echo "  Health: http://127.0.0.1:1002/health"
echo
echo "It should appear on the panel's Agents page within a minute."
