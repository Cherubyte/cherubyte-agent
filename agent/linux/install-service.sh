#!/usr/bin/env bash
# Installs the Cherubyte agent as a systemd service, from a single binary.
#
#   sudo ./install-service.sh --panel http://192.168.1.9:1001 --token <token> [--name sala]
#
# No Python, no virtualenv, no Docker. Needs root: the ARP sweep uses raw
# sockets and the unit is installed system-wide.
set -euo pipefail

UNIT=cherubyte-agent.service
BIN=/usr/local/bin/cherubyte-agent
CONF_DIR=/etc/cherubyte-agent
STATE_DIR=/var/lib/cherubyte-agent
HERE="$(cd "$(dirname "$0")" && pwd)"

PANEL=""; TOKEN=""; NAME="$(hostname -s 2>/dev/null || hostname)"; SRC="$HERE/cherubyte-agent"
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
command -v systemctl >/dev/null || { echo "systemd not found — see the Docker instructions instead." >&2; exit 1; }
[ -n "$PANEL" ] || { echo "--panel is required (the URL of your Cherubyte panel)." >&2; exit 2; }
[ -n "$TOKEN" ] || { echo "--token is required (mint one in the panel, Config > Agents)." >&2; exit 2; }
[ -f "$SRC" ] || { echo "cherubyte-agent binary not found at $SRC — pass --binary." >&2; exit 1; }

for tool in ping ip; do
  command -v "$tool" >/dev/null || echo "WARNING: '$tool' not found; install iputils-ping and iproute2." >&2
done

echo ">> Installing $SRC -> $BIN"
install -m 0755 "$SRC" "$BIN"

install -d -m 0755 "$CONF_DIR" "$STATE_DIR"
cat > "$CONF_DIR/agent.env" <<CONF
CHERUBYTE_AGENT_PANEL_URL=$PANEL
CHERUBYTE_AGENT_ENROL_TOKEN=$TOKEN
CHERUBYTE_AGENT_NAME=$NAME
CONF
# It carries the enrolment token, and the key file beside it is a bearer
# credential for this network's inventory.
chmod 600 "$CONF_DIR/agent.env"

install -m 0644 "$HERE/$UNIT" "/etc/systemd/system/$UNIT"
systemctl daemon-reload
systemctl enable --now "$UNIT"

echo
echo "Cherubyte agent installed as '$NAME'."
echo "  Panel:  $PANEL"
echo "  Config: $CONF_DIR/agent.env"
echo "  Logs:   journalctl -u $UNIT -f"
echo "  Health: http://127.0.0.1:1002/health"
echo
echo "It should appear on the panel's Agents page within a minute."
