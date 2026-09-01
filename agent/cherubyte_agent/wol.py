"""Send a Wake-on-LAN magic packet.

The panel queues a MAC and hands it back on a report ack; the agent, which sits
on the target's segment, broadcasts the packet. A magic packet is six 0xFF
bytes followed by the target MAC repeated sixteen times, sent as a UDP broadcast
to port 9 (discard) — and port 7 as well, since some NICs listen there.
"""

from __future__ import annotations

import logging
import re
import socket

logger = logging.getLogger("cherubyte.agent.wol")

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_PORTS = (9, 7)


def _packet(mac: str) -> bytes | None:
    if not _MAC_RE.match(mac.strip()):
        return None
    raw = bytes.fromhex(mac.strip().replace(":", "").replace("-", ""))
    return b"\xff" * 6 + raw * 16


def send(mac: str, *, broadcast: str = "255.255.255.255") -> bool:
    """Broadcast a magic packet for `mac`. Returns True if it went out."""
    pkt = _packet(mac)
    if pkt is None:
        logger.warning("not a MAC address, skipping wake: %r", mac)
        return False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            for port in _PORTS:
                s.sendto(pkt, (broadcast, port))
    except OSError as exc:
        logger.warning("wake for %s failed: %s", mac, exc)
        return False
    logger.info("sent Wake-on-LAN to %s", mac)
    return True


def send_all(macs: list[str]) -> int:
    return sum(send(m) for m in macs)
