"""Passive ARP listening, alongside the active sweep.

The active sweep only learns about a host that answers *our* probe. A host
that is momentarily busy, rate-limiting replies, or simply answers someone
else's "who has" first is invisible to it that cycle. ARP is broadcast on a
flat LAN, so every request and reply crossing the wire names a real sender —
this just listens for those, for the life of the service, and hands the
result to the scanner to fold in alongside what it found itself.

Same privilege as the active sweep (CAP_NET_RAW); no extra promiscuous mode
needed since ARP is already broadcast.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("cherubyte.arp_sniffer")

_IGNORED_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


@dataclass
class PassiveHost:
    mac: str
    ip: str
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


_hosts: dict[str, PassiveHost] = {}
_sniffer = None
_lock = threading.Lock()


def all_hosts() -> dict[str, PassiveHost]:
    with _lock:
        return dict(_hosts)


def _handle(pkt) -> None:
    try:
        from scapy.all import ARP

        if ARP not in pkt:
            return
        arp = pkt[ARP]
        # op 1 = who-has (request), op 2 = is-at (reply) — both carry a real
        # sender. A duplicate-address probe sends from 0.0.0.0 and names
        # nobody yet.
        mac = (arp.hwsrc or "").lower()
        ip = arp.psrc or ""
        if not mac or mac in _IGNORED_MACS or not ip or ip == "0.0.0.0":
            return
        with _lock:
            _hosts[mac] = PassiveHost(mac=mac, ip=ip)
    except Exception as exc:  # noqa: BLE001
        logger.debug("ARP parse error: %s", exc)


def start() -> None:
    global _sniffer
    if _sniffer is not None:
        return
    try:
        from scapy.all import AsyncSniffer

        _sniffer = AsyncSniffer(filter="arp", store=False, prn=_handle)
        _sniffer.start()
        logger.info("Passive ARP sniffer started")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Passive ARP sniffer could not start: %s", exc)
        _sniffer = None


def stop() -> None:
    global _sniffer
    if _sniffer is not None:
        try:
            _sniffer.stop()
        except Exception:  # noqa: BLE001
            pass
        _sniffer = None
