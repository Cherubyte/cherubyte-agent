"""Passive DHCP sniffing.

Runs a background sniffer for the life of the service. Two things come out of it:

  * per client MAC, a fingerprint from its DISCOVER/REQUEST:
      option 55 -> Parameter Request List (the "DHCP fingerprint")
      option 60 -> Vendor Class Identifier
      option 12 -> hostname the client asked for
  * per server IP, the fact that something answered with an OFFER/ACK — so the
    panel can notice a DHCP server that is not the one it expects (a second
    router handed out on the LAN by mistake, or not by mistake).

Both directions are UDP 67/68 broadcast, so no promiscuous mode is needed.
Needs CAP_NET_RAW (same as the ARP scan).
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("cherubyte.dhcp")


@dataclass
class DhcpFingerprint:
    mac: str
    param_list: str = ""            # e.g. "1,3,6,15,31,33,43,44,46,47,121,249,252"
    vendor_class: str | None = None
    requested_hostname: str | None = None
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DhcpServer:
    ip: str
    mac: str | None = None
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


_MSG_TYPES = {
    "discover": 1, "offer": 2, "request": 3, "decline": 4,
    "ack": 5, "nak": 6, "release": 7, "inform": 8,
}

_prints: dict[str, DhcpFingerprint] = {}
_servers: dict[str, DhcpServer] = {}
_sniffer = None
_lock = threading.Lock()


def get(mac: str) -> DhcpFingerprint | None:
    return _prints.get(mac.lower())


def all_fingerprints() -> dict[str, DhcpFingerprint]:
    return dict(_prints)


def all_servers() -> dict[str, DhcpServer]:
    return dict(_servers)


def _handle(pkt) -> None:
    try:
        from scapy.all import DHCP, Ether

        if DHCP not in pkt:
            return
        mac = pkt[Ether].src.lower() if Ether in pkt else None
        opts = {}
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                opts[opt[0]] = opt[1]

        msg_type = opts.get("message-type")
        if isinstance(msg_type, str):  # scapy sometimes hands back the name
            msg_type = _MSG_TYPES.get(msg_type)

        # OFFER (2) / ACK (5) come *from* a DHCP server. Record which one.
        if msg_type in (2, 5):
            server_ip = opts.get("server_id")
            if isinstance(server_ip, bytes):
                server_ip = server_ip.decode("utf-8", "ignore")
            if not server_ip:
                try:
                    from scapy.all import IP

                    server_ip = pkt[IP].src if IP in pkt else None
                except Exception:  # noqa: BLE001
                    server_ip = None
            if server_ip:
                with _lock:
                    _servers[server_ip] = DhcpServer(ip=server_ip, mac=mac)
                logger.debug("DHCP server %s (%s) answered", server_ip, mac)
            return

        if msg_type not in (1, 3):  # DISCOVER / REQUEST
            return

        prl = opts.get("param_req_list")
        param_list = (
            ",".join(str(x) for x in prl) if isinstance(prl, (list, tuple, bytes)) else ""
        )
        if isinstance(prl, bytes):
            param_list = ",".join(str(b) for b in prl)

        vendor = opts.get("vendor_class_id")
        if isinstance(vendor, bytes):
            vendor = vendor.decode("utf-8", "ignore")
        hostname = opts.get("hostname")
        if isinstance(hostname, bytes):
            hostname = hostname.decode("utf-8", "ignore")

        if not mac:
            return
        with _lock:
            _prints[mac] = DhcpFingerprint(
                mac=mac,
                param_list=param_list,
                vendor_class=vendor or None,
                requested_hostname=hostname or None,
            )
        logger.debug("DHCP fp %s prl=%s vci=%s", mac, param_list, vendor)
    except Exception as exc:  # noqa: BLE001
        logger.debug("DHCP parse error: %s", exc)


def start() -> None:
    global _sniffer
    if _sniffer is not None:
        return
    try:
        from scapy.all import AsyncSniffer

        _sniffer = AsyncSniffer(
            filter="udp and (port 67 or port 68)", store=False, prn=_handle
        )
        _sniffer.start()
        logger.info("DHCP sniffer started")
    except Exception as exc:  # noqa: BLE001
        logger.warning("DHCP sniffer could not start: %s", exc)
        _sniffer = None


def stop() -> None:
    global _sniffer
    if _sniffer is not None:
        try:
            _sniffer.stop()
        except Exception:  # noqa: BLE001
            pass
        _sniffer = None
