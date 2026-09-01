"""Active identity probes layered on top of the ARP sweep.

Each function returns a dict keyed by IP address. Everything is best-effort,
short-timeout and swallows its own errors so a failing probe never breaks a scan.

Signals collected:
  * mDNS / DNS-SD  -> friendly name, model code, service types  (zeroconf)
  * SSDP / UPnP    -> friendlyName, manufacturer, modelName      (raw UDP + XML)
  * NetBIOS        -> Windows/SMB name                           (raw UDP 137)
  * LLMNR          -> Windows name, NetBIOS's modern replacement (raw UDP 5355)
  * HTTP banner    -> Server header + <title>                    (socket)
"""

from __future__ import annotations

import logging
import re
import socket
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

logger = logging.getLogger("cherubyte.discovery")


@dataclass
class Identity:
    names: list[str] = field(default_factory=list)      # candidate friendly names
    model: str | None = None                            # model code / name
    vendor: str | None = None                           # manufacturer
    services: set[str] = field(default_factory=set)     # mdns service types seen
    http_server: str | None = None
    os_hint: str | None = None

    def add_name(self, n: str | None) -> None:
        n = (n or "").strip().rstrip(".")
        if n and n not in self.names:
            self.names.append(n)


# --------------------------------------------------------------------------- mDNS

_MDNS_TYPES = [
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_sonos._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_http._tcp.local.",
    "_workstation._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_device-info._tcp.local.",
    "_companion-link._tcp.local.",
    "_homekit._tcp.local.",
    "_hap._tcp.local.",
    "_amzn-wplay._tcp.local.",
    "_nvstream._tcp.local.",
    "_miio._udp.local.",
    "_esphomelib._tcp.local.",
    "_matter._tcp.local.",
]


def _discover_mdns_types(zc, timeout: float) -> set[str]:
    """Every service type actually advertised on the network (RFC 6763 §9's
    meta-query), beyond our curated `_MDNS_TYPES` list — the only way to catch
    a device (Hue, Ring, Roku, and the rest of the smart-home zoo) that
    advertises a type nobody thought to hardcode."""
    try:
        from zeroconf import ZeroconfServiceTypes
    except Exception:  # noqa: BLE001
        return set()
    try:
        return set(ZeroconfServiceTypes.find(zc=zc, timeout=timeout))
    except Exception as exc:  # noqa: BLE001
        logger.debug("mDNS service-type enumeration failed: %s", exc)
        return set()


def mdns_scan(duration: float = 4.0) -> dict[str, Identity]:
    try:
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    except Exception:  # noqa: BLE001
        return {}

    out: dict[str, Identity] = {}

    def ident(ip: str) -> Identity:
        return out.setdefault(ip, Identity())

    class Listener(ServiceListener):
        def _handle(self, zc, type_, name):
            try:
                info = zc.get_service_info(type_, name, timeout=1500)
            except Exception:  # noqa: BLE001
                return
            if not info:
                return
            addrs = []
            try:
                addrs = info.parsed_addresses()
            except Exception:  # noqa: BLE001
                pass
            props = {}
            for k, v in (info.properties or {}).items():
                try:
                    props[k.decode(errors="ignore").lower()] = (
                        v.decode(errors="ignore") if isinstance(v, bytes) else v
                    )
                except Exception:  # noqa: BLE001
                    continue
            short = name.split(f".{type_}")[0].split(".")[0]
            for ip in addrs:
                idn = ident(ip)
                idn.services.add(type_.replace("._tcp.local.", "").replace("._udp.local.", ""))
                idn.add_name(props.get("fn"))          # googlecast friendly name
                idn.add_name(props.get("n"))
                idn.add_name(short)
                if info.server:
                    idn.add_name(info.server.split(".")[0])
                model = (
                    props.get("model")
                    or props.get("md")                 # googlecast
                    or props.get("am")                 # airplay model
                    or props.get("ty")                 # printer type
                )
                if model and not idn.model:
                    idn.model = model
                if props.get("manufacturer") and not idn.vendor:
                    idn.vendor = props["manufacturer"]
                if props.get("usb_mfg") and not idn.vendor:
                    idn.vendor = props["usb_mfg"]

        def add_service(self, zc, type_, name):
            self._handle(zc, type_, name)

        def update_service(self, zc, type_, name):
            self._handle(zc, type_, name)

        def remove_service(self, zc, type_, name):
            pass

    zc = None
    try:
        zc = Zeroconf()
        discovered = _discover_mdns_types(zc, timeout=min(2.0, duration))
        types = sorted(set(_MDNS_TYPES) | discovered)

        listener = Listener()
        browsers = [ServiceBrowser(zc, t, listener) for t in types]
        import time

        time.sleep(duration)
        for b in browsers:
            try:
                b.cancel()
            except Exception:  # noqa: BLE001
                pass
    except Exception as exc:  # noqa: BLE001
        logger.debug("mDNS scan failed: %s", exc)
    finally:
        if zc is not None:
            try:
                zc.close()
            except Exception:  # noqa: BLE001
                pass
    return out


# --------------------------------------------------------------------------- SSDP

def ssdp_scan(timeout: float = 3.0) -> dict[str, Identity]:
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()

    locations: dict[str, str] = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(timeout)
    try:
        s.sendto(msg, ("239.255.255.250", 1900))
        import time

        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                break
            except OSError:
                break
            m = re.search(rb"LOCATION:\s*(\S+)", data, re.I)
            if m:
                locations.setdefault(addr[0], m.group(1).decode(errors="ignore").strip())
    finally:
        s.close()

    out: dict[str, Identity] = {}
    for ip, loc in locations.items():
        idn = Identity()
        idn.services.add("ssdp")
        try:
            xml = _http_get(loc, timeout=2.0, max_bytes=20000)
            if xml:
                root = ET.fromstring(re.sub(r"\sxmlns=\"[^\"]+\"", "", xml, count=0))
                for tag in ("friendlyName", "modelName", "modelNumber",
                            "manufacturer", "modelDescription"):
                    el = root.find(f".//{tag}")
                    if el is None or not el.text:
                        continue
                    val = el.text.strip()
                    if tag == "friendlyName":
                        idn.add_name(val)
                    elif tag == "manufacturer":
                        idn.vendor = idn.vendor or val
                    elif tag in ("modelName", "modelNumber") and not idn.model:
                        idn.model = val
        except Exception as exc:  # noqa: BLE001
            logger.debug("SSDP parse failed for %s: %s", ip, exc)
        out[ip] = idn
    return out


# ------------------------------------------------------------------------ NetBIOS

def netbios_name(ip: str, timeout: float = 0.8) -> str | None:
    # NBSTAT node-status request for the wildcard name "*".
    header = struct.pack(">HHHHHH", 0xA248, 0x0000, 1, 0, 0, 0)
    # First-level encoded "*" padded with 0x00 -> 32 bytes "CKAAAA..."
    enc = b"CK" + b"AA" * 15
    question = b"\x20" + enc + b"\x00" + struct.pack(">HH", 0x0021, 0x0001)
    query = header + question

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, (ip, 137))
        data, _ = s.recvfrom(2048)
    except (socket.timeout, OSError):
        return None
    finally:
        s.close()

    try:
        # skip DNS-ish header (12) + answer name (34) + type/class/ttl (8) + rdlen (2)
        pos = 12 + 34 + 8 + 2
        num_names = data[pos]
        pos += 1
        best = None
        for _ in range(num_names):
            raw = data[pos:pos + 15].decode("ascii", "ignore").rstrip(" \x00")
            suffix = data[pos + 15]
            flags = struct.unpack(">H", data[pos + 16:pos + 18])[0]
            pos += 18
            group = bool(flags & 0x8000)
            if raw in ("", "__MSBROWSE__") or "\x01\x02" in raw:
                continue
            if suffix == 0x00 and not group:      # workstation service = the hostname
                return raw
            if suffix == 0x20 and not group and not best:  # file server service
                best = raw
        return best
    except Exception:  # noqa: BLE001
        return None


# -------------------------------------------------------------------------- LLMNR

def _encode_dns_name(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        out += bytes([len(label)]) + label.encode("ascii")
    return bytes(out) + b"\x00"


def _decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """A DNS name starting at `offset`, following compression pointers (RFC
    1035 §4.1.4). Returns (name, offset just past the name *as it appears in
    the stream* — i.e. past the pointer, not into the jump)."""
    labels: list[str] = []
    pos = offset
    end: int | None = None       # where reading resumes in the original stream
    hops = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated DNS name")
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if end is None:
                end = pos + 2
            hops += 1
            if hops > 20:           # guard against a pointer loop
                raise ValueError("DNS name compression loop")
            pos = ((length & 0x3F) << 8) | data[pos + 1]
            continue
        pos += 1
        labels.append(data[pos:pos + length].decode("ascii", "ignore"))
        pos += length
    return ".".join(labels), (end if end is not None else pos)


def _parse_ptr_response(data: bytes) -> str | None:
    """The name from the first PTR answer in a DNS/LLMNR-format response, or
    None. Split out from llmnr_name() so the wire-format parsing is testable
    without a real socket."""
    ancount = struct.unpack(">H", data[6:8])[0]
    if ancount < 1:
        return None
    _, pos = _decode_dns_name(data, 12)
    pos += 4  # QTYPE + QCLASS
    for _ in range(ancount):
        _, pos = _decode_dns_name(data, pos)
        rtype, _, _, rdlength = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        if rtype == 12:  # PTR
            name, _ = _decode_dns_name(data, pos)
            return name.rstrip(".") or None
        pos += rdlength
    return None


def _ptr_query(ip: str, server: str, port: int, timeout: float) -> str | None:
    """A DNS/LLMNR-format PTR query for `ip`'s reverse name, sent to
    `(server, port)`. Shared by llmnr_name() (server=ip, port=5355) and
    gateway_reverse_dns() (server=the gateway, port=53) — same wire format,
    different destination."""
    octets = ip.split(".")
    if len(octets) != 4:
        return None
    qname = ".".join(reversed(octets)) + ".in-addr.arpa"

    header = struct.pack(">HHHHHH", 0x1357, 0x0000, 1, 0, 0, 0)
    question = _encode_dns_name(qname) + struct.pack(">HH", 12, 1)  # PTR, IN
    query = header + question

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, (server, port))
        data, _ = s.recvfrom(2048)
    except (socket.timeout, OSError):
        return None
    finally:
        s.close()

    try:
        return _parse_ptr_response(data)
    except Exception:  # noqa: BLE001
        return None


def llmnr_name(ip: str, timeout: float = 0.8) -> str | None:
    """RFC 4795 reverse lookup — LLMNR is Windows' successor to NetBIOS name
    resolution, still answered by many current hosts (including some where
    NetBIOS-over-TCP/IP has been turned off). Unlike mDNS's reverse lookup
    (restricted by RFC 6762 to self-assigned 169.254/16 addresses only),
    LLMNR answers PTR queries for a host's regular address."""
    return _ptr_query(ip, server=ip, port=5355, timeout=timeout)


def gateway_reverse_dns(ip: str, gateway: str, timeout: float = 0.8) -> str | None:
    """A standard unicast DNS PTR query sent straight to the gateway, bypassing
    whatever local resolver `_reverse_dns()` (socket.gethostbyaddr) goes
    through. Works around a common, well-documented default: systemd-resolved
    answers a PTR query for an RFC1918 address out of its own negative cache
    rather than forwarding it upstream, unless the DHCP lease supplied a
    matching routing domain — so the OS resolver can report nothing even
    though the router itself (almost always also the LAN's DNS server) would
    happily answer the same query directly."""
    return _ptr_query(ip, server=gateway, port=53, timeout=timeout)


# --------------------------------------------------------------------------- HTTP

def _http_get(url: str, timeout: float = 1.5, max_bytes: int = 8000) -> str | None:
    m = re.match(r"https?://([^/:]+)(?::(\d+))?(/.*)?$", url)
    if not m:
        return None
    host, port, path = m.group(1), int(m.group(2) or 80), m.group(3) or "/"
    try:
        with socket.create_connection((host, port), timeout=timeout) as c:
            c.settimeout(timeout)
            c.sendall(
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                f"User-Agent: Cherubyte\r\nConnection: close\r\n\r\n".encode()
            )
            chunks = []
            got = 0
            while got < max_bytes:
                b = c.recv(4096)
                if not b:
                    break
                chunks.append(b)
                got += len(b)
        return b"".join(chunks).decode("utf-8", "ignore")
    except OSError:
        return None


def ttl_os_hint(ip: str) -> str | None:
    """Guess the OS family from the IP TTL of a single ping (same-subnet = 0 hops)."""
    try:
        from scapy.all import ICMP, IP, sr1  # lazy import

        resp = sr1(IP(dst=ip) / ICMP(), timeout=1, verbose=False)
    except Exception:  # noqa: BLE001
        return None
    if resp is None or not resp.haslayer("IP"):
        return None
    ttl = resp["IP"].ttl
    if ttl <= 0:
        return None
    if ttl <= 32:
        return "embedded"
    if ttl <= 64:
        return "unix"      # Linux / macOS / iOS / Android — refined later by vendor
    if ttl <= 128:
        return "Windows"
    return "embedded"


def http_banner(ip: str) -> Identity | None:
    for port in (80, 8080, 443):
        raw = _http_get(f"http://{ip}:{port}/", timeout=1.0)
        if not raw:
            continue
        idn = Identity()
        idn.services.add("http")
        srv = re.search(r"^Server:\s*(.+)$", raw, re.I | re.M)
        if srv:
            idn.http_server = srv.group(1).strip()
        title = re.search(r"<title[^>]*>([^<]{1,80})</title>", raw, re.I)
        if title:
            idn.add_name(title.group(1).strip())
        return idn
    return None
