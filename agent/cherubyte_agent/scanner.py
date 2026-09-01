"""Network discovery: raw ARP sweep (scapy) + layered active identity probes.

Requires CAP_NET_RAW / root to send ARP frames. See README for setup.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .config import settings
from . import arp_sniffer, dhcp_sniffer, discovery, snmp

logger = logging.getLogger("cherubyte.scanner")

# Ports probed to help classify a device and to offer quick actions in the UI.
# Kept focused to stay fast — all probed in one parallel round.
PROBE_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    53: "dns",
    80: "http",
    139: "netbios",
    443: "https",
    445: "smb",
    515: "printer",
    554: "rtsp",
    631: "ipp",
    1880: "http",       # Node-RED
    1883: "mqtt",
    2049: "nfs",
    2375: "http",       # Docker API
    3000: "http",       # Grafana / dev servers
    3001: "http",
    3306: "mysql",
    3389: "rdp",
    5000: "upnp",
    5001: "http-alt",
    5353: "mdns",
    5432: "postgresql",
    5601: "http",       # Kibana
    5900: "vnc",
    5901: "vnc",
    5985: "winrm",
    6379: "redis",
    7000: "airplay",
    8000: "http-alt",
    8009: "chromecast",
    8080: "http-alt",
    8081: "http-alt",
    8123: "http",       # Home Assistant
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9090: "http",       # Prometheus / Cockpit
    9100: "jetdirect",
    9200: "elasticsearch",
    9443: "https-alt",
    11211: "memcached",
    19999: "http",      # Netdata
    27017: "mongodb",
    32400: "plex",
    62078: "apple-sync",
}


@dataclass
class Host:
    mac: str
    ip: str
    hostname: str | None = None            # reverse DNS
    open_ports: dict[int, str] = field(default_factory=dict)
    # enrichment signals
    mdns_name: str | None = None
    mdns_model: str | None = None
    mdns_services: list[str] = field(default_factory=list)
    ssdp_name: str | None = None
    ssdp_vendor: str | None = None
    ssdp_model: str | None = None
    netbios_name: str | None = None
    llmnr_name: str | None = None
    http_server: str | None = None
    http_title: str | None = None
    ttl_os: str | None = None
    dhcp_param_list: str = ""
    dhcp_vendor_class: str | None = None
    dhcp_hostname: str | None = None
    snmp_sysname: str | None = None
    snmp_sysdescr: str | None = None
    lldp_neighbors: list = field(default_factory=list)
    os_guess: str | None = None
    # True when this sweep fully probed the host; False on a discovery-only
    # cycle, where the absence of a signal means nothing was asked.
    identified: bool = False
    subnet: str | None = None            # CIDR of the sweep that found this host


# ------------------------------------------------------- identification cadence

# A host's identity (name, model, open ports, OS) barely changes, but probing it
# is by far the most expensive part of a cycle. Discovery — who is on the
# network — runs every cycle; identification is spread out.
_identified_at: dict[str, float] = {}   # mac -> monotonic clock
_known_ips: set[str] = set()            # IPs seen in a previous cycle
_last_full_sweep: float | None = None
_offlink_warned: set[str] = set()       # CIDRs we've already logged the routed-subnet warning for


def reset_scan_caches() -> None:
    """Forget the cadence state (used by tests and after a config change)."""
    _identified_at.clear()
    _known_ips.clear()
    _offlink_warned.clear()
    global _last_full_sweep
    _last_full_sweep = None


def _select_for_identification(hosts: list[Host], now: float) -> list[Host]:
    """The hosts to fully probe this cycle.

    Never-seen hosts always win — a new device must be identified at once.
    The rest come oldest-first and are capped, which both bounds the work per
    cycle and staggers hosts that were all discovered together.
    """
    interval = settings.identify_interval_seconds
    if interval <= 0:  # 0 disables the cadence: probe everything, every cycle
        return list(hosts)

    fresh: list[Host] = []
    stale: list[Host] = []
    for h in hosts:
        last = _identified_at.get(h.mac)
        if last is None:
            fresh.append(h)
        elif (now - last) >= interval:
            stale.append(h)
    stale.sort(key=lambda h: _identified_at.get(h.mac, 0.0))

    batch = settings.identify_batch
    if batch <= 0:
        return fresh + stale
    return (fresh + stale)[: max(batch, len(fresh))]


def _due_for_full_sweep(now: float) -> bool:
    """Whether to ping the whole range, rather than only the known addresses."""
    if _last_full_sweep is None:
        return True
    return (now - _last_full_sweep) >= max(
        settings.full_sweep_interval_seconds, settings.scan_interval_seconds
    )


# ---------------------------------------------------------------- subnet / ARP

def _route_for(cidr: str) -> tuple[str | None, bool]:
    """Ask the OS routing table how a destination in `cidr` is actually
    reached: which interface, and whether it's on that interface's own
    network (on-link) or beyond a gateway.

    This matters because ARP is link-local — it can only ever find a host
    that's on-link. A routed destination answers pings (routing works fine)
    but never an ARP broadcast, which is why a subnet reachable "by IP" can
    still show zero devices: the fix there isn't a setting, it's another
    agent that actually lives on that network — Cherubyte is a panel and one
    or more agents by design (see the README's Architecture section).
    """
    from scapy.all import conf

    try:
        net = ipaddress.ip_network(cidr, strict=False)
        probe = str(next(net.hosts(), net.network_address))
        iface, _, gw = conf.route.route(probe)
    except Exception:  # noqa: BLE001
        return None, True  # unknown -> assume on-link, i.e. today's behaviour
    return (str(iface) if iface else None), gw in ("0.0.0.0", "", None)


def _gateway_for(ip: str) -> str | None:
    """The gateway the OS would route through to reach `ip` — almost always
    also the LAN's DNS server, and so a fallback reverse-DNS target when the
    OS resolver itself comes up empty (see discovery.gateway_reverse_dns)."""
    from scapy.all import conf

    try:
        _, _, gw = conf.route.route(ip)
    except Exception:  # noqa: BLE001
        return None
    return gw if gw not in ("0.0.0.0", "", None) else None


def _scan_targets() -> list[tuple[str, str | None]]:
    """Every (CIDR, iface) pair to sweep. Multiple configured subnets win;
    then a single `subnet`; then auto-detection.

    An operator-pinned `interface` always wins outright. Otherwise each
    subnet resolves its *own* interface from the routing table — a box with
    more than one NIC (or a VLAN sub-interface) needs the ARP sweep for each
    configured subnet to go out the interface that's actually on that
    subnet, not whichever one scapy would pick by default.
    """
    pinned = settings.interface or None
    if settings.subnets:
        out: list[tuple[str, str | None]] = []
        for s in settings.subnets:
            cidr = (s.get("cidr") or "").strip()
            if not cidr:
                continue
            try:
                cidr = str(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning("ignoring invalid configured subnet %r", cidr)
                continue
            out.append((cidr, pinned or _route_for(cidr)[0]))
        if out:
            return out
    if settings.subnet:
        return [(settings.subnet, pinned or _route_for(settings.subnet)[0])]
    return [_detect_subnet()]


def _detect_subnet() -> tuple[str, str | None]:
    if settings.subnet:
        return settings.subnet, settings.interface or None

    from scapy.all import conf, get_if_addr, get_if_list

    iface = settings.interface or conf.iface
    try:
        ip = get_if_addr(str(iface))
    except Exception:  # noqa: BLE001
        ip = None

    if not ip or ip == "0.0.0.0":
        for cand in get_if_list():
            if cand == "lo":
                continue
            addr = get_if_addr(cand)
            if addr and addr != "0.0.0.0":
                iface, ip = cand, addr
                break

    if not ip or ip == "0.0.0.0":
        raise RuntimeError("Could not determine local IP; set CHERUBYTE_SUBNET.")

    net = ipaddress.ip_network(f"{ip}/24", strict=False)
    return str(net), str(iface)


def _merge_passive_hosts(
    hosts: dict[str, Host], targets: list[tuple[str, str | None]]
) -> None:
    """Fold in anything arp_sniffer overheard that this cycle's active sweep
    didn't already find — same identity, just observed rather than solicited.

    arp_sniffer never forgets a MAC it has ever seen, so a sighting has to be
    recent enough that the host could plausibly still be there — otherwise a
    device seen once, long ago, would read as online forever."""
    if not settings.enable_passive_arp:
        return
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=settings.passive_arp_ttl_seconds
    )
    for mac, seen in arp_sniffer.all_hosts().items():
        if mac in hosts or seen.last_seen < cutoff:
            continue
        cidr = next((c for c, _ in targets if _in_subnet(seen.ip, c)), None)
        if cidr is None:
            continue
        hosts[mac] = Host(mac=mac, ip=seen.ip, subnet=cidr)


def _arp_scan(full_sweep: bool = True) -> list[Host]:
    from scapy.all import ARP, Ether, srp

    targets = _scan_targets()
    hosts: dict[str, Host] = {}

    def _tag(mac: str, ip: str, cidr: str) -> None:
        h = hosts.get(mac)
        if h is None:
            hosts[mac] = Host(mac=mac, ip=ip, subnet=cidr)
        else:
            if not h.ip:
                h.ip = ip
            if h.subnet is None:
                h.subnet = cidr

    for cidr, iface in targets:
        _, on_link = _route_for(cidr)
        logger.info("discovery sweep %s (iface=%s)", cidr, iface)

        if on_link:
            # 1) active ARP sweep — a broadcast, so only useful on-link (ARP
            #    doesn't cross a router; see _route_for).
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
            try:
                answered, _ = srp(
                    pkt, timeout=settings.arp_timeout, verbose=False, iface=iface, retry=2
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("ARP sweep failed for %s: %s", cidr, exc)
                answered = []
            for _, rcv in answered:
                _tag(rcv.hwsrc.lower(), rcv.psrc, cidr)
        elif cidr not in _offlink_warned:
            _offlink_warned.add(cidr)
            logger.warning(
                "%s is reached through a gateway, not on-link on this agent's "
                "interface(s) — skipping the ARP broadcast there (ARP cannot "
                "cross a router, even though ping/IP reachability works fine). "
                "Reliable discovery there needs a Cherubyte agent running on "
                "that network — run one agent per subnet rather than adding a "
                "routed subnet to this agent's list.",
                cidr,
            )

        # 2) ICMP ping sweep — wakes / reaches hosts that ignore our raw ARP,
        #    and populates the kernel neighbour table for step 3
        try:
            pinged = _ping_sweep(cidr, known_only=not full_sweep)
        except Exception as exc:  # noqa: BLE001
            logger.debug("ping sweep failed: %s", exc)
            pinged = []

        if not on_link and pinged:
            # No ARP means no MAC will ever surface for these — the OS
            # neighbour table stays empty for a routed destination — so this
            # ping result is the only liveness signal this subnet can offer.
            # Reported, not turned into a Host: Cherubyte's device identity is
            # MAC-keyed throughout, and there's no MAC here to key it with.
            logger.info(
                "%s: %d host(s) answered ping with no discoverable MAC (%s)",
                cidr,
                len(pinged),
                ", ".join(sorted(pinged)[:10]) + ("…" if len(pinged) > 10 else ""),
            )

    # 3) merge the kernel ARP / neighbour table (anything the OS has seen)
    for ip, mac in _neighbour_table().items():
        cidr = next((c for c, _ in targets if _in_subnet(ip, c)), None)
        if cidr is None:
            continue
        _tag(mac, ip, cidr)

    # 4) merge whatever the passive ARP sniffer has overheard — a host that
    #    answered someone else's "who has" rather than ours this cycle
    _merge_passive_hosts(hosts, targets)

    # ARP never sees the host we're running on — add it explicitly.
    me = _local_host(targets[0][1] if targets else None)
    if me and me.mac not in hosts:
        me.subnet = next((c for c, _ in targets if _in_subnet(me.ip, c)), None)
        hosts[me.mac] = me
    return list(hosts.values())


def _ping_targets(cidr: str, known_only: bool) -> list[str]:
    """Addresses to ping in this subnet.

    Pinging a whole /24 means one `ping` process per address, every cycle, per
    subnet. Most of that range is empty, and its only purpose is to catch hosts
    that ignore ARP — a rare, slow-changing set. So the full range is swept
    occasionally, while the addresses already known keep being pinged every
    cycle (otherwise an ARP-ignoring host would flap offline between sweeps).
    """
    net = ipaddress.ip_network(cidr, strict=False)
    if known_only:
        known = [ip for ip in _known_ips if _in_subnet(ip, cidr)]
        if known:
            return known
        # nothing known here yet — fall through to a full sweep
    targets = [str(h) for h in net.hosts()]
    if len(targets) > 512:  # keep it sane on big subnets
        targets = targets[:512]
    return targets


def _ping_sweep(cidr: str, known_only: bool = False) -> list[str]:
    """OS-level ICMP sweep — fast, parallel, and it refreshes the kernel
    neighbour table (which _neighbour_table then reads). Avoids scapy's slow
    per-destination ARP resolution.

    Returns the addresses that answered, so a caller who can't get a MAC any
    other way (a routed subnet — see _route_for) still has a cheap liveness
    signal to report."""
    import subprocess

    targets = _ping_targets(cidr, known_only)

    def ping(ip: str) -> str | None:
        try:
            res = subprocess.run(
                ["ping", "-c", "1", "-W", "1", "-n", "-q", ip],
                capture_output=True,
                timeout=2,
            )
            return ip if res.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            return None

    with ThreadPoolExecutor(max_workers=64) as ex:
        return [ip for ip in ex.map(ping, targets) if ip]


def _neighbour_table() -> dict[str, str]:
    """{ip: mac} from `ip neigh` (REACHABLE/STALE/DELAY/PROBE), lowercased."""
    import subprocess

    out: dict[str, str] = {}
    try:
        res = subprocess.run(
            ["ip", "-4", "neigh", "show"],
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return out
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[1] == "dev" and "lladdr" in parts:
            ip = parts[0]
            mac = parts[parts.index("lladdr") + 1].lower()
            state = parts[-1]
            if mac != "00:00:00:00:00:00" and state not in ("FAILED", "INCOMPLETE"):
                out[ip] = mac
    return out


def _in_subnet(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _local_host(iface: str | None) -> Host | None:
    try:
        import socket as _s

        from scapy.all import get_if_addr, get_if_hwaddr

        ifn = str(iface) if iface else None
        ip = get_if_addr(ifn) if ifn else None
        mac = get_if_hwaddr(ifn) if ifn else None
        if not ip or ip == "0.0.0.0" or not mac:
            return None
        h = Host(mac=mac.lower(), ip=ip)
        try:
            h.hostname = _s.gethostname()
        except OSError:
            pass
        return h
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------- per-host probes

def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


async def _probe_ports_many(
    ips: list[str], timeout: float = 0.5
) -> dict[str, dict[int, str]]:
    """Probe every (ip, port) pair on one event loop.

    A TCP connect is pure IO wait, so this needs no threads at all. The old
    shape — a pool of hosts, each opening its own pool of ports — could reach
    ~600 threads on a full subnet; here concurrency is one bounded number.
    """
    out: dict[str, dict[int, str]] = {ip: {} for ip in ips}
    if not ips:
        return out
    sem = asyncio.Semaphore(max(1, settings.port_probe_concurrency))

    async def probe(ip: str, port: int, name: str) -> None:
        async with sem:
            writer = None
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout
                )
                out[ip][port] = name
            except (OSError, asyncio.TimeoutError):
                return
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except OSError:
                        pass

    await asyncio.gather(
        *(probe(ip, port, name) for ip in ips for port, name in PROBE_PORTS.items())
    )
    return out


def _probe_host(host: Host) -> Host:
    """The blocking half of identification: everything that is not a TCP connect.

    Ports are probed beforehand by `_probe_ports_many`, so `host.open_ports` is
    already populated when this runs.
    """
    if settings.enable_reverse_dns:
        host.hostname = _reverse_dns(host.ip)
        if not host.hostname:
            # The OS resolver came back with nothing — on many self-hosted
            # Linux boxes that's systemd-resolved silently refusing to
            # forward a private-range PTR query rather than the network
            # actually lacking one. Ask the gateway directly instead.
            gw = _gateway_for(host.ip)
            if gw:
                host.hostname = discovery.gateway_reverse_dns(host.ip, gw)

    if 139 in host.open_ports or 445 in host.open_ports:
        host.netbios_name = discovery.netbios_name(host.ip)
    else:
        host.netbios_name = discovery.netbios_name(host.ip, timeout=0.5)

    host.llmnr_name = discovery.llmnr_name(host.ip)

    if host.open_ports.keys() & {80, 8080, 443}:
        banner = discovery.http_banner(host.ip)
        if banner:
            host.http_server = banner.http_server
            if banner.names:
                host.http_title = banner.names[0]

    host.ttl_os = discovery.ttl_os_hint(host.ip)

    if settings.enable_snmp:
        community = settings.snmp_community or "public"
        host.snmp_sysname, host.snmp_sysdescr = snmp.sys_info(host.ip, community)
        if host.snmp_sysdescr or host.snmp_sysname:
            host.lldp_neighbors = snmp.lldp_neighbors(host.ip, community)

    fp = dhcp_sniffer.get(host.mac)
    if fp:
        host.dhcp_param_list = fp.param_list
        host.dhcp_vendor_class = fp.vendor_class
        host.dhcp_hostname = fp.requested_hostname
    return host


# --------------------------------------------------------------------- full scan

def _merge_network_discovery(
    hosts: list[Host], mdns: dict, ssdp: dict
) -> None:
    by_ip = {h.ip: h for h in hosts}
    for ip, idn in (mdns or {}).items():
        h = by_ip.get(ip)
        if not h:
            continue
        if idn.names:
            h.mdns_name = idn.names[0]
        h.mdns_model = idn.model
        h.mdns_services = sorted(idn.services)
        if idn.vendor:
            h.ssdp_vendor = h.ssdp_vendor or idn.vendor

    for ip, idn in (ssdp or {}).items():
        h = by_ip.get(ip)
        if not h:
            continue
        if idn.names:
            h.ssdp_name = idn.names[0]
        h.ssdp_vendor = h.ssdp_vendor or idn.vendor
        h.ssdp_model = idn.model


def _probe_hosts_blocking(hosts: list[Host]) -> None:
    """The remaining blocking probes, in a pool bounded by the batch size."""
    if not hosts:
        return
    with ThreadPoolExecutor(max_workers=min(len(hosts), 24)) as ex:
        list(ex.map(_probe_host, hosts))


async def scan_network() -> list[Host]:
    """One discovery pass, plus identification for the hosts that are due.

    Discovery is cheap and runs every cycle. Identification (ports, reverse DNS,
    NetBIOS, HTTP, TTL, mDNS, SSDP) is the expensive half and runs only for
    hosts that are new or whose identity has gone stale.
    """
    global _last_full_sweep
    now = time.monotonic()
    full_sweep = _due_for_full_sweep(now)

    hosts = await asyncio.to_thread(_arp_scan, full_sweep)
    if full_sweep:
        _last_full_sweep = now
    if not hosts:
        return hosts

    _known_ips.clear()
    _known_ips.update(h.ip for h in hosts if h.ip)
    # a MAC that has left should not keep a slot in the cadence table forever
    live = {h.mac for h in hosts}
    for mac in [m for m in _identified_at if m not in live]:
        del _identified_at[mac]

    targets = _select_for_identification(hosts, now)
    if not targets:
        logger.debug("cheap cycle: %d hosts, none due for identification", len(hosts))
        return hosts

    logger.info(
        "identifying %d of %d hosts%s",
        len(targets),
        len(hosts),
        " (full sweep)" if full_sweep else "",
    )

    # network-wide discovery is wall-clock bound (~4s mDNS, ~3s SSDP), so start
    # it first and let the per-host probes run underneath it
    mdns_task = asyncio.create_task(asyncio.to_thread(discovery.mdns_scan))
    ssdp_task = asyncio.create_task(asyncio.to_thread(discovery.ssdp_scan))

    if settings.enable_port_probe:
        port_map = await _probe_ports_many([h.ip for h in targets])
        for h in targets:
            h.open_ports = port_map.get(h.ip, {})

    # NetBIOS and the HTTP banner read host.open_ports, so they follow the ports
    await asyncio.to_thread(_probe_hosts_blocking, targets)

    mdns, ssdp = await asyncio.gather(mdns_task, ssdp_task, return_exceptions=True)
    _merge_network_discovery(
        targets,
        mdns if isinstance(mdns, dict) else {},
        ssdp if isinstance(ssdp, dict) else {},
    )

    for h in targets:
        _identified_at[h.mac] = now
        h.identified = True
    return hosts


def local_subnet() -> str:
    try:
        return _scan_targets()[0][0]
    except Exception:  # noqa: BLE001
        return settings.subnet or "unknown"


def local_subnets() -> list[str]:
    try:
        return [c for c, _ in _scan_targets()]
    except Exception:  # noqa: BLE001
        return [settings.subnet] if settings.subnet else []
