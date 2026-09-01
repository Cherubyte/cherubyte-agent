"""Turn one sweep into one report.

The conversion is deliberately dumb: every field is something observed, copied
across as-is. No judgement is made here — see the protocol module for why.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from cherubyte_protocol import (
    AgentReport,
    DhcpServerObservation,
    HostObservation,
    WanObservation,
)

from . import dhcp_sniffer, hoststat, wan
from .config import settings
from .scanner import Host, local_subnets, scan_network

logger = logging.getLogger("cherubyte.agent.collector")


def to_observation(host: Host) -> HostObservation:
    return HostObservation(
        mac=host.mac,
        ip=host.ip,
        subnet=host.subnet,
        identified=host.identified,
        hostname=host.hostname,
        open_ports=host.open_ports,
        mdns_name=host.mdns_name,
        mdns_model=host.mdns_model,
        mdns_services=host.mdns_services,
        ssdp_name=host.ssdp_name,
        ssdp_vendor=host.ssdp_vendor,
        ssdp_model=host.ssdp_model,
        netbios_name=host.netbios_name,
        llmnr_name=host.llmnr_name,
        http_server=host.http_server,
        http_title=host.http_title,
        ttl_os=host.ttl_os,
        dhcp_param_list=host.dhcp_param_list,
        dhcp_vendor_class=host.dhcp_vendor_class,
        dhcp_hostname=host.dhcp_hostname,
        snmp_sysname=host.snmp_sysname,
        snmp_sysdescr=host.snmp_sysdescr,
        lldp_neighbors=list(host.lldp_neighbors),
    )


async def collect() -> AgentReport:
    """One sweep plus one internet probe, as a report.

    A sweep that raises is still reported, as an unhealthy one with no hosts:
    silence and "the network is empty" look identical to the panel otherwise,
    and only one of them should stop it expiring devices.
    """
    hosts: list[Host] = []
    healthy = True
    try:
        hosts = await scan_network()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Sweep failed")
        healthy = False
    else:
        # A healthy sweep always finds at least the machine the agent runs on.
        healthy = bool(hosts)
        if not healthy:
            logger.warning("Sweep found no hosts at all — reporting it as degraded")

    wan_samples: list[WanObservation] = []
    if settings.wan_enabled:
        target = settings.wan_target or "1.1.1.1"
        ok, latency = await wan.probe(target)
        # Only chase the egress address when the internet answered at all —
        # otherwise the lookup is three guaranteed timeouts per cycle.
        egress = await wan.public_ip() if ok else None
        wan_samples.append(
            WanObservation(
                target=target, ok=ok, latency_ms=latency,
                at=datetime.now(timezone.utc), public_ip=egress,
            )
        )

    return AgentReport(
        sent_at=datetime.now(timezone.utc),
        subnets=local_subnets(),
        hosts=[to_observation(h) for h in hosts],
        wan=wan_samples,
        dhcp_servers=[
            DhcpServerObservation(ip=s.ip, mac=s.mac, last_seen=s.last_seen)
            for s in dhcp_sniffer.all_servers().values()
        ],
        dhcp_fingerprints=len(dhcp_sniffer.all_fingerprints()),
        healthy=healthy,
        health_port=settings.health_port,
        host_temp_c=hoststat.read_cpu_temp(),
    )
