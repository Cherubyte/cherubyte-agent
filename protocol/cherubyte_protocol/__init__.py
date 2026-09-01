"""The wire contract between an agent and a panel.

Both sides import these models rather than each keeping its own copy. The two
processes ship as separate images and can be upgraded independently, so a
duplicated schema would not diverge loudly — it would diverge in one field, on
one release, and the panel would quietly store nothing for it.

The split they describe: **the agent observes, the panel decides.** Everything
here is something the agent saw on the wire. Nothing here is a conclusion —
classification, naming, presence and alerting are the panel's, computed from
these observations, so improving them never needs an agent upgrade.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

#: Bumped when a change is not backward compatible. The panel refuses a report
#: whose version it does not implement, rather than storing a partial reading of
#: it — a rejected report is visible, a half-parsed one is not. The agent and
#: panel ship from one repo and upgrade together, so this is an exact match, not
#: a floor.
#:
#: v2: adds `AgentReport.dhcp_servers` — the DHCP servers the passive sniffer
#:     saw answering on the LAN, so the panel can flag an unexpected one.
#: v3: adds `HostObservation.snmp_sysname` / `snmp_sysdescr` and
#:     `HostObservation.lldp_neighbors` — optional SNMP / LLDP-MIB reads, so the
#:     panel can name managed gear and draw the links between switches.
#: v4: adds `HostObservation.llmnr_name` — an LLMNR reverse lookup, another
#:     name source for Windows hosts alongside NetBIOS.
PROTOCOL_VERSION = 4

__all__ = [
    "PROTOCOL_VERSION",
    "AgentConfig",
    "AgentReport",
    "ReportAck",
    "EnrolRequest",
    "EnrolResponse",
    "HostObservation",
    "WanObservation",
    "DhcpServerObservation",
    "LldpNeighbor",
]


class LldpNeighbor(BaseModel):
    """A link this host's LLDP-MIB reports: `local_port` of this host connects to
    `remote_port` of the device identified by `remote_chassis` / `remote_name`.
    """

    local_port: str | None = None
    remote_chassis: str | None = None
    remote_port: str | None = None
    remote_name: str | None = None


class HostObservation(BaseModel):
    """One host as a single sweep saw it."""

    mac: str
    ip: str
    subnet: str | None = None

    # True when this sweep fully probed the host. False on a discovery-only
    # cycle, where the absence of a signal means "not asked" rather than
    # "not there" — the panel needs the difference to avoid reading a skipped
    # cycle as every port closing at once.
    identified: bool = False

    hostname: str | None = None                     # reverse DNS
    open_ports: dict[int, str] = Field(default_factory=dict)
    mdns_name: str | None = None
    mdns_model: str | None = None
    mdns_services: list[str] = Field(default_factory=list)
    ssdp_name: str | None = None
    ssdp_vendor: str | None = None
    ssdp_model: str | None = None
    netbios_name: str | None = None
    # LLMNR (RFC 4795, UDP 5355) reverse lookup — Microsoft's successor to
    # NetBIOS name resolution, still answered by many current Windows hosts
    # even where NetBIOS-over-TCP/IP has been turned off.
    llmnr_name: str | None = None
    http_server: str | None = None
    http_title: str | None = None
    ttl_os: str | None = None
    dhcp_param_list: str = ""
    dhcp_vendor_class: str | None = None
    dhcp_hostname: str | None = None
    # SNMP (opt-in, community read). sysDescr is a strong OS / vendor signal for
    # managed gear ("Cisco IOS Software…", "RouterOS…", "Ubuntu…").
    snmp_sysname: str | None = None
    snmp_sysdescr: str | None = None
    # LLDP-MIB neighbours walked from this host over SNMP — the raw material for
    # a topology map when there are managed switches to ask.
    lldp_neighbors: list[LldpNeighbor] = Field(default_factory=list)


class DhcpServerObservation(BaseModel):
    """A DHCP server the agent's passive sniffer saw answering on the LAN.

    An observation, not a verdict: whether a given server is meant to be there
    is the panel's call (it knows the gateway and the operator's allowlist).
    """

    ip: str
    mac: str | None = None
    last_seen: datetime | None = None


class WanObservation(BaseModel):
    """One internet reachability probe."""

    target: str
    ok: bool
    latency_ms: float | None = None
    at: datetime | None = None
    # The network's egress address as seen from the internet, resolved from the
    # agent's vantage point during this probe. None when the probe failed or the
    # lookup did not answer. It is an observation like any other here — what the
    # panel does with it (show it, redact it) is the panel's.
    public_ip: str | None = None


class AgentReport(BaseModel):
    """One sweep, as delivered to the panel."""

    protocol_version: int = PROTOCOL_VERSION
    sent_at: datetime
    # CIDRs this agent swept, so the panel can group and label them without
    # having to see the interfaces itself.
    subnets: list[str] = Field(default_factory=list)
    hosts: list[HostObservation] = Field(default_factory=list)
    wan: list[WanObservation] = Field(default_factory=list)
    # DHCP servers seen answering on the LAN (from the passive sniffer). The
    # panel flags any that is not the gateway or on the operator's allowlist.
    dhcp_servers: list[DhcpServerObservation] = Field(default_factory=list)
    # DHCP fingerprints the agent's passive sniffer has collected, by MAC.
    dhcp_fingerprints: int = 0
    # False when the sweep found nothing at all. A healthy sweep always sees at
    # least the agent's own host, so this is "the scan is broken", not "the
    # network emptied" — and the panel must not expire devices on it.
    healthy: bool = True
    # Where this agent's health/trigger server is listening. The panel uses it,
    # with the address the report arrived from, to ask for an out-of-band sweep.
    health_port: int = 1002


class AgentConfig(BaseModel):
    """What the panel wants this agent to do, sent back with every ack.

    The point is that an agent is configured from the panel, not from the box
    it runs on: installing one should mean a URL and a token and nothing else.
    An operator who *does* set a variable locally keeps it — see the agent's
    `apply_config`, which treats an explicitly set environment variable as
    pinned. Otherwise a value set on the machine would be silently overwritten
    on the first report, and the operator would have no way to see why.
    """

    scan_interval_seconds: int = 60
    identify_interval_seconds: int = 900
    identify_batch: int = 16
    full_sweep_interval_seconds: int = 900
    port_probe_concurrency: int = 256
    arp_timeout: float = 2.0
    enable_reverse_dns: bool = True
    enable_port_probe: bool = True
    enable_dhcp_sniffer: bool = True
    # Passive ARP listening, alongside (not instead of) the active sweep —
    # catches a host that answers someone else's ARP but missed ours.
    enable_passive_arp: bool = True
    # SNMP is off unless asked for — it needs a community string and most LANs
    # have nothing that answers it.
    enable_snmp: bool = False
    snmp_community: str = "public"
    wan_enabled: bool = True
    wan_target: str = "1.1.1.1"
    # Empty means "work it out from the interface".
    subnets: list[str] = Field(default_factory=list)


class ReportAck(BaseModel):
    """The panel's answer to a report."""

    ok: bool = True
    found: int = 0
    degraded: bool = False
    config: AgentConfig = Field(default_factory=AgentConfig)
    # Set when someone pressed Sweep in the panel and it could not reach the
    # agent's trigger port directly. The agent should run one cycle now instead
    # of waiting out the rest of its interval.
    scan_now: bool = False
    # MAC addresses the panel wants woken — the agent sends a Wake-on-LAN magic
    # packet to each on its local segment. Additive and optional: an old agent
    # ignores the field, a new agent against an old panel sees an empty list.
    wake: list[str] = Field(default_factory=list)


class EnrolRequest(BaseModel):
    """An agent asking to be admitted, once, with a token an operator issued."""

    token: str
    name: str
    version: str = ""


class EnrolResponse(BaseModel):
    agent_id: int
    #: Shown exactly once. The panel stores only a hash of it.
    key: str
    name: str
