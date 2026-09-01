"""The seam between the two images.

They ship separately and can be upgraded separately, so the failure to guard
against is not a crash — it is one field quietly stopping crossing, on one
release, with both sides still reporting success.
"""

from datetime import datetime, timezone

from cherubyte_protocol import (
    PROTOCOL_VERSION,
    AgentReport,
    HostObservation,
    LldpNeighbor,
    WanObservation,
)

from cherubyte_agent.collector import to_observation
from cherubyte_agent.scanner import Host


def a_host() -> Host:
    """A host with every observable field populated, so nothing can be dropped
    silently by the conversion."""
    host = Host(mac="aa:bb:cc:dd:ee:01", ip="192.168.1.10", subnet="192.168.1.0/24")
    host.identified = True
    host.hostname = "portatil.lan"
    host.open_ports = {22: "ssh", 443: "https"}
    host.mdns_name = "Portatil"
    host.mdns_model = "MacBookPro18,3"
    host.mdns_services = ["_smb", "_airplay"]
    host.ssdp_name = "Portatil UPnP"
    host.ssdp_vendor = "Apple"
    host.ssdp_model = "MacBook"
    host.netbios_name = "PORTATIL"
    host.llmnr_name = "PORTATIL-LLMNR"
    host.http_server = "nginx"
    host.http_title = "Home"
    host.ttl_os = "unix"
    host.dhcp_param_list = "1,3,6,15"
    host.dhcp_vendor_class = "MSFT 5.0"
    host.dhcp_hostname = "portatil"
    host.snmp_sysname = "core-sw"
    host.snmp_sysdescr = "Cisco IOS Software"
    host.lldp_neighbors = [
        LldpNeighbor(local_port="1", remote_name="edge-sw", remote_port="24")
    ]
    return host


def test_every_observable_field_survives_the_conversion():
    host = a_host()
    obs = to_observation(host)

    for field in HostObservation.model_fields:
        assert getattr(obs, field) == getattr(host, field), (
            f"{field} did not survive the trip from the scanner to the wire"
        )


def test_the_scanner_has_no_observable_field_the_wire_cannot_carry():
    """Adding a signal to the scanner and forgetting the protocol is the exact
    way this seam breaks. Fail here rather than dropping it at runtime."""
    carried = set(HostObservation.model_fields)
    # what the scanner holds for its own use rather than to report
    internal = {"os_guess"}
    observable = {f for f in Host.__dataclass_fields__} - internal

    missing = observable - carried
    assert not missing, f"the scanner observes {missing}, which no wire field carries"


def test_a_report_round_trips_through_json():
    """The panel parses JSON off a socket, not a Python object."""
    report = AgentReport(
        sent_at=datetime.now(timezone.utc),
        subnets=["192.168.1.0/24"],
        hosts=[to_observation(a_host())],
        wan=[WanObservation(target="1.1.1.1", ok=True, latency_ms=8.0, public_ip="203.0.113.5")],
    )

    revived = AgentReport.model_validate_json(report.model_dump_json())

    assert revived.protocol_version == PROTOCOL_VERSION
    assert revived.hosts[0].open_ports == {22: "ssh", 443: "https"}
    assert revived.hosts[0].mdns_services == ["_smb", "_airplay"]
    assert revived.wan[0].public_ip == "203.0.113.5"


def test_an_unidentified_host_reports_that_it_was_not_asked():
    """The distinction the panel needs to avoid reading a skipped cycle as
    every port closing at once."""
    host = Host(mac="aa:bb:cc:dd:ee:02", ip="192.168.1.11")
    assert to_observation(host).identified is False
