"""On-demand per-device probes: ping, a port scan, and a traceroute — the
agent's half of #57. The panel hands these back on a report ack; a bad probe
must never sink the report cycle, and a result must reach the next report's
`action_results`, not the one that carried the request."""

import asyncio
import socket

import pytest
from cherubyte_protocol import DeviceActionRequest

from cherubyte_agent import actions, wan
from cherubyte_agent.scanner import PROBE_PORTS


@pytest.fixture(autouse=True)
def _clean_pending():
    actions.take_pending()
    yield
    actions.take_pending()


# --------------------------------------------------------------------- ping

async def test_ping_ok_reports_latency_and_no_loss(monkeypatch):
    async def fake_probe(ip, timeout=2.0):
        return True, 12.5

    monkeypatch.setattr(wan, "probe", fake_probe)
    result = await actions.run_one(DeviceActionRequest(id=1, kind="ping", ip="1.2.3.4"))
    assert result.ok is True
    assert result.latency_ms == 12.5
    assert result.packet_loss == 0.0
    assert result.error is None


async def test_ping_failure_is_reported_not_raised(monkeypatch):
    async def fake_probe(ip, timeout=2.0):
        return False, None

    monkeypatch.setattr(wan, "probe", fake_probe)
    result = await actions.run_one(DeviceActionRequest(id=2, kind="ping", ip="192.0.2.1"))
    assert result.ok is False
    assert result.packet_loss == 1.0
    assert result.error


# ---------------------------------------------------------------- port scan

@pytest.fixture
def open_port():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    yield srv.getsockname()[1]
    srv.close()


async def test_quick_port_scan_finds_a_listening_port(open_port, monkeypatch):
    monkeypatch.setitem(PROBE_PORTS, open_port, "test")
    try:
        result = await actions.run_one(
            DeviceActionRequest(id=3, kind="port_scan_quick", ip="127.0.0.1")
        )
    finally:
        del PROBE_PORTS[open_port]
    assert result.ok is True
    assert result.open_ports == {open_port: "test"}


async def test_port_scan_reports_no_ports_open_rather_than_failing():
    # nothing listens on 127.0.0.1:1 in a test sandbox
    result = await actions._port_scan("127.0.0.1", {1: "nope"})
    assert result == {"ok": True, "open_ports": {}}


async def test_full_port_scan_covers_well_known_ports_plus_probe_ports():
    assert set(range(1, 1025)).issubset(actions.FULL_PORTS)
    for port in PROBE_PORTS:
        assert port in actions.FULL_PORTS
    assert actions.FULL_PORTS[443] == "https"  # a named PROBE_PORTS entry wins


# ---------------------------------------------------------------- traceroute

_LINUX_OUTPUT = (
    "traceroute to 8.8.8.8 (8.8.8.8), 20 hops max, 60 byte packets\n"
    " 1  192.168.1.1  0.456 ms\n"
    " 2  10.0.0.1  12.345 ms\n"
    " 3  *\n"
    " 4  8.8.8.8  20.1 ms\n"
)


def test_parse_traceroute_reads_hops_and_timeouts():
    hops = actions.parse_traceroute(_LINUX_OUTPUT)
    assert [h.ttl for h in hops] == [1, 2, 3, 4]
    assert hops[0].ip == "192.168.1.1"
    assert hops[0].rtt_ms == 0.456
    assert hops[2].ip is None
    assert hops[2].rtt_ms is None
    assert hops[3].ip == "8.8.8.8"


def test_parse_traceroute_of_empty_output_is_no_hops():
    assert actions.parse_traceroute("") == []


async def test_traceroute_survives_a_missing_binary(monkeypatch):
    async def no_binary(*a, **kw):
        raise FileNotFoundError("traceroute")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", no_binary)
    result = await actions.run_one(DeviceActionRequest(id=4, kind="traceroute", ip="8.8.8.8"))
    assert result.ok is False
    assert "not installed" in result.error


# ------------------------------------------------------------- dispatch/queue

async def test_unknown_kind_is_reported_not_raised():
    result = await actions.run_one(DeviceActionRequest(id=5, kind="reboot", ip="1.2.3.4"))
    assert result.ok is False
    assert "unknown" in result.error


async def test_a_runner_that_raises_is_caught(monkeypatch):
    async def boom(ip):
        raise RuntimeError("network is on fire")

    monkeypatch.setitem(actions._RUNNERS, "ping", boom)
    result = await actions.run_one(DeviceActionRequest(id=6, kind="ping", ip="1.2.3.4"))
    assert result.ok is False
    assert "network is on fire" in result.error


async def test_run_all_runs_every_request_concurrently(monkeypatch):
    async def fake_probe(ip, timeout=2.0):
        return True, 1.0

    monkeypatch.setattr(wan, "probe", fake_probe)
    reqs = [DeviceActionRequest(id=i, kind="ping", ip="1.2.3.4") for i in range(3)]
    results = await actions.run_all(reqs)
    assert sorted(r.id for r in results) == [0, 1, 2]


async def test_results_are_stashed_for_the_next_cycle_not_returned_now(monkeypatch):
    async def fake_probe(ip, timeout=2.0):
        return True, 1.0

    monkeypatch.setattr(wan, "probe", fake_probe)
    assert actions.take_pending() == []
    await actions.run_and_stash([DeviceActionRequest(id=7, kind="ping", ip="1.2.3.4")])
    pending = actions.take_pending()
    assert [r.id for r in pending] == [7]
    # draining is destructive — a second read is empty until more actions run
    assert actions.take_pending() == []


async def test_run_and_stash_of_nothing_is_a_no_op():
    await actions.run_and_stash([])
    assert actions.take_pending() == []
