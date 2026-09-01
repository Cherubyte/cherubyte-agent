"""The identification cadence and the async port prober.

Probing used to run a pool of hosts, each opening its own pool of ports — up to
~600 threads on a full subnet — and every host was re-probed every cycle. These
tests pin the replacement: one bounded event loop, and a staggered cadence.
"""

import asyncio
import socket

import pytest

from cherubyte_agent import scanner
from cherubyte_agent.scanner import (
    Host,
    _due_for_full_sweep,
    _ping_targets,
    _probe_ports_many,
    _select_for_identification,
)


@pytest.fixture(autouse=True)
def _clean_caches():
    scanner.reset_scan_caches()
    yield
    scanner.reset_scan_caches()


def host(mac: str, ip: str = "192.168.1.10") -> Host:
    return Host(mac=mac, ip=ip)


# ------------------------------------------------------------------- port probe

@pytest.fixture
def open_port():
    """A real listening socket, so the probe is tested against a live TCP stack."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    yield srv.getsockname()[1]
    srv.close()


async def test_probe_finds_a_listening_port(open_port, monkeypatch):
    monkeypatch.setattr(scanner, "PROBE_PORTS", {open_port: "test"})
    result = await _probe_ports_many(["127.0.0.1"])
    assert result == {"127.0.0.1": {open_port: "test"}}


async def test_probe_ignores_a_closed_port(monkeypatch):
    # port 1 on loopback: nothing listens there
    monkeypatch.setattr(scanner, "PROBE_PORTS", {1: "nope"})
    result = await _probe_ports_many(["127.0.0.1"])
    assert result == {"127.0.0.1": {}}


async def test_probe_reports_every_ip_even_with_no_open_ports(monkeypatch):
    monkeypatch.setattr(scanner, "PROBE_PORTS", {1: "nope"})
    result = await _probe_ports_many(["127.0.0.1", "127.0.0.2"])
    assert set(result) == {"127.0.0.1", "127.0.0.2"}


async def test_probe_mixes_open_and_closed(open_port, monkeypatch):
    monkeypatch.setattr(scanner, "PROBE_PORTS", {open_port: "test", 1: "nope"})
    result = await _probe_ports_many(["127.0.0.1"])
    assert result["127.0.0.1"] == {open_port: "test"}


async def test_probe_of_nothing_is_a_no_op():
    assert await _probe_ports_many([]) == {}


async def test_probe_respects_the_concurrency_limit(open_port, monkeypatch):
    """The whole point of the rewrite: concurrency is one bounded number."""
    monkeypatch.setattr(scanner.settings, "port_probe_concurrency", 4)
    monkeypatch.setattr(scanner, "PROBE_PORTS", {open_port: "test"})

    in_flight = 0
    peak = 0
    real_open = asyncio.open_connection

    async def counting_open(*a, **kw):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        try:
            return await real_open(*a, **kw)
        finally:
            in_flight -= 1

    monkeypatch.setattr(asyncio, "open_connection", counting_open)
    await _probe_ports_many([f"127.0.0.{i}" for i in range(1, 21)])
    assert peak <= 4, f"concurrency limit exceeded: {peak}"


async def test_slow_ports_time_out_rather_than_hanging(monkeypatch):
    monkeypatch.setattr(scanner, "PROBE_PORTS", {9: "discard"})

    async def never(*a, **kw):
        await asyncio.sleep(30)

    monkeypatch.setattr(asyncio, "open_connection", never)
    result = await asyncio.wait_for(
        _probe_ports_many(["192.0.2.1"], timeout=0.05), timeout=5
    )
    assert result == {"192.0.2.1": {}}


# ------------------------------------------------------------ cadence selection

def test_new_hosts_are_always_identified(monkeypatch):
    monkeypatch.setattr(scanner.settings, "identify_interval_seconds", 900)
    hosts = [host(f"aa:bb:cc:00:00:{i:02x}") for i in range(5)]
    assert _select_for_identification(hosts, now=1000.0) == hosts


def test_recently_identified_hosts_are_skipped(monkeypatch):
    monkeypatch.setattr(scanner.settings, "identify_interval_seconds", 900)
    h = host("aa:bb:cc:00:00:01")
    scanner._identified_at[h.mac] = 1000.0
    assert _select_for_identification([h], now=1100.0) == []


def test_stale_hosts_come_back_round(monkeypatch):
    monkeypatch.setattr(scanner.settings, "identify_interval_seconds", 900)
    h = host("aa:bb:cc:00:00:01")
    scanner._identified_at[h.mac] = 1000.0
    assert _select_for_identification([h], now=1000.0 + 901) == [h]


def test_the_batch_caps_stale_hosts(monkeypatch):
    monkeypatch.setattr(scanner.settings, "identify_interval_seconds", 900)
    monkeypatch.setattr(scanner.settings, "identify_batch", 3)
    hosts = [host(f"aa:bb:cc:00:00:{i:02x}") for i in range(10)]
    for i, h in enumerate(hosts):
        scanner._identified_at[h.mac] = 1000.0 + i  # oldest first
    picked = _select_for_identification(hosts, now=2000.0)
    assert len(picked) == 3
    assert picked == hosts[:3], "the longest-unseen hosts should go first"


def test_new_hosts_are_never_starved_by_the_batch(monkeypatch):
    """A burst of new devices must all be identified, cap or no cap."""
    monkeypatch.setattr(scanner.settings, "identify_interval_seconds", 900)
    monkeypatch.setattr(scanner.settings, "identify_batch", 2)
    new = [host(f"aa:bb:cc:11:11:{i:02x}") for i in range(5)]
    old = [host(f"aa:bb:cc:22:22:{i:02x}") for i in range(5)]
    for h in old:
        scanner._identified_at[h.mac] = 0.0
    picked = _select_for_identification(new + old, now=2000.0)
    assert all(h in picked for h in new)


def test_zero_interval_restores_the_old_behaviour(monkeypatch):
    monkeypatch.setattr(scanner.settings, "identify_interval_seconds", 0)
    hosts = [host(f"aa:bb:cc:00:00:{i:02x}") for i in range(4)]
    for h in hosts:
        scanner._identified_at[h.mac] = 1999.0
    assert _select_for_identification(hosts, now=2000.0) == hosts


# ----------------------------------------------------------------- sweep targets

def test_first_sweep_is_always_full():
    assert _due_for_full_sweep(now=10.0) is True


def test_full_sweep_waits_for_its_interval(monkeypatch):
    monkeypatch.setattr(scanner.settings, "full_sweep_interval_seconds", 900)
    monkeypatch.setattr(scanner.settings, "scan_interval_seconds", 60)
    scanner._last_full_sweep = 1000.0
    assert _due_for_full_sweep(now=1500.0) is False
    assert _due_for_full_sweep(now=1901.0) is True


def test_known_only_ping_targets_just_the_addresses_seen_before():
    scanner._known_ips.update({"192.168.1.5", "192.168.1.9", "10.0.0.4"})
    targets = _ping_targets("192.168.1.0/24", known_only=True)
    assert sorted(targets) == ["192.168.1.5", "192.168.1.9"], "other subnets excluded"


def test_known_only_falls_back_to_the_full_range_when_nothing_is_known():
    targets = _ping_targets("192.168.1.0/24", known_only=True)
    assert len(targets) == 254


def test_a_full_sweep_covers_the_whole_range():
    scanner._known_ips.add("192.168.1.5")
    assert len(_ping_targets("192.168.1.0/24", known_only=False)) == 254


def test_large_subnets_stay_bounded():
    assert len(_ping_targets("10.0.0.0/16", known_only=False)) == 512
