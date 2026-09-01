"""Folding the passive ARP sniffer's sightings into a sweep's host list."""

from datetime import datetime, timedelta, timezone

import pytest

from cherubyte_agent import arp_sniffer, scanner
from cherubyte_agent.arp_sniffer import PassiveHost
from cherubyte_agent.scanner import Host, _merge_passive_hosts

TARGETS = [("192.168.1.0/24", None)]


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.setattr(scanner.settings, "enable_passive_arp", True)
    monkeypatch.setattr(scanner.settings, "passive_arp_ttl_seconds", 300)
    arp_sniffer._hosts.clear()
    yield
    arp_sniffer._hosts.clear()


def test_a_passively_seen_host_is_added():
    arp_sniffer._hosts["aa:bb:cc:00:00:01"] = PassiveHost(
        mac="aa:bb:cc:00:00:01", ip="192.168.1.50"
    )
    hosts: dict[str, Host] = {}
    _merge_passive_hosts(hosts, TARGETS)
    assert "aa:bb:cc:00:00:01" in hosts
    assert hosts["aa:bb:cc:00:00:01"].ip == "192.168.1.50"
    assert hosts["aa:bb:cc:00:00:01"].subnet == "192.168.1.0/24"


def test_a_host_the_active_sweep_already_found_is_not_overwritten():
    arp_sniffer._hosts["aa:bb:cc:00:00:01"] = PassiveHost(
        mac="aa:bb:cc:00:00:01", ip="192.168.1.99"
    )
    hosts = {"aa:bb:cc:00:00:01": Host(mac="aa:bb:cc:00:00:01", ip="192.168.1.50")}
    _merge_passive_hosts(hosts, TARGETS)
    assert hosts["aa:bb:cc:00:00:01"].ip == "192.168.1.50"


def test_a_sighting_outside_the_swept_subnets_is_dropped():
    arp_sniffer._hosts["aa:bb:cc:00:00:01"] = PassiveHost(
        mac="aa:bb:cc:00:00:01", ip="10.0.0.5"
    )
    hosts: dict[str, Host] = {}
    _merge_passive_hosts(hosts, TARGETS)
    assert hosts == {}


def test_disabled_means_nothing_is_merged(monkeypatch):
    monkeypatch.setattr(scanner.settings, "enable_passive_arp", False)
    arp_sniffer._hosts["aa:bb:cc:00:00:01"] = PassiveHost(
        mac="aa:bb:cc:00:00:01", ip="192.168.1.50"
    )
    hosts: dict[str, Host] = {}
    _merge_passive_hosts(hosts, TARGETS)
    assert hosts == {}


def test_a_sighting_older_than_the_ttl_is_not_merged():
    """A MAC seen once, long ago, must not read as online forever — the
    sniffer's cache never expires on its own, so the merge has to."""
    arp_sniffer._hosts["aa:bb:cc:00:00:01"] = PassiveHost(
        mac="aa:bb:cc:00:00:01",
        ip="192.168.1.50",
        last_seen=datetime.now(timezone.utc) - timedelta(seconds=301),
    )
    hosts: dict[str, Host] = {}
    _merge_passive_hosts(hosts, TARGETS)
    assert hosts == {}


def test_a_sighting_within_the_ttl_is_merged():
    arp_sniffer._hosts["aa:bb:cc:00:00:01"] = PassiveHost(
        mac="aa:bb:cc:00:00:01",
        ip="192.168.1.50",
        last_seen=datetime.now(timezone.utc) - timedelta(seconds=299),
    )
    hosts: dict[str, Host] = {}
    _merge_passive_hosts(hosts, TARGETS)
    assert "aa:bb:cc:00:00:01" in hosts
