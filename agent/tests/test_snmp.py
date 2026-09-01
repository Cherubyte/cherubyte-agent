"""Parsing the net-snmp command-line output."""

import pytest

from cherubyte_agent import snmp

_LLDP_WALK = """\
.1.0.8802.1.1.2.1.4.1.1.4.0.1.1 "GigabitEthernet0/1"
.1.0.8802.1.1.2.1.4.1.1.5.0.1.1 "aa:bb:cc:dd:ee:01"
.1.0.8802.1.1.2.1.4.1.1.7.0.1.1 "Gi0/24"
.1.0.8802.1.1.2.1.4.1.1.9.0.1.1 "edge-sw-1"
.1.0.8802.1.1.2.1.4.1.1.5.0.2.1 "aa:bb:cc:dd:ee:02"
.1.0.8802.1.1.2.1.4.1.1.7.0.2.1 "Gi0/1"
.1.0.8802.1.1.2.1.4.1.1.9.0.2.1 "ap-lobby"
"""


@pytest.fixture
def _tools(monkeypatch):
    monkeypatch.setattr(snmp.shutil, "which", lambda _n: "/usr/bin/" + _n)


def test_available_warns_when_missing(monkeypatch):
    monkeypatch.setattr(snmp.shutil, "which", lambda _n: None)
    snmp._warned = False
    assert snmp.available() is False


def test_sys_info(monkeypatch, _tools):
    calls = []

    def fake_run(args, timeout):
        calls.append(args)
        return '"core-sw-1"\n' if args[-1] == snmp.OID_SYSNAME else '"Cisco IOS Software, C2960"\n'

    monkeypatch.setattr(snmp, "_run", fake_run)
    name, desc = snmp.sys_info("192.168.1.2", "public")
    assert name == "core-sw-1"
    assert desc.startswith("Cisco IOS Software")


def test_lldp_neighbors(monkeypatch, _tools):
    monkeypatch.setattr(snmp, "_run", lambda args, timeout: _LLDP_WALK)
    neighbours = snmp.lldp_neighbors("192.168.1.2", "public")
    names = sorted(n.remote_name for n in neighbours)
    assert names == ["ap-lobby", "edge-sw-1"]
    edge = next(n for n in neighbours if n.remote_name == "edge-sw-1")
    assert edge.remote_port == "Gi0/24"
    assert edge.local_port == "1"


def test_lldp_returns_empty_when_snmp_missing(monkeypatch):
    monkeypatch.setattr(snmp.shutil, "which", lambda _n: None)
    assert snmp.lldp_neighbors("192.168.1.2", "public") == []
