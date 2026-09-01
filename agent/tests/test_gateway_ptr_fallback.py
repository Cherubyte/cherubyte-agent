"""Reverse-DNS fallback: ask the gateway directly when the OS resolver draws
a blank.

Many self-hosted Linux boxes run systemd-resolved, which by default answers a
PTR query for an RFC1918 address out of its own negative cache instead of
forwarding it upstream — so `_reverse_dns()` (socket.gethostbyaddr, which goes
through that same local stub) can report nothing even though the router
itself would happily answer the identical query. `_probe_host()` now falls
back to asking the gateway directly (discovery.gateway_reverse_dns) whenever
the OS resolver comes up empty.
"""

from cherubyte_agent import discovery, scanner
from cherubyte_agent.scanner import Host, _gateway_for, _probe_host


def _fake_route(gateway: str | None):
    def route(dest):
        return "eth0", "0.0.0.0", (gateway or "0.0.0.0")

    return route


# ------------------------------------------------------------------ _gateway_for

def test_gateway_for_returns_the_routed_gateway(monkeypatch):
    from scapy.all import conf

    monkeypatch.setattr(conf.route, "route", _fake_route("192.168.1.1"))
    assert _gateway_for("192.168.1.50") == "192.168.1.1"


def test_gateway_for_is_none_when_there_is_no_gateway(monkeypatch):
    from scapy.all import conf

    monkeypatch.setattr(conf.route, "route", _fake_route(None))
    assert _gateway_for("192.168.1.50") is None


def test_gateway_for_is_none_on_a_routing_lookup_failure(monkeypatch):
    from scapy.all import conf

    def boom(dest):
        raise OSError("no route")

    monkeypatch.setattr(conf.route, "route", boom)
    assert _gateway_for("192.168.1.50") is None


# --------------------------------------------------------- _probe_host() wiring

def _quiet_probe_host_deps(monkeypatch):
    """Everything _probe_host() touches besides reverse DNS, stubbed out so
    these tests exercise only the hostname fallback path."""
    monkeypatch.setattr(discovery, "netbios_name", lambda *a, **kw: None)
    monkeypatch.setattr(discovery, "llmnr_name", lambda *a, **kw: None)
    monkeypatch.setattr(discovery, "http_banner", lambda *a, **kw: None)
    monkeypatch.setattr(discovery, "ttl_os_hint", lambda *a, **kw: None)
    monkeypatch.setattr(scanner.dhcp_sniffer, "get", lambda mac: None)
    monkeypatch.setattr(scanner.settings, "enable_snmp", False)


def test_falls_back_to_the_gateway_when_the_os_resolver_finds_nothing(monkeypatch):
    from scapy.all import conf

    _quiet_probe_host_deps(monkeypatch)
    monkeypatch.setattr(scanner.settings, "enable_reverse_dns", True)
    monkeypatch.setattr(scanner, "_reverse_dns", lambda ip: None)
    monkeypatch.setattr(conf.route, "route", _fake_route("192.168.1.1"))
    monkeypatch.setattr(
        discovery, "gateway_reverse_dns", lambda ip, gateway, **kw: "printer.lan"
    )

    host = _probe_host(Host(mac="aa:bb:cc:00:00:01", ip="192.168.1.50"))
    assert host.hostname == "printer.lan"


def test_the_os_resolver_is_trusted_when_it_has_an_answer(monkeypatch):
    from scapy.all import conf

    _quiet_probe_host_deps(monkeypatch)
    monkeypatch.setattr(scanner.settings, "enable_reverse_dns", True)
    monkeypatch.setattr(scanner, "_reverse_dns", lambda ip: "laptop.lan")
    monkeypatch.setattr(conf.route, "route", _fake_route("192.168.1.1"))
    called = False

    def fake_gateway_reverse_dns(ip, gateway, **kw):
        nonlocal called
        called = True
        return "should-not-be-used"

    monkeypatch.setattr(discovery, "gateway_reverse_dns", fake_gateway_reverse_dns)

    host = _probe_host(Host(mac="aa:bb:cc:00:00:01", ip="192.168.1.50"))
    assert host.hostname == "laptop.lan"
    assert called is False, "a real OS-resolver answer must not be second-guessed"


def test_no_fallback_without_a_gateway(monkeypatch):
    from scapy.all import conf

    _quiet_probe_host_deps(monkeypatch)
    monkeypatch.setattr(scanner.settings, "enable_reverse_dns", True)
    monkeypatch.setattr(scanner, "_reverse_dns", lambda ip: None)
    monkeypatch.setattr(conf.route, "route", _fake_route(None))
    called = False

    def fake_gateway_reverse_dns(ip, gateway, **kw):
        nonlocal called
        called = True
        return "unused"

    monkeypatch.setattr(discovery, "gateway_reverse_dns", fake_gateway_reverse_dns)

    host = _probe_host(Host(mac="aa:bb:cc:00:00:01", ip="192.168.1.50"))
    assert host.hostname is None
    assert called is False


def test_reverse_dns_disabled_means_no_fallback_either(monkeypatch):
    _quiet_probe_host_deps(monkeypatch)
    monkeypatch.setattr(scanner.settings, "enable_reverse_dns", False)
    monkeypatch.setattr(scanner, "_reverse_dns", lambda ip: (_ for _ in ()).throw(
        AssertionError("must not be called when reverse DNS is disabled")
    ))
    called = False

    def fake_gateway_reverse_dns(ip, gateway, **kw):
        nonlocal called
        called = True
        return "unused"

    monkeypatch.setattr(discovery, "gateway_reverse_dns", fake_gateway_reverse_dns)

    host = _probe_host(Host(mac="aa:bb:cc:00:00:01", ip="192.168.1.50"))
    assert host.hostname is None
    assert called is False
