"""LLMNR reverse lookup (RFC 4795) and dynamic mDNS service-type discovery.

Both target the same real gap: Fing-style tools see hostnames Cherubyte
missed, because our old mDNS browse only asked for ~22 hardcoded service
types, and NetBIOS is the only Windows name source (which some networks
disable in favor of LLMNR). Neither fix touches a live socket in these
tests — the DNS-format wire parsing and the type-discovery logic are both
pure functions, tested directly.
"""

import struct

import pytest

from cherubyte_agent import discovery


def _dns_name(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return bytes(out) + b"\x00"


# ------------------------------------------------------------- name encode/decode

def test_encode_decode_round_trip():
    raw = discovery._encode_dns_name("5.1.168.192.in-addr.arpa")
    name, pos = discovery._decode_dns_name(raw, 0)
    assert name == "5.1.168.192.in-addr.arpa"
    assert pos == len(raw)


def test_decode_follows_a_compression_pointer():
    prefix = _dns_name("foo.local")
    data = prefix + b"\xc0\x00"  # a second name that's just a pointer to the first
    name, pos = discovery._decode_dns_name(data, len(prefix))
    assert name == "foo.local"
    assert pos == len(data)


def test_decode_rejects_a_pointer_loop():
    data = b"\xc0\x00"  # points at itself
    with pytest.raises(ValueError):
        discovery._decode_dns_name(data, 0)


# -------------------------------------------------------------- _parse_ptr_response

def _dns_header(ancount: int) -> bytes:
    return struct.pack(">HHHHHH", 0x1357, 0x8400, 1, ancount, 0, 0)


def _query_question(qname: str) -> bytes:
    return _dns_name(qname) + struct.pack(">HH", 12, 1)  # PTR, IN


def test_parses_a_ptr_answer():
    question = _query_question("5.1.168.192.in-addr.arpa")
    rdata = _dns_name("desktop-ab12.local")
    answer = (
        b"\xc0\x0c"  # NAME: pointer back to the question's QNAME (offset 12)
        + struct.pack(">HHIH", 12, 1, 120, len(rdata))
        + rdata
    )
    data = _dns_header(ancount=1) + question + answer
    assert discovery._parse_ptr_response(data) == "desktop-ab12.local"


def test_no_answers_means_no_name():
    data = _dns_header(ancount=0) + _query_question("5.1.168.192.in-addr.arpa")
    assert discovery._parse_ptr_response(data) is None


def test_skips_a_non_ptr_answer_before_the_real_one():
    question = _query_question("5.1.168.192.in-addr.arpa")
    a_rdata = b"\xc0\xa8\x01\x05"  # a 4-byte A record, irrelevant here
    a_answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, len(a_rdata)) + a_rdata
    ptr_rdata = _dns_name("host.local")
    ptr_answer = b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 120, len(ptr_rdata)) + ptr_rdata
    data = _dns_header(ancount=2) + question + a_answer + ptr_answer
    assert discovery._parse_ptr_response(data) == "host.local"


# --------------------------------------------------------------- llmnr_name() I/O

def test_llmnr_name_returns_none_on_a_bad_ip():
    assert discovery.llmnr_name("not-an-ip") is None


def test_llmnr_name_returns_none_when_the_socket_times_out(monkeypatch):
    import socket as socket_module

    class TimingOutSocket:
        def settimeout(self, t):
            pass

        def sendto(self, *a):
            pass

        def recvfrom(self, *a):
            raise socket_module.timeout()

        def close(self):
            pass

    monkeypatch.setattr(socket_module, "socket", lambda *a, **kw: TimingOutSocket())
    assert discovery.llmnr_name("192.168.1.5") is None


# -------------------------------------------------- gateway_reverse_dns() targeting

def test_gateway_reverse_dns_queries_the_gateway_on_port_53(monkeypatch):
    """The whole point: unlike llmnr_name() (queries the host itself, port
    5355), this must go to the gateway, on standard DNS port 53 — bypassing
    whatever the OS resolver would have done."""
    import socket as socket_module

    sent: dict = {}

    class RecordingSocket:
        def settimeout(self, t):
            pass

        def sendto(self, data, addr):
            sent["addr"] = addr

        def recvfrom(self, *a):
            raise socket_module.timeout()

        def close(self):
            pass

    monkeypatch.setattr(socket_module, "socket", lambda *a, **kw: RecordingSocket())
    discovery.gateway_reverse_dns("192.168.1.50", gateway="192.168.1.1")
    assert sent["addr"] == ("192.168.1.1", 53)


def test_llmnr_name_queries_the_host_itself_on_port_5355(monkeypatch):
    import socket as socket_module

    sent: dict = {}

    class RecordingSocket:
        def settimeout(self, t):
            pass

        def sendto(self, data, addr):
            sent["addr"] = addr

        def recvfrom(self, *a):
            raise socket_module.timeout()

        def close(self):
            pass

    monkeypatch.setattr(socket_module, "socket", lambda *a, **kw: RecordingSocket())
    discovery.llmnr_name("192.168.1.50")
    assert sent["addr"] == ("192.168.1.50", 5355)


# --------------------------------------------------------- dynamic mDNS type union

def test_discover_mdns_types_returns_what_the_network_enumeration_finds(monkeypatch):
    import zeroconf

    monkeypatch.setattr(
        zeroconf.ZeroconfServiceTypes,
        "find",
        classmethod(lambda cls, zc=None, timeout=5: ("_hue._tcp.local.", "_matter._tcp.local.")),
    )
    found = discovery._discover_mdns_types(zc=object(), timeout=1.0)
    assert found == {"_hue._tcp.local.", "_matter._tcp.local."}


def test_discover_mdns_types_is_quiet_on_failure(monkeypatch):
    import zeroconf

    def boom(cls, zc=None, timeout=5):
        raise OSError("no interfaces")

    monkeypatch.setattr(zeroconf.ZeroconfServiceTypes, "find", classmethod(boom))
    assert discovery._discover_mdns_types(zc=object(), timeout=1.0) == set()
