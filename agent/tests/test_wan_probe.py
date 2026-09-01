"""The agent's internet probe. Storing and alerting on these readings is the
panel's job; all the agent does is take one."""

import pytest

from cherubyte_agent import wan


def test_rtt_is_parsed_from_real_ping_output():
    linux = (b"64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms\n"
             b"--- 1.1.1.1 ping statistics ---\n")
    assert wan.parse_rtt(linux) == 12.3
    assert wan.parse_rtt(b"64 bytes from 10.0.0.1: time<1 ms") == 1.0
    assert wan.parse_rtt(b"64 bytes from x: time=0.043 ms") == 0.043


def test_rtt_is_none_when_the_output_has_none():
    assert wan.parse_rtt(b"") is None
    assert wan.parse_rtt(b"Destination Host Unreachable") is None


async def test_probe_reports_unreachable_instead_of_raising():
    """Covers an unroutable target and a host with no `ping` binary at all —
    either way the scheduled job must not blow up."""
    # TEST-NET-1, reserved by RFC 5737 and never routable
    ok, latency = await wan.probe("192.0.2.1", timeout=1.0)
    assert ok is False
    assert latency is None


async def test_probe_survives_a_missing_ping_binary(monkeypatch):
    async def no_binary(*a, **kw):
        raise FileNotFoundError("ping")

    monkeypatch.setattr(wan.asyncio, "create_subprocess_exec", no_binary)
    assert await wan.probe("1.1.1.1") == (False, None)


# ---------------------------------------------------------------- public IP

class _FakeResponse:
    def __init__(self, text: str, status: int = 200):
        self.text = text
        self._status = status

    def raise_for_status(self):
        if self._status >= 400:
            raise wan.httpx.HTTPStatusError("boom", request=None, response=None)


class _FakeClient:
    def __init__(self, answers):
        self._answers = answers

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url):
        answer = self._answers.get(url)
        if isinstance(answer, Exception):
            raise answer
        if answer is None:
            raise wan.httpx.ConnectError("unreachable")
        return _FakeResponse(answer)


def _use_client(monkeypatch, answers):
    monkeypatch.setattr(wan.httpx, "AsyncClient", lambda *a, **kw: _FakeClient(answers))


async def test_public_ip_parses_the_cloudflare_trace(monkeypatch):
    _use_client(monkeypatch, {
        "https://one.one.one.one/cdn-cgi/trace": "fl=1\nip=198.51.100.9\nts=0\n",
    })
    assert await wan.public_ip() == "198.51.100.9"


async def test_public_ip_falls_through_to_the_next_source(monkeypatch):
    _use_client(monkeypatch, {
        "https://one.one.one.one/cdn-cgi/trace": None,          # unreachable
        "https://api.ipify.org": "  203.0.113.42  ",
    })
    assert await wan.public_ip() == "203.0.113.42"


async def test_public_ip_is_none_when_nothing_answers_or_the_body_is_junk(monkeypatch):
    _use_client(monkeypatch, {
        "https://one.one.one.one/cdn-cgi/trace": "ip=not-an-ip\n",
        "https://api.ipify.org": "<html>error</html>",
        "https://ipv4.icanhazip.com": None,
    })
    assert await wan.public_ip() is None


async def test_public_ip_rejects_an_ipv6_answer_and_falls_through(monkeypatch):
    _use_client(monkeypatch, {
        "https://one.one.one.one/cdn-cgi/trace": "ip=2001:db8::1\n",
        "https://api.ipify.org": "198.51.100.23",
    })
    assert await wan.public_ip() == "198.51.100.23"


