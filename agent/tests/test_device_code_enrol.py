"""Enrolling by asking, rather than by being handed a token.

The agent's half. What matters here is that it survives the wait: somebody has
to read a link off a terminal and walk to a browser, and in between the machine
may be restarted, the service may be slow to start, and the panel will keep
answering "not yet". None of that may lose the code that was already printed,
because the link in the terminal stops working the moment a new one is issued.
"""

from __future__ import annotations

import json
import time

import httpx
import pytest

from cherubyte_agent import reporter
from cherubyte_agent.config import settings


@pytest.fixture(autouse=True)
def state(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "state_file", str(tmp_path / "agent.json"))
    monkeypatch.setattr(settings, "panel_url", "http://panel.test")
    monkeypatch.setattr(settings, "name", "kitchen-pi")
    monkeypatch.setattr(settings, "enrol_token", "")
    yield tmp_path


def _transport(handler):
    return httpx.MockTransport(handler)


@pytest.fixture
def panel(monkeypatch):
    """A stand-in panel, scripted per test."""
    calls: list[tuple[str, dict]] = []
    script: dict[str, object] = {"approved": False, "code": "K7RQ-4TDX", "secret": "s" * 40}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        calls.append((request.url.path, body))
        if request.url.path.endswith("/device-code"):
            return httpx.Response(
                200,
                json={
                    "code": script["code"],
                    "poll_secret": script["secret"],
                    "verification_url": f"http://panel.test/a/{script['code']}",
                    "expires_in": 600,
                    "interval": 3,
                },
            )
        if request.url.path.endswith("/device-token"):
            if body.get("poll_secret") != script["secret"]:
                return httpx.Response(403, text="no")
            if not script["approved"]:
                return httpx.Response(202, text="waiting")
            return httpx.Response(
                200, json={"agent_id": 7, "key": "k" * 40, "name": "kitchen-pi"}
            )
        return httpx.Response(404)

    real = httpx.AsyncClient

    def patched(**kw):
        kw.pop("transport", None)
        return real(transport=_transport(handler), **kw)

    monkeypatch.setattr(httpx, "AsyncClient", patched)
    return script, calls


@pytest.mark.asyncio
async def test_it_asks_for_a_code_and_waits(panel):
    script, calls = panel
    with pytest.raises(reporter.AwaitingApproval):
        await reporter.enrol_by_approval()

    assert [path for path, _ in calls] == [
        "/api/agents/device-code",
        "/api/agents/device-token",
    ]
    # It told the panel what it calls itself, so the approval page has
    # something to show.
    assert calls[0][1]["name"] == "kitchen-pi"


@pytest.mark.asyncio
async def test_the_printed_link_survives_a_restart(panel, caplog):
    # The link is on somebody's terminal. Asking for a second code would make
    # the one they are looking at stop working, with no explanation.
    script, calls = panel
    with caplog.at_level("WARNING"):
        with pytest.raises(reporter.AwaitingApproval):
            await reporter.enrol_by_approval()
    assert "K7RQ-4TDX" in caplog.text
    assert "/a/K7RQ-4TDX" in caplog.text

    for _ in range(3):
        with pytest.raises(reporter.AwaitingApproval):
            await reporter.enrol_by_approval()

    assert [p for p, _ in calls].count("/api/agents/device-code") == 1


@pytest.mark.asyncio
async def test_it_collects_the_key_once_approved(panel, state):
    script, _ = panel
    with pytest.raises(reporter.AwaitingApproval):
        await reporter.enrol_by_approval()

    script["approved"] = True
    agent_id, key = await reporter.enrol_by_approval()

    assert (agent_id, key) == (7, "k" * 40)
    assert reporter.load_credentials() == (7, "k" * 40)
    # And the half-finished enrolment is cleared, so a later restart does not
    # try to collect a spent code.
    assert reporter.load_pending() is None


@pytest.mark.asyncio
async def test_the_key_is_written_where_only_this_machine_can_read_it(panel, state):
    script, _ = panel
    script["approved"] = True
    await reporter.enrol_by_approval()

    import sys

    if sys.platform != "win32":
        mode = (state / "agent.json").stat().st_mode & 0o777
        assert mode == 0o600


@pytest.mark.asyncio
async def test_a_refused_code_is_forgotten_rather_than_polled_forever(panel):
    script, calls = panel
    with pytest.raises(reporter.AwaitingApproval):
        await reporter.enrol_by_approval()

    # The panel now refuses it: expired, or already collected elsewhere.
    script["secret"] = "different"
    with pytest.raises(reporter.NotEnrolled):
        await reporter.enrol_by_approval()

    assert reporter.load_pending() is None
    # So the next attempt starts again instead of hammering a dead code.
    script["secret"] = "s" * 40
    with pytest.raises(reporter.AwaitingApproval):
        await reporter.enrol_by_approval()
    assert [p for p, _ in calls].count("/api/agents/device-code") == 2


@pytest.mark.asyncio
async def test_an_expired_pending_code_is_not_reused(panel, state):
    script, calls = panel
    with pytest.raises(reporter.AwaitingApproval):
        await reporter.enrol_by_approval()

    stale = json.loads((state / "enrolment.json").read_text())
    stale["expires_at"] = time.time() - 1
    (state / "enrolment.json").write_text(json.dumps(stale))

    with pytest.raises(reporter.AwaitingApproval):
        await reporter.enrol_by_approval()
    assert [p for p, _ in calls].count("/api/agents/device-code") == 2


@pytest.mark.asyncio
async def test_an_unreadable_pending_file_is_ignored_not_fatal(panel, state):
    (state / "enrolment.json").write_text("{ this is not json")
    assert reporter.load_pending() is None
    with pytest.raises(reporter.AwaitingApproval):
        await reporter.enrol_by_approval()


# -- which path the agent takes ---------------------------------------------


@pytest.mark.asyncio
async def test_a_pre_auth_token_skips_the_waiting_entirely(panel, monkeypatch):
    # The unattended path: imaging a machine, or a config management run.
    # There is nobody at a browser, so it must not stop to wait for one.
    from cherubyte_agent import main

    monkeypatch.setattr(settings, "enrol_token", "preauth-token")
    used: list[str] = []

    async def enrol():
        used.append("token")
        return (3, "key")

    async def approval():
        used.append("approval")
        raise AssertionError("should not have waited for a human")

    monkeypatch.setattr(reporter, "enrol", enrol)
    monkeypatch.setattr(reporter, "enrol_by_approval", approval)
    monkeypatch.setattr(reporter, "load_credentials", lambda: None)

    assert await main._ensure_enrolled() == (3, "key")
    assert used == ["token"]


@pytest.mark.asyncio
async def test_waiting_for_approval_is_not_reported_as_a_failure(panel, monkeypatch):
    # A machine sitting at the enrolment prompt is working correctly, and the
    # health endpoint has to say something a person can act on rather than
    # "enrolment failed".
    from cherubyte_agent import main

    # `_state` is module-level and outlives a test, so the flag an earlier one
    # set has to be cleared rather than assumed.
    main._state.update({"enrolled": False, "last_error": None})
    monkeypatch.setattr(reporter, "load_credentials", lambda: None)

    async def approval():
        raise reporter.AwaitingApproval("K7RQ-4TDX")

    monkeypatch.setattr(reporter, "enrol_by_approval", approval)

    assert await main._ensure_enrolled() is None
    assert "K7RQ-4TDX" in main._state["last_error"]
    assert "approval" in main._state["last_error"]
    assert main._state["enrolled"] is False


# -- somewhere to find the link ----------------------------------------------


@pytest.mark.asyncio
async def test_the_link_is_left_in_a_file_a_person_can_find(panel, state, monkeypatch):
    # A Windows service has no console. The link printed to a log nobody reads
    # is how an agent ends up waiting forever with no way to admit it.
    from cherubyte_agent import config

    monkeypatch.setattr(config, "config_dir", lambda: state)
    with pytest.raises(reporter.AwaitingApproval):
        await reporter.enrol_by_approval()

    notice = (state / "enrolment.txt").read_text()
    assert "K7RQ-4TDX" in notice
    assert "http://panel.test/a/K7RQ-4TDX" in notice


@pytest.mark.asyncio
async def test_the_file_goes_away_once_the_machine_is_admitted(panel, state, monkeypatch):
    # A stale note telling somebody to approve a machine that is already
    # reporting is worse than no note.
    from cherubyte_agent import config

    monkeypatch.setattr(config, "config_dir", lambda: state)
    with pytest.raises(reporter.AwaitingApproval):
        await reporter.enrol_by_approval()
    assert (state / "enrolment.txt").exists()

    panel[0]["approved"] = True
    await reporter.enrol_by_approval()
    assert not (state / "enrolment.txt").exists()


@pytest.mark.asyncio
async def test_a_notice_that_cannot_be_written_is_not_fatal(panel, state, monkeypatch):
    # The agent still works and still logs the link; the file is the copy for
    # somebody who was not watching.
    #
    # The unwritable directory is a real file standing where a directory needs
    # to be, rather than a patched mkdir: patching it broke saving the pending
    # code as well, which is the thing under test failing for the wrong reason.
    from cherubyte_agent import config

    blocker = state / "blocker"
    blocker.write_text("not a directory")
    monkeypatch.setattr(config, "config_dir", lambda: blocker / "inside")

    with pytest.raises(reporter.AwaitingApproval):
        await reporter.enrol_by_approval()
    # The enrolment itself carried on: the code was requested and stored.
    assert reporter.load_pending() is not None


# -- what an unadmitted agent is allowed to do -------------------------------


@pytest.mark.asyncio
async def test_nothing_is_sniffed_until_the_machine_is_admitted(panel, monkeypatch):
    # It used to start both sniffers at startup, so an agent waiting to be
    # approved was already capturing packets on somebody's machine - work it
    # had nowhere to send, on a machine whose owner had not said yes yet.
    from cherubyte_agent import arp_sniffer, dhcp_sniffer, main

    started: list[str] = []
    monkeypatch.setattr(arp_sniffer, "start", lambda: started.append("arp"))
    monkeypatch.setattr(dhcp_sniffer, "start", lambda: started.append("dhcp"))
    monkeypatch.setattr(reporter, "load_credentials", lambda: None)

    async def waiting():
        raise reporter.AwaitingApproval("K7RQ-4TDX")

    monkeypatch.setattr(reporter, "enrol_by_approval", waiting)

    await main._cycle()
    assert started == []


@pytest.mark.asyncio
async def test_sniffing_begins_once_it_is_admitted(panel, monkeypatch):
    from cherubyte_agent import arp_sniffer, dhcp_sniffer, main

    started: list[str] = []
    monkeypatch.setattr(arp_sniffer, "start", lambda: started.append("arp"))
    monkeypatch.setattr(dhcp_sniffer, "start", lambda: started.append("dhcp"))
    monkeypatch.setattr(reporter, "load_credentials", lambda: (7, "key"))
    monkeypatch.setattr(settings, "auto_update", False)

    async def nothing_to_report(*_a, **_k):
        raise RuntimeError("stop here; the sniffers are what this is about")

    monkeypatch.setattr(main, "collect", nothing_to_report)
    with pytest.raises(RuntimeError):
        await main._cycle()

    assert sorted(started) == ["arp", "dhcp"]
