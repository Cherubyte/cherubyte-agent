"""The command line and the tray icon.

Both exist for one reason: the agent is a service, and a service cannot tell
anybody anything. The first Windows install ended up with a machine that was
either working or not, with no way to find out and no way to see the link that
would have admitted it.

So what is worth testing here is not the drawing. It is that the three states
somebody actually cares about - not admitted, admitted and reporting, running
but refused - are told apart correctly and described in words that mean
something. The icon and the window are thin layers over that.
"""

from __future__ import annotations

import json

import pytest

from cherubyte_agent import cli, tray
from cherubyte_agent.config import settings


@pytest.fixture
def answers(monkeypatch):
    """What the health endpoint says, per test."""
    body: dict = {"value": None, "raise_http": None}

    class _Response:
        def __init__(self, payload):
            self._payload = json.dumps(payload).encode()

        def read(self):
            return self._payload

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def close(self):
            # HTTPError wraps whatever it is given as a file object and closes
            # it on collection. Without this the teardown raises in a
            # destructor, which pytest reports as an unrelated warning.
            pass

    def urlopen(*_a, **_k):
        if body["raise_http"] is not None:
            import urllib.error

            raise urllib.error.HTTPError(
                "u", 503, "degraded", None, _Response(body["raise_http"])
            )
        if body["value"] is None:
            import urllib.error

            raise urllib.error.URLError("connection refused")
        return _Response(body["value"])

    monkeypatch.setattr(cli.urllib.request, "urlopen", urlopen)
    return body


# -- reading the service -----------------------------------------------------


def test_a_degraded_agent_is_read_rather_than_treated_as_absent(answers):
    # It answers 503 with the body that explains why, and that is exactly the
    # case worth reporting. Letting the error propagate would report the most
    # interesting failure as "not running".
    answers["raise_http"] = {"status": "degraded", "enrolled": False, "version": "1.2.3"}
    state = cli.read_state()
    assert state is not None
    assert state["status"] == "degraded"


def test_an_agent_that_is_not_running_reads_as_nothing(answers):
    answers["value"] = None
    assert cli.read_state() is None


def test_status_says_where_it_looked_when_nothing_answers(answers, capsys):
    answers["value"] = None
    assert cli.cmd_status() == 1
    out = capsys.readouterr().out
    # The address matters: somebody whose agent is on another port needs to
    # see that this looked in the wrong place.
    assert str(settings.health_port) in out
    assert "not answering" in out


def test_status_shows_the_link_when_one_is_waiting(answers, capsys):
    answers["value"] = {
        "status": "degraded",
        "enrolled": False,
        "version": "1.2.3",
        "panel_url": "https://app.test",
        "enrolment_url": "https://app.test/a/K7RQ-4TDX",
        "enrolment_code": "K7RQ-4TDX",
    }
    cli.cmd_status()
    out = capsys.readouterr().out
    assert "https://app.test/a/K7RQ-4TDX" in out
    assert "K7RQ-4TDX" in out


def test_status_exits_nonzero_when_the_agent_is_unhappy(answers):
    # So a monitoring script can use it without parsing anything.
    answers["value"] = {"status": "degraded", "enrolled": False}
    assert cli.cmd_status() == 1
    answers["value"] = {"status": "ok", "enrolled": True, "last_report_ok": True}
    assert cli.cmd_status() == 0


def test_up_on_an_admitted_machine_does_not_start_again(answers, capsys):
    # Otherwise running it twice out of uncertainty produces a second code and
    # invalidates the link somebody is already looking at.
    answers["value"] = {"status": "ok", "enrolled": True, "panel_url": "https://app.test"}
    assert cli.cmd_up(open_browser=False) == 0
    assert "already admitted" in capsys.readouterr().out


def test_up_says_so_when_the_agent_is_not_running(answers, capsys):
    answers["value"] = None
    assert cli.cmd_up(open_browser=False) == 1
    assert "not running" in capsys.readouterr().out


def test_unknown_commands_print_the_usage(capsys):
    assert cli.run(["nonsense"]) == 2
    assert "cherubyte-agent status" in capsys.readouterr().err


def test_version_is_the_one_compiled_in(capsys):
    from cherubyte_agent.reporter import AGENT_VERSION

    assert cli.run(["version"]) == 0
    assert capsys.readouterr().out.strip() == AGENT_VERSION


# -- what the icon is saying -------------------------------------------------


def test_the_three_states_are_told_apart():
    assert tray._state_of(None) == tray.OFFLINE
    assert tray._state_of({"enrolled": False}) == tray.ATTENTION
    # Running and enrolled, but the panel is refusing it. Green here would be
    # the worst possible answer: everything looks fine and no data is arriving.
    assert tray._state_of({"enrolled": True, "last_report_ok": False}) == tray.ATTENTION
    assert tray._state_of({"enrolled": True, "last_report_ok": True}) == tray.OK


def test_the_summary_says_something_a_person_can_act_on():
    assert tray._summary(None) == "Not running"
    assert "approved" in tray._summary({"enrolled": False, "enrolment_url": "u"})
    assert "refusing" in tray._summary({"enrolled": True, "last_report_ok": False})
    assert "41" in tray._summary({"enrolled": True, "last_report_ok": True, "found": 41})


def test_the_icon_differs_between_states():
    # Not about the drawing, about there being a difference to see at all.
    images = {state: tray._icon_image(state).tobytes() for state in (tray.OK, tray.ATTENTION, tray.OFFLINE)}
    assert len(set(images.values())) == 3


def test_hiding_the_icon_does_not_stop_the_agent():
    # They are different processes and only one of them matters. A menu item
    # that silently stopped monitoring the network would be a trap.
    icon = tray.Tray()

    class _FakeIcon:
        def __init__(self):
            self.stopped = False

        def stop(self):
            self.stopped = True

    icon.icon = _FakeIcon()
    icon._quit()
    assert icon.icon.stopped
    assert icon._stop.is_set()


# -- saving settings ---------------------------------------------------------


def test_settings_refuse_an_address_that_is_not_one(tmp_path, monkeypatch):
    from cherubyte_agent import cli as cli_module

    monkeypatch.setattr(cli_module, "CONFIG_FILE", tmp_path / "agent.env")
    assert cli.run(["apply-settings", "--panel", "app.cherubyte.app"]) == 2
    assert not (tmp_path / "agent.env").exists()


def test_saving_settings_keeps_the_lines_it_was_not_asked_about(tmp_path, monkeypatch):
    # Rewriting the file wholesale would drop the enrolment token, leaving an
    # agent that cannot enrol again and no sign of why.
    from cherubyte_agent import cli as cli_module

    config = tmp_path / "agent.env"
    config.write_text(
        "CHERUBYTE_AGENT_PANEL_URL=http://old\n"
        "CHERUBYTE_AGENT_ENROL_TOKEN=keep-me\n"
        "CHERUBYTE_AGENT_SUBNET=192.168.1.0/24\n"
    )
    monkeypatch.setattr(cli_module, "CONFIG_FILE", config)
    monkeypatch.setattr(cli_module, "_restart_service", lambda: None)

    assert cli.run(["apply-settings", "--panel", "https://new.test/", "--name", "sala"]) == 0

    written = config.read_text()
    assert "CHERUBYTE_AGENT_PANEL_URL=https://new.test" in written
    assert "CHERUBYTE_AGENT_NAME=sala" in written
    assert "CHERUBYTE_AGENT_ENROL_TOKEN=keep-me" in written
    assert "CHERUBYTE_AGENT_SUBNET=192.168.1.0/24" in written
    # And the old panel line is gone rather than duplicated.
    assert written.count("CHERUBYTE_AGENT_PANEL_URL") == 1


def test_saving_without_rights_says_that_rather_than_failing_obscurely(tmp_path, monkeypatch):
    from cherubyte_agent import cli as cli_module

    config = tmp_path / "agent.env"
    monkeypatch.setattr(cli_module, "CONFIG_FILE", config)

    def refuse(*_a, **_k):
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr(cli_module.CONFIG_FILE.__class__, "write_text", refuse)
    code = cli.run(["apply-settings", "--panel", "https://new.test"])
    assert code == 13
