"""The command line, which is the secondary way in.

The primary one is the tray icon and the installer. This exists because
support questions are answered by asking somebody to run one command and paste
the output, and because a headless install has no tray to click.

It talks to the running service over the local health endpoint rather than
reading its files. Two reasons: the files are readable only by administrators,
so a plain user could not run `status` at all; and the endpoint is what the
service actually believes, where the files are only what it was told.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

from .config import CONFIG_FILE, settings

USAGE = """Cherubyte agent

  cherubyte-agent status      what the agent is doing right now
  cherubyte-agent up          admit this machine to a panel
  cherubyte-agent version     which build this is
  cherubyte-agent tray        run the status icon (started for you at login)

With no arguments it runs the agent itself, which is what the service does.
"""


def _endpoint(path: str = "/health") -> str:
    host = "127.0.0.1" if settings.health_host in ("0.0.0.0", "") else settings.health_host
    return f"http://{host}:{settings.health_port}{path}"


def read_state(timeout: float = 4.0) -> dict | None:
    """What the service says about itself, or None if it is not answering.

    A degraded agent answers 503 with the same body, and that is the case
    worth reporting — so the error is read rather than raised past.
    """
    try:
        with urllib.request.urlopen(_endpoint(), timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read())
        except Exception:  # noqa: BLE001
            return None
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _describe(state: dict) -> list[str]:
    lines = [
        f"  version    {state.get('version') or 'unknown'}",
        f"  panel      {state.get('panel_url') or 'not set'}",
    ]
    if not state.get("enrolled"):
        lines.append("  state      not admitted to a panel yet")
        if state.get("enrolment_url"):
            lines += [
                "",
                "  Approve this machine at:",
                f"    {state['enrolment_url']}",
                f"  Code: {state.get('enrolment_code') or ''}",
            ]
        else:
            lines.append("  (asking the panel for a code; try again in a moment)")
        return lines

    last = state.get("last_report_ok")
    reporting = "reporting" if last is not False else "the panel is refusing its reports"
    lines.append(f"  state      {reporting}")
    if state.get("last_sweep"):
        lines.append(f"  last sweep {state['last_sweep']}")
    if state.get("found") is not None:
        lines.append(f"  found      {state['found']} devices")
    if state.get("last_error"):
        lines.append(f"  note       {state['last_error']}")
    return lines


def cmd_status() -> int:
    state = read_state()
    if state is None:
        print("The Cherubyte agent is not answering on " + _endpoint() + ".")
        print("")
        print("It is either not running, or still starting up. On Windows:")
        print("  Get-Service CherubyteAgent")
        return 1
    print("Cherubyte agent")
    for line in _describe(state):
        print(line)
    return 0 if state.get("status") == "ok" else 1


def cmd_up(open_browser: bool = True) -> int:
    """Show the link that admits this machine, and wait for somebody to use it.

    The service is what actually enrols; this watches it. So running `up` on a
    machine that is already admitted says so rather than starting again, and
    running it twice does not produce two codes.
    """
    state = read_state()
    if state is None:
        print("The agent is not running, so there is nothing to admit yet.")
        return 1
    if state.get("enrolled"):
        print("This machine is already admitted to " + str(state.get("panel_url")))
        return 0

    # The service asks for a code on its first cycle, which may not have
    # happened yet on a fresh start.
    deadline = time.monotonic() + 90
    url = state.get("enrolment_url")
    while not url and time.monotonic() < deadline:
        time.sleep(2)
        state = read_state() or {}
        if state.get("enrolled"):
            print("Admitted.")
            return 0
        url = state.get("enrolment_url")

    if not url:
        print("The agent has not managed to ask the panel for a code.")
        print("Check that it can reach " + str(state.get("panel_url")) + ".")
        return 1

    print("")
    print("  Approve this machine at:")
    print("")
    print("    " + url)
    print("")
    print("  Code: " + str(state.get("enrolment_code") or ""))
    print("")

    if open_browser:
        try:
            import webbrowser

            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass

    print("Waiting for you to approve it. Ctrl+C to stop watching.", end="", flush=True)
    while time.monotonic() < deadline:
        time.sleep(3)
        print(".", end="", flush=True)
        state = read_state() or {}
        if state.get("enrolled"):
            print("")
            print("Admitted. The agent is reporting.")
            return 0
    print("")
    print("Nobody approved it in time. Run this again for a new code.")
    return 1


def cmd_apply_settings(argv: list[str]) -> int:
    """Write the configuration and restart the service. Needs to be elevated.

    Deliberately the only thing that writes `agent.env`. The settings window
    re-launches this with an administrator prompt rather than writing the file
    itself, so there is one place that touches the configuration and one place
    that has to be allowed to.

    Not in the usage text: it is an implementation detail of the window, and a
    person typing it by hand is better served by editing the file.
    """
    import argparse

    parser = argparse.ArgumentParser(prog="cherubyte-agent apply-settings")
    parser.add_argument("--panel", required=True)
    parser.add_argument("--name", default="")
    parser.add_argument("--auto-update", default="true")
    args = parser.parse_args(argv[1:])

    if not args.panel.startswith(("http://", "https://")):
        print("The panel address must start with http:// or https://", file=sys.stderr)
        return 2

    lines = [
        f"CHERUBYTE_AGENT_PANEL_URL={args.panel.rstrip('/')}",
        f"CHERUBYTE_AGENT_NAME={args.name}",
        f"CHERUBYTE_AGENT_AUTO_UPDATE={str(args.auto_update).lower()}",
    ]
    # The enrolment token, if one was used, stays exactly as it was. Rewriting
    # the file from scratch would drop it, and the next restart would find an
    # agent with a key it can still use and no way to get another.
    try:
        for existing in CONFIG_FILE.read_text().splitlines():
            key = existing.split("=", 1)[0].strip()
            if key and key not in {line.split("=", 1)[0] for line in lines}:
                lines.append(existing)
    except OSError:
        pass

    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text("\n".join(lines) + "\n")
    except PermissionError:
        print(
            "Writing " + str(CONFIG_FILE) + " needs administrator rights.",
            file=sys.stderr,
        )
        return 13
    except OSError as exc:
        print(f"Could not write {CONFIG_FILE}: {exc}", file=sys.stderr)
        return 1

    print(f"Wrote {CONFIG_FILE}")
    _restart_service()
    return 0


def _restart_service() -> None:
    """Bounce the service so it reads what was just written.

    Best effort and never fatal: the settings are on disk either way, and a
    restart that did not happen costs one reboot rather than a lost setting.
    """
    import subprocess

    commands = {
        "win32": [["sc.exe", "stop", "CherubyteAgent"], ["sc.exe", "start", "CherubyteAgent"]],
        "darwin": [
            ["launchctl", "kickstart", "-k", "system/pt.qqc.cherubyte-agent"],
        ],
    }.get(sys.platform, [["systemctl", "restart", "cherubyte-agent"]])
    for command in commands:
        try:
            subprocess.run(command, capture_output=True, timeout=30)
        except Exception as exc:  # noqa: BLE001
            print(f"Could not run {command[0]}: {exc}", file=sys.stderr)


def run(argv: list[str]) -> int:
    command = argv[0] if argv else ""
    if command == "status":
        return cmd_status()
    if command == "up":
        return cmd_up(open_browser="--no-browser" not in argv)
    if command == "version":
        from .reporter import AGENT_VERSION

        print(AGENT_VERSION)
        return 0
    if command == "apply-settings":
        return cmd_apply_settings(argv)
    if command == "tray":
        from .tray import run as run_tray

        return run_tray()
    print(USAGE, file=sys.stderr)
    return 2
