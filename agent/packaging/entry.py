"""PyInstaller entry point.

On Windows the binary is a service and must speak the Service Control Manager
protocol. Everywhere else it is an ordinary foreground process, because systemd
and launchd supervise a normal process and want it to stay in the foreground.
"""

import sys

# The verbs this binary answers to besides being a service. Kept apart from
# the Windows service framework's own words - install, update, remove, start,
# stop, restart, debug - which pywin32 parses out of the same argv.
CLI_COMMANDS = {"status", "up", "version", "tray", "apply-settings", "--help", "-h", "help"}


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] in CLI_COMMANDS:
        from cherubyte_agent.cli import run

        raise SystemExit(run(argv))

    if sys.platform == "win32":
        from cherubyte_agent.winservice import main as service_main

        service_main()
        return

    import uvicorn

    from cherubyte_agent.config import settings

    uvicorn.run(
        "cherubyte_agent.main:app", host=settings.health_host, port=settings.health_port
    )


if __name__ == "__main__":
    main()
