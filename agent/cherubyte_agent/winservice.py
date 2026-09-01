"""Windows service wrapper for the agent.

A console executable registered with `sc create` does not work: the Service
Control Manager expects the process to answer its control requests, and one
that does not is killed with "error 1053: the service did not respond to the
start or control request in a timely fashion". So the executable has to speak
the SCM protocol itself, which is what this does.

Built into a single .exe by the `agent-windows` workflow, which then installs
it, starts it and calls its health endpoint on a real Windows runner — the
packaging and the service registration are the parts most likely to be wrong,
and neither can be exercised anywhere else.
"""

from __future__ import annotations

import sys
import threading

import servicemanager
import win32event
import win32service
import win32serviceutil

SERVICE_NAME = "CherubyteAgent"


class CherubyteAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = "Cherubyte Agent"
    _svc_description_ = "Scans this network and reports to a Cherubyte panel."

    def __init__(self, args):
        super().__init__(args)
        self._stop_event = win32event.CreateEvent(None, 0, 0, None)
        self._server = None

    def SvcStop(self) -> None:
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self._server is not None:
            # Ask uvicorn to unwind rather than killing the process: the agent
            # may be mid-report, and a half-sent report is worse than a late one.
            self._server.should_exit = True
        win32event.SetEvent(self._stop_event)

    def SvcDoRun(self) -> None:
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        import uvicorn

        from .config import settings

        config = uvicorn.Config(
            "cherubyte_agent.main:app",
            host=settings.health_host,
            port=settings.health_port,
            log_config=None,
        )
        self._server = uvicorn.Server(config)

        thread = threading.Thread(target=self._server.run, daemon=True)
        thread.start()
        win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)
        thread.join(timeout=20)


def main() -> None:
    """Entry point for the packaged executable.

    With no arguments the SCM is starting us, so hand control to the dispatcher.
    With arguments a person is, so accept install/start/stop/remove.
    """
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(CherubyteAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(CherubyteAgentService)


if __name__ == "__main__":
    main()
