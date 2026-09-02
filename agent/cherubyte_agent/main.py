"""The agent process: sweep, report, repeat.

It holds no database and serves no UI. The only thing it listens on is a health
endpoint, so a container runtime can tell a wedged agent from a working one.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from . import actions, arp_sniffer, dhcp_sniffer, reporter, updater, wol
from .collector import collect
from .config import apply_config, settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
logger = logging.getLogger("cherubyte.agent")

_state: dict = {
    "enrolled": False,
    "last_report_at": None,
    "last_report_ok": None,
    "last_hosts": None,
    "last_error": None,
}

# Set to cut the loop's wait short: the panel's Sweep button (via POST /trigger
# or the scan_now flag on an ack) asks for one cycle now rather than at the end
# of the interval.
_wake = asyncio.Event()


async def _ensure_enrolled() -> tuple[int, str] | None:
    stored = reporter.load_credentials()
    if stored:
        _state["enrolled"] = True
        return stored
    try:
        # A pre-auth token wins when one is set: that is the unattended path,
        # for imaging a machine or a config management run, and it must not
        # stop to wait for a human who is not there.
        if settings.enrol_token:
            issued = await reporter.enrol()
        else:
            issued = await reporter.enrol_by_approval()
    except reporter.AwaitingApproval as exc:
        # Not a failure. Somebody is walking to their browser.
        _state["last_error"] = f"waiting for approval of code {exc}"
        return None
    except reporter.NotEnrolled as exc:
        _state["last_error"] = str(exc)
        logger.error("%s", exc)
        return None
    except Exception as exc:  # noqa: BLE001
        _state["last_error"] = f"enrolment failed: {exc}"
        logger.warning("Enrolment attempt failed: %s", exc)
        return None
    _state["enrolled"] = True
    _state["last_error"] = None
    return issued


def _start_sniffers() -> None:
    """Begin listening, now that this agent has been admitted.

    Deliberately not at startup. An agent waiting to be approved has nowhere
    to send anything it hears, so capturing packets before then is work with
    no purpose - and on a machine whose owner has not yet said yes. Both
    start() calls are idempotent, so calling this every cycle costs a branch.
    """
    if settings.enable_dhcp_sniffer:
        dhcp_sniffer.start()
    if settings.enable_passive_arp:
        arp_sniffer.start()


async def _cycle() -> None:
    credentials = await _ensure_enrolled()
    if credentials is None:
        return
    agent_id, key = credentials
    _start_sniffers()
    # Before the sweep, not after: if this installs something it exits, and
    # doing a full scan first would throw that work away.
    await _maybe_update(agent_id, key)
    report = await collect()
    # Outcomes from actions the previous cycle picked up — there was nothing
    # to send them on until this report.
    report.action_results = actions.take_pending()
    ack = await reporter.send(report, agent_id, key)
    if ack is not None:
        changed = apply_config(ack.config)
        if changed:
            logger.info("Panel configuration applied: %s", ", ".join(sorted(changed)))
        if getattr(ack, "scan_now", False):
            # The panel wanted a sweep and could not reach us directly.
            logger.info("Panel requested an out-of-band sweep")
            _wake.set()
        macs = getattr(ack, "wake", None) or []
        if macs:
            wol.send_all(macs)
        pending_actions = getattr(ack, "actions", None) or []
        if pending_actions:
            logger.info("Running %d on-demand action(s) from the panel", len(pending_actions))
            await actions.run_and_stash(pending_actions)
    _state.update(
        last_report_at=datetime.now(timezone.utc).isoformat(),
        last_report_ok=ack is not None,
        last_hosts=len(report.hosts),
    )
    logger.info(
        "Reported %d hosts (%s)",
        len(report.hosts),
        "accepted" if ack is not None else "refused",
    )


# None until the first check, rather than 0.0. `time.monotonic()` counts from
# an arbitrary point — on Linux, boot — so comparing an interval against 0.0
# means "has this machine been up for six hours", not "has it been six hours
# since the last check". A machine rebooted daily would never have updated.
_last_update_check: float | None = None


async def _maybe_update(agent_id: int, key: str) -> None:
    """Check for a newer release, occasionally, and install it if it verifies.

    Exits the process on success rather than trying to carry on: the binary
    under this process has been replaced, and the service manager starting the
    new one is the whole mechanism. Everything up to that point leaves the
    running agent untouched, so a failure here costs one log line.
    """
    global _last_update_check
    if not settings.auto_update:
        return
    now = time.monotonic()
    if (
        _last_update_check is not None
        and now - _last_update_check < settings.update_check_interval_seconds
    ):
        return
    _last_update_check = now

    try:
        installed = await updater.check_and_apply(agent_id, key, reporter.AGENT_VERSION)
    except (updater.UpdateError, Exception) as exc:  # noqa: BLE001
        # Never fatal. An agent that stops reporting because an update failed
        # is worse than one running last month's build.
        logger.warning("Update check failed: %s", exc)
        return
    if installed:
        logger.warning("Restarting into %s", installed)
        # The service manager brings it back. Both units are Restart=on-failure,
        # and a clean exit here would not be restarted — so this is deliberately
        # a failing status.
        os._exit(1)


async def _loop() -> None:
    # a short delay so the panel has a chance to be up in a compose start
    await asyncio.sleep(3)
    while True:
        try:
            await _cycle()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            _state["last_error"] = str(exc)
            logger.exception("Cycle failed")
        # Sleep out the interval, but wake early if a sweep was asked for.
        _wake.clear()
        try:
            await asyncio.wait_for(_wake.wait(), timeout=max(15, settings.scan_interval_seconds))
        except asyncio.TimeoutError:
            pass


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # The sniffers are NOT started here. They used to be, which meant an agent
    # nobody had admitted yet was already capturing packets on somebody's
    # machine - doing work whose results it had nowhere to send, and listening
    # before anyone had said it could. They start on the first cycle that has
    # credentials instead. See _start_sniffers.
    # Getting this far is the proof the new binary works, so the one it
    # replaced can go.
    updater.sweep_previous()
    task = asyncio.create_task(_loop())
    logger.info("Cherubyte agent up; panel=%s", reporter.panel_base())
    yield
    task.cancel()
    dhcp_sniffer.stop()
    arp_sniffer.stop()


app = FastAPI(title="Cherubyte agent", version=reporter.AGENT_VERSION, lifespan=lifespan)


@app.post("/trigger")
async def trigger():
    """Ask the loop to run a cycle now. The panel calls this when someone
    presses Sweep and it can reach the agent directly; otherwise it falls back
    to the scan_now flag on the next report's ack."""
    _wake.set()
    return {"queued": True}


@app.get("/health")
async def health():
    """Healthy means the loop is running and the panel accepted the last report.

    Reporting healthy while every report is being refused would hide the one
    failure that makes the agent useless.
    """
    ok = _state["enrolled"] and _state["last_report_ok"] is not False
    return JSONResponse(
        {"status": "ok" if ok else "degraded", **_state},
        status_code=200 if ok else 503,
    )
