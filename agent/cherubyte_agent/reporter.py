"""The agent's half of the wire: enrolment, then reporting.

The agent pushes; the panel never reaches back. That is not a preference — an
agent sits on somebody's LAN behind NAT, so a panel that polled would need a
way in, which is the one thing a customer will not grant. Pushing also means
the same agent works unchanged when a relay is later put between the two: only
`panel_url` changes.
"""

from __future__ import annotations

import json
import time
import logging
from pathlib import Path

import httpx
from cherubyte_protocol import AgentReport, EnrolRequest, EnrolResponse, ReportAck

from .config import settings

logger = logging.getLogger("cherubyte.agent.reporter")

# The agent's own version — this repo's source of truth for it. Bump on every
# change; a GitHub release is tagged `v<this>` and the panel offers that build
# for download. (Independent of the panel's version and of PROTOCOL_VERSION.)
AGENT_VERSION = "1.2.2"


class NotEnrolled(RuntimeError):
    """No key yet, and no way to get one."""


class AwaitingApproval(RuntimeError):
    """A code has been issued and nobody has approved it yet.

    Not an error in the sense the others are: it is the normal state of a
    machine sitting at the enrolment prompt, and the caller waits rather than
    giving up.
    """


def _state_path() -> Path:
    return Path(settings.state_file)


def load_credentials() -> tuple[int, str] | None:
    """The (agent_id, key) issued at enrolment, if this agent has been admitted."""
    path = _state_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return int(data["agent_id"]), str(data["key"])
    except (ValueError, KeyError, OSError) as exc:
        logger.warning("Ignoring unreadable agent state at %s: %s", path, exc)
        return None


def save_credentials(agent_id: int, key: str) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"agent_id": agent_id, "key": key}))
    # the key is a bearer credential for this LAN's inventory
    path.chmod(0o600)


def panel_base() -> str:
    return settings.panel_url.rstrip("/")


async def enrol() -> tuple[int, str]:
    """Spend the enrolment token for a long-lived key.

    Raises NotEnrolled when there is no token — an agent with neither key nor
    token is misconfigured, and saying so beats retrying forever against a
    panel that will always refuse it.
    """
    if not settings.enrol_token:
        raise NotEnrolled(
            "No key stored and CHERUBYTE_AGENT_ENROL_TOKEN is empty. Issue a token "
            "in the panel (Agents) and set it, or mount the state file."
        )
    payload = EnrolRequest(
        token=settings.enrol_token,
        name=settings.name or "agent",
        version=AGENT_VERSION,
    )
    async with httpx.AsyncClient(timeout=settings.report_timeout_seconds) as client:
        response = await client.post(
            f"{panel_base()}/api/agents/enrol", json=payload.model_dump()
        )
    if response.status_code >= 400:
        raise NotEnrolled(
            f"Panel refused enrolment ({response.status_code}): {response.text[:200]}"
        )
    issued = EnrolResponse.model_validate(response.json())
    save_credentials(issued.agent_id, issued.key)
    logger.info("Enrolled with the panel as agent %s (%s)", issued.agent_id, issued.name)
    return issued.agent_id, issued.key


# ── enrolling by approval ──────────────────────────────────────────────────
#
# The other way in, and the one a person uses. Rather than carrying a token
# from the panel to this machine, the machine asks for a code, prints a link,
# and somebody already signed in to the panel approves it. Nothing is copied,
# so nothing is left in a shell history or a config file afterwards.
#
# The shape is the OAuth device flow: a short code for the human, a long secret
# for the machine, and polling until the answer changes. Which means it works
# on a headless box over SSH, where opening a browser locally does not.


def _pending_path() -> Path:
    """Where an unfinished enrolment is kept between restarts.

    Alongside the key, because it becomes the key. Without this a service that
    restarts while somebody is walking to their browser would throw away the
    code it just printed and ask for another, and the link in the terminal
    would quietly stop working.
    """
    return _state_path().with_name("enrolment.json")


def load_pending() -> dict | None:
    path = _pending_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (ValueError, OSError):
        return None
    if not data.get("code") or not data.get("poll_secret"):
        return None
    if time.time() > float(data.get("expires_at", 0)):
        return None
    return data


def save_pending(data: dict) -> None:
    path = _pending_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    # The poll secret collects a key, so it is a credential like any other.
    path.chmod(0o600)


def _notice_path() -> Path:
    """Where the approval link is left for a person to find.

    Next to the configuration rather than the state file, because somebody
    looking for it will be looking where the installer told them the config
    lives, not where a key they have never seen is kept.
    """
    from .config import config_dir

    return config_dir() / "enrolment.txt"


def _leave_notice(pending: dict) -> None:
    """Write the link to a file, since a service has nowhere to print it."""
    text = "\n".join(
        [
            "This machine is waiting to be admitted to a Cherubyte panel.",
            "",
            "  Open:  " + str(pending.get("verification_url", "")),
            "  Code:  " + str(pending.get("code", "")),
            "",
            "Approve it while signed in to your panel. This file disappears",
            "once the machine has been admitted.",
            "",
        ]
    )
    try:
        path = _notice_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    except OSError as exc:
        # The agent still works and still prints the link; this is the copy
        # for somebody who was not watching.
        logger.warning("Could not write the enrolment notice: %s", exc)


def clear_pending() -> None:
    _pending_path().unlink(missing_ok=True)
    # The link is dead once the code is spent, and a stale file telling
    # somebody to approve a machine that is already reporting is worse than
    # no file at all.
    _notice_path().unlink(missing_ok=True)


async def request_device_code() -> dict:
    """Ask the panel for a code, and remember it."""
    async with httpx.AsyncClient(timeout=settings.report_timeout_seconds) as client:
        response = await client.post(
            f"{panel_base()}/api/agents/device-code",
            json={"name": settings.name or "", "version": AGENT_VERSION},
        )
    if response.status_code >= 400:
        raise NotEnrolled(
            f"Panel refused to issue an enrolment code ({response.status_code}): "
            f"{response.text[:200]}"
        )
    issued = response.json()
    issued["expires_at"] = time.time() + float(issued.get("expires_in", 600))
    save_pending(issued)
    return issued


async def collect_device_key(pending: dict) -> tuple[int, str]:
    """Try to collect the key. Raises AwaitingApproval until somebody says yes."""
    async with httpx.AsyncClient(timeout=settings.report_timeout_seconds) as client:
        response = await client.post(
            f"{panel_base()}/api/agents/device-token",
            json={"code": pending["code"], "poll_secret": pending["poll_secret"]},
        )
    if response.status_code == 202:
        raise AwaitingApproval(pending["code"])
    if response.status_code >= 400:
        # The code is spent, expired or wrong. Forget it so the next attempt
        # asks for a fresh one instead of polling a dead code forever.
        clear_pending()
        raise NotEnrolled(
            f"Enrolment code refused ({response.status_code}): {response.text[:200]}"
        )
    issued = EnrolResponse.model_validate(response.json())
    save_credentials(issued.agent_id, issued.key)
    clear_pending()
    logger.info("Enrolled with the panel as agent %s (%s)", issued.agent_id, issued.name)
    return issued.agent_id, issued.key


async def enrol_by_approval() -> tuple[int, str]:
    """One step of the approval flow: ask if needed, then try to collect.

    Called repeatedly by the caller's own loop rather than blocking here, so a
    service is never wedged inside enrolment and its health endpoint keeps
    answering while somebody finds their browser.
    """
    pending = load_pending()
    if pending is None:
        pending = await request_device_code()
        _leave_notice(pending)
        logger.warning(
            "\n\n  This machine is not enrolled yet.\n"
            "  To admit it, open:\n\n      %s\n\n"
            "  and approve the code %s. The link is good for %d minutes.\n",
            pending.get("verification_url", ""),
            pending.get("code", ""),
            int(float(pending.get("expires_in", 600)) // 60),
        )
    return await collect_device_key(pending)


async def send(report: AgentReport, agent_id: int, key: str) -> ReportAck | None:
    """Deliver one report and return the panel's ack, or None if it did not land.

    Never raises: a panel that is down must not stop the sweep loop, and the
    next report carries the current state anyway.
    """
    try:
        async with httpx.AsyncClient(timeout=settings.report_timeout_seconds) as client:
            response = await client.post(
                f"{panel_base()}/api/agents/{agent_id}/report",
                content=report.model_dump_json(),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {key}",
                },
            )
    except httpx.HTTPError as exc:
        logger.warning("Could not reach the panel: %s", exc)
        return None
    if response.status_code == 401:
        logger.error("Panel rejected this agent's key — re-enrolment needed")
        return None
    if response.status_code >= 400:
        logger.warning("Panel refused the report (%s): %s", response.status_code,
                       response.text[:200])
        return None
    try:
        return ReportAck.model_validate(response.json())
    except (ValueError, TypeError) as exc:
        # The report landed; only the ack was unreadable. Say so, but do not
        # treat a delivered sweep as a failure.
        logger.warning("Panel ack was unreadable: %s", exc)
        return ReportAck()
