"""The agent's half of the wire: enrolment, then reporting.

The agent pushes; the panel never reaches back. That is not a preference — an
agent sits on somebody's LAN behind NAT, so a panel that polled would need a
way in, which is the one thing a customer will not grant. Pushing also means
the same agent works unchanged when a relay is later put between the two: only
`panel_url` changes.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import httpx
from cherubyte_protocol import AgentReport, EnrolRequest, EnrolResponse, ReportAck

from .config import settings

logger = logging.getLogger("cherubyte.agent.reporter")

# The agent's own version — this repo's source of truth for it. Bump on every
# change; a GitHub release is tagged `v<this>` and the panel offers that build
# for download. (Independent of the panel's version and of PROTOCOL_VERSION.)
AGENT_VERSION = "1.1.1"


class NotEnrolled(RuntimeError):
    """No key yet, and no token to get one with."""


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
