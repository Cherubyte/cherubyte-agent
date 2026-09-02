"""Replacing this binary with a newer one, safely.

Downloads come from the agent's own panel, which is the only address it is
already talking to and the only one guaranteed to be reachable from a LAN
behind a firewall. That puts the panel in the path of every update, so
**nothing is executed on the panel's word**: the digest list is signed by a key
compiled into this binary, and a download whose digest is not in that list is
deleted rather than installed. See `release_key`.

**Swapping a running executable.** Windows will not let you overwrite one, but
it will let you rename it, and so will everything else. So the dance is:

    binary       -> binary.old      (the running one steps aside)
    binary.new   -> binary          (the verified download takes its place)
    exit                             (the service manager starts the new one)

The `.old` copy is deleted on the next start, which doubles as the signal that
the new binary got far enough to run. If it never starts, the file is still
there and a person has one rename to get back.

**Only for a packaged binary.** Running from a source checkout, there is
nothing to replace and pip is the update mechanism, so it declines rather than
doing something clever.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import httpx

from .config import settings
from .release_key import (
    SIGNATURE_NAME,
    SUMS_NAME,
    VerificationError,
    check_asset,
    verify_sums,
)

logger = logging.getLogger("cherubyte.agent.updater")

PLATFORM_KEY = (
    "windows" if sys.platform == "win32" else "macos" if sys.platform == "darwin" else "linux"
)


class UpdateError(RuntimeError):
    """The update could not be completed. The running binary is untouched."""


def running_binary() -> Path | None:
    """The executable to replace, or None when running from source.

    PyInstaller sets `frozen`; without it this is a checkout or a pip install
    and there is no single file that is the agent.
    """
    if not getattr(sys, "frozen", False):
        return None
    return Path(sys.executable).resolve()


def sweep_previous() -> None:
    """Delete the binary we stepped aside from, if the new one is running.

    Called at startup, and getting here *is* the proof that the new binary
    works: it started, imported its own modules and reached this line. Until
    then the old one is deliberately left where a person can rename it back.
    """
    current = running_binary()
    if current is None:
        return
    previous = current.with_name(current.name + ".old")
    if previous.exists():
        try:
            previous.unlink()
            logger.info("Removed the previous binary after a successful start")
        except OSError as exc:
            # Not fatal. A stale file wastes disk and nothing else.
            logger.warning("Could not remove %s: %s", previous, exc)


def _version_tuple(value: str) -> tuple:
    parts = []
    for chunk in (value or "").strip().lstrip("v").split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts or [0])


def is_newer(candidate: str, current: str) -> bool:
    return _version_tuple(candidate) > _version_tuple(current)


async def _fetch(client: httpx.AsyncClient, url: str, agent_id: int, key: str) -> httpx.Response:
    response = await client.get(url, headers={"Authorization": f"Bearer {key}"})
    if response.status_code >= 400:
        raise UpdateError(f"{url} returned {response.status_code}")
    return response


async def check_and_apply(agent_id: int, key: str, current_version: str) -> str | None:
    """Update if there is a newer, properly signed release. Returns its version.

    Returns None when there is nothing to do, and raises only when something
    went wrong that is worth reporting. Either way the running binary is left
    alone unless the replacement has been downloaded and verified in full.
    """
    binary = running_binary()
    if binary is None:
        return None

    base = settings.panel_url.rstrip("/")
    async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
        manifest = (
            await _fetch(client, f"{base}/api/agents/{agent_id}/update", agent_id, key)
        ).json()

        version = str(manifest.get("version") or "")
        if not version or not is_newer(version, current_version):
            return None

        if not manifest.get("sums") or not manifest.get("signature"):
            # An older release, from before signing. Refusing is the whole
            # point: an unsigned update is one the panel could have written.
            raise UpdateError(
                f"release {version} carries no signed digest list; not installing it"
            )

        import base64

        digests = verify_sums(
            manifest["sums"].encode("utf-8"), base64.b64decode(manifest["signature"])
        )
        asset_name = (manifest.get("assets") or {}).get(PLATFORM_KEY)
        if not asset_name:
            raise UpdateError(f"release {version} has no build for {PLATFORM_KEY}")

        payload = (
            await _fetch(
                client,
                f"{base}/api/agents/{agent_id}/update/download?platform={PLATFORM_KEY}",
                agent_id,
                key,
            )
        ).content

    # Before anything touches the filesystem.
    check_asset(payload, asset_name, digests)

    staged = binary.with_name(binary.name + ".new")
    previous = binary.with_name(binary.name + ".old")
    try:
        staged.write_bytes(payload)
        staged.chmod(0o755)
    except OSError as exc:
        staged.unlink(missing_ok=True)
        raise UpdateError(f"could not write the new binary: {exc}") from exc

    try:
        previous.unlink(missing_ok=True)
        # Rename rather than overwrite: Windows refuses to overwrite a running
        # executable but is happy to rename one out of the way.
        os.replace(binary, previous)
        os.replace(staged, binary)
    except OSError as exc:
        # Put it back if the second rename is what failed, so a half-swap does
        # not leave the service with no binary at all.
        if not binary.exists() and previous.exists():
            os.replace(previous, binary)
        staged.unlink(missing_ok=True)
        raise UpdateError(f"could not swap the binary: {exc}") from exc

    logger.warning(
        "Updated to %s. Exiting so the service manager starts the new binary; "
        "the previous one is kept as %s until it does.",
        version,
        previous.name,
    )
    return version
