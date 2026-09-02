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


def _installed_marker() -> Path:
    """Where the last version this updater installed is recorded."""
    return Path(settings.state_file).with_name("installed-version")


def last_installed() -> str:
    try:
        return _installed_marker().read_text().strip()
    except OSError:
        return ""


def _record_installed(version: str) -> None:
    try:
        marker = _installed_marker()
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(version)
    except OSError as exc:
        # Not fatal, but it is the thing that stops an update loop, so it is
        # worth being loud about.
        logger.warning("Could not record the installed version: %s", exc)


SOURCE = "source"
ONEFILE = "onefile"
ONEDIR = "onedir"


def packaging_mode() -> str:
    """How this agent was built, which decides how it can be replaced.

    A onefile build is a single executable that unpacks itself to a temporary
    directory at each start, so swapping that one file is a complete update.
    A onedir build is a folder of libraries beside the executable: replacing
    the executable alone would leave it loading last version's libraries,
    which fails in ways that look nothing like a bad update.

    PyInstaller sets `_MEIPASS` to wherever it unpacked to. For onefile that
    is a temporary directory somewhere else; for onedir it is inside the
    installed folder. That is the difference, and it is more reliable than a
    build-time constant somebody has to remember to change.
    """
    if not getattr(sys, "frozen", False):
        return SOURCE
    unpacked = getattr(sys, "_MEIPASS", None)
    if not unpacked:
        return ONEFILE
    here = Path(sys.executable).resolve().parent
    try:
        return ONEDIR if Path(unpacked).resolve().is_relative_to(here) else ONEFILE
    except (OSError, ValueError):
        return ONEFILE


def running_binary() -> Path | None:
    """The executable to replace, or None when it cannot be replaced this way.

    Only a onefile build can be updated by swapping one file. Anything else
    goes through its installer, which is the thing that knows how to stop the
    service, replace a folder of locked libraries and start it again.
    """
    if packaging_mode() != ONEFILE:
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
        return  # source, or a folder build that updates through its installer
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
        if packaging_mode() == ONEDIR:
            # Not an error, and not silence either: an agent that quietly
            # stopped updating itself would look identical to one that was
            # already current.
            logger.info(
                "This build updates through its installer, which is not wired up yet. "
                "Reinstall from the latest release to move to a newer version."
            )
        return None

    base = settings.panel_url.rstrip("/")
    async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
        manifest = (
            await _fetch(client, f"{base}/api/agents/{agent_id}/update", agent_id, key)
        ).json()

        version = str(manifest.get("version") or "")
        if not version or not is_newer(version, current_version):
            return None

        if version == last_installed():
            # We already installed this and are still reporting something
            # older, which means the version compiled into the binary does not
            # match the release it came from. Without this the agent would
            # install it, exit, restart, and do the whole thing again forever.
            logger.error(
                "Refusing to install %s again: this agent reports itself as %s after "
                "already updating to %s, so its compiled-in version does not match the "
                "release it came from. Updates are stopped until that is fixed.",
                version,
                current_version,
                version,
            )
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

    _record_installed(version)
    logger.warning(
        "Updated to %s. Exiting so the service manager starts the new binary; "
        "the previous one is kept as %s until it does.",
        version,
        previous.name,
    )
    return version
