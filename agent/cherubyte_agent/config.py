"""Agent configuration.

Two sources, in this order: the environment, then a config file at a
well-known per-OS path. The environment wins, so a container keeps being
configured with `-e` and nothing changes for Docker.

**Why a file at all, rather than environment variables everywhere.** On Windows
a service does not reliably see machine environment variables set after boot:
the Service Control Manager caches its environment block, so a variable written
by an installer is invisible to the service it just registered until the
machine reboots. The agent would start with the built-in defaults, never find a
panel, and report itself healthy-but-idle — which is exactly what happened, and
what the CI check was too weak to catch.

A file is also the same mechanism on all three platforms, so the Windows,
systemd and launchd installers differ only in where they write it.
"""

import os
import sys
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


def config_dir() -> Path:
    """Where an installer writes `agent.env`."""
    if sys.platform == "win32":
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "Cherubyte Agent"
    if sys.platform == "darwin":
        return Path("/Library/Application Support/Cherubyte Agent")
    return Path("/etc/cherubyte-agent")


def state_dir() -> Path:
    """Where the key issued at enrolment is kept between restarts.

    Deliberately outside the install directory on every platform, so upgrading
    the binary cannot lose the key — and enrolment tokens are single-use, so
    losing it means needing a fresh one.
    """
    if sys.platform == "win32":
        return config_dir()
    if sys.platform == "darwin":
        return Path("/Library/Application Support/Cherubyte Agent")
    return Path("/var/lib/cherubyte-agent")


CONFIG_FILE = config_dir() / "agent.env"
STATE_DIR = state_dir()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        # A repo checkout keeps working from agent/.env; an installed agent
        # reads the file its installer wrote. Both are optional.
        env_file=(BASE_DIR / ".env", CONFIG_FILE),
        env_prefix="CHERUBYTE_AGENT_",
        extra="ignore",
    )

    # Where the panel is, and how this agent proves who it is. The enrolment
    # token is spent once, on first start, for a long-lived key.
    panel_url: str = "http://panel:1001"
    enrol_token: str = ""
    name: str = ""
    # Where the issued key is kept between restarts. Mount this.
    state_file: str = str(STATE_DIR / "agent.json")

    # Health endpoint, so a container runtime can tell a wedged agent from a
    # working one. Deliberately not an API — the agent takes no orders.
    health_host: str = "0.0.0.0"
    health_port: int = 1002

    # Scanning. Mirrors what the panel used to own; see the scanner module.
    subnet: str = ""
    subnets: list[dict] = []
    interface: str = ""
    scan_interval_seconds: int = 60
    arp_timeout: float = 2.0
    identify_interval_seconds: int = 900
    identify_batch: int = 16
    full_sweep_interval_seconds: int = 900
    port_probe_concurrency: int = 256
    enable_reverse_dns: bool = True
    enable_port_probe: bool = True
    enable_dhcp_sniffer: bool = True
    enable_passive_arp: bool = True
    # A passive sighting older than this cannot vouch for a host still being
    # there — keeps arp_sniffer's never-forgets cache from pinning a device
    # online long after it has actually left. Kept below the panel's
    # offline_after_seconds (180s) so one stray overheard packet can never hold
    # a device online longer than the panel's own grace window would have.
    passive_arp_ttl_seconds: int = 120
    enable_snmp: bool = False
    snmp_community: str = "public"

    # Internet reachability probe, reported alongside the sweep.
    wan_enabled: bool = True
    wan_target: str = "1.1.1.1"

    # How long to wait for the panel before giving up on one report.
    report_timeout_seconds: float = 30.0


settings = Settings()

# Fields the operator set explicitly on this machine. The panel's configuration
# fills in everything else, but never overrules these: a value set on the box
# and then silently overwritten on the first report is a setting whose owner
# has no way to see why it did not take.
PINNED: frozenset[str] = frozenset(settings.model_fields_set)


def apply_config(config, *, pinned: frozenset[str] = PINNED) -> list[str]:
    """Adopt the panel's configuration for every field not pinned locally.

    Returns the names of the fields that changed, so a restart is not needed to
    tell whether the panel is actually driving this agent.
    """
    changed: list[str] = []
    for field, value in config.model_dump().items():
        if field in pinned or not hasattr(settings, field):
            continue
        if field == "subnets":
            value = [{"cidr": c, "label": ""} for c in value]
        if getattr(settings, field) == value:
            continue
        setattr(settings, field, value)
        changed.append(field)
    return changed
