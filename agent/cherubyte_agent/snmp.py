"""Optional SNMP reads, via the net-snmp command-line tools.

Off by default: SNMP needs a community string and most home LANs have nothing
that answers it. When enabled, for each identified host the agent asks for:

  * sysName / sysDescr  — a strong OS and vendor signal for managed gear
  * the LLDP-MIB neighbour table  — which of this device's ports connects to
    which port of which neighbour, i.e. the raw material for a topology map

Shelling out to `snmpget` / `snmpwalk` rather than pulling in pysnmp: it is the
same shape as the agent's existing `ping` / `ip neigh` calls, and pysnmp's
asyncio story is its own project. `snmp` must be installed (it is, in the
image); a missing binary degrades to "no SNMP data", logged once.
"""

from __future__ import annotations

import logging
import shutil
import subprocess

from cherubyte_protocol import LldpNeighbor

logger = logging.getLogger("cherubyte.agent.snmp")

OID_SYSNAME = "1.3.6.1.2.1.1.5.0"
OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"
# lldpRemTable — chassis id (.5), port id (.7), sys name (.9), index is
# <timeMark>.<localPort>.<remIndex>
OID_LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"

_warned = False


def available() -> bool:
    global _warned
    ok = shutil.which("snmpget") is not None and shutil.which("snmpwalk") is not None
    if not ok and not _warned:
        logger.warning("SNMP is enabled but net-snmp (snmpget/snmpwalk) is not installed")
        _warned = True
    return ok


def _run(args: list[str], timeout: float) -> str | None:
    try:
        res = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if res.returncode != 0:
        return None
    return res.stdout


def _get(ip: str, community: str, oid: str, timeout: float) -> str | None:
    out = _run(
        ["snmpget", "-v2c", "-c", community, "-Oqv", "-t", "1", "-r", "0", ip, oid],
        timeout,
    )
    if out is None:
        return None
    value = out.strip().strip('"')
    return value or None


def sys_info(
    ip: str, community: str, *, timeout: float = 2.0
) -> tuple[str | None, str | None]:
    """(sysName, sysDescr) for `ip`, or (None, None) if it does not answer."""
    if not available():
        return None, None
    return (
        _get(ip, community, OID_SYSNAME, timeout),
        _get(ip, community, OID_SYSDESCR, timeout),
    )


def _parse_lldp(text: str) -> list[LldpNeighbor]:
    # each line: ".1.0.8802.1.1.2.1.4.1.1.<col>.<t>.<localPort>.<rem>  value"
    by_index: dict[str, dict[str, str]] = {}
    prefix = "." + OID_LLDP_REM + "."
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        oid, _, value = line.partition(" ")
        value = value.strip().strip('"')
        if not oid.startswith(prefix):
            continue
        rest = oid[len(prefix):].split(".")
        if len(rest) < 4:
            continue
        col, index = rest[0], ".".join(rest[1:])
        slot = by_index.setdefault(index, {})
        if col == "5":
            slot["remote_chassis"] = value
        elif col == "7":
            slot["remote_port"] = value
        elif col == "9":
            slot["remote_name"] = value
        # rest[2] is the local port number in the standard index layout
        slot.setdefault("local_port", rest[2] if len(rest) >= 3 else None)

    out: list[LldpNeighbor] = []
    for slot in by_index.values():
        if slot.get("remote_chassis") or slot.get("remote_name"):
            out.append(LldpNeighbor(**{k: v for k, v in slot.items() if v}))
    return out


def lldp_neighbors(
    ip: str, community: str, *, timeout: float = 3.0
) -> list[LldpNeighbor]:
    if not available():
        return []
    out = _run(
        ["snmpwalk", "-v2c", "-c", community, "-Oqn", "-t", "1", "-r", "0", ip, OID_LLDP_REM],
        timeout,
    )
    if not out:
        return []
    try:
        return _parse_lldp(out)
    except Exception as exc:  # noqa: BLE001
        logger.debug("LLDP parse failed for %s: %s", ip, exc)
        return []
