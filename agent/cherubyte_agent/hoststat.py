"""Read the temperature of the machine this agent runs on.

Linux only, and dependency-free: the kernel exposes every thermal sensor under
`/sys/class/thermal/thermal_zoneN/`. A Raspberry Pi has one zone (the SoC); an
x86 box has several, and there the package sensor is the one worth charting.

Everything here is best-effort — a host with no readable sensor (most
containers, and every macOS / Windows agent) just reports nothing, and the
panel leaves that host off the chart.
"""

from __future__ import annotations

import glob
import logging

logger = logging.getLogger("cherubyte.agent.hoststat")

# Sensor types that name a CPU/package reading, best first. `x86_pkg_temp` is
# the Intel package sensor; `cpu-thermal` / `soc` cover the ARM SBCs.
_PREFERRED = ("x86_pkg_temp", "cpu-thermal", "cpu_thermal", "cpu", "soc")


def _read_zone(path: str) -> float | None:
    try:
        with open(f"{path}/temp") as fh:
            milli = int(fh.read().strip())
    except (OSError, ValueError):
        return None
    celsius = milli / 1000.0
    # Sanity gate: a plausible die temperature, not a sensor returning 0 or a
    # raw millivolt reading.
    return round(celsius, 1) if 1.0 < celsius < 150.0 else None


def read_cpu_temp() -> float | None:
    """The host's CPU/SoC temperature in °C, or None if nothing readable."""
    zones = sorted(glob.glob("/sys/class/thermal/thermal_zone*"))
    if not zones:
        return None

    typed: dict[str, float] = {}
    for zone in zones:
        value = _read_zone(zone)
        if value is None:
            continue
        try:
            with open(f"{zone}/type") as fh:
                kind = fh.read().strip().lower()
        except OSError:
            kind = ""
        typed[kind] = value

    if not typed:
        return None
    for want in _PREFERRED:
        for kind, value in typed.items():
            if want in kind:
                return value
    # No recognised type — take the hottest zone, which on an SBC is the die.
    return max(typed.values())
