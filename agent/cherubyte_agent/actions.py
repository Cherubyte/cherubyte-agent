"""On-demand per-device probes: ping, a port scan, or a traceroute.

The panel queues these against a device and hands them back on a report ack —
`ReportAck.actions` — the same broadcast-to-every-reporting-agent delivery as
Wake-on-LAN (see `wol.py`): only the agent on the target's own segment gets a
real answer, so the others just see every probe fail and report that back
truthfully rather than guessing which of them it was.

Results do not go out with the report that carried the request — there is
nothing to attach them to yet. Instead they are stashed here and folded into
`AgentReport.action_results` on the *next* cycle's report, by `main._cycle`.
"""

from __future__ import annotations

import asyncio
import logging
import re

from cherubyte_protocol import DeviceActionRequest, DeviceActionResult, TracerouteHop

from . import wan
from .config import settings
from .scanner import PROBE_PORTS

logger = logging.getLogger("cherubyte.agent.actions")

_PORT_PROBE_TIMEOUT = 0.5
_TRACEROUTE_MAX_HOPS = 20
_TRACEROUTE_HOP_WAIT = 1.5
_TRACEROUTE_TIMEOUT = 40.0

# "full" adds every well-known port (1-1024) to the curated PROBE_PORTS list
# already used for identification, so a full scan still names whatever
# PROBE_PORTS knows about instead of only the bare numbers below 1024.
FULL_PORTS: dict[int, str] = {p: "" for p in range(1, 1025)}
FULL_PORTS.update(PROBE_PORTS)

_HOP_LINE = re.compile(
    r"^\s*(\d+)\s+(?:(\d{1,3}(?:\.\d{1,3}){3})\s+([\d.]+)\s*ms|\*)"
)


async def _ping(ip: str) -> dict:
    ok, rtt = await wan.probe(ip, timeout=2.0)
    return {
        "ok": ok,
        "latency_ms": rtt,
        "packet_loss": 0.0 if ok else 1.0,
        "error": None if ok else "no reply",
    }


async def _port_scan(ip: str, ports: dict[int, str]) -> dict:
    sem = asyncio.Semaphore(max(1, settings.port_probe_concurrency))
    open_ports: dict[int, str] = {}

    async def probe(port: int, name: str) -> None:
        async with sem:
            writer = None
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), _PORT_PROBE_TIMEOUT
                )
                open_ports[port] = name
            except (OSError, asyncio.TimeoutError):
                return
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except OSError:
                        pass

    await asyncio.gather(*(probe(port, name) for port, name in ports.items()))
    return {"ok": True, "open_ports": open_ports}


def parse_traceroute(output: str) -> list[TracerouteHop]:
    """One `TracerouteHop` per numbered line — `-q 1` means exactly one probe
    per hop, so there is exactly one line to read per hop, `*` for a timeout."""
    hops: list[TracerouteHop] = []
    for line in output.splitlines():
        m = _HOP_LINE.match(line)
        if not m:
            continue
        ttl, ip, rtt = m.group(1), m.group(2), m.group(3)
        hops.append(TracerouteHop(ttl=int(ttl), ip=ip, rtt_ms=float(rtt) if rtt else None))
    return hops


async def _traceroute(ip: str) -> dict:
    try:
        proc = await asyncio.create_subprocess_exec(
            "traceroute", "-n", "-q", "1",
            "-w", str(_TRACEROUTE_HOP_WAIT), "-m", str(_TRACEROUTE_MAX_HOPS), ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=_TRACEROUTE_TIMEOUT)
    except FileNotFoundError:
        return {"ok": False, "error": "traceroute is not installed on this agent"}
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timed out"}
    return {"ok": True, "hops": parse_traceroute(out.decode(errors="replace"))}


_RUNNERS = {
    "ping": _ping,
    "port_scan_quick": lambda ip: _port_scan(ip, PROBE_PORTS),
    "port_scan_full": lambda ip: _port_scan(ip, FULL_PORTS),
    "traceroute": _traceroute,
}


async def run_one(req: DeviceActionRequest) -> DeviceActionResult:
    runner = _RUNNERS.get(req.kind)
    if runner is None:
        return DeviceActionResult(id=req.id, ok=False, error=f"unknown action kind: {req.kind!r}")
    try:
        data = await runner(req.ip)
    except Exception as exc:  # noqa: BLE001 — a bad probe must not sink the cycle
        logger.warning("action %s (%s) on %s failed: %s", req.id, req.kind, req.ip, exc)
        return DeviceActionResult(id=req.id, ok=False, error=str(exc)[:200])
    return DeviceActionResult(id=req.id, **data)


async def run_all(reqs: list[DeviceActionRequest]) -> list[DeviceActionResult]:
    """Every queued action against a different device, so nothing here needs
    to be serialised — run them all concurrently."""
    if not reqs:
        return []
    return list(await asyncio.gather(*(run_one(r) for r in reqs)))


# Results a cycle produced but had nothing to send them on yet — see the
# module docstring. `main._cycle` drains this into the next report.
_pending: list[DeviceActionResult] = []


def take_pending() -> list[DeviceActionResult]:
    global _pending
    out, _pending = _pending, []
    return out


async def run_and_stash(reqs: list[DeviceActionRequest]) -> None:
    if not reqs:
        return
    _pending.extend(await run_all(reqs))
