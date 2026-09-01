"""`_neighbour_table` reads the kernel ARP cache — and must only trust an entry
the kernel currently considers reachable.

A device that has left the network sits in the neighbour table as STALE (with
its last-known MAC) for a long time, and the agent's own per-cycle ping to the
now-dead address keeps that STALE lladdr alive. Folding STALE in as liveness
pinned departed devices online forever — the bug this guards against.
"""

from __future__ import annotations

import subprocess

from cherubyte_agent import scanner

_SAMPLE = """\
192.168.1.1 dev wlan0 lladdr aa:aa:aa:00:00:01 REACHABLE
192.168.1.50 dev wlan0 lladdr aa:aa:aa:00:00:50 STALE
192.168.1.51 dev wlan0 lladdr aa:aa:aa:00:00:51 DELAY
192.168.1.52 dev wlan0 lladdr aa:aa:aa:00:00:52 PROBE
192.168.1.53 dev wlan0  FAILED
192.168.1.54 dev wlan0 lladdr aa:aa:aa:00:00:54 PERMANENT
192.168.1.55 dev wlan0 lladdr 00:00:00:00:00:00 REACHABLE
"""


def _fake_run(monkeypatch, stdout: str):
    def run(*_a, **_k):
        return subprocess.CompletedProcess([], 0, stdout=stdout, stderr="")

    monkeypatch.setattr(subprocess, "run", run)


def test_only_reachable_and_permanent_entries_count(monkeypatch):
    _fake_run(monkeypatch, _SAMPLE)
    table = scanner._neighbour_table()
    assert table == {
        "192.168.1.1": "aa:aa:aa:00:00:01",
        "192.168.1.54": "aa:aa:aa:00:00:54",
    }


def test_stale_entry_for_a_departed_host_is_ignored(monkeypatch):
    _fake_run(
        monkeypatch,
        "192.168.1.213 dev wlan0 lladdr 1a:96:f0:e0:05:4a STALE\n",
    )
    assert scanner._neighbour_table() == {}


def test_a_failing_ip_command_is_swallowed(monkeypatch):
    def boom(*_a, **_k):
        raise OSError("no ip binary")

    monkeypatch.setattr(subprocess, "run", boom)
    assert scanner._neighbour_table() == {}
