"""The agent reads its own host's CPU/SoC temperature from sysfs."""

from __future__ import annotations

from cherubyte_agent import hoststat


def _zone(tmp_path, name, kind, milli):
    d = tmp_path / name
    d.mkdir()
    (d / "type").write_text(kind + "\n")
    (d / "temp").write_text(f"{milli}\n")
    return d


def test_no_sysfs_returns_none(monkeypatch):
    monkeypatch.setattr(hoststat.glob, "glob", lambda _p: [])
    assert hoststat.read_cpu_temp() is None


def test_single_zone_pi_style(monkeypatch, tmp_path):
    _zone(tmp_path, "thermal_zone0", "cpu-thermal", 47321)
    monkeypatch.setattr(hoststat.glob, "glob", lambda _p: [str(tmp_path / "thermal_zone0")])
    assert hoststat.read_cpu_temp() == 47.3


def test_prefers_the_package_sensor(monkeypatch, tmp_path):
    _zone(tmp_path, "thermal_zone0", "acpitz", 40000)
    _zone(tmp_path, "thermal_zone1", "x86_pkg_temp", 62000)
    monkeypatch.setattr(
        hoststat.glob,
        "glob",
        lambda _p: [str(tmp_path / "thermal_zone0"), str(tmp_path / "thermal_zone1")],
    )
    assert hoststat.read_cpu_temp() == 62.0


def test_implausible_reading_is_dropped(monkeypatch, tmp_path):
    _zone(tmp_path, "thermal_zone0", "cpu", 0)
    monkeypatch.setattr(hoststat.glob, "glob", lambda _p: [str(tmp_path / "thermal_zone0")])
    assert hoststat.read_cpu_temp() is None
