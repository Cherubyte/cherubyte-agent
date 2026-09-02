"""The native installers write their systemd unit / launchd plist inline, so a
piped `curl … | sudo bash` install needs no sibling files. The canonical unit
files are still in the tree as the reference — these guard against the two
drifting apart.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent  # agent/


def _significant_lines(text: str) -> list[str]:
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)  # XML comment blocks
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "<?xml", "<!DOCTYPE", '"http://')):
            continue
        out.append(line)
    return out


def test_linux_installer_embeds_every_unit_directive():
    unit = (_ROOT / "linux" / "cherubyte-agent.service").read_text()
    script = (_ROOT / "linux" / "install-service.sh").read_text()
    missing = [l for l in _significant_lines(unit) if l not in script]
    assert not missing, f"install-service.sh is missing unit lines: {missing}"


def test_macos_installer_embeds_every_plist_key():
    plist = (_ROOT / "macos" / "pt.qqc.cherubyte-agent.plist").read_text()
    script = (_ROOT / "macos" / "install-daemon.sh").read_text()
    missing = [l for l in _significant_lines(plist) if l not in script]
    assert not missing, f"install-daemon.sh is missing plist lines: {missing}"


def test_the_powershell_installers_are_ascii_only():
    """No character above 127 in a .ps1, ever.

    Windows PowerShell 5.1 - which is what `shell: powershell` runs, and what
    is on a stock Windows box - reads a UTF-8 file with no byte order mark as
    ANSI. An em dash is three bytes there, and the last of them decodes to a
    right double quotation mark, which the parser accepts as a string
    delimiter. The file then fails to parse somewhere else entirely, with an
    error pointing at a line that is perfectly fine.

    A byte order mark would also fix it, but a BOM is an invisible property
    that any editor or tool can quietly drop. Staying inside ASCII cannot be
    dropped by accident.
    """
    offenders = {}
    for path in sorted((_ROOT / "windows").glob("*.ps1")):
        bad = [
            (n, line)
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if any(ord(c) > 127 for c in line)
        ]
        if bad:
            offenders[path.name] = bad
    assert not offenders, (
        "non-ASCII in a PowerShell script: "
        + "; ".join(f"{name} line {n}" for name, lines in offenders.items() for n, _ in lines)
    )
