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
