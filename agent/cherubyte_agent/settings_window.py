"""The settings window.

Tkinter, because it ships with Python and therefore adds no dependency to a
binary that already has to carry a network stack. It is not pretty. It is one
window with six fields, opened from a tray menu, and the alternative was a
second GUI toolkit for one screen.

**Saving needs administrator rights, and that is not an accident.** The
configuration lives in a directory only administrators can write, and the
panel address is in it. A non-administrator who could change that could point
this machine's entire network inventory at a server they control, and the
agent would dutifully send it. So the window is readable by anyone and the
save re-launches the binary elevated to do the write.

Most settings are not here on purpose. Scan interval, subnets and the rest are
pushed down by the panel and shown read-only, because a value set here that
the panel then overwrites is a setting whose owner has no way to see why it
did not take.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path

from .cli import read_state
from .config import CONFIG_FILE, settings

logger = logging.getLogger("cherubyte.agent.settings")


def _binary() -> str:
    """This executable, for re-launching elevated."""
    return sys.executable if getattr(sys, "frozen", False) else sys.argv[0]


def apply_elevated(panel_url: str, name: str, auto_update: bool) -> tuple[bool, str]:
    """Ask the operating system to run the write as an administrator.

    Returns (started, message). Started only says the prompt was accepted, not
    that the write succeeded — the elevated process is a separate one and its
    output goes to its own console. The window re-reads the configuration
    afterwards, which is the honest way to know.
    """
    args = [
        "apply-settings",
        "--panel",
        panel_url,
        "--name",
        name,
        "--auto-update",
        "true" if auto_update else "false",
    ]
    try:
        if sys.platform == "win32":
            import ctypes

            # ShellExecute with "runas" is what produces the UAC prompt. A
            # plain subprocess would simply fail with access denied, which is
            # a worse thing to show somebody than a prompt.
            quoted = " ".join(f'"{a}"' for a in args)
            rc = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", _binary(), quoted, None, 1
            )
            if rc <= 32:
                return False, "The elevation prompt was refused."
            return True, "Saving..."

        if sys.platform == "darwin":
            inner = " ".join(f"'{a}'" for a in [_binary(), *args])
            script = f'do shell script "{inner}" with administrator privileges'
            subprocess.run(["osascript", "-e", script], check=True, capture_output=True)
            return True, "Saved."

        subprocess.run(["pkexec", _binary(), *args], check=True)
        return True, "Saved."
    except subprocess.CalledProcessError as exc:
        return False, f"Could not save: {exc}"
    except Exception as exc:  # noqa: BLE001
        return False, f"Could not save: {exc}"


def open_settings() -> None:
    try:
        import tkinter as tk
        from tkinter import ttk
    except ImportError:
        logger.error("Tkinter is not available, so there is no settings window")
        return

    health = read_state(timeout=3) or {}

    root = tk.Tk()
    root.title("Cherubyte agent")
    root.resizable(False, False)
    frame = ttk.Frame(root, padding=16)
    frame.grid(sticky="nsew")

    row = 0

    def label(text: str, value: str) -> None:
        nonlocal row
        ttk.Label(frame, text=text).grid(row=row, column=0, sticky="w", pady=3, padx=(0, 12))
        ttk.Label(frame, text=value).grid(row=row, column=1, sticky="w", pady=3)
        row += 1

    ttk.Label(frame, text="This machine", font=("", 11, "bold")).grid(
        row=row, column=0, columnspan=2, sticky="w", pady=(0, 8)
    )
    row += 1
    label("Status", health.get("status", "not running"))
    label("Version", health.get("version", "unknown"))
    label("Devices seen", str(health.get("found", "-")))
    if health.get("enrolment_url"):
        label("Waiting", "approve at " + health["enrolment_url"])

    ttk.Separator(frame, orient="horizontal").grid(
        row=row, column=0, columnspan=2, sticky="ew", pady=12
    )
    row += 1

    ttk.Label(frame, text="Settings", font=("", 11, "bold")).grid(
        row=row, column=0, columnspan=2, sticky="w", pady=(0, 8)
    )
    row += 1

    panel_var = tk.StringVar(value=health.get("panel_url") or settings.panel_url)
    name_var = tk.StringVar(value=settings.name or "")
    update_var = tk.BooleanVar(value=bool(settings.auto_update))

    def field(text: str, var, width: int = 34):
        nonlocal row
        ttk.Label(frame, text=text).grid(row=row, column=0, sticky="w", pady=3, padx=(0, 12))
        ttk.Entry(frame, textvariable=var, width=width).grid(row=row, column=1, sticky="w", pady=3)
        row += 1

    field("Panel address", panel_var)
    field("This machine's name", name_var)
    ttk.Checkbutton(frame, text="Keep itself up to date", variable=update_var).grid(
        row=row, column=1, sticky="w", pady=3
    )
    row += 1

    ttk.Separator(frame, orient="horizontal").grid(
        row=row, column=0, columnspan=2, sticky="ew", pady=12
    )
    row += 1

    # Everything the panel decides. Shown, because "why is it scanning that
    # subnet" is a real question, and not editable, because a value set here
    # that the panel overwrites on the next report is a lie.
    ttk.Label(
        frame,
        text="Scanning is configured on the panel, not here.",
        foreground="#666",
    ).grid(row=row, column=0, columnspan=2, sticky="w")
    row += 1
    label("Scan every", f"{settings.scan_interval_seconds}s")
    label("Config file", str(CONFIG_FILE))

    status = ttk.Label(frame, text="", foreground="#666")
    status.grid(row=row, column=0, columnspan=2, sticky="w", pady=(12, 0))
    row += 1

    def save() -> None:
        panel = panel_var.get().strip()
        if not panel.startswith(("http://", "https://")):
            status.config(text="The panel address needs to start with http:// or https://")
            return
        status.config(text="Asking for administrator rights...")
        root.update_idletasks()
        ok, message = apply_elevated(panel, name_var.get().strip(), update_var.get())
        status.config(text=message if not ok else "Saved. The agent is restarting.")

    buttons = ttk.Frame(frame)
    buttons.grid(row=row, column=0, columnspan=2, sticky="e", pady=(12, 0))
    ttk.Button(buttons, text="Close", command=root.destroy).grid(row=0, column=0, padx=4)
    ttk.Button(buttons, text="Save", command=save).grid(row=0, column=1)

    root.mainloop()
