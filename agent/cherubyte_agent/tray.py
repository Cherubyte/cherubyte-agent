"""The status icon, which is the answer to "I don't know if it's running".

The agent is a service. A service has no window, no console and no way to tell
anyone anything — which is how the first Windows install ended up with a
machine that was either working or not and no way to find out, and an
enrolment link printed to a log nobody was reading.

This runs in the user's session, not as the service, and asks the service how
it is over the loopback health endpoint. It holds no credentials and can read
nothing the service owns, which is what lets it run unprivileged.

**Everything that changes state goes through the service.** The tray can open
a browser and it can ask the service to do something; it cannot write the
configuration, because that lives in a directory only administrators can write
and asking for elevation on a click somebody did not expect is worse than
sending them to a window that explains itself.
"""

from __future__ import annotations

import logging
import threading
import time
import webbrowser

from .cli import read_state
from .reporter import AGENT_VERSION

logger = logging.getLogger("cherubyte.agent.tray")

POLL_SECONDS = 5

# Three states worth telling apart at a glance, and no more. A tray icon that
# needs a legend is a tray icon nobody reads.
OK = "ok"
ATTENTION = "attention"
OFFLINE = "offline"


def _state_of(health: dict | None) -> str:
    if health is None:
        return OFFLINE
    if not health.get("enrolled"):
        return ATTENTION
    if health.get("last_report_ok") is False:
        return ATTENTION
    return OK


def _summary(health: dict | None) -> str:
    if health is None:
        return "Not running"
    if not health.get("enrolled"):
        return "Waiting to be approved" if health.get("enrolment_url") else "Not admitted yet"
    if health.get("last_report_ok") is False:
        return "The panel is refusing its reports"
    found = health.get("found")
    return f"Reporting - {found} devices" if found is not None else "Reporting"


def _icon_image(state: str):
    """A dot, drawn rather than shipped as a file.

    Three 64px images in a repository is three things to keep in step with a
    design nobody will look at twice. Drawn here they cannot drift, and the
    binary does not have to carry data files.
    """
    from PIL import Image, ImageDraw

    colours = {
        OK: (34, 160, 92),
        ATTENTION: (222, 152, 32),
        OFFLINE: (130, 130, 138),
    }
    image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse((8, 8, 56, 56), fill=colours.get(state, colours[OFFLINE]))
    if state == ATTENTION:
        # A gap in the ring reads as "needs you" without needing a second
        # colour to be distinguishable by somebody who cannot see one.
        draw.ellipse((22, 22, 42, 42), fill=(0, 0, 0, 0))
    return image


class Tray:
    def __init__(self) -> None:
        self.health: dict | None = None
        self.icon = None
        self._stop = threading.Event()

    # -- what the menu does ------------------------------------------------

    def _approve(self, *_a) -> None:
        url = (self.health or {}).get("enrolment_url")
        if url:
            webbrowser.open(url)

    def _open_panel(self, *_a) -> None:
        panel = (self.health or {}).get("panel_url")
        if panel:
            webbrowser.open(panel)

    def _open_settings(self, *_a) -> None:
        from .settings_window import open_settings

        # In a thread: the settings window runs its own event loop, and
        # blocking here would freeze the icon while it is open.
        threading.Thread(target=open_settings, daemon=True).start()

    def _quit(self, *_a) -> None:
        # Only the icon goes. The service keeps running, which is the point of
        # it being a service — and a menu item that silently stopped monitoring
        # the network would be a trap.
        self._stop.set()
        if self.icon is not None:
            self.icon.stop()

    # -- the menu, rebuilt each time it is opened --------------------------

    def _menu(self):
        import pystray

        health = self.health or {}
        items = [
            pystray.MenuItem(_summary(health), None, enabled=False),
        ]
        if health.get("enrolment_url"):
            items.append(
                pystray.MenuItem(
                    f"Approve this machine ({health.get('enrolment_code', '')})",
                    self._approve,
                    default=True,
                )
            )
        items += [
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open panel", self._open_panel, enabled=bool(health.get("panel_url"))),
            pystray.MenuItem("Settings...", self._open_settings),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(f"Cherubyte agent {AGENT_VERSION}", None, enabled=False),
            pystray.MenuItem("Hide this icon", self._quit),
        ]
        return pystray.Menu(*items)

    # -- the loop ----------------------------------------------------------

    def _poll(self) -> None:
        while not self._stop.is_set():
            previous = _state_of(self.health)
            self.health = read_state(timeout=3)
            current = _state_of(self.health)
            if self.icon is not None:
                self.icon.icon = _icon_image(current)
                self.icon.title = "Cherubyte - " + _summary(self.health)
                self.icon.menu = self._menu()
                if current != previous and current == ATTENTION and self.health:
                    if self.health.get("enrolment_url"):
                        self._notify("This machine is waiting to be approved.")
            self._stop.wait(POLL_SECONDS)

    def _notify(self, message: str) -> None:
        try:
            self.icon.notify(message, "Cherubyte")
        except Exception:  # noqa: BLE001
            # Notifications are unavailable on some desktops and are not worth
            # failing over; the icon already says it.
            pass

    def run(self) -> int:
        import pystray

        self.health = read_state(timeout=3)
        self.icon = pystray.Icon(
            "cherubyte",
            _icon_image(_state_of(self.health)),
            "Cherubyte - " + _summary(self.health),
            menu=self._menu(),
        )
        threading.Thread(target=self._poll, daemon=True).start()
        self.icon.run()
        return 0


def run() -> int:
    try:
        return Tray().run()
    except ImportError as exc:
        logger.error("The tray icon needs pystray and Pillow: %s", exc)
        return 3
    except Exception as exc:  # noqa: BLE001
        # A tray that will not start must not look like an agent that will not
        # start. They are different processes and only one of them matters.
        logger.exception("The tray icon stopped: %s", exc)
        return 1
