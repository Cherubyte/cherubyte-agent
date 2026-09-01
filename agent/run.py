#!/usr/bin/env python3
"""Entrypoint for the Cherubyte agent.

Needs CAP_NET_RAW for the ARP sweep and the DHCP sniffer, and host networking
to see the LAN at all — see the Docker section of the README.
"""

from __future__ import annotations

import uvicorn

from cherubyte_agent.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "cherubyte_agent.main:app", host=settings.health_host, port=settings.health_port
    )
