"""The out-of-band sweep.

The loop normally sleeps out its interval between cycles. Sweep in the panel
should not have to wait for that: POST /trigger (or a scan_now on the last ack)
wakes it now.
"""

import asyncio

import pytest
from fastapi.testclient import TestClient

from cherubyte_agent import main


@pytest.fixture(autouse=True)
def _clear():
    main._wake.clear()
    yield
    main._wake.clear()


def test_the_trigger_endpoint_wakes_the_loop():
    client = TestClient(main.app)
    # the FastAPI lifespan would start the real sweep loop; exercise the route
    # against the app without it by calling the handler through the router
    assert not main._wake.is_set()
    r = client.post("/trigger")
    assert r.status_code == 200
    assert r.json() == {"queued": True}
    assert main._wake.is_set()


@pytest.mark.asyncio
async def test_the_interval_wait_returns_early_once_woken():
    async def waiter():
        try:
            await asyncio.wait_for(main._wake.wait(), timeout=30)
            return "woken"
        except asyncio.TimeoutError:
            return "waited"

    task = asyncio.create_task(waiter())
    await asyncio.sleep(0)
    main._wake.set()
    assert await task == "woken"
