"""The public key releases are signed with, and how a download is checked.

**Why this is compiled in rather than fetched.** An agent updates itself by
asking its own panel what the current version is and pulling the binary from
there. If it also asked the panel which key to trust, the panel could hand it
any binary and any key to match — and a panel is the one thing in this system
that already has enough access to be worth compromising. Baking the key in is
what turns "the panel can reconfigure my agent", which was always true, into
something short of "the panel can run code as root on every machine an agent
is installed on".

So the trust chain is: this constant, in this binary, signs a list of digests;
the list names the digest of the next binary; nothing is executed until the
digest matches. The panel serves the bytes and cannot change what they say.

**Rotating the key is a real cost**, which is why it is worth stating. Agents
already installed carry the old public key, so a new key means they cannot
verify anything signed with it and stop updating themselves until somebody
reinstalls them. If the private half is ever lost, that is the recovery, and
it is manual on every machine.
"""

from __future__ import annotations

import base64
import hashlib

# Imported here rather than inside the function that uses it, deliberately.
# Lazily, a packaged binary that PyInstaller had failed to bundle this into
# would build, start, run for weeks and only fail at the moment it tried to
# verify an update — which is the one path that has to work.
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Ed25519, base64 of the 32 raw bytes. Generated 2 Sep 2026; the private half
# lives only in the cherubyte-agent repository's Actions secrets.
RELEASE_PUBLIC_KEY = "5vFRsEiIF25Sq5C7vfRufi5feoxEexxwk3iabmkNGG4="

# The two files a signed release carries alongside its binaries.
SUMS_NAME = "SHA256SUMS"
SIGNATURE_NAME = "SHA256SUMS.sig"


class VerificationError(RuntimeError):
    """A download could not be shown to be the one that was built."""


def verify_sums(sums: bytes, signature: bytes) -> dict[str, str]:
    """Check the digest list against the release key, and parse it.

    Raises rather than returning a flag: every caller of this is about to run
    the file it describes, and an ignored return value there is the whole
    vulnerability.
    """
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(RELEASE_PUBLIC_KEY))
    try:
        key.verify(signature, sums)
    except InvalidSignature as exc:
        raise VerificationError(
            "the release digest list is not signed by the Cherubyte release key"
        ) from exc

    digests: dict[str, str] = {}
    for line in sums.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # `sha256sum` format: "<hex>  <name>", two spaces, name may contain any
        # of its own.
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, name = parts[0].strip(), parts[1].strip().lstrip("*")
        if len(digest) == 64:
            digests[name] = digest.lower()
    if not digests:
        raise VerificationError("the release digest list is signed but empty")
    return digests


def digest_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_asset(data: bytes, name: str, digests: dict[str, str]) -> None:
    """Refuse a download that is not the one the signed list names."""
    expected = digests.get(name)
    if expected is None:
        raise VerificationError(f"{name} is not in the signed digest list")
    actual = digest_of(data)
    if actual != expected:
        raise VerificationError(
            f"{name} does not match the signed digest "
            f"(expected {expected[:12]}…, got {actual[:12]}…)"
        )
