#!/usr/bin/env bash
# Refresh the vendored `protocol/` from the main repository.
#
#   scripts/sync-protocol.sh              # re-copy from the pinned protocol/UPSTREAM
#   scripts/sync-protocol.sh <git-ref>    # move the pin to <git-ref>, then copy
#
# `cherubyte_protocol` is the wire contract with the panel and its source of
# truth is `protocol/` in Cherubyte/cherubyte. This keeps the vendored copy
# byte-identical to a known commit there; CI (`protocol-drift`) fails if it
# isn't.
set -euo pipefail
cd "$(dirname "$0")/.."

UPSTREAM_REPO="${CHERUBYTE_UPSTREAM_REPO:-https://github.com/Cherubyte/cherubyte.git}"
PIN_FILE="protocol/UPSTREAM"

ref="${1:-$(cat "$PIN_FILE")}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo ">> Fetching protocol/ from $UPSTREAM_REPO @ $ref"
git -C "$tmp" init -q
git -C "$tmp" remote add origin "$UPSTREAM_REPO"
git -C "$tmp" fetch -q --depth 1 origin "$ref"
sha="$(git -C "$tmp" rev-parse FETCH_HEAD)"
git -C "$tmp" checkout -q FETCH_HEAD -- protocol

rm -rf protocol/cherubyte_protocol protocol/pyproject.toml
cp -r "$tmp/protocol/cherubyte_protocol" protocol/cherubyte_protocol
cp "$tmp/protocol/pyproject.toml" protocol/pyproject.toml
echo "$sha" > "$PIN_FILE"

echo ">> protocol/UPSTREAM = $sha"
if git diff --quiet -- protocol; then
  echo ">> No change — vendored copy already matches."
else
  echo ">> Updated. Review and commit:"
  git --no-pager diff --stat -- protocol
fi
