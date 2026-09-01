# Cherubyte agent

The half of [Cherubyte](https://github.com/Cherubyte/cherubyte) that touches the
network. It sweeps a LAN, works out what each device is, and pushes what it saw
to a panel. It holds no database and serves no UI — which is why it is also the
only half that needs raw sockets and host networking.

One agent per network. Discovery is a layer-2 job, so the agent has to sit on
the segment it watches; the panel does not, and can live anywhere.

## Layout

| Path | What it is |
|---|---|
| `agent/cherubyte_agent/` | the package — discovery, scanning, sniffers, reporting |
| `agent/tests/` | the suite |
| `agent/linux`, `agent/macos`, `agent/windows` | native service installers |
| `agent/packaging/` | the PyInstaller spec that produces one binary per platform |
| `protocol/` | the wire contract with the panel — see the warning below |
| `scripts/` | systemd unit and installer for running from a source checkout |
| `Dockerfile.agent` | the container image |

## `protocol/` is a vendored copy, pinned and drift-checked

`cherubyte_protocol` is the contract between an agent and a panel. Its source of
truth is `protocol/` in the [main repository](https://github.com/Cherubyte/cherubyte),
where the panel imports it — the panel is the half that *defines* what it will
accept. This directory is a **vendored copy** of that, and `protocol/UPSTREAM`
records the exact `cherubyte` commit it was taken from.

Two copies of a contract is the failure the contract exists to prevent — change
one side, ship it, and the halves disagree at runtime rather than at build time.
Two things keep them honest:

- **`scripts/sync-protocol.sh`** re-copies `protocol/` from the pinned `UPSTREAM`
  commit (pass a new SHA to move the pin). Run it, commit the result, done.
- **CI** (`protocol-drift` job) re-runs that sync against `UPSTREAM` and fails on
  any diff — so a wire change landed on only one side cannot merge here.
- **`agent/tests/test_contract.py`** fails if a `Host` field has no home in the
  protocol.

So a wire-format change is deliberately two commits: land it in `cherubyte`,
then bump `UPSTREAM` and re-sync here.

## Installing

An agent needs two things: a panel URL and an enrolment token that panel minted.
Everything else is configured in the panel and sent back with every report. Mint
a token in **Settings ▸ Agents** — the page prints the filled-in command for
each method.

The native installers drop **one binary** and register it with the system's own
service manager. No Python, no virtualenv, no Docker.

**Linux** (systemd):

```bash
sudo ./install-service.sh --panel http://your-panel:1001 --token <token>
# logs:   journalctl -u cherubyte-agent -f
# remove: sudo ./uninstall-service.sh
```

**macOS** (launchd):

```bash
sudo ./install-daemon.sh --panel http://your-panel:1001 --token <token>
# logs:   tail -f /var/log/cherubyte-agent.log
# remove: sudo ./uninstall-daemon.sh
```

**Windows**, from an elevated PowerShell:

```powershell
.\install-service.ps1 -PanelUrl http://your-panel:1001 -EnrolToken <token>
# remove: .\uninstall-service.ps1
```

**Docker** (Linux host):

```bash
docker run -d --name cherubyte-agent --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v cherubyte-agent:/var/lib/cherubyte-agent \
  -e CHERUBYTE_AGENT_PANEL_URL=http://your-panel:1001 \
  -e CHERUBYTE_AGENT_ENROL_TOKEN=<token> \
  ghcr.io/cherubyte/cherubyte-agent:latest
```

Keep the state volume. Without it the agent re-enrols on every restart, and an
enrolment token is single use.

Every installer writes the same `agent.env` and keeps the enrolment key outside
the install directory, so upgrading the binary never loses it:

| | Config and state |
|---|---|
| Linux | `/etc/cherubyte-agent/agent.env` · `/var/lib/cherubyte-agent` |
| macOS | `/Library/Application Support/Cherubyte Agent/` |
| Windows | `%ProgramData%\Cherubyte Agent\` |

Environment variables override the file, prefixed `CHERUBYTE_AGENT_` — which is
what keeps the Docker instructions above working unchanged.

## Running from source

```bash
python -m venv agent/.venv
agent/.venv/bin/pip install ./protocol
agent/.venv/bin/pip install -r agent/requirements-dev.txt
cd agent && ../agent/.venv/bin/python run.py
```

`scripts/install-agent-service.sh` registers that checkout as a systemd service,
with the network capabilities granted by systemd rather than by running as root.

## Tests

```bash
cd agent
pip install ../protocol
pip install -r requirements-dev.txt
pytest -q
```

`agent-binaries.yml` goes further than the suite can: it builds the binary for
each platform, installs it as a real service on the runner, points it at a stub
panel and asserts that it **enrolled** — packaging, service registration and the
configuration path cannot be exercised any other way.

## Building the binaries

```bash
pip install ./protocol -r agent/requirements.txt pyinstaller==6.11.1
cd agent/packaging && pyinstaller --clean --noconfirm cherubyte-agent.spec
```

## Releasing

The agent's version lives in one place: `AGENT_VERSION` in
`agent/cherubyte_agent/reporter.py`. Bump it in the change, then after merge:

```bash
gh release create "v$(python -c 'import agent.cherubyte_agent.reporter as r; print(r.AGENT_VERSION)')" --generate-notes
```

That fires `agent-binaries.yml` (attaches the three native binaries to the
release) and `images.yml` (publishes `ghcr.io/cherubyte/cherubyte-agent`
`:latest` `:X.Y` `:X.Y.Z`). The panel reads `releases/latest` from this repo and
offers that build in **Settings ▸ Agents**.

## Licence

MIT — see [LICENSE](LICENSE).
