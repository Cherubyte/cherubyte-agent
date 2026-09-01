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

## `protocol/` is a copy, and copies drift

`cherubyte_protocol` is the contract between an agent and a panel, and the panel
side of it lives in the [main repository](https://github.com/Cherubyte/cherubyte),
where the backend imports the same package. This directory is a **vendored
copy**, taken from `cherubyte-protocol` version `3.0.0`.

Two copies of a contract is precisely the failure the contract exists to
prevent: change one side, ship it, and the two halves disagree at runtime rather
than at build time. Until this is resolved — by publishing the package, by a
submodule, or by keeping it in one repository and consuming it from there — a
change to the wire format has to be made in **both** places in the same change,
and `agent/tests/test_contract.py` is the test that will tell you if it was not.

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

## Licence

MIT — see [LICENSE](LICENSE).
