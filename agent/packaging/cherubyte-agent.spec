# PyInstaller spec shared by all three platforms.
#
# One binary, no Python on the target. The Windows build additionally needs the
# pywin32 service framework, which is imported lazily and therefore invisible to
# PyInstaller's analysis — without naming it the service installs and then fails
# to start, which is the least helpful moment to find out.

import sys

WINDOWS = sys.platform == "win32"

hidden = [
    "cherubyte_agent.main",
    "cherubyte_protocol",
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
]
# The Rust extension behind Ed25519 verification. PyInstaller ships a hook for
# cryptography, but this is what the agent uses to check a release signature
# before installing it, and a binary that cannot verify is a binary that can
# never update itself again. Named explicitly rather than trusted to analysis.
#
# It is also why release_key imports cryptography at module scope: if this is
# ever missed, the service fails to start and the workflow step below catches
# it, rather than the binary running for weeks and failing at the one moment
# it matters.
hidden += ["cryptography.hazmat.bindings._rust"]

if WINDOWS:
    hidden += ["win32timezone", "cherubyte_agent.winservice"]

a = Analysis(
    ["entry.py"],
    pathex=[".."],
    binaries=[],
    datas=[],
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    # pkg_resources is excluded deliberately. Nothing the agent imports uses it
    # — checked, module by module — but PyInstaller bundles a runtime hook for
    # it whenever setuptools is present in the build environment, and that hook
    # pulls in jaraco.context, which needs `backports`, which does not get
    # collected. The binary then dies at startup with ModuleNotFoundError before
    # a single line of our code runs. Leaving it out removes the hook entirely.
    excludes=["tkinter", "matplotlib", "pkg_resources", "setuptools"],
)
pyz = PYZ(a.pure, a.zipped_data)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name="cherubyte-agent",
    debug=False,
    strip=False,
    upx=False,
    console=True,
)
