"""`armorix update` — replaces a standalone CLI install (from install.sh / install.ps1) with the latest release.

The only network call Armorix makes on its own initiative, and only when the user runs this command:
it asks GitHub for the latest version, downloads the archive for this OS and checks it against SHA256SUMS.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from . import __version__

REPO = "Abubakr-code/armorix"
API = f"https://api.github.com/repos/{REPO}/releases/latest"


class UpdateError(Exception):
    pass


def asset_name() -> str:
    system, machine = platform.system(), platform.machine().lower()
    arch = "arm64" if machine in {"arm64", "aarch64"} else "x86_64"
    if system == "Windows":
        return "armorix-cli-windows-x64.zip"
    if system == "Darwin":
        return f"armorix-cli-macos-{arch}.tar.gz"
    return f"armorix-cli-linux-{arch}.tar.gz"


def install_root() -> Path | None:
    """The directory install.sh / install.ps1 created, or None when this copy was installed another way."""
    if not getattr(sys, "frozen", False):
        return None
    exe = Path(sys.executable).resolve()
    if platform.system() == "Windows":
        root = exe.parent.parent  # %LOCALAPPDATA%\Armorix\cli\armorix\armorix.exe
        return root if root.name.lower() == "cli" else None
    root = exe.parent.parent.parent  # ~/.armorix/lib/armorix/armorix
    return root if exe.parent.parent.name == "lib" and (root / "bin").is_dir() else None


def _version_tuple(v: str) -> tuple:
    return tuple(int(p) if p.isdigit() else 0 for p in v.lstrip("v").split(".")[:3])


def latest() -> dict:
    req = urllib.request.Request(API, headers={"Accept": "application/vnd.github+json", "User-Agent": f"armorix/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            rel = json.load(resp)
    except OSError as exc:
        raise UpdateError(f"cannot reach GitHub: {exc}") from None
    tag = str(rel.get("tag_name", "")).lstrip("v")
    assets = {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])}
    return {"version": tag, "newer": _version_tuple(tag) > _version_tuple(__version__), "assets": assets, "page": rel.get("html_url", "")}


def _download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": f"armorix/{__version__}"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as fh:
        shutil.copyfileobj(resp, fh)


def update(log=print) -> str:
    info = latest()
    if not info["newer"]:
        return f"armorix {__version__} is the latest version"
    root = install_root()
    if root is None:
        exe = Path(sys.executable).resolve()
        if "Armorix" in exe.parts or "resources" in exe.parts:
            raise UpdateError(f"armorix {info['version']} is out — this copy comes with the desktop app; update the app ({info['page']})")
        raise UpdateError(f"armorix {info['version']} is out — this copy was not installed with install.sh; "
                          "reinstall: curl -fsSL https://abubakr-code.github.io/install.sh | sh")
    name = asset_name()
    if name not in info["assets"] or "SHA256SUMS" not in info["assets"]:
        raise UpdateError(f"release {info['version']} has no {name}")

    if platform.system() == "Windows":
        # A running .exe cannot replace its own folder: hand over to the installer once this process exits.
        script = "Start-Sleep -Seconds 2; irm https://abubakr-code.github.io/install.ps1 | iex"
        subprocess.Popen(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                         creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))
        return f"updating to armorix {info['version']} in a new window…"

    with tempfile.TemporaryDirectory(prefix="armorix-update-") as tmp:
        archive, sums = Path(tmp) / name, Path(tmp) / "SHA256SUMS"
        log(f"downloading {name} ({info['version']})")
        _download(info["assets"][name], archive)
        _download(info["assets"]["SHA256SUMS"], sums)
        expected = next((line.split()[0] for line in sums.read_text().splitlines() if line.strip().endswith(" " + name)), None)
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        if expected != actual:
            raise UpdateError("checksum mismatch — download corrupted or tampered with; nothing was changed")
        staging = root / "lib.new"
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir()
        if name.endswith(".zip"):
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(staging)
        else:
            with tarfile.open(archive) as tf:
                tf.extractall(staging, filter="data")
        binary = staging / "armorix" / "armorix"
        if not binary.exists():
            raise UpdateError("the archive has an unexpected layout; nothing was changed")
        binary.chmod(0o755)
        old = root / "lib.old"
        shutil.rmtree(old, ignore_errors=True)
        os.replace(root / "lib", old)
        os.replace(staging, root / "lib")
        shutil.rmtree(old, ignore_errors=True)
    return f"updated armorix {__version__} → {info['version']}"


def check() -> str:
    info = latest()
    if info["newer"]:
        return f"armorix {info['version']} is available (you have {__version__}) — run: armorix update"
    return f"armorix {__version__} is the latest version"
