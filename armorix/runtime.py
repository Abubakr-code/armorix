"""Finds or starts a local AI engine, and installs one when there is none.

Order of preference:
  1. an Ollama that already runs with the model (developers who have it),
  2. Armorix's own llama.cpp server (`llama-server`, ~17 MB) + a GGUF model in the data dir.
The engine binary ships inside the desktop installer; only the model (~1.1 GB) is
downloaded on first use — or imported from a file for air-gapped machines.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import socket
import subprocess
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path

from .ai import AIUnavailable, LocalAI
from .deps.osv import data_dir

LLAMA_BUILD = "b11236"
LLAMA_ASSETS = {
    ("Linux", "x86_64"): "ubuntu-x64.tar.gz",
    ("Linux", "aarch64"): "ubuntu-arm64.tar.gz",
    ("Darwin", "arm64"): "macos-arm64.tar.gz",
    ("Darwin", "x86_64"): "macos-x64.tar.gz",
    ("Windows", "AMD64"): "win-cpu-x64.zip",
    ("Windows", "ARM64"): "win-cpu-arm64.zip",
}
MODEL = {
    "name": "qwen2.5-coder-1.5b-instruct-q4_k_m.gguf",
    "url": "https://huggingface.co/Qwen/Qwen2.5-Coder-1.5B-Instruct-GGUF/resolve/main/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf",
    "sha256": "cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046",
    "bytes": 1_117_320_768,
}
PORT = 11435  # next to Ollama's 11434, never clashes with it


def ai_dir() -> Path:
    return data_dir() / "ai"


def model_path() -> Path:
    return ai_dir() / "models" / MODEL["name"]


def _exe(name: str) -> str:
    return name + ".exe" if platform.system() == "Windows" else name


def server_binary() -> Path | None:
    """Bundled next to the app (ARMORIX_LLAMA_DIR), or previously downloaded into the data dir."""
    candidates = []
    if os.environ.get("ARMORIX_LLAMA_DIR"):
        candidates.append(Path(os.environ["ARMORIX_LLAMA_DIR"]))
    candidates.append(ai_dir() / "llama")
    for base in candidates:
        for found in base.rglob(_exe("llama-server")) if base.exists() else []:
            return found.resolve()  # absolute: the server is started with cwd = its own folder
    return None


def _ollama() -> LocalAI | None:
    ai = LocalAI()
    try:
        ai.check()
        return ai
    except AIUnavailable:
        return None


def _port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


_server: subprocess.Popen | None = None


def status() -> dict:
    ollama = _ollama()
    return {
        "ollama": bool(ollama),
        "engine": str(server_binary() or ""),
        "model": model_path().exists(),
        "model_bytes": MODEL["bytes"],
        "running": bool(ollama) or _port_open(PORT),
        "ready": bool(ollama) or (server_binary() is not None and model_path().exists()),
    }


def start(wait: float = 90) -> LocalAI:
    """A ready-to-use LocalAI, starting the bundled llama.cpp server if needed."""
    global _server
    ollama = _ollama()
    if ollama:
        return ollama
    ai = LocalAI(url=f"http://127.0.0.1:{PORT}", model="armorix-coder", backend="llamacpp")
    if not _port_open(PORT):
        binary = server_binary()
        if binary is None:
            raise AIUnavailable("AI engine is not installed — run: armorix ai setup")
        if not model_path().exists():
            raise AIUnavailable("AI model is not downloaded — run: armorix ai setup")
        threads = str(max(2, (os.cpu_count() or 4) - 2))
        _server = subprocess.Popen(
            [str(binary), "-m", str(model_path()), "--host", "127.0.0.1", "--port", str(PORT), "-c", "4096", "-t", threads, "--no-webui"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=binary.parent,
            env={**os.environ,
                 "LD_LIBRARY_PATH": f"{binary.parent}:{os.environ.get('LD_LIBRARY_PATH', '')}",
                 "DYLD_LIBRARY_PATH": f"{binary.parent}:{os.environ.get('DYLD_LIBRARY_PATH', '')}"},
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    deadline = time.time() + wait
    while time.time() < deadline:
        try:
            ai.check()
            return ai
        except AIUnavailable:
            if _server is not None and _server.poll() is not None:
                raise AIUnavailable("AI engine exited while loading the model") from None
            time.sleep(0.5)
    raise AIUnavailable("AI engine did not become ready in time")


def stop() -> None:
    global _server
    if _server is not None and _server.poll() is None:
        _server.terminate()
    _server = None


def _download(url: str, dest: Path, progress=None, expected: int | None = None, sha256: str | None = None) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    done = part.stat().st_size if part.exists() else 0
    req = urllib.request.Request(url, headers={"Range": f"bytes={done}-"} if done else {})
    with urllib.request.urlopen(req, timeout=60) as resp, open(part, "ab" if done and resp.status == 206 else "wb") as fh:
        if resp.status != 206:
            done = 0
        total = expected or (done + int(resp.headers.get("Content-Length", 0)))
        while chunk := resp.read(1 << 20):
            fh.write(chunk)
            done += len(chunk)
            if progress:
                progress("download", done, total, dest.name)
    if sha256:
        digest = hashlib.sha256()
        with open(part, "rb") as fh:
            while block := fh.read(1 << 22):
                digest.update(block)
        if digest.hexdigest() != sha256:
            part.unlink()
            raise AIUnavailable(f"{dest.name}: checksum mismatch — download corrupted, try again")
    part.replace(dest)
    return dest


def install_engine(progress=None) -> Path:
    key = (platform.system(), platform.machine())
    if key not in LLAMA_ASSETS:
        raise AIUnavailable(f"no prebuilt AI engine for {key[0]} {key[1]}")
    asset = LLAMA_ASSETS[key]
    url = f"https://github.com/ggml-org/llama.cpp/releases/download/{LLAMA_BUILD}/llama-{LLAMA_BUILD}-bin-{asset}"
    archive = _download(url, ai_dir() / "downloads" / asset, progress)
    target = ai_dir() / "llama"
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)
    if asset.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(target)
    else:
        with tarfile.open(archive) as tf:
            tf.extractall(target, filter="data")
    archive.unlink(missing_ok=True)
    binary = server_binary()
    if binary is None:
        raise AIUnavailable("engine archive did not contain llama-server")
    binary.chmod(0o755)
    return binary


def setup(progress=None) -> dict:
    """Everything needed for offline AI: engine (unless bundled / Ollama present) and the model."""
    if _ollama():
        return status()
    if server_binary() is None:
        install_engine(progress)
    if not model_path().exists():
        _download(MODEL["url"], model_path(), progress, MODEL["bytes"], MODEL["sha256"])
    return status()


def import_model(file: str) -> Path:
    """Air-gapped: copy a GGUF brought on a USB stick."""
    src = Path(file)
    if src.suffix != ".gguf" or not src.is_file():
        raise AIUnavailable("expected a .gguf model file")
    model_path().parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, model_path())
    return model_path()
