"""Builds desktop/vendor/{engine,llama} for the current OS — run before electron-builder.

    python packaging/prepare.py            # engine (PyInstaller) + llama.cpp server
Used locally and by .github/workflows/release.yml on Linux, macOS and Windows runners.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "desktop" / "vendor"
sys.path.insert(0, str(ROOT))
from armorix.runtime import LLAMA_ASSETS, LLAMA_BUILD  # noqa: E402

# Only what llama-server needs; the release archive also carries ~40 unrelated tools.
KEEP = ("llama-server", "libllama", "libggml", "libmtmd", "ggml-", "llama.dll", "mtmd.dll", "libomp", "libgomp", "vcruntime", "msvcp")
SKIP = ("bench", "perplexity", "cli-impl", "batched", "quantize", "tokenize", "imatrix", "run-impl", "gguf-split", "tts", "mtmd-cli",
        "rpc-server", "completion-impl", "fit-params-impl")
FULL_VERSION = re.compile(r"\.so\.\d+\.\d+|\.\d+\.\d+\.\d+\.dylib$")  # libllama.so.0.5.0 / libllama.0.5.0.dylib


def _dedupe(target: Path) -> None:
    """Keep the soname each binary links (libx.so.0 / libx.0.dylib), drop full-version and dev duplicates."""
    names = {p.name for p in target.iterdir()}
    for p in list(target.iterdir()):
        n = p.name
        if FULL_VERSION.search(n):
            p.unlink()
        elif n.endswith(".so") and f"{n}.0" in names:
            p.unlink()
        elif n.endswith(".dylib") and n.replace(".dylib", ".0.dylib") in names:
            p.unlink()


def build_engine() -> None:
    work = ROOT / "build" / "pyinstaller"
    cmd = [
        sys.executable, "-m", "PyInstaller", str(ROOT / "packaging" / "armorix_entry.py"),
        "--name", "armorix", "--onedir", "--console", "--noconfirm", "--clean",
        "--distpath", str(VENDOR), "--workpath", str(work), "--specpath", str(work),
        "--collect-all", "tree_sitter_javascript", "--collect-all", "tree_sitter_typescript",
        "--collect-all", "tree_sitter_python", "--collect-submodules", "rich", "--collect-submodules", "armorix",
    ]
    subprocess.run(cmd, check=True)
    shutil.rmtree(VENDOR / "engine", ignore_errors=True)
    (VENDOR / "armorix").rename(VENDOR / "engine")


def fetch_llama() -> None:
    asset = LLAMA_ASSETS[(platform.system(), platform.machine())]
    url = f"https://github.com/ggml-org/llama.cpp/releases/download/{LLAMA_BUILD}/llama-{LLAMA_BUILD}-bin-{asset}"
    cache = ROOT / "build" / asset
    if not cache.exists():
        cache.parent.mkdir(parents=True, exist_ok=True)
        print("downloading", url)
        with urllib.request.urlopen(url, timeout=120) as resp:
            cache.write_bytes(resp.read())
    staging = ROOT / "build" / "llama-extract"
    shutil.rmtree(staging, ignore_errors=True)
    if asset.endswith(".zip"):
        zipfile.ZipFile(cache).extractall(staging)
    else:
        with tarfile.open(cache) as tf:
            tf.extractall(staging, filter="data")
    target = VENDOR / "llama"
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)
    for f in staging.rglob("*"):
        name = f.name
        if f.is_dir() or not any(k in name for k in KEEP) or any(k in name for k in SKIP):
            continue
        shutil.copy2(f.resolve(), target / name)  # dereference symlinks (.so.0 → .so.0.x)
        if name.startswith("llama-server"):
            (target / name).chmod(0o755)
    _dedupe(target)
    print("llama files:", sorted(p.name for p in target.iterdir()))


if __name__ == "__main__":
    VENDOR.mkdir(parents=True, exist_ok=True)
    if "--llama-only" not in sys.argv:
        build_engine()
    fetch_llama()
