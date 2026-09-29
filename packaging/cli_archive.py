"""Packs the PyInstaller engine (desktop/vendor/engine) as the standalone CLI download for this OS.

    python packaging/cli_archive.py            → desktop/release/armorix-cli-<os>-<arch>.tar.gz (.zip on Windows)
Layout inside the archive: armorix/armorix(.exe) + armorix/_internal — what install.sh / install.ps1 expect.
"""

from __future__ import annotations

import platform
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENGINE = ROOT / "desktop" / "vendor" / "engine"
OUT = ROOT / "desktop" / "release"
sys.path.insert(0, str(ROOT))
from armorix.selfupdate import asset_name  # noqa: E402


def main() -> Path:
    exe = ENGINE / ("armorix.exe" if platform.system() == "Windows" else "armorix")
    if not exe.exists():
        raise SystemExit(f"{exe} not found — run packaging/prepare.py first")
    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / asset_name()
    files = sorted(p for p in ENGINE.rglob("*") if p.is_file())
    if target.suffix == ".zip":
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for f in files:
                zf.write(f, Path("armorix") / f.relative_to(ENGINE))
    else:
        with tarfile.open(target, "w:gz", compresslevel=9) as tf:
            for f in files:
                info = tf.gettarinfo(f, str(Path("armorix") / f.relative_to(ENGINE)))
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                with open(f, "rb") as fh:
                    tf.addfile(info, fh)
    print(f"{target}  {target.stat().st_size / 1e6:.1f} MB")
    return target


if __name__ == "__main__":
    main()
