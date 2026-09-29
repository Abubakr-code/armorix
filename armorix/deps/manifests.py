"""Exact dependency versions from lockfiles (and pinned requirements)."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "poetry.lock", "Pipfile.lock", "uv.lock"}


@dataclass(frozen=True)
class Dependency:
    ecosystem: str  # "npm" | "PyPI"
    name: str
    version: str
    file: str
    line: int


def is_manifest(path: Path) -> bool:
    name = path.name
    return name in LOCKFILES or name == "package.json" or (name.startswith("requirements") and name.endswith(".txt"))


def _line(text: str, *needles: str) -> int:
    for needle in needles:
        i = text.find(needle)
        if i >= 0:
            return text.count("\n", 0, i) + 1
    return 1


def _npm_lock(text: str, rel: str):
    data = json.loads(text)
    if "packages" in data:  # lockfile v2/v3
        for key, meta in data["packages"].items():
            if not key or "version" not in meta or meta.get("link"):
                continue
            name = key.rsplit("node_modules/", 1)[-1]
            yield Dependency("npm", name, meta["version"], rel, _line(text, f'"{key}"'))
    else:  # v1
        stack = list(data.get("dependencies", {}).items())
        while stack:
            name, meta = stack.pop()
            if "version" in meta:
                yield Dependency("npm", name, meta["version"], rel, _line(text, f'"{name}": {{'))
            stack.extend(meta.get("dependencies", {}).items())


YARN_BLOCK = re.compile(r'^"?(@?[^@\s"]+)@[^\n]*:\n\s+version:?\s+"?([^"\n]+)"?', re.MULTILINE)


def _yarn_lock(text: str, rel: str):
    for m in YARN_BLOCK.finditer(text):
        yield Dependency("npm", m.group(1), m.group(2), rel, text.count("\n", 0, m.start()) + 1)


def _package_json(text: str, rel: str, has_lock: bool):
    """Only used when there is no lockfile: exact pins, or the floor of ^ / ~ ranges."""
    if has_lock:
        return
    data = json.loads(text)
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            m = re.match(r"^[\^~=v]*(\d+\.\d+\.\d+(?:-[\w.]+)?)$", str(spec).strip())
            if m:
                yield Dependency("npm", name, m.group(1), rel, _line(text, f'"{name}"'))


REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;#,]+)", re.MULTILINE)


def _requirements(text: str, rel: str):
    for m in REQ.finditer(text):
        yield Dependency("PyPI", m.group(1), m.group(2), rel, text.count("\n", 0, m.start()) + 1)


def _toml_lock(text: str, rel: str):
    for pkg in tomllib.loads(text).get("package", []):
        if pkg.get("name") and pkg.get("version"):
            yield Dependency("PyPI", pkg["name"], pkg["version"], rel, _line(text, f'name = "{pkg["name"]}"'))


def _pipfile_lock(text: str, rel: str):
    data = json.loads(text)
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            version = str(meta.get("version", "")).lstrip("=")
            if version:
                yield Dependency("PyPI", name, version, rel, _line(text, f'"{name}"'))


def parse(path: Path, rel: str) -> list[Dependency]:
    text = path.read_text(encoding="utf-8", errors="replace")
    name = path.name
    try:
        if name in {"package-lock.json", "npm-shrinkwrap.json"}:
            deps = _npm_lock(text, rel)
        elif name == "yarn.lock":
            deps = _yarn_lock(text, rel)
        elif name == "package.json":
            has_lock = any((path.parent / f).exists() for f in ("package-lock.json", "yarn.lock", "npm-shrinkwrap.json", "pnpm-lock.yaml"))
            deps = _package_json(text, rel, has_lock)
        elif name in {"poetry.lock", "uv.lock"}:
            deps = _toml_lock(text, rel)
        elif name == "Pipfile.lock":
            deps = _pipfile_lock(text, rel)
        else:
            deps = _requirements(text, rel)
        return list(dict.fromkeys(deps))
    except (ValueError, tomllib.TOMLDecodeError):
        return []
