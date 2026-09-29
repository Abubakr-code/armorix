"""Walks a project, parses each file once and runs every applicable rule."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .deps.check import check_manifest
from .deps.manifests import is_manifest, parse
from .deps.osv import OsvDb
from .finding import Finding
from .parsing import GRAMMARS, load
from .rules import ALL_RULES
from .taint import Analyzer

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build", ".next", ".nuxt",
    "coverage", "vendor", "site-packages", ".pytest_cache", ".mypy_cache", ".idea", ".turbo", ".cache",
}
CONFIG_SUFFIXES = {".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".sh"}
MAX_BYTES = 1_000_000


@dataclass
class ScanResult:
    root: Path
    findings: list[Finding] = field(default_factory=list)
    files: int = 0
    languages: Counter = field(default_factory=Counter)
    lines: int = 0
    seconds: float = 0.0
    errors: list[str] = field(default_factory=list)
    dependencies: int = 0  # packages checked against OSV
    db_available: bool = False


def _wanted(path: Path) -> bool:
    name = path.name.lower()
    if name.endswith((".min.js", ".map", ".lock")) or name == "package-lock.json":
        return False
    return path.suffix.lower() in GRAMMARS or path.suffix.lower() in CONFIG_SUFFIXES or name.startswith(".env")


def discover(root: Path, want=_wanted) -> list[Path]:
    if root.is_file():
        return [root] if want(root) or root.suffix else []
    found = []
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir() and not entry.is_symlink():
                if entry.name not in SKIP_DIRS:
                    stack.append(entry)
            elif entry.is_file() and want(entry) and entry.stat().st_size <= 50 * MAX_BYTES:
                found.append(entry)
    return sorted(found)


def scan(target: str | Path, deps: bool = True, db: OsvDb | None = None, progress=None, cancelled=None) -> ScanResult:
    """`progress(phase, done, total, detail)` is called as work advances; `cancelled()` stops early."""
    root = Path(target).resolve()
    result = ScanResult(root=root)
    started = time.perf_counter()
    base = root if root.is_dir() else root.parent
    seen = set()
    report = progress or (lambda *a: None)
    files = discover(root)
    for index, path in enumerate(files, 1):
        if cancelled and cancelled():
            break
        if path.stat().st_size > MAX_BYTES:
            continue
        rel = str(path.relative_to(base))
        report("code", index, len(files), rel)
        try:
            src = load(path, rel)
        except OSError as exc:
            result.errors.append(f"{rel}: {exc}")
            continue
        result.files += 1
        result.lines += len(src.lines)
        if src.grammar:
            result.languages[src.family] += 1
        taint = Analyzer(src) if src.tree is not None and src.family in {"js", "py"} else None
        for rule in ALL_RULES:
            if "*" not in rule.families and src.family not in rule.families:
                continue
            for f in rule.check(src, taint):
                if f.key not in seen:
                    seen.add(f.key)
                    result.findings.append(f)
    if deps:
        db = db or OsvDb()
        result.db_available = db.available
        if db.available:
            manifests = discover(root, is_manifest)
            for index, path in enumerate(manifests, 1):
                rel = str(path.relative_to(base))
                report("deps", index, len(manifests), rel)
                result.dependencies += len(parse(path, rel))
                result.findings.extend(check_manifest(db, path, rel))
    result.findings.sort(key=lambda f: (-f.severity, f.file, f.line))
    result.seconds = time.perf_counter() - started
    return result
