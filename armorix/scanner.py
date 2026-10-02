"""Walks a project, parses each file once and runs every applicable rule.

Big projects are analysed in parallel worker processes; unchanged files come from the result cache.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass, field
from multiprocessing import get_context
from pathlib import Path

from .cache import ResultCache, file_key
from .deps.check import check_manifest
from .deps.manifests import is_manifest, parse
from .deps.osv import OsvDb
from .finding import Finding, Severity
from .parsing import GRAMMARS, load
from .project import ProjectConfig, assign_fingerprints, file_ignored, load_config, read_baseline, suppressed
from .rules import ALL_RULES, TEXT_FILES
from . import crossfile, embedded, polyglot
from .rules.infra import line_finding
from .polyglot import POLY_FAMILIES, PolyAnalyzer
from .taint import TAINT_FAMILIES, Analyzer

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build", ".next", ".nuxt",
    "coverage", "vendor", "site-packages", ".pytest_cache", ".mypy_cache", ".idea", ".turbo", ".cache",
    "third_party", "third-party", "bower_components", ".gradle", ".terraform", ".svelte-kit", ".output",
    ".tox", ".nox", ".ruff_cache", "Pods", ".dart_tool", ".angular", ".parcel-cache", ".vercel", ".serverless", ".vscode-test",
}
CONFIG_SUFFIXES = {".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".sh", ".tf"}
# Pages and single-file components: their <script> blocks are JavaScript nobody else looks at.
PAGE_SUFFIXES = {".html", ".htm", ".vue", ".svelte"}
MAX_BYTES = 1_000_000
PARALLEL_MIN_FILES = 80


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
    suppressed: int = 0  # silenced with armorix-ignore
    baselined: int = 0  # hidden because they are in the baseline
    cached: int = 0  # files answered from the cache
    config: str | None = None  # armorix.toml that was applied


def _wanted(path: Path) -> bool:
    name = path.name.lower()
    if name.endswith((".min.js", ".map", ".lock", ".bundle.js")) or name == "package-lock.json":
        return False
    return (path.suffix.lower() in GRAMMARS or path.suffix.lower() in CONFIG_SUFFIXES or path.suffix.lower() in PAGE_SUFFIXES
            or name.startswith(".env")
            or name in TEXT_FILES or name.startswith("dockerfile") or name.endswith(".dockerfile"))


def discover(root: Path, want=_wanted, config: ProjectConfig | None = None) -> list[Path]:
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
            try:
                if entry.is_dir() and not entry.is_symlink():
                    if entry.name not in SKIP_DIRS and not (config and config.excluded(entry.relative_to(root).as_posix() + "/")):
                        stack.append(entry)
                elif entry.is_file() and want(entry) and entry.stat().st_size <= MAX_BYTES:
                    if config and config.excluded(entry.relative_to(root).as_posix()):
                        continue
                    found.append(entry)
            except OSError:
                continue
    return sorted(found)


def analyze_file(path: Path, rel: str, disabled: frozenset[str] = frozenset(),
                 php_sources: dict | None = None) -> dict:
    """Everything the scanner needs from one file, as plain data (runs in worker processes)."""
    src = load(path, rel)
    out = {"lines": len(src.lines), "family": src.family if src.grammar else None, "findings": [], "suppressed": 0}
    if file_ignored(src.lines) or vendored(src):
        return out
    poly = src.tree is not None and src.family in POLY_FAMILIES
    inherited = crossfile.inherited_for(src.text, rel, php_sources) if php_sources and src.family == "php" else None
    taint = (PolyAnalyzer(src, inherited) if poly else Analyzer(src)) if src.tree is not None and (poly or src.family in TAINT_FAMILIES) else None
    seen = set()
    for rule in ALL_RULES:
        if rule.id in disabled or ("*" not in rule.families and src.family not in rule.families):
            continue
        if not rule.wants(src):
            continue
        for f in rule.check(src, taint):
            if f.key in seen:
                continue
            seen.add(f.key)
            if suppressed(f, src.lines):
                out["suppressed"] += 1
                continue
            out["findings"].append(f.to_dict())
    if path.suffix.lower() in {".vue", ".svelte"} and "ARX-XSS" not in disabled:
        xss = next(r for r in ALL_RULES if r.id == "ARX-XSS")
        for line, expr, syntax in embedded.raw_html_bindings(src):
            f = line_finding(xss, src, line, Severity.MEDIUM,
                             f"`{syntax}` renders `{expr[:60]}` as raw HTML — escaping is off, so any user data in it runs as script.",
                             "Render it as text ({{ value }}), or pass it through DOMPurify.sanitize() first.")
            if f.key not in seen:
                seen.add(f.key)
                if suppressed(f, src.lines):
                    out["suppressed"] += 1
                else:
                    out["findings"].append(f.to_dict())
    if src.family in {"php", "py"} or path.suffix.lower() in PAGE_SUFFIXES:
        # A <script> block inside a page (or inside a Python string holding one) is JavaScript the
        # file's own parser never looks at.
        page = embedded.inline_js(src)
        if page is not None:
            page_taint = Analyzer(page)
            for rule in ALL_RULES:
                if rule.id in disabled or "js" not in rule.families or not rule.wants(page):
                    continue
                for f in rule.check(page, page_taint):
                    if f.key in seen:
                        continue
                    seen.add(f.key)
                    if suppressed(f, src.lines):
                        out["suppressed"] += 1
                        continue
                    out["findings"].append(f.to_dict())
    if poly:  # PHP / Go / Java: one table-driven pass over the language's sinks
        for f in polyglot.check(src, taint, disabled):
            if f.key in seen:
                continue
            seen.add(f.key)
            if suppressed(f, src.lines):
                out["suppressed"] += 1
                continue
            out["findings"].append(f.to_dict())
    return out


VENDOR_BANNER = re.compile(r"@license|\(c\)\s*(?:19|20)\d\d|Copyright|Released under the MIT|jQuery (?:JavaScript Library|v\d)|"
                           r"\bLicensed under\b|SPDX-License-Identifier", re.IGNORECASE)
VENDOR_NAMES = re.compile(r"(?:^|[/\\])(?:jquery[\w.-]*|moxie|plupload[\w.-]*|tinymce[\w.-]*|codemirror[\w.-]*|lodash[\w.-]*|underscore[\w.-]*|"
                          r"backbone[\w.-]*|bootstrap[\w.-]*|react(?:-dom)?\.\w+|vue\.\w+|angular[\w.-]*|d3[\w.-]*|chart[\w.-]*|"
                          r"swfobject|mediaelement[\w.-]*|twemoji[\w.-]*|masonry[\w.-]*|imagesloaded[\w.-]*|hoverintent[\w.-]*)\.js$", re.IGNORECASE)


VENDOR_DIRS = {"tinymce", "jquery", "plupload", "codemirror", "mediaelement", "swfupload", "thickbox", "jcrop", "imgareaselect", "crop",
               "ckeditor", "froala", "fullcalendar", "select2", "datatables", "highlight", "prism", "ace", "monaco", "pdfjs", "mathjax"}


def vendored(src) -> bool:
    """A third-party JS library copied into the repo (jquery.js, tinymce …): its own project audits it, and it is noise here."""
    if src.family != "js":
        return False
    if VENDOR_NAMES.search(src.rel) or any(p.lower() in VENDOR_DIRS for p in src.rel.split("/")[:-1]):
        return True
    if src.lines and (max(map(len, src.lines[:50])) > 3000 or len(src.text) / max(1, len(src.lines)) > 400):
        return True  # minified / bundled output
    head = src.text[:1500]
    return len(src.lines) > 600 and bool(VENDOR_BANNER.search(head)) and not src.rel.startswith(("src/", "app/", "lib/", "server/"))


def _analyze_batch(batch: list[tuple[str, str]], disabled: frozenset[str],
                   php_sources: dict | None = None) -> list[tuple[str, dict | None, str | None]]:
    results = []
    for path, rel in batch:
        try:
            results.append((rel, analyze_file(Path(path), rel, disabled, php_sources), None))
        except Exception as exc:  # a parser crash in one file must not stop the scan
            results.append((rel, None, f"{rel}: {exc.__class__.__name__}: {exc}"))
    return results


def _workers() -> int:
    env = os.environ.get("ARMORIX_WORKERS")
    if env and env.isdigit():
        return max(1, int(env))
    return max(1, min(8, (os.cpu_count() or 2) - 1))


def scan(target: str | Path, deps: bool = True, db: OsvDb | None = None, progress=None, cancelled=None,
         config: ProjectConfig | None = None, baseline: set[str] | Path | None = None, use_cache: bool = True) -> ScanResult:
    """`progress(phase, done, total, detail)` is called as work advances; `cancelled()` stops early."""
    root = Path(target).resolve()
    result = ScanResult(root=root)
    started = time.perf_counter()
    base = root if root.is_dir() else root.parent
    config = config or load_config(root)
    result.config = str(config.source) if config.source else None
    disabled = frozenset(config.disable)
    report = progress or (lambda *a: None)
    stop = cancelled or (lambda: False)

    files = discover(root, config=config)
    jobs: list[tuple[Path, str]] = [(p, p.relative_to(base).as_posix()) for p in files]

    # PHP include shares one variable scope, so the flow often starts in another file: read the
    # project once for names filled from a superglobal, before any file is analysed on its own.
    php = [(p, rel) for p, rel in jobs if p.suffix.lower() in {".php", ".phtml", ".inc"}]
    php_sources = crossfile.php_sources(php) if php else None
    php_salt = hashlib.sha256(repr(sorted(php_sources.items())).encode()).hexdigest()[:12] if php_sources else ""

    # cache lookup
    cache = ResultCache() if use_cache else None
    keys: dict[str, str] = {}
    hits: dict[str, dict] = {}
    if cache and cache.con:
        for path, rel in jobs:
            try:
                extra = php_salt if (php_sources and path.suffix.lower() in {".php", ".phtml", ".inc"}) else ""
                keys[rel] = file_key(rel + extra, path.read_bytes(), disabled)
            except OSError:
                pass
        by_key = cache.get_many(list(keys.values()))
        hits = {rel: by_key[k] for rel, k in keys.items() if k in by_key}
    todo = [(str(p), rel) for p, rel in jobs if rel not in hits]
    fresh: dict[str, dict] = {}
    done = len(hits)
    total = len(jobs)
    report("code", done, total, "")

    def take(batch_results):
        nonlocal done
        for rel, data, error in batch_results:
            done += 1
            if error:
                result.errors.append(error)
            elif data is not None:
                fresh[rel] = data
        report("code", done, total, batch_results[-1][0] if batch_results else "")

    workers = _workers()
    if len(todo) >= PARALLEL_MIN_FILES and workers > 1:
        size = max(4, min(64, len(todo) // (workers * 4) or 1))
        batches = [todo[i:i + size] for i in range(0, len(todo), size)]
        try:
            with ProcessPoolExecutor(max_workers=workers, mp_context=get_context("spawn")) as pool:
                pending = {pool.submit(_analyze_batch, b, disabled, php_sources) for b in batches}
                while pending:
                    if stop():
                        for fut in pending:
                            fut.cancel()
                        break
                    finished, pending = wait(pending, timeout=0.25, return_when=FIRST_COMPLETED)
                    for fut in finished:
                        take(fut.result())
        except (OSError, RuntimeError) as exc:  # no process support (sandbox) → fall back to one process
            result.errors.append(f"parallel scan unavailable ({exc}); scanned sequentially")
            for item in todo:
                if item[1] in fresh:
                    continue
                if stop():
                    break
                take(_analyze_batch([item], disabled, php_sources))
    else:
        for item in todo:
            if stop():
                break
            take(_analyze_batch([item], disabled, php_sources))

    if cache:
        cache.put_many({keys[rel]: data for rel, data in fresh.items() if rel in keys})
    result.cached = len(hits)

    for rel, data in {**hits, **fresh}.items():
        result.files += 1
        result.lines += data["lines"]
        result.suppressed += data.get("suppressed", 0)
        if data["family"]:
            result.languages[data["family"]] += 1
        result.findings.extend(Finding.from_dict(f) for f in data["findings"])

    if deps and "ARX-DEP" not in disabled and not stop():
        db = db or OsvDb()
        result.db_available = db.available
        if db.available:
            manifests = discover(root, is_manifest, config)
            for index, path in enumerate(manifests, 1):
                rel = path.relative_to(base).as_posix()
                report("deps", index, len(manifests), rel)
                result.dependencies += len(parse(path, rel))
                result.findings.extend(check_manifest(db, path, rel))

    result.findings = [f for f in result.findings if f.severity >= config.min_severity]
    assign_fingerprints(result.findings)
    if baseline is None and config.baseline is not None and config.baseline.exists():
        baseline = config.baseline
    if baseline is not None:
        known = read_baseline(baseline) if isinstance(baseline, Path) else baseline
        kept = [f for f in result.findings if f.fingerprint not in known]
        result.baselined = len(result.findings) - len(kept)
        result.findings = kept
    result.findings.sort(key=lambda f: (-f.severity, f.file, f.line))
    result.seconds = time.perf_counter() - started
    return result


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity for f in findings)
    return {s.name.lower(): counts.get(s, 0) for s in Severity}
