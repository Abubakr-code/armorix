"""Per-project settings a team commits next to its code.

  armorix.toml / .armorix.toml   exclude paths, disable rules, minimum severity, baseline file
  .armorixignore                 gitignore-style paths to skip
  // armorix-ignore              inline: silence a finding on this line or the next one
  # armorix-ignore: ARX-SQLI     … only for the listed rules
  armorix-ignore-file            in the first lines of a file: skip the whole file
  baseline                       known findings (fingerprints) that are hidden, so CI fails only on new ones
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .finding import Finding, Severity

CONFIG_NAMES = ("armorix.toml", ".armorix.toml")
IGNORE_FILE = ".armorixignore"
INLINE = re.compile(r"armorix-ignore(?!-file)(?:\s*[:=]?\s*(?P<ids>ARX-[\w-]+(?:\s*,\s*ARX-[\w-]+)*))?", re.IGNORECASE)
FILE_MARK = "armorix-ignore-file"


@dataclass
class ProjectConfig:
    root: Path
    exclude: list[str] = field(default_factory=list)
    disable: set[str] = field(default_factory=set)
    min_severity: Severity = Severity.LOW
    baseline: Path | None = None
    include_tests: bool = False  # test code is not shipped; its fake keys and unsafe fixtures are noise
    source: Path | None = None  # the config file that was read, if any

    def excluded(self, rel: str) -> bool:
        return matches(rel, self.exclude) or (not self.include_tests and is_test_path(rel))


TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "__mocks__", "__fixtures__", "fixtures", "testdata", "test-data",
             "e2e", "cypress", "playwright", "testing"}
TEST_FILE = re.compile(r"(?:^test_.*\.py$|_test\.(?:py|go|c|cc|cpp)$|\.(?:test|spec|e2e-spec|cy)\.[cm]?[jt]sx?$|^conftest\.py$)")


def is_test_path(rel: str) -> bool:
    parts = rel.replace("\\", "/").strip("/").split("/")
    if any(p.lower() in TEST_DIRS for p in parts[:-1]) or (rel.endswith("/") and parts[-1].lower() in TEST_DIRS):
        return True
    return not rel.endswith("/") and bool(TEST_FILE.search(parts[-1]))


def _patterns(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


def matches(rel: str, patterns: list[str]) -> bool:
    """gitignore-lite: `dir/` any folder of that name, `a/b/*.js` anchored at the root, `*.min.js` any file name."""
    rel = rel.replace("\\", "/").lstrip("./")
    parts = rel.split("/")
    for raw in patterns:
        pat = raw.replace("\\", "/")
        negate = pat.startswith("!")
        if negate:
            continue  # negation is rare in ignore files for scanners; not supported
        if pat.endswith("/"):
            name = pat.rstrip("/").lstrip("/")
            if "/" in name:
                if rel == name or rel.startswith(name + "/"):
                    return True
            elif any(fnmatch.fnmatchcase(p, name) for p in parts[:-1]) or fnmatch.fnmatchcase(rel, name):
                return True
        elif "/" in pat.strip("/"):
            anchored = pat.lstrip("/")
            if fnmatch.fnmatchcase(rel, anchored) or rel.startswith(anchored.rstrip("*").rstrip("/") + "/") and anchored.endswith("**"):
                return True
            if fnmatch.fnmatchcase(rel, anchored + "/*"):
                return True
        elif any(fnmatch.fnmatchcase(p, pat.lstrip("/")) for p in parts):
            return True
    return False


def load_config(root: Path) -> ProjectConfig:
    base = root if root.is_dir() else root.parent
    cfg = ProjectConfig(root=base)
    for name in CONFIG_NAMES:
        path = base / name
        if path.is_file():
            try:
                data = tomllib.loads(path.read_text(encoding="utf-8"))
            except (tomllib.TOMLDecodeError, OSError) as exc:
                raise ValueError(f"{path}: {exc}") from None
            section = data.get("scan", data)
            cfg.exclude += [str(p) for p in section.get("exclude", [])]
            cfg.disable |= {str(r).upper() for r in section.get("disable", [])}
            if "min_severity" in section:
                cfg.min_severity = Severity.parse(str(section["min_severity"]))
            if "include_tests" in section:
                cfg.include_tests = bool(section["include_tests"])
            if section.get("baseline"):
                cfg.baseline = base / str(section["baseline"])
            cfg.source = path
            break
    ignore = base / IGNORE_FILE
    if ignore.is_file():
        cfg.exclude += _patterns(ignore.read_text(encoding="utf-8", errors="replace"))
    return cfg


def suppressed(finding: Finding, lines: list[str]) -> bool:
    """`armorix-ignore` on the finding's line or the line above (optionally limited to rule ids)."""
    for n in (finding.line, finding.line - 1):
        if 0 < n <= len(lines):
            m = INLINE.search(lines[n - 1])
            if m and (not m.group("ids") or finding.rule_id.upper() in {i.strip().upper() for i in m.group("ids").split(",")}):
                return True
    return False


def file_ignored(lines: list[str]) -> bool:
    return any(FILE_MARK in line for line in lines[:5])


# ── fingerprints & baseline ─────────────────────────────────────
def fingerprint(finding: Finding, occurrence: int = 0) -> str:
    """Stable across unrelated edits: rule + file + the code itself, not the line number."""
    code = " ".join(finding.snippet.split())
    key = f"{finding.rule_id}|{finding.file.replace(chr(92), '/')}|{code}|{occurrence}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:20]


def assign_fingerprints(findings: list[Finding]) -> None:
    seen: dict[tuple, int] = {}
    for f in sorted(findings, key=lambda f: (f.file, f.line, f.rule_id)):
        base = (f.rule_id, f.file, " ".join(f.snippet.split()))
        n = seen.get(base, 0)
        seen[base] = n + 1
        f.fingerprint = fingerprint(f, n)


def write_baseline(path: Path, findings: list[Finding]) -> int:
    entries = sorted({f.fingerprint: {"rule": f.rule_id, "file": f.file, "line": f.line} for f in findings}.items())
    path.write_text(json.dumps({"tool": "armorix", "version": 1, "findings": dict(entries)}, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return len(entries)


def read_baseline(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read baseline {path}: {exc}") from None
    return set(data.get("findings", {}))


HASH_COMMENT = {".py", ".sh", ".yml", ".yaml", ".toml", ".tf", ".rb", ".pl", ".r", ".ini", ".cfg", ".conf", ".properties"}
SLASH_COMMENT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh",
                 ".go", ".java", ".php", ".kt", ".swift", ".rs", ".cs", ".scala", ".dart"}


def add_suppression(path: Path, line: int, rule: str) -> bool:
    """Writes `armorix-ignore: RULE` above `line`, matching its indentation. False when the format has no comments (JSON)."""
    name = path.name.lower()
    if path.suffix.lower() in SLASH_COMMENT:
        marker = "//"
    elif path.suffix.lower() in HASH_COMMENT or name.startswith((".env", "dockerfile", "containerfile")):
        marker = "#"
    else:
        return False
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    if not 0 < line <= len(lines):
        return False
    target = lines[line - 1]
    indent = target[: len(target) - len(target.lstrip())]
    newline = "\r\n" if target.endswith("\r\n") else "\n"
    lines.insert(line - 1, f"{indent}{marker} armorix-ignore: {rule}{newline}")
    path.write_text("".join(lines), encoding="utf-8")
    return True
