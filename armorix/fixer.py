"""AI patches that must survive a re-scan before Armorix will show or apply them.

    finding → code window (enclosing function) → local model → candidate code
            → splice into a temp copy → syntax check → re-scan → verified / rejected
"""

from __future__ import annotations

import difflib
from collections import Counter
import re
import shutil
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path

from .ai import LocalAI
from .finding import Finding
from .names import globals_for, scope
from .parsing import GRAMMARS, load, walk
from .scanner import scan

FUNCTIONS = {
    "function_declaration", "function_expression", "arrow_function", "method_definition", "generator_function_declaration",
    "function_definition", "decorated_definition",
}
MAX_WINDOW = 40
LANG = {"javascript": "javascript", "typescript": "typescript", "tsx": "tsx", "python": "python", "c": "c", "cpp": "cpp"}
FENCE = re.compile(r"```[\w+-]*\n(.*?)```", re.DOTALL)


@dataclass
class Patch:
    finding: Finding
    start: int  # 1-based, inclusive
    end: int
    original: str
    fixed: str
    diff: str
    verified: bool
    reason: str
    seconds: float
    imports: list[str] = field(default_factory=list)  # hoisted to the top of the file on apply


def window(path: Path, rel: str, finding: Finding) -> tuple[int, int]:
    """Smallest enclosing function around the finding and its trace; else a few lines of context."""
    src = load(path, rel)
    lines = [finding.line, *(s.line for s in finding.trace)]
    lo, hi = min(lines), max(lines)
    best = None
    for node in walk(src.tree.root_node):
        if node.type not in FUNCTIONS:
            continue
        s, e = node.start_point[0] + 1, node.end_point[0] + 1
        # Must enclose the vulnerable call itself — not a callback passed to it on the same line.
        starts_before = s < lo or (s == lo and node.start_point[1] < finding.column - 1)
        if starts_before and e >= hi and e - s < MAX_WINDOW and (best is None or e - s < best[1] - best[0]):
            best = (s, e)
    if best:
        return best
    return max(1, lo - 1), min(len(src.lines), hi + 1)


TOP_DECL = re.compile(r"^(?:const|let|var)\s+[\w${}\s,]+=\s*[^;{]*;?\s*$|^[A-Za-z_]\w*\s*=\s*[^\n]*$")


def _context(lines: list[str], start: int, family: str) -> str:
    """Only imports and one-line top-level declarations — never other handlers, which small models copy."""
    keep = [ln.rstrip("\n") for ln in lines[: start - 1]
            if IMPORT[family].match(ln) or (not ln[:1].isspace() and TOP_DECL.match(ln.rstrip("\n")))]
    return "\n".join(keep[:20])


def _drop_echo(body: str, lines: list[str], start: int, end: int) -> str:
    """Removes lines the model copied from outside the window (context echo)."""
    inside = {ln.strip() for ln in lines[start - 1:end]}
    outside = {ln.strip() for i, ln in enumerate(lines) if not (start - 1 <= i < end) and len(ln.strip()) > 3}
    kept = [ln for ln in body.splitlines() if not (ln.strip() in outside and ln.strip() not in inside)]
    return "\n".join(kept)


def _prompt(finding: Finding, lang: str, code: str, context: str, feedback: str = "") -> str:
    retry = f"\nYour previous patch was REJECTED by the verifier: {feedback}. Produce a different, correct fix.\n" if feedback else ""
    return f"""You are Armorix, a security engineer that patches vulnerable code.

File context (read-only, already present — do not repeat it):
```{lang}
{context}
```

Vulnerability: {finding.title} ({finding.cwe})
Details: {finding.message}
Required fix: {finding.fix}

Rewrite the code below so the vulnerability is gone.
Rules:
- Reply with ONLY the corrected code in a single ```{lang} block — no explanation.
- Return the complete replacement for exactly these lines; keep names, behaviour and style.
- Only use functions and variables that already exist in the file context or the language standard library.
  Never invent helpers (no isPrivateIP, ALLOWED_HOSTS, sanitize…) — write the check inline instead.
- If you need a new import, put it on the first line(s) of your code block; it will be moved to the top of the file.

{retry}
```{lang}
{code}
```"""


def _extract(reply: str) -> str | None:
    m = FENCE.search(reply)
    body = m.group(1) if m else (reply if "```" not in reply else None)
    return body.strip("\n") if body and body.strip() else None


IMPORT = {
    "py": re.compile(r"^\s*(?:import\s+[\w.]+(?:\s+as\s+\w+)?(?:\s*,\s*[\w.]+(?:\s+as\s+\w+)?)*|from\s+[\w.]+\s+import\s+.+)\s*$"),
    "js": re.compile(r"^\s*(?:(?:const|let|var)\s+[\w${}\s,:]+=\s*require\([^)]*\);?|import\s+.+\s+from\s+['\"][^'\"]+['\"];?)\s*$"),
    "c": re.compile(r"^\s*#\s*include\s*[<\"][^>\"]+[>\"]\s*$"),
}


def _split_imports(body: str, family: str) -> tuple[list[str], str]:
    """Leading import lines of the model's reply, and the rest of the code."""
    lines = body.splitlines()
    imports = []
    while lines and (IMPORT[family].match(lines[0]) or (imports and not lines[0].strip())):
        line = lines.pop(0)
        if line.strip():
            imports.append(line.strip())
    return imports, "\n".join(lines)


def _hoist(lines: list[str], imports: list[str], family: str) -> tuple[list[str], int]:
    """Inserts new imports after the file's last top-level import; returns (lines, number inserted)."""
    existing = {ln.strip() for ln in lines}
    new = [imp + "\n" for imp in imports if imp not in existing]
    if not new:
        return lines, 0
    last = 0
    for i, ln in enumerate(lines[:60]):
        if IMPORT[family].match(ln):
            last = i + 1
    return lines[:last] + new + lines[last:], len(new)


def _reindent(code: str, indent: str) -> str:
    return textwrap.indent(textwrap.dedent(code), indent, lambda line: line.strip() != "")


def propose(ai: LocalAI, root: Path, finding: Finding, attempts: int = 2) -> Patch | None:
    path = root / finding.file if root.is_dir() else root
    grammar = GRAMMARS.get(path.suffix.lower())
    if grammar is None:  # .env / config: nothing to rewrite, the value must be removed and rotated
        return None
    started = time.perf_counter()
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    start, end = window(path, finding.file, finding)
    original = "".join(lines[start - 1:end])
    indent = re.match(r"[ \t]*", lines[start - 1]).group(0)

    family = {"python": "py", "c": "c", "cpp": "c"}.get(grammar, "js")
    feedback, fixed, diff, verified, reason = "", "", "", False, "model returned no code"
    shift = 0
    for _ in range(attempts):
        reply = ai.generate(_prompt(finding, LANG[grammar], textwrap.dedent(original).rstrip("\n"), _context(lines, start, family), feedback))
        body = _extract(reply)
        if body is None:
            feedback = reason = "no code block in the reply"
            continue
        imports, body = _split_imports(textwrap.dedent(body), family)
        body = _drop_echo(body, lines, start, end).strip("\n")
        if not body.strip():
            feedback = reason = "reply contained only imports"
            continue
        fixed = _reindent(body, indent).rstrip("\n") + "\n"
        head, shift = _hoist(lines[:start - 1], imports, family)
        new_lines = head + fixed.splitlines(keepends=True) + lines[end:]
        diff = "".join(difflib.unified_diff(lines, new_lines, f"a/{finding.file}", f"b/{finding.file}", n=1))
        if fixed.strip() == original.strip():
            verified, reason = False, "model returned the code unchanged"
        else:
            verified, reason = _verify(path, finding, "".join(lines), "".join(new_lines), start + shift, start + shift + fixed.count("\n") - 1)
        if verified:
            break
        feedback = reason
    patch = Patch(finding, start, end, original, fixed, diff, verified, reason, time.perf_counter() - started)
    patch.imports = imports if verified else []
    return patch


def _verify(path: Path, finding: Finding, old_text: str, new_text: str, lo: int, hi: int) -> tuple[bool, str]:
    """Re-parse and re-scan the patched file in isolation; reject made-up names and new issues."""
    with tempfile.TemporaryDirectory(prefix="armorix-verify-") as tmp:
        old_file, new_file = Path(tmp) / "old" / path.name, Path(tmp) / "new" / path.name
        for f, content in ((old_file, old_text), (new_file, new_text)):
            f.parent.mkdir()
            f.write_text(content, encoding="utf-8")
        old_src, new_src = load(old_file, path.name), load(new_file, path.name)
        if new_src.tree.root_node.has_error:
            return False, "patched code does not parse"
        before = scan(old_file, deps=False).findings
        after = scan(new_file, deps=False).findings

    same = [f for f in after if f.rule_id == finding.rule_id and lo - 1 <= f.line <= hi + 1]
    if same:
        return False, f"{finding.rule_id} still detected at line {same[0].line}"
    # Count-based, file-wide: a patch that duplicates vulnerable code must not hide behind "already known".
    grown = Counter((f.rule_id, f.snippet) for f in after) - Counter((f.rule_id, f.snippet) for f in before)
    if grown:
        return False, f"patch introduced {next(iter(grown))[0]}"
    if len(after) >= len(before):
        return False, "issue count did not go down"

    misuse = _api_misuse(new_src, lo, hi) or _weak_fix(finding, new_text.splitlines()[lo - 1:hi])
    if misuse:
        return False, misuse

    # Hallucination guard: every name the patch uses must exist somewhere (old file, new file, builtins).
    _, old_used = scope(old_src)
    old_defined, _ = scope(old_src)
    new_defined, new_used = scope(new_src)
    known_names = old_defined | new_defined | set(old_used) | globals_for(new_src.family)
    invented = sorted(n for n, line in new_used.items() if lo <= line <= hi and n not in known_names)
    if invented:
        return False, f"patch uses undefined name `{invented[0]}`"
    return True, "re-scan clean"


# Calls small models commonly get wrong in a way that parses but breaks at runtime.
ARRAY_FIRST_ARG = {("js", "execFile"), ("js", "execFileSync"), ("js", "spawn"), ("js", "spawnSync")}


def _api_misuse(src, lo: int, hi: int) -> str | None:
    for call in src.call_nodes:
        line = call.start_point[0] + 1
        if not lo <= line <= hi:
            continue
        fn = call.child_by_field_name("function")
        name = fn.child_by_field_name("property") if fn is not None and fn.type == "member_expression" else fn
        arg_list = call.child_by_field_name("arguments")
        first = arg_list.named_children[0] if arg_list is not None and arg_list.named_children else None
        if name is not None and (src.family, name.text.decode()) in ARRAY_FIRST_ARG and first is not None and first.type == "array":
            return f"{name.text.decode()}() takes the program name first, then an argument array"
    return None


INTERNAL_HOSTS = re.compile(r"""['"](?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|169\.254\.169\.254|metadata\.google\.internal)['"]""")


def _weak_fix(finding: Finding, patched: list[str]) -> str | None:
    """Fixes that pass the scanner but defeat their own purpose."""
    if finding.rule_id == "ARX-SSRF" and any(INTERNAL_HOSTS.search(line) for line in patched):
        return "SSRF allow-list must not include localhost / internal addresses"
    return None


def apply(root: Path, patches: list[Patch]) -> list[Patch]:
    """Writes verified patches bottom-up per file (earlier line numbers stay valid); skips overlaps."""
    applied = []
    by_file: dict[str, list[Patch]] = {}
    for p in patches:
        if p.verified:
            by_file.setdefault(p.finding.file, []).append(p)
    for rel, items in by_file.items():
        path = root / rel if root.is_dir() else root
        backup = path.with_name(path.name + ".armorix.bak")
        if not backup.exists():
            shutil.copy2(path, backup)
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        taken: list[tuple[int, int]] = []
        imports: list[str] = []
        for p in sorted(items, key=lambda p: -p.start):
            if any(not (p.end < s or p.start > e) for s, e in taken):
                continue
            lines[p.start - 1:p.end] = p.fixed.splitlines(keepends=True)
            taken.append((p.start, p.end))
            imports += [i for i in p.imports if i not in imports]
            applied.append(p)
        if imports:
            family = "py" if path.suffix == ".py" else "c" if path.suffix in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"} else "js"
            lines, _ = _hoist(lines, imports, family)
        path.write_text("".join(lines), encoding="utf-8")
    return applied
