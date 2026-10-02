"""Taint that crosses PHP files.

PHP's `include` pulls another file into the *same* variable scope, so a legacy app routinely
splits one flow in two: `pages/low.php` does `$file = $_GET['page']`, `index.php` does
`include($file)`. Each file on its own looks harmless, and a per-file analyser finds nothing.

This pass reads the project once and answers a narrow question: which variable names does some
file fill straight from a superglobal? A file that then *uses* such a name without ever binding
it itself is almost certainly the other half of that flow, so the name is treated as tainted
there, with the trace pointing at the file that filled it.

Deliberately narrow — the name must come directly from a superglobal, and the using file must
have no binding of its own (assignment, foreach, parameter, `global`, `static`, `catch`). On
WordPress (1,899 PHP files) that leaves nothing; on DVWA it finds the file-inclusion flow.
"""

from __future__ import annotations

import re
from pathlib import Path

# $file = $_GET['page']  ·  $id = (int) $_POST['id']  ·  $x = $_REQUEST['y']
ASSIGNED_FROM_SUPERGLOBAL = re.compile(
    r"\$(\w+)\s*=\s*(?:\([^)]{0,20}\)\s*)?\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[", re.ASCII)

# Anything that gives the name a value of its own in the using file.
_BINDINGS = (
    r"\$%s\s*(?:=[^=]|\.=|\+=|-=|\*=|/=|\?\?=)",   # assignment, in any form
    r"\bas\s*&?\s*\$%s\b",                         # foreach (… as $x) and foreach (… as $k => $x)
    r"=>\s*&?\s*\$%s\b",
    r"\bfunction\b[^(){};]{0,200}\([^)]{0,400}\$%s\b",   # parameter
    r"\b(?:global|static)\s+[^;]{0,200}\$%s\b",
    r"\bcatch\s*\([^)]{0,120}\$%s\b",
    r"\blist\s*\([^)]{0,200}\$%s\b",
    r"\$%s\s*=",                                   # ...and the plain form, for anything above missed
)

# `if ( isset($_REQUEST['t']) && taxonomy_exists($_REQUEST['t']) ) { $taxnow = $_REQUEST['t']; }`
# is the safe shape, and WordPress uses it everywhere: the value was checked before it was stored.
GUARDED = re.compile(r"\b(?:if|elseif|while|switch)\b[^{;]{0,300}(?:"
                     r"\w*_exists\s*\(|in_array\s*\(|array_key_exists\s*\(|array_search\s*\(|"
                     r"preg_match\s*\(|is_numeric\s*\(|ctype_\w+\s*\(|filter_var\s*\(|"
                     r"==\s*['\"]|===\s*['\"]|\bin\s+array)", re.ASCII)

MAX_FILES = 4000  # a cap so an enormous repo cannot turn this into the slow part


def _bound_in(text: str, name: str) -> bool:
    n = re.escape(name)
    return any(re.search(pattern % n, text) for pattern in _BINDINGS)


INCLUDE = re.compile(r"\b(?:include|require)(?:_once)?\b[^;]{0,240}", re.IGNORECASE)


def _includes(text: str) -> str:
    return " ".join(m.group(0) for m in INCLUDE.finditer(text))


def php_sources(files: list[tuple[Path, str]]) -> dict[str, tuple[str, int, str]]:
    """{name: (file it was filled in, line, that file's include statements)} for names filled from a superglobal."""
    found: dict[str, tuple[str, int, str]] = {}
    for path, rel in files[:MAX_FILES]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in ASSIGNED_FROM_SUPERGLOBAL.finditer(text):
            name = m.group(1)
            if name in found or GUARDED.search(text[max(0, m.start() - 300):m.start()]):
                continue
            found[name] = (rel, text.count("\n", 0, m.start()) + 1, _includes(text))
    return found


def _linked(using_rel: str, using_includes: str, source_rel: str, source_includes: str) -> bool:
    """The two files are the two halves of one include: one of them pulls the other in.

    Matched loosely on purpose — DVWA includes "source/{$level}.php", so the directory has to count —
    but two unrelated pages of a big app that happen to share a variable name are not linked."""
    s_name, u_name = source_rel.rsplit("/", 1)[-1], using_rel.rsplit("/", 1)[-1]
    s_dir = source_rel.rsplit("/", 1)[0] if "/" in source_rel else ""
    s_dir_last = s_dir.rsplit("/", 1)[-1]
    return (s_name in using_includes or u_name in source_includes
            or bool(s_dir_last and f"{s_dir_last}/" in using_includes))


def inherited_for(text: str, rel: str, sources: dict) -> dict[str, tuple[str, int]]:
    """The names this file uses but never binds, and that a file it is included with filled from the request."""
    out = {}
    mine = None
    for name, (where, line, their_includes) in sources.items():
        if where == rel or f"${name}" not in text:
            continue
        if _bound_in(text, name):
            continue
        mine = _includes(text) if mine is None else mine
        if not _linked(rel, mine, where, their_includes):
            continue
        out[name] = (where, line)
    return out
