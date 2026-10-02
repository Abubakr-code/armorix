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


def php_sources(files: list[tuple[Path, str]]) -> dict[str, tuple[str, int]]:
    """{variable name: (file it was filled in, line)} for names filled straight from a superglobal."""
    found: dict[str, tuple[str, int]] = {}
    for path, rel in files[:MAX_FILES]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in ASSIGNED_FROM_SUPERGLOBAL.finditer(text):
            name = m.group(1)
            if name in found or GUARDED.search(text[max(0, m.start() - 300):m.start()]):
                continue
            found[name] = (rel, text.count("\n", 0, m.start()) + 1)
    return found


def inherited_for(text: str, rel: str, sources: dict[str, tuple[str, int]]) -> dict[str, tuple[str, int]]:
    """The names this file uses but never binds — so they can only have come from an include."""
    out = {}
    for name, (where, line) in sources.items():
        if where == rel or f"${name}" not in text:
            continue
        if _bound_in(text, name):
            continue
        out[name] = (where, line)
    return out
