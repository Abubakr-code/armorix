"""JavaScript written inside a PHP or HTML page.

A PHP page that prints a `<script>` block is where DOM XSS lives in most legacy apps — the
PHP parser sees that block as a string, so nothing in it is ever analysed. This lifts the
inline scripts out as one JavaScript file and hands them to the ordinary JS rules.

Everything outside a `<script>` body is replaced by blanks rather than removed, so offsets
and line numbers stay exactly as they are in the real file and a finding points at the line
the developer will open.
"""

from __future__ import annotations

import re

from .parsing import SourceFile, _parser

SCRIPT = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
# `src=` loads another file (scanned on its own); a non-JS type is data, not code.
EXTERNAL = re.compile(r"\bsrc\s*=", re.IGNORECASE)
NON_JS_TYPE = re.compile(r"""\btype\s*=\s*["']?\s*(?!(?:text|application)/(?:java|ecma)script|module)[\w./+-]+""", re.IGNORECASE)
PHP_TAG = re.compile(r"<\?(?:php|=)?.*?(?:\?>|\Z)", re.DOTALL)


def inline_js(src: SourceFile) -> SourceFile | None:
    """The page's inline scripts as a JavaScript SourceFile, or None when it has none."""
    if "<script" not in src.text.lower():
        return None
    blank = ["\n" if ch == "\n" else " " for ch in src.text]
    found = False
    for m in SCRIPT.finditer(src.text):
        attrs, body = m.group(1), m.group(2)
        if EXTERNAL.search(attrs) or NON_JS_TYPE.search(attrs) or not body.strip():
            continue
        # `<?php echo $x; ?>` inside a script is not JavaScript; blank it so the parse stays clean.
        body = PHP_TAG.sub(lambda p: re.sub(r"[^\n]", " ", p.group(0)), body)
        # A script written inside a Python or PHP string carries that language's escapes: `alert(\"x\")`.
        # Undo them in place — same length, so every offset still points at the real line.
        if src.family in {"py", "php"}:
            body = re.sub(r"""\\(["'])""", r" \1", body)
        blank[m.start(2):m.end(2)] = list(body)
        found = True
    if not found:
        return None
    text = "".join(blank)
    return SourceFile(path=src.path, rel=src.rel, text=text, grammar="javascript",
                      tree=_parser("javascript").parse(text.encode("utf-8")), lines=src.lines)


# Raw-HTML bindings in component templates: Vue's v-html and Svelte's {@html} switch the framework's
# escaping off for one expression. (Angular's [innerHTML] is still sanitised, so it is not one of them.)
RAW_BINDING = re.compile(r"""\bv-html\s*=\s*(["'])(?P<vue>.*?)\1|\{@html\s+(?P<svelte>[^}]+)\}""", re.DOTALL)
CLEANED = re.compile(r"DOMPurify|sanitize|purify|escape", re.IGNORECASE)


def raw_html_bindings(src: SourceFile):
    """(line, expression, syntax) for every raw-HTML binding whose expression is not a plain string."""
    out = []
    for m in RAW_BINDING.finditer(src.text):
        expr = (m.group("vue") if m.group("vue") is not None else m.group("svelte") or "").strip()
        if not expr or CLEANED.search(expr) or re.fullmatch(r"""(['"`]).*\1""", expr, re.DOTALL):
            continue
        line = src.text.count("\n", 0, m.start()) + 1
        out.append((line, expr, "v-html" if m.group("vue") is not None else "{@html}"))
    return out
