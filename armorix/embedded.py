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
        blank[m.start(2):m.end(2)] = list(body)
        found = True
    if not found:
        return None
    text = "".join(blank)
    return SourceFile(path=src.path, rel=src.rel, text=text, grammar="javascript",
                      tree=_parser("javascript").parse(text.encode("utf-8")), lines=src.lines)
