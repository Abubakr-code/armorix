"""Server-side templates: output written without escaping, and which of it comes from the request.

Every engine escapes by default and every engine has a way to switch that off for one expression —
EJS `<%- x %>`, Pug `!{x}`, Handlebars `{{{x}}}`, Jinja / Django / Nunjucks `{{ x|safe }}`,
Twig `{{ x|raw }}`, Blade `{!! x !!}`, ERB `<%== x %>`. In a layered app the template is a separate
file from the controller that fills it, so the controller's `res.render("products", {term: req.query.q})`
is recorded too (modules.collect) and decides whether a raw expression carries request data.
"""

from __future__ import annotations

import re

SUFFIXES = (".ejs", ".pug", ".jade", ".hbs", ".handlebars", ".mustache", ".njk", ".nunjucks", ".twig",
            ".jinja", ".jinja2", ".j2", ".erb", ".blade.php", ".html", ".htm")

RAW = [
    ("EJS", re.compile(r"<%-\s*(?P<e>.+?)\s*-?%>", re.S)),
    ("ERB", re.compile(r"<%==\s*(?P<e>.+?)\s*-?%>", re.S)),
    ("Pug", re.compile(r"!\{(?P<e>[^}]+)\}|^\s*[\w.#-]*(?:\([^)]*\))?\s*!=\s*(?P<e2>.+)$", re.M)),
    ("Handlebars", re.compile(r"\{\{\{\s*(?P<e>[^}]+?)\s*\}\}\}|\{\{&\s*(?P<e2>[^}]+?)\s*\}\}")),
    ("Jinja", re.compile(r"\{\{\s*(?P<e>[^}|]+?)\s*\|\s*(?:safe|raw)\b[^}]*\}\}")),
    ("Blade", re.compile(r"\{!!\s*(?P<e>.+?)\s*!!\}", re.S)),
]
# Layout slots and partials: rendering another template's output is what they are for.
LAYOUT = re.compile(r"^(?:include\b|body$|content$|yield\b|partial\b|block\b|super\(\)|csrf_|\$?slot\b|renderBody|"
                    r"[\w.]*(?:\.html|_html|Html|HTML)$|.*\b(?:DOMPurify|sanitize|escape|json_encode|tojson|JSON\.stringify)\b)")
AUTOESCAPE_OFF = re.compile(r"\{%-?\s*autoescape\s+(?:false|off)\s*-?%\}")


def raw_outputs(text: str, rel: str) -> list[tuple[int, str, str]]:
    """(line, expression, engine) for each expression written without escaping."""
    if rel.endswith((".html", ".htm")) and "{{" not in text and "<%" not in text and "{!!" not in text:
        return []  # a plain page; its scripts are handled by embedded.py
    out = []
    for engine, pattern in RAW:
        if engine == "Blade" and not rel.endswith(".blade.php"):
            continue
        if engine == "Pug" and not rel.endswith((".pug", ".jade")):
            continue
        if engine in {"EJS", "ERB"} and not rel.endswith((".ejs", ".erb", ".html", ".htm")):
            continue
        for m in pattern.finditer(text):
            expr = (m.group("e") or (m.groupdict().get("e2") or "")).strip()
            if not expr or LAYOUT.match(expr) or re.fullmatch(r"""(['"]).*\1|\d+""", expr):
                continue
            out.append((text.count("\n", 0, m.start()) + 1, expr, engine))
    for m in AUTOESCAPE_OFF.finditer(text):
        out.append((text.count("\n", 0, m.start()) + 1, "autoescape off", "Jinja"))
    return sorted(set(out))


def root_name(expr: str) -> str:
    """`output.products[i].name` → `output`, `user.bio|e` → `user`."""
    m = re.match(r"\s*([A-Za-z_$][\w$]*)", expr)
    return m.group(1) if m else ""


def resolve(name: str, files: set[str]) -> list[str]:
    """Template files a render("app/products") call can mean: views/app/products.ejs, templates/app/products.html …"""
    name = name.strip("/")
    hits = []
    for rel in files:
        if not rel.endswith(SUFFIXES):
            continue
        stem = rel
        for suf in SUFFIXES:
            if stem.endswith(suf):
                stem = stem[: -len(suf)]
                break
        if stem == name or stem.endswith("/" + name) or rel == name or rel.endswith("/" + name):
            hits.append(rel)
    return hits
