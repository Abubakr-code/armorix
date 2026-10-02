"""Taint that crosses JavaScript / TypeScript and Python modules.

A layered app splits every flow: the route reads `req.query.threshold`, hands it to
`allocationsDAO.getByUserIdAndThreshold(userId, threshold)`, and the DAO builds the query in
another file. Analysed one file at a time, the route has no sink and the DAO has no source.

Each file's first analysis also reports the calls it makes to functions it does not define,
with the arguments that were tainted. This module resolves those calls to the file and function
they land in — through `require` / `import`, `new Service()` instances, TypeScript constructor
injection, and as a last resort a method name that only one file in the project defines — and the
scanner analyses the target again with those parameters tainted. Repeating that a few times
follows route → service → repository chains.
"""

from __future__ import annotations

import posixpath
import re

JS_EXT = (".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs")
PY_EXT = (".py",)

# const X = require('./a')  ·  const X = require('./a').Name
_REQUIRE = re.compile(r"""(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)(?:\.(\w+))?""")
# const { a, b: c } = require('./a')
_REQUIRE_DESTRUCT = re.compile(r"""(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)""")
# import X, { a, b as c } from './a'  ·  import { a } from './a'  ·  import * as X from './a'
_IMPORT = re.compile(r"""import\s+(?:(\w+)\s*,?\s*)?(?:\{([^}]*)\})?\s*(?:\*\s*as\s+(\w+))?\s*from\s*['"]([^'"]+)['"]""")
_NEW = re.compile(r"""(?:this\.)?(\w+)\s*=\s*new\s+(\w+)\s*\(""")
_CTOR = re.compile(r"""constructor\s*\(([^)]*)\)""", re.S)
_DI_PARAM = re.compile(r"""(?:private|public|protected|readonly)\s+(?:readonly\s+)?(\w+)\s*:\s*(\w+)""")

_PY_FROM = re.compile(r"""^[ \t]*from\s+(\.*[\w.]*)\s+import\s+\(?([^\n#)]+)""", re.M)
_PY_IMPORT = re.compile(r"""^[ \t]*import\s+([\w.]+)(?:\s+as\s+(\w+))?\s*$""", re.M)
_PY_NEW = re.compile(r"""(?:self\.)?(\w+)\s*=\s*([A-Z]\w*)\s*\(""")

# Too common to pick a single definition by name alone.
COMMON = {"get", "set", "find", "findOne", "findAll", "findById", "save", "update", "delete", "remove", "create",
          "query", "execute", "run", "send", "render", "handle", "process", "load", "fetch", "call", "apply",
          "init", "start", "stop", "close", "open", "read", "write", "list", "add", "push", "map", "filter",
          "validate", "parse", "format", "toString", "then", "catch", "emit", "on", "use", "next", "log",
          "__init__", "main", "index", "show", "store", "edit", "destroy", "count", "exists", "search"}


def _names(spec: str) -> list[tuple[str, str]]:
    """`a, b as c` / `a, b: c` → [(local, exported)]."""
    out = []
    for part in spec.replace("\n", " ").split(","):
        part = part.strip().strip("()")
        if not part or part.startswith("type "):
            continue
        m = re.match(r"(\w+)\s*(?:as|:)\s*(\w+)", part)
        out.append((m.group(2), m.group(1)) if m else (part.split()[0], part.split()[0]))
    return out


def collect(src, taint) -> dict:
    """What another file's analysis needs from this one: imports, instances, and tainted outgoing calls."""
    text = src.text
    imports: dict[str, list] = {}   # local name → [module spec, exported name | None for the module itself]
    instances: dict[str, str] = {}  # variable / property → class name
    if src.family == "js":
        for m in _REQUIRE.finditer(text):
            imports[m.group(1)] = [m.group(2), m.group(3)]
        for m in _REQUIRE_DESTRUCT.finditer(text):
            for local, exported in _names(m.group(1)):
                imports[local] = [m.group(2), exported]
        for m in _IMPORT.finditer(text):
            default, braces, star, spec = m.groups()
            if default:
                imports[default] = [spec, "default"]
            if star:
                imports[star] = [spec, None]
            for local, exported in _names(braces or ""):
                imports[local] = [spec, exported]
        for m in _NEW.finditer(text):
            instances[m.group(1)] = m.group(2)
        for m in _CTOR.finditer(text):  # NestJS / Angular constructor injection
            for p in _DI_PARAM.finditer(m.group(1)):
                instances[p.group(1)] = p.group(2)
    elif src.family == "py":
        for m in _PY_FROM.finditer(text):
            for local, exported in _names(m.group(2)):
                imports[local] = [m.group(1), exported]
        for m in _PY_IMPORT.finditer(text):
            imports[m.group(2) or m.group(1).split(".")[-1]] = [m.group(1), None]
        for m in _PY_NEW.finditer(text):
            if m.group(2) in imports:
                instances[m.group(1)] = m.group(2)

    calls = []
    local = set(taint.functions) if taint is not None else set()
    if taint is not None:
        for call in src.call_nodes:
            obj, name = taint._callee_name(call)
            if not name or (not obj and name in local):
                continue  # a call to a function in this file is followed already
            args, _ = taint.call_arguments(call)
            tainted = {}
            for i, arg in enumerate(args):
                via = taint.tainted_by(arg)
                if via:
                    tainted[str(i)] = f"{taint.root(via)} ({src.rel}:{call.start_point[0] + 1})"
            if tainted:
                calls.append({"obj": obj or "", "name": name, "args": tainted})
    return {"imports": imports, "instances": instances, "calls": calls, "defs": sorted(local),
            "renders": _renders(src, taint) if taint is not None else []}


RENDER_JS = {"render", "view"}
RENDER_PY = {"render_template", "render", "TemplateResponse", "render_to_response", "render_to_string"}


def _renders(src, taint) -> list[dict]:
    """res.render("products", {term: req.query.q}) / render_template("a.html", q=…) / render(request, "a.html", {…}):
    the template, and which of the names it receives carry request data."""
    from .parsing import text, walk
    out = []
    for call in src.call_nodes:
        obj, name = taint._callee_name(call)
        args, kwargs = taint.call_arguments(call)
        if src.family == "js" and name in RENDER_JS and obj in {"res", "response", "reply", "ctx", "h"}:
            pass
        elif src.family == "py" and name in RENDER_PY:
            pass
        else:
            continue
        strings = [a for a in args if a.type in {"string", "template_string"} and taint.is_literal(a)]
        if not strings:
            continue
        template = text(strings[0]).strip("'\"`")
        keys: dict[str, str] = {}
        line = call.start_point[0] + 1
        for ctx in [a for a in args if a.type in {"object", "dictionary"}]:
            for pair in ctx.named_children:
                if pair.type == "pair":
                    key = text(pair.child_by_field_name("key")).strip("'\"")
                    value = pair.child_by_field_name("value")
                elif pair.type == "shorthand_property_identifier":
                    key, value = text(pair), pair
                else:
                    continue
                via = taint.tainted_by(value)
                if via:
                    keys[key] = f"{taint.root(via)} ({src.rel}:{line})"
        for key, value in (kwargs or {}).items():
            via = taint.tainted_by(value)
            if via:
                keys[key] = f"{taint.root(via)} ({src.rel}:{line})"
        if src.family == "py":  # Flask's render_template(name, q=…) arrives as keyword_argument nodes
            box = call.child_by_field_name("arguments")
            for kw in (box.named_children if box is not None else []):
                if kw.type == "keyword_argument":
                    via = taint.tainted_by(kw.child_by_field_name("value"))
                    if via:
                        keys[text(kw.child_by_field_name("name"))] = f"{taint.root(via)} ({src.rel}:{line})"
        out.append({"template": template, "keys": keys})
    return out


def _resolve_js(spec: str, from_rel: str, files: set[str]) -> str | None:
    if spec.startswith("@/"):
        base = "src/" + spec[2:]
    elif spec.startswith("."):
        base = posixpath.normpath(posixpath.join(posixpath.dirname(from_rel), spec))
    else:
        return None  # a package from node_modules
    for cand in [base] + [base + e for e in JS_EXT] + [f"{base}/index{e}" for e in JS_EXT]:
        if cand in files:
            return cand
    return None


def _resolve_py(spec: str, from_rel: str, files: set[str]) -> str | None:
    dots = len(spec) - len(spec.lstrip("."))
    mod = spec.lstrip(".").replace(".", "/")
    if dots:
        here = posixpath.dirname(from_rel)
        for _ in range(dots - 1):
            here = posixpath.dirname(here)
        base = posixpath.join(here, mod) if mod else here
        cands = [base + ".py", base + "/__init__.py"]
    else:
        cands = [mod + ".py", mod + "/__init__.py"]
    for cand in cands:
        if cand in files:
            return cand
    if not dots and mod:  # an absolute import from a package below the scan root
        tail = (mod + ".py", mod + "/__init__.py")
        hits = [f for f in files if f.endswith(tuple("/" + t for t in tail))]
        if len(hits) == 1:
            return hits[0]
    return None


def resolve(spec: str, from_rel: str, files: set[str]) -> str | None:
    return _resolve_py(spec, from_rel, files) if from_rel.endswith(PY_EXT) else _resolve_js(spec, from_rel, files)


def _named_after(receiver: str, rel: str) -> bool:
    flat = lambda v: re.sub(r"[^a-z0-9]", "", v.lower())  # noqa: E731
    stem = flat(posixpath.basename(rel).rsplit(".", 1)[0])
    who = flat(receiver)
    return len(stem) >= 4 and len(who) >= 4 and (stem in who or who in stem)


def inbound(data: dict[str, dict], files: set[str]) -> dict[str, dict[str, dict[str, str]]]:
    """{target file: {function name: {argument index: where the tainted value came from}}}."""
    by_name: dict[str, set[str]] = {}
    for rel, d in data.items():
        for name in (d.get("modules") or {}).get("defs", []):
            by_name.setdefault(name, set()).add(rel)

    out: dict[str, dict[str, dict[str, str]]] = {}
    for rel, d in data.items():
        mods = d.get("modules")
        if not mods or not mods["calls"]:
            continue
        imports, instances = mods["imports"], mods["instances"]
        for call in mods["calls"]:
            obj, name = call["obj"], call["name"]
            head = obj.split(".")[-1] if obj else ""
            target = None
            if not obj and name in imports:                       # f(x) — imported function
                spec, exported = imports[name]
                target, fn = resolve(spec, rel, files), exported if exported not in (None, "default") else name
            elif head in imports and imports[head][1] in (None, "default"):  # dao.f(x) — module object
                target, fn = resolve(imports[head][0], rel, files), name
            elif head in instances and instances[head] in imports:  # svc.f(x) / this.svc.f(x) — an instance
                target, fn = resolve(imports[instances[head]][0], rel, files), name
            if target is None and name not in COMMON and len(name) >= 6 and head:
                owners = by_name.get(name, set()) - {rel}
                # a method only one file defines — and the receiver is named after that file
                # (allocationsDAO ↔ allocations-dao.js, userService ↔ user.service.ts), so `api.Class.extend`
                # does not land on some other file's extend()
                if len(owners) == 1 and _named_after(head, next(iter(owners))):
                    target, fn = next(iter(owners)), name
            if target is None or target == rel:
                continue
            slot = out.setdefault(target, {}).setdefault(fn, {})
            for i, desc in call["args"].items():
                slot.setdefault(i, desc)
    return out
