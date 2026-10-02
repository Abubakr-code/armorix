"""File-level taint tracking with lexical scopes and simple inter-procedural flow.

Answers two questions for the rules:
  * is this expression attacker-controlled?  (reaches back to an HTTP / CLI / event source)
  * is this expression a *dynamically built* string?  (concatenation, template, f-string …)

Variables live in the scope of the function that assigns them; a lookup walks outward
through enclosing functions to the module, so closures work and a `data` in one handler
does not taint a `data` in another. Taint also crosses function boundaries inside a file:
  * call sites: `build(req.query.id)` taints the parameter of `function build(id)`;
  * returns:   `def user_input(): return request.args["q"]` makes `user_input()` a source;
  * frameworks: Flask/FastAPI route parameters, Django view kwargs, NestJS @Body/@Query/@Param,
    AWS Lambda `event` fields are sources.
Numeric casts (`int(x)`, `parseInt(x)`, `Number(x)` …) stop taint.

Rules use "tainted" for critical findings and "dynamic but untainted" for lower-confidence
ones, so a miss here lowers severity instead of hiding the bug.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from tree_sitter import Node

from .parsing import SourceFile, line_of, text, walk

TAINT_FAMILIES = {"js", "py"}

# Attacker-controlled entry points, matched against the source text of a node.
JS_SOURCE = re.compile(
    r"^(?:req|request|ctx(?:\.request)?)\.(?:query|body|params|headers|cookies|signedCookies|files|file)\b"
    # the request line itself: path and query string are fully attacker-controlled
    r"|^(?:req|request|ctx(?:\.request)?)\.(?:url|originalUrl|rawHeaders|querystring|href)\b"
    r"|^(?:req|request|ctx(?:\.request)?)\.(?:path|hostname|host)\b"
    r"|^(?:req|request|ctx(?:\.request)?)\.(?:get|header|param)\("
    r"|^(?:req|request)\.(?:json|text|formData)\(\)"
    r"|^(?:[\w$]+\.)*searchParams\.get(?:All)?\("
    r"|^event\.(?:body|queryStringParameters|multiValueQueryStringParameters|pathParameters|headers)\b"
    r"|^process\.argv\b"
    r"|^(?:window\.|document\.)?location\.(?:search|hash|href|pathname)\b"
    # Angular: the router hands the query string straight to the component
    r"|^(?:this\.)?(?:route|activatedRoute|_route)\.(?:snapshot\.)?(?:queryParams|params|queryParamMap|paramMap|fragment)\b"
    r"|^document\.(?:URL|documentURI|referrer)\b"
)
PY_SOURCE = re.compile(
    r"^request\.(?:args|form|values|json|files|cookies|headers|data|GET|POST|FILES|META|body|query_params|path_params)\b"
    r"|^request\.(?:get_json|get_data|stream)\b"
    r"|^request\.(?:path|full_path|url|base_url|url_root|referrer|host|user_agent|remote_addr|path_info)\b"
    r"|^request\.(?:get_full_path|build_absolute_uri|get_host)\("
    r"|^event\[['\"](?:body|queryStringParameters|pathParameters|headers)['\"]\]"
    r"|^event\.get\(\s*['\"](?:body|queryStringParameters|pathParameters|headers)['\"]"
    r"|^sys\.argv\b"
    r"|^input\("
)
HANDLER_CLASS = re.compile(r"^\s*class\s+\w+\s*\([^)]*\b(?:Base|SimpleHTTP|CGIHTTP)?HTTPRequestHandler\b", re.M)
PY_HANDLER_SOURCE = re.compile(PY_SOURCE.pattern + r"|^self\.(?:path|headers|rfile|requestline|raw_requestline)\b")
# Calls whose first argument is a name (a hook, an action) rather than data that flows into the result.
NAME_FIRST = {"apply_filters", "apply_filters_ref_array", "apply_filters_deprecated", "do_action", "do_action_ref_array"}
SOURCE_TYPES = {"member_expression", "attribute", "call", "call_expression", "subscript", "subscript_expression"}

# Casting to a number (or a UUID / ObjectId) leaves nothing to inject; so does hashing —
# a digest is hex or base64, so it can carry neither a quote nor an operator into a sink.
SAFE_CASTS = {"int", "float", "bool", "len", "abs", "round", "parseInt", "parseFloat", "Number", "Boolean", "isNaN",
              "UUID", "ObjectId", "isValidObjectId", "Math.floor", "Math.round", "Math.trunc", "uuid.UUID", "Decimal",
              "hexdigest", "hash", "hash_password", "hashSync", "sha1", "sha224", "sha256", "sha384", "sha512",
              "md5", "hmac", "randomUUID", "uuid4"}
NUMERIC_TYPES = re.compile(r"^(?:int|float|bool|number|boolean|bigint|UUID|uuid\.UUID|datetime|date|Decimal|PositiveInt|conint\(.*\))$")
NUMBER_NODES = {"number", "integer", "float", "true", "false", "null", "none", "int_literal", "float_literal",
                "decimal_integer_literal", "true_lit", "false_lit"}
# A hash / UUID digest is hex or base64: it cannot carry a quote or an operator into a query.
DIGEST = re.compile(r"(?i)^(?:hash|hash_password|sha1|sha224|sha256|sha384|sha512|md5|hmac|digest|hexdigest|crc32|uuid4|randomUUID)$")

ASSIGN = {
    "js": {"variable_declarator": ("name", "value"), "assignment_expression": ("left", "right"),
           "augmented_assignment_expression": ("left", "right"), "for_in_statement": ("left", "right")},
    "py": {"assignment": ("left", "right"), "augmented_assignment": ("left", "right"), "for_statement": ("left", "right"),
           "named_expression": ("name", "value")},
}
DECLARES = {"variable_declarator"}  # JS: always a new variable in the current scope
NAME_TYPES = {"identifier", "shorthand_property_identifier_pattern"}
FUNCTION_TYPES = {"function_declaration", "generator_function_declaration", "function_expression", "function",
                  "arrow_function", "method_definition", "function_definition", "lambda"}
RETURNS = {"return_statement"}

ROUTE_DECORATOR = re.compile(r"^@\s*[\w.]+\.(route|get|post|put|patch|delete|api_route|websocket)\s*\(")
FLASK_PARAM = re.compile(r"<(?:(\w+):)?(\w+)>")
BRACE_PARAM = re.compile(r"\{(\w+)(?::(\w+))?\}")
FASTAPI_SKIP_TYPES = re.compile(r"Request|Response|Session|BackgroundTasks|WebSocket|Depends|Security|HTTPConnection|Engine|Connection")
NEST_SOURCES = {"Body", "Query", "Param", "Headers", "Req", "Request", "UploadedFile"}


@dataclass
class Origin:
    """Where a variable picked up its taint — used to print the source → sink path."""

    line: int
    code: str
    via: tuple | None = None  # key of another tainted variable it came from
    source: str | None = None  # the entry point text, when taken directly from one


class Var(str):
    """A tainted variable as the rules see it: prints as its name, remembers which scope it lives in."""

    key: tuple

    def __new__(cls, name: str, key: tuple):
        obj = super().__new__(cls, name)
        obj.key = key
        return obj


class Analyzer:
    # Per-language knobs; polyglot.PolyAnalyzer overrides them for PHP / Go / Java.
    name_types = NAME_TYPES
    call_types = {"call", "call_expression"}
    function_types = FUNCTION_TYPES
    return_types = RETURNS
    declares = DECLARES
    self_receivers = {"", "this", "self", "cls"}
    source_types = SOURCE_TYPES

    def __init__(self, src: SourceFile):
        self.src = src
        self.family = src.family
        self.source_re = self.source_pattern()
        self.assign_types = self.assignment_fields()
        self.tainted: dict[tuple, Origin] = {}
        self.dynamic: dict[tuple, Node] = {}
        self._scopes: dict[int, tuple] = {}
        self.functions = self._index_functions()
        self._propagate()

    def source_pattern(self) -> re.Pattern:
        if self.family == "js":
            return JS_SOURCE
        # The standard library's own server: in a BaseHTTPRequestHandler subclass `self.path` is the
        # raw request line and `self.headers` / `self.rfile` the rest of the request. `self.path` means
        # nothing in any other class, so this only applies where such a handler is declared.
        if HANDLER_CLASS.search(self.src.text):
            return PY_HANDLER_SOURCE
        return PY_SOURCE

    def assignment_fields(self) -> dict:
        return ASSIGN.get(self.family, {})

    # ── scopes ──────────────────────────────────────────────────
    def scopes(self, node: Node) -> tuple:
        """Enclosing function node ids, innermost first, ending with 0 (the module)."""
        cached = self._scopes.get(node.id)
        if cached is not None:
            return cached
        chain = []
        cur = node.parent
        while cur is not None:
            if cur.type in self.function_types:
                chain.append(cur.id)
            cur = cur.parent
        chain.append(0)
        result = tuple(chain)
        self._scopes[node.id] = result
        return result

    def _lookup(self, table: dict, name: str, node: Node) -> tuple | None:
        for sid in self.scopes(node):
            if (sid, name) in table:
                return (sid, name)
        return None

    def _target_key(self, name: str, node: Node, declares: bool) -> tuple:
        if not declares:
            existing = self._lookup(self.tainted, name, node) or self._lookup(self.dynamic, name, node)
            if existing:
                return existing
        return (self.scopes(node)[0], name)

    # ── sources & taint ─────────────────────────────────────────
    def is_source(self, node: Node) -> bool:
        if node.type not in self.source_types:
            return False
        return bool(self.source_re.match(text(node)))

    def _callee_name(self, call: Node) -> tuple[str, str]:
        fn = call.child_by_field_name("function")
        if fn is None:
            return "", ""
        if fn.type in {"member_expression", "attribute"}:
            prop = fn.child_by_field_name("property") or fn.child_by_field_name("attribute")
            return text(fn.child_by_field_name("object")), text(prop)
        return "", text(fn)

    # ── reaching definitions (light) ────────────────────────────
    # Taint itself is flow-insensitive; at a *use* we look at the latest plain assignment before it in an enclosing
    # block. `$id = $_GET['id']; $id = intval($id); query($id)` → the use sees the clean intval() value.
    BLOCKS = {"block", "statement_block", "compound_statement", "program", "module", "source_file", "statement_list",
              "function_body", "class_body", "declaration_list", "switch_body"}

    def _block_of(self, node: Node) -> Node | None:
        cur = node.parent
        while cur is not None and cur.type not in self.BLOCKS:
            cur = cur.parent
        return cur

    def _clean_here(self, key: tuple, use: Node) -> bool:
        defs = self._defs.get(key) if hasattr(self, "_defs") else None
        if not defs:
            return False
        best, best_at = None, -1
        for start, block, value, plain in defs:
            if start >= use.start_byte:
                break
            if block is not None and block.start_byte <= use.start_byte < block.end_byte:
                best, best_at = (value, plain), start
        if best is None or not best[1]:
            return False
        # A later assignment inside a branch (`if c: q = request.args["q"]`) does not dominate the use,
        # but it *may* reach it — so it cannot be ignored just because the last unconditional one was clean.
        later = [(value, plain) for start, block, value, plain in defs if best_at < start < use.start_byte]
        if any(not plain for _, plain in later):
            return False
        for value in [best[0]] + [v for v, _ in later]:
            if value.id in self._checking:
                return False
            self._checking.add(value.id)
            try:
                if self.tainted_by(value) is not None:
                    return False
            finally:
                self._checking.discard(value.id)
        return True

    def _record_defs(self, assignments) -> None:
        self._defs: dict[tuple, list] = {}
        self._checking: set[int] = set()
        for node, names, value in assignments:
            plain = node.type in self.declares or node.type in {"assignment_expression", "assignment", "assignment_statement",
                                                                  "short_var_declaration", "variable_declarator"}
            if node.type in {"for_in_statement", "for_statement", "range_clause", "enhanced_for_statement"}:
                plain = False
            if len(names) != 1:
                plain = False  # destructuring / tuple targets: keep the conservative answer
            for name, name_node in names:
                key = self._lookup(self.tainted, name, name_node) or self._lookup(self.dynamic, name, name_node) \
                    or (self.scopes(name_node)[0], name)
                self._defs.setdefault(key, []).append((node.start_byte, self._block_of(node), value, plain))
        for items in self._defs.values():
            items.sort(key=lambda d: d[0])

    def _safe_cast(self, node: Node) -> bool:
        if node.type not in self.call_types:
            return False
        obj, name = self._callee_name(node)
        return name in SAFE_CASTS or f"{obj}.{name}" in SAFE_CASTS

    def tainted_by(self, node: Node | None) -> str | None:
        """The source text or tainted variable (a `Var`) that `node` depends on."""
        if node is None:
            return None
        stack = [node]
        while stack:
            n = stack.pop()
            if self._safe_cast(n):
                continue
            if self.is_source(n):
                return text(n)
            if n.type in self.call_types:
                ret = self._return_key(n)
                if ret:
                    return Var(text(n), ret)
                # Not narrowed for lookups: sessions.get(req.cookies.token) returns the *requester's own*
                # record, whose fields (username, bio …) they wrote themselves — Juice Shop's SSTI is that.
                if self._callee_name(n)[1] in NAME_FIRST:
                    # apply_filters("hook_{$action}", $value): the first argument names a hook, it is not the value
                    stack.extend(reversed(self.call_arguments(n)[0][1:]))
                    continue
            if n.type in self.name_types and n.type != "shorthand_property_identifier_pattern":
                key = self._lookup(self.tainted, text(n), n)
                if key and not self._clean_here(key, n):
                    return Var(text(n), key)
            if n.type in {"lambda", "arrow_function", "function_expression"} and n is not node:
                continue  # a callback's body is not the value itself
            if n.type in {"ternary_expression", "conditional_expression"}:
                # `cond ? a : b` — the value is a or b; the condition only decides which
                cond = n.child_by_field_name("condition")
                named = n.named_children
                if cond is None and self.family == "py" and len(named) == 3:
                    cond = named[1]
                stack.extend(reversed([c for c in named if cond is None or c.id != cond.id]))
                continue
            if n.type in {"subscript_expression", "subscript"}:
                # users[req.params.id] is server data picked by an untrusted key, not the key itself
                obj = n.child_by_field_name("object") or n.child_by_field_name("value")
                if obj is not None:
                    stack.append(obj)
                    continue
            stack.extend(reversed(n.children))
        return None

    # ── dynamic strings ─────────────────────────────────────────
    def is_literal(self, node: Node | None) -> bool:
        if node is None:
            return False
        if node.type == "string":
            return not any(c.type in {"interpolation", "template_substitution"} for c in node.children)
        if node.type == "template_string":
            return not any(c.type == "template_substitution" for c in node.children)
        if node.type == "concatenated_string":
            return all(self.is_literal(c) for c in node.named_children)
        return False

    def provably_safe(self, node: Node | None, seen: tuple = ()) -> bool:
        """True when this expression can only ever hold a number or a digest, so no quote or operator
        can reach a query. `Number(id)` already cast the value — reporting it again is noise."""
        if node is None or len(seen) > 6:
            return False
        t = node.type
        if t in NUMBER_NODES:
            return True
        if t in {"string", "template_string", "concatenated_string"}:
            subs = [c for c in node.children if c.type in {"interpolation", "template_substitution"}]
            return all(self.provably_safe(c, seen) for c in subs)
        if t in self.call_types:
            if self._safe_cast(node):
                return True
            obj, name = self._callee_name(node)
            return bool(DIGEST.match(name) or (obj and DIGEST.match(obj.rsplit(".", 1)[-1])))
        if t in {"binary_expression", "binary_operator", "parenthesized_expression", "interpolation",
                 "template_substitution", "unary_expression", "await_expression", "await"}:
            kids = [c for c in node.named_children if c.type != "comment"]
            return bool(kids) and all(self.provably_safe(c, seen) for c in kids)
        if t in self.name_types and t != "attribute" and t != "member_expression":
            name = text(node)
            if name in seen:
                return False
            key = self._lookup(self.tainted, name, node) or self._lookup(self.dynamic, name, node) \
                or (self.scopes(node)[0], name)
            value = None
            for start, block, val, plain in getattr(self, "_defs", {}).get(key) or []:
                if start >= node.start_byte:
                    break
                if plain and (block is None or block.start_byte <= node.start_byte < block.end_byte):
                    value = val
            return value is not None and self.provably_safe(value, seen + (name,))
        return False

    def is_dynamic_string(self, node: Node | None) -> bool:
        if node is None:
            return False
        t = node.type
        if t in {"string", "template_string", "concatenated_string"}:
            return not self.is_literal(node)
        if t in self.name_types:
            return self._lookup(self.dynamic, text(node), node) is not None
        if t in {"parenthesized_expression", "await_expression", "await"}:
            return any(self.is_dynamic_string(c) for c in node.named_children)
        if t in {"binary_expression", "binary_operator"}:
            op = text(node.child_by_field_name("operator"))
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if op == "+":
                stringy = any(self._stringy(side) for side in (left, right))
                return stringy and not (self.is_literal(left) and self.is_literal(right))
            if op == "%" and self.family == "py":  # "... %s" % value
                return self._stringy(left)
        if t in {"call", "call_expression"}:  # "...".format(x)  /  "".concat(x)  /  ",".join(x)
            fn = node.child_by_field_name("function")
            if fn is not None and fn.type in {"attribute", "member_expression"}:
                prop = fn.child_by_field_name("attribute") or fn.child_by_field_name("property")
                obj = fn.child_by_field_name("object")
                if text(prop) in {"format", "concat", "join", "replace"} and self._stringy(obj):
                    return True
        return False

    def _stringy(self, node: Node | None) -> bool:
        return node is not None and (node.type in {"string", "template_string"} or self.is_dynamic_string(node))

    def string_value(self, node: Node | None) -> str:
        """Best-effort text of a string expression, following one variable hop."""
        if node is not None and node.type in self.name_types:
            key = self._lookup(self.dynamic, text(node), node)
            if key:
                return text(self.dynamic[key])
        return text(node)

    # ── functions ───────────────────────────────────────────────
    def _function_name(self, fn: Node) -> str | None:
        name = fn.child_by_field_name("name")
        if name is not None:
            return text(name)
        parent = fn.parent
        if parent is None:
            return None
        if parent.type == "variable_declarator":
            return text(parent.child_by_field_name("name"))
        if parent.type == "pair":
            return text(parent.child_by_field_name("key")).strip("'\"")
        if parent.type in {"assignment_expression", "assignment"}:
            left = text(parent.child_by_field_name("left"))
            return left.rsplit(".", 1)[-1]
        # `HOST, PORT, FETCH = "…", 80, lambda url: urlopen(url)` — the name at the same position
        if parent.type in self.TUPLES and parent.parent is not None and parent.parent.type in {"assignment", "assignment_expression"}:
            pairs = self._paired(parent.parent.child_by_field_name("left"), parent)
            for target, value in pairs or []:
                if value.id == fn.id:
                    return text(target).rsplit(".", 1)[-1]
        return None

    def _params(self, fn: Node) -> list[list[tuple[str, Node]]]:
        """Parameter i → the names it binds (destructuring binds several) and the parameter node."""
        single = fn.child_by_field_name("parameter")  # JS `x => …`
        if single is not None:
            return [[(text(single), single)]]
        box = fn.child_by_field_name("parameters")
        if box is None:
            return []
        out = []
        for p in box.named_children:
            if p.type == "comment":
                continue
            if p.type in self.name_types:
                out.append([(text(p), p)])
                continue
            target = (p.child_by_field_name("pattern") or p.child_by_field_name("name")
                      or p.child_by_field_name("left") or next((c for c in p.named_children if c.type in self.name_types), None) or p)
            names = [(text(n), p) for n in walk(target) if n.type in self.name_types]
            out.append(names[:1] if target.type in self.name_types else names)
        return out

    def _index_functions(self) -> dict[str, list[Node]]:
        found: dict[str, list[Node]] = {}
        for node in self.src.nodes:
            if node.type in self.function_types:
                name = self._function_name(node)
                if name:
                    found.setdefault(name, []).append(node)
        return found

    def _is_method(self, fn: Node) -> bool:
        cur = fn.parent
        while cur is not None and cur.type in {"block", "decorated_definition", "class_body"}:
            cur = cur.parent
        return cur is not None and cur.type in {"class_definition", "class_declaration", "class"}

    def _return_key(self, call: Node) -> tuple | None:
        obj, name = self._callee_name(call)
        if not name or obj not in self.self_receivers:
            return None
        key = ("ret", name)
        return key if key in self.tainted else None

    # ── propagation ─────────────────────────────────────────────
    def _assignments(self):
        for node in self.src.nodes:
            fields = self.assign_types.get(node.type)
            if not fields:
                continue
            target, value = (node.child_by_field_name(f) for f in fields)
            if target is None or value is None:
                continue
            # `code, content, params = OK, PAGE, dict(query)` pairs up element by element; treating the
            # right side as one value would taint `code` and `content` along with `params`.
            pairs = self._paired(target, value)
            if pairs:
                for t, v in pairs:
                    yield node, [(text(n), n) for n in walk(t) if n.type in self.name_types], v
                continue
            names = [(text(n), n) for n in walk(target) if n.type in self.name_types]
            yield node, names, value

    TUPLES = {"pattern_list", "tuple_pattern", "expression_list", "tuple", "array_pattern", "array"}

    def _paired(self, target, value):
        if target.type not in self.TUPLES or value.type not in self.TUPLES:
            return None
        left = [c for c in target.named_children if c.type != "comment"]
        right = [c for c in value.named_children if c.type != "comment"]
        if len(left) != len(right) or len(left) < 2 or any(c.type in {"list_splat_pattern", "rest_pattern", "list_splat",
                                                                        "spread_element"} for c in left + right):
            return None
        return list(zip(left, right))

    def _taint(self, key: tuple, origin: Origin) -> bool:
        if key in self.tainted:
            return False
        self.tainted[key] = origin
        return True

    def _origin(self, at: Node, via) -> Origin:
        from_var = isinstance(via, Var)
        return Origin(line_of(at), self.src.line(line_of(at)), via=via.key if from_var else None,
                      source=None if from_var else via)

    def _framework_sources(self) -> None:
        """Handler parameters that the framework fills from the request."""
        fastapi = "fastapi" in self.src.text or "starlette" in self.src.text
        views_file = "views" in self.src.path.name
        for fns in self.functions.values():
            for fn in fns:
                params = self._params(fn)
                if not params:
                    continue
                if self.family == "py":
                    self._python_handler(fn, params, fastapi, views_file)
                elif self.family == "js":
                    self._nest_handler(fn)

    def _python_handler(self, fn: Node, params, fastapi: bool, views_file: bool) -> None:
        decorated = fn.parent is not None and fn.parent.type == "decorated_definition"
        decorators = [text(d) for d in fn.parent.named_children if d.type == "decorator"] if decorated else []
        route = next((d for d in decorators if ROUTE_DECORATOR.match(d)), None)
        names = [p[0] for p in params if p]
        line = line_of(fn)
        if route:
            flask = {name: conv for conv, name in FLASK_PARAM.findall(route)}
            brace = {name: conv for name, conv in BRACE_PARAM.findall(route)}
            for pname, pnode in names:
                if pname in {"self", "cls"}:
                    continue
                ann = pnode.child_by_field_name("type")
                ann_text = text(ann) if ann is not None else ""
                default = pnode.child_by_field_name("value")
                if pname in flask:
                    if flask[pname] in {"int", "float", "uuid"}:
                        continue
                elif pname in brace:
                    if brace[pname] in {"int", "float", "uuid"} or NUMERIC_TYPES.match(ann_text):
                        continue
                elif not fastapi or FASTAPI_SKIP_TYPES.search(ann_text) or NUMERIC_TYPES.match(ann_text) \
                        or (default is not None and re.match(r"\s*(Depends|Security)\(", text(default))):
                    continue
                self._taint((fn.id, pname), Origin(line, self.src.line(line), source=f"route parameter `{pname}`"))
        elif views_file and names and names[0][0] in {"request", "self"}:
            if names[0][0] == "request":
                rest = names[1:]
            elif len(names) > 1 and names[1][0] == "request":
                rest = names[2:]
            else:
                rest = []
            for pname, pnode in rest:
                ann = pnode.child_by_field_name("type")
                if ann is not None and NUMERIC_TYPES.match(text(ann)):
                    continue
                if pnode.child_by_field_name("value") is not None or pnode.type in {"list_splat_pattern", "dictionary_splat_pattern"}:
                    continue
                self._taint((fn.id, pname), Origin(line, self.src.line(line), source=f"URL parameter `{pname}`"))

    # `this.route.queryParams.subscribe(p => …)` and `fetch(u).then(r => …)`: the value arrives in
    # the callback, so the callback's first parameter holds it.
    DELIVERS = {"subscribe", "then", "forEach", "map", "flatMap", "mergeMap", "switchMap", "tap"}

    def _callback_sources(self) -> None:
        for call in self.src.call_nodes:
            obj, name = self._callee_name(call)
            if name not in self.DELIVERS:
                continue
            fn = call.child_by_field_name("function")
            receiver = fn.child_by_field_name("object") if fn is not None else None
            if receiver is None:
                continue
            via = text(receiver) if self.is_source(receiver) else self.tainted_by(receiver)
            if not via:
                continue
            args, _ = self.call_arguments(call)
            cb = next((a for a in args if a.type in self.function_types), None)
            params = self._params(cb)[0] if cb is not None and self._params(cb) else []
            for pname, pnode in params[:1]:
                self._taint((cb.id, pname), self._origin(receiver, via))

    def _nest_handler(self, fn: Node) -> None:
        box = fn.child_by_field_name("parameters")
        for p in box.named_children if box is not None else []:
            decos = [c for c in p.named_children if c.type == "decorator"]
            if not decos:
                continue
            deco = text(decos[0])
            m = re.match(r"@(\w+)", deco)
            if not m or m.group(1) not in NEST_SOURCES or re.search(r"Parse(?:Int|Float|Bool|UUID|Enum)Pipe", deco):
                continue
            type_node = p.child_by_field_name("type")
            if type_node is not None and re.search(r"\b(number|boolean)\b", text(type_node)):
                continue
            target = p.child_by_field_name("pattern")
            for n in walk(target) if target is not None else []:
                if n.type in NAME_TYPES:
                    self._taint((fn.id, text(n)), Origin(line_of(p), self.src.line(line_of(p)), source=f"@{m.group(1)}() {text(n)}"))

    def call_arguments(self, call: Node) -> tuple[list[Node], dict[str, Node]]:
        """(positional, keyword) argument nodes of a call."""
        box = call.child_by_field_name("arguments")
        if box is None:
            return [], {}
        positional = [a for a in box.named_children if a.type not in {"comment", "keyword_argument"}]
        keywords = {text(a.child_by_field_name("name")): a.child_by_field_name("value")
                    for a in box.named_children if a.type == "keyword_argument"}
        return positional, keywords

    def _call_sites(self) -> bool:
        """`helper(req.query.x)` → the helper's parameter is tainted inside the helper."""
        changed = False
        for call in self.src.call_nodes:
            obj, name = self._callee_name(call)
            fns = self.functions.get(name)
            if not fns or obj not in self.self_receivers:
                continue
            positional, keywords = self.call_arguments(call)
            if not positional and not keywords:
                continue
            for fn in fns:
                params = self._params(fn)
                if obj in {"self", "cls"} or (self.family == "py" and self._is_method(fn) and params and params[0] and params[0][0][0] in {"self", "cls"}):
                    params = params[1:]
                for i, arg in enumerate(positional):
                    if i >= len(params):
                        break
                    via = self.tainted_by(arg)
                    if via:
                        for pname, _ in params[i]:
                            changed |= self._taint((fn.id, pname), self._origin(call, via))
                for kw, value in keywords.items():
                    via = self.tainted_by(value)
                    if via:
                        for group in params:
                            for pname, _ in group:
                                if pname == kw:
                                    changed |= self._taint((fn.id, pname), self._origin(call, via))
        return changed

    def _returns(self) -> bool:
        """A function that returns tainted data makes its callers' results tainted."""
        changed = False
        for name, fns in self.functions.items():
            key = ("ret", name)
            if key in self.tainted:
                continue
            for fn in fns:
                body = fn.child_by_field_name("body")
                if body is None:
                    continue
                values = []
                if fn.type in {"arrow_function", "lambda"} and body.type != "statement_block":
                    values.append(body)
                for n in walk(body):
                    if n.type in self.return_types and n.named_children and self.scopes(n)[0] == fn.id:
                        values.append(n.named_children[0])
                for value in values:
                    via = self.tainted_by(value)
                    if via:
                        changed |= self._taint(key, self._origin(value, via))
                        break
                if key in self.tainted:
                    break
        return changed

    def _propagate(self) -> None:
        self._framework_sources()
        if self.family == "js":
            self._callback_sources()
        assignments = list(self._assignments())
        for _ in range(8):
            changed = False
            for node, names, value in assignments:
                via = self.tainted_by(value)
                dynamic = self.is_dynamic_string(value)
                declares = node.type in self.declares
                for name, name_node in names:
                    key = self._target_key(name, name_node, declares)
                    if via and not (isinstance(via, Var) and via.key == key):
                        changed |= self._taint(key, self._origin(value, via))
                    if dynamic and key not in self.dynamic:
                        self.dynamic[key] = value
                        changed = True
            changed |= self._call_sites()
            changed |= self._returns()
            if not changed:
                break
        self._record_defs(assignments)

    # ── tracing ─────────────────────────────────────────────────
    def root(self, via: str) -> str:
        """The original entry point behind a tainted name: `sql` → `req.query.id`."""
        chain = self.origin_chain(via)
        return chain[0].source if chain and chain[0].source else str(via)

    def origin_chain(self, via: str) -> list[Origin]:
        """Follows `a = b; b = req.query.x` back to the original source, oldest first."""
        key = getattr(via, "key", None)
        chain, seen = [], set()
        while key is not None and key in self.tainted and key not in seen:
            seen.add(key)
            origin = self.tainted[key]
            chain.append(origin)
            key = origin.via
        return list(reversed(chain))
