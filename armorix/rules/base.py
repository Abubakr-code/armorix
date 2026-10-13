"""Shared helpers for AST rules: call inspection and finding construction."""

from __future__ import annotations

import re

from tree_sitter import Node

from ..finding import Finding, Severity, TraceStep
from ..parsing import SourceFile, line_of, text, walk
from ..taint import Analyzer

CALLS = {"call_expression", "call", "new_expression"}
FUNCTION_TYPES = {"function_declaration", "function_expression", "arrow_function", "method_definition", "function_definition"}


class Rule:
    id: str = ""
    cwe: str = ""
    title: str = ""
    description: str = ""
    families: tuple[str, ...] = ("js", "py")

    def wants(self, src: SourceFile) -> bool:
        """Cheap pre-filter on the file (name, text) before `check` runs."""
        return True

    def check(self, src: SourceFile, taint: Analyzer | None) -> list[Finding]:
        raise NotImplementedError


def calls(src: SourceFile):
    return src.call_nodes


def callee(call: Node) -> tuple[str, str]:
    """(object, name) of a call: `db.query(...)` → ("db", "query"), `eval(x)` → ("", "eval")."""
    fn = call.child_by_field_name("function") or call.child_by_field_name("constructor")
    if fn is None:
        return "", ""
    if fn.type in {"member_expression", "attribute"}:
        prop = fn.child_by_field_name("property") or fn.child_by_field_name("attribute")
        return text(fn.child_by_field_name("object")), text(prop)
    return "", text(fn)


def args(call: Node) -> list[Node]:
    node = call.child_by_field_name("arguments")
    if node is None:
        return []
    return [c for c in node.named_children if c.type not in {"comment", "keyword_argument"}]


def kwarg(call: Node, name: str) -> Node | None:
    """Python keyword argument value, or a JS `{ name: value }` in any argument."""
    node = call.child_by_field_name("arguments")
    if node is None:
        return None
    for c in node.named_children:
        if c.type == "keyword_argument" and text(c.child_by_field_name("name")) == name:
            return c.child_by_field_name("value")
        if c.type == "object":
            for pair in c.named_children:
                if pair.type == "pair" and text(pair.child_by_field_name("key")) == name:
                    return pair.child_by_field_name("value")
    return None


def sanitizer_call(node: Node | None, names: tuple[str, ...], src: SourceFile | None = None) -> Node | None:
    """The call inside `node` that actually sanitizes — or None.

    A sanitizer counts only when it is *called*: `DOMPurify.sanitize(x)`, `html.escape(x)`. A variable,
    property, comment or string that merely contains the word (`unsanitized`, `isEscaped`) proves nothing.
    The name has to start a word of the callee (`sanitizeHtml` yes, `unsanitize` no), and a `DOMPurify`
    declared in the same file is a local stand-in rather than the library."""
    if node is None:
        return None
    wanted = [n.rstrip("(").lower() for n in names]
    for n in walk(node):
        if n.type not in CALLS:
            continue
        fn = n.child_by_field_name("function") or n.child_by_field_name("constructor")
        if fn is None:
            continue
        tokens = [t for t in re.split(r"[^\w$]+", text(fn)) if t]
        if "DOMPurify" in tokens and src is not None and re.search(
                r"(?m)^\s*(?:export\s+)?(?:const|let|var|function|class)\s+DOMPurify\b", src.text):
            continue  # DOMPurify.sanitize(x) where DOMPurify is this file's own object, not the library
        if any(token.lower().startswith(w) for token in tokens for w in wanted):
            return n
    return None


# ── allow-list guards (Python and JS/TS) ─────────────────────────
EXIT_CALLS = {"exit", "quit", "_exit", "abort"}
MUTATORS = {"py": r"update|add|append|extend|setdefault|pop|popitem|clear|remove|discard|insert|__setitem__",
            "js": r"push|pop|shift|unshift|splice|add|delete|clear|set|fill|sort|reverse"}
SAFE_KEY = re.compile(r"^[\w][\w.\- ]*$")
SOURCE_NODES = {"py": {"attribute", "subscript", "call"}, "js": {"member_expression", "subscript_expression", "call_expression"}}
REBIND = {"py": {"assignment", "augmented_assignment", "for_statement", "named_expression"},
          "js": {"assignment_expression", "augmented_assignment_expression", "variable_declarator", "for_in_statement"}}
JS_JUMPS = {"return_statement", "throw_statement", "continue_statement", "break_statement"}


def _norm(t: str) -> str:
    return re.sub(r"\s+", "", t)


def _declaration(src: SourceFile, name: str) -> Node | None:
    """The single top-level binding `NAME = value` (Python assignment / JS const), or None if absent or repeated."""
    found = []
    for n in src.tree.root_node.named_children:
        if n.type == "export_statement" and n.named_children:
            n = n.named_children[-1]
        if src.family == "py":
            if n.type == "expression_statement" and n.named_children and n.named_children[0].type == "assignment" \
                    and text(n.named_children[0].child_by_field_name("left")) == name:
                found.append(n.named_children[0].child_by_field_name("right"))
        elif n.type in {"lexical_declaration", "variable_declaration"}:
            found += [d.child_by_field_name("value") for d in n.named_children
                      if d.type == "variable_declarator" and text(d.child_by_field_name("name")) == name]
    return found[0] if len(found) == 1 else None


def _constant_members(src: SourceFile, taint: Analyzer, container: Node | None, strict: bool = True, depth: int = 0) -> bool:
    """A literal list / set / dict whose entries are all fixed strings (and, when `strict`, plain names —
    never `../x` or `/etc/x`). A named container must be bound once at module level and never extended."""
    if container is None or depth > 3:
        return False
    fam = src.family
    if container.type == "identifier":
        name = text(container)
        value = _declaration(src, name)
        if value is None:
            return False
        n = re.escape(name)
        if fam == "py":
            changed = re.search(rf"(?<![\w.]){n}\s*(?:\[[^\n]*\]\s*=(?!=)|\|=|\+=|\.(?:{MUTATORS['py']})\()", src.text) \
                or re.search(rf"\bglobal\s+[^\n]*\b{n}\b", src.text)
        else:
            changed = re.search(rf"(?<![\w.$]){n}\s*(?:\[[^\n]*\]\s*=(?!=)|\.(?:{MUTATORS['js']})\()", src.text) \
                or len(re.findall(rf"(?<![\w.$]){n}\s*(?:[|&?+]{{1,2}})?=(?!=)", src.text)) > 1 \
                or re.search(rf"Object\.(?:assign|defineProperty|setPrototypeOf)\(\s*{n}\b", src.text)
        return not changed and _constant_members(src, taint, value, strict, depth + 1)
    if fam == "js":
        if container.type == "call_expression" and callee(container) == ("Object", "freeze") and args(container):
            return _constant_members(src, taint, args(container)[0], strict, depth + 1)
        if container.type == "new_expression" and text(container.child_by_field_name("constructor")) == "Set" and args(container):
            return _constant_members(src, taint, args(container)[0], strict, depth + 1)
        kinds = {"array", "object"}
    else:
        kinds = {"dictionary", "set", "list", "tuple", "frozenset"}
    if container.type not in kinds:
        return False
    entries = []
    for c in container.named_children:
        if c.type == "comment":
            continue
        if c.type == "pair":
            c = c.child_by_field_name("key")
            if c is not None and c.type == "property_identifier":
                entries.append(c)
                continue
        entries.append(c)
    if not entries or any(e is None or e.type not in {"string", "template_string", "property_identifier"} or
                          (e.type != "property_identifier" and not taint.is_literal(e)) for e in entries):
        return False
    names = [text(e).strip("\"'`") for e in entries]
    return all(n and (not strict or (SAFE_KEY.match(n) and ".." not in n)) for n in names)


def _terminates(block: Node | None, fam: str = "py") -> bool:
    """The branch cannot fall through: it ends in raise / return / throw / exit() / abort()."""
    if block is None:
        return False
    stmts = [c for c in block.named_children if c.type != "comment"] if block.type in {"block", "statement_block"} else [block]
    if not stmts:
        return False
    last = stmts[-1]
    if last.type in ({"raise_statement", "return_statement", "continue_statement", "break_statement"} if fam == "py" else JS_JUMPS):
        return True
    if last.type == "expression_statement" and last.named_children and last.named_children[0].type in CALLS:
        return callee(last.named_children[0])[1] in EXIT_CALLS
    return False


def _aliases(name: str, scope: Node, before: int, fam: str = "py") -> set[str]:
    """Other spellings of the value held by `name` at byte offset `before`: `project, t = sys.argv[1:]`
    makes `sys.argv[1]` the same value as `project`; `const p = req.query.p` makes `req.query.p` the same."""
    out, queue = set(), [name]
    while queue:
        cur = queue.pop()
        if cur in out:
            continue
        out.add(cur)
        for a in walk(scope):
            if a.end_byte > before:
                continue
            if fam == "js":
                if a.type == "variable_declarator" and text(a.child_by_field_name("name")) == cur and a.child_by_field_name("value") is not None:
                    right = a.child_by_field_name("value")
                elif a.type == "assignment_expression" and text(a.child_by_field_name("left")) == cur:
                    right = a.child_by_field_name("right")
                else:
                    continue
                out.add(_norm(text(right)))
                if right.type == "identifier":
                    queue.append(text(right))
                continue
            if a.type != "assignment":
                continue
            left, right = a.child_by_field_name("left"), a.child_by_field_name("right")
            if left is None or right is None:
                continue
            if left.type == "identifier" and text(left) == cur:
                out.add(_norm(text(right)))
                if right.type == "identifier":
                    queue.append(text(right))
            elif left.type in {"pattern_list", "tuple_pattern"}:
                names = [text(c) for c in left.named_children]
                if cur not in names or any(c.type == "list_splat_pattern" for c in left.named_children):
                    continue
                k = names.index(cur)
                if right.type == "subscript" and right.child_by_field_name("subscript") is not None \
                        and right.child_by_field_name("subscript").type == "slice":
                    m = re.fullmatch(r"\s*(\d*)\s*:\s*(\d*)\s*", text(right.child_by_field_name("subscript")))
                    if m:
                        out.add(_norm(f"{text(right.child_by_field_name('value'))}[{int(m.group(1) or 0) + k}]"))
                elif right.type in {"tuple", "list", "expression_list"} and len(right.named_children) == len(names):
                    out.add(_norm(text(right.named_children[k])))
    return out


def _or_operands(cond: Node | None, fam: str = "py"):
    if cond is None:
        return
    if cond.type == "parenthesized_expression" and cond.named_children:
        yield from _or_operands(cond.named_children[0], fam)
    elif cond.type == ("boolean_operator" if fam == "py" else "binary_expression") \
            and text(cond.child_by_field_name("operator")) == ("or" if fam == "py" else "||"):
        yield from _or_operands(cond.child_by_field_name("left"), fam)
        yield from _or_operands(cond.child_by_field_name("right"), fam)
    else:
        yield cond


def _rejects_unlisted(op: Node, fam: str = "py") -> tuple[Node, Node] | None:
    """The value and the list in a check that is true when the value is NOT in the list:
    `x not in ALLOWED`, `not (x in ALLOWED)`, `!ALLOWED.includes(x)`, `ALLOWED.indexOf(x) === -1`."""
    if fam == "py":
        if op.type == "not_operator" and op.named_children:
            inner = op.named_children[-1]
            while inner.type == "parenthesized_expression" and inner.named_children:
                inner = inner.named_children[0]
            return _membership(inner, "in")
        return _membership(op, "not in")
    if op.type == "unary_expression" and text(op.child_by_field_name("operator")) == "!":
        inner = op.child_by_field_name("argument")
        while inner is not None and inner.type == "parenthesized_expression" and inner.named_children:
            inner = inner.named_children[0]
        if inner is not None and inner.type == "call_expression":
            obj, name = callee(inner)
            fn, a = inner.child_by_field_name("function"), args(inner)
            if name in {"includes", "has"} and a and fn is not None and fn.type == "member_expression":
                return a[0], fn.child_by_field_name("object")
        if inner is not None and inner.type == "binary_expression" and text(inner.child_by_field_name("operator")) == "in":
            return inner.child_by_field_name("left"), inner.child_by_field_name("right")
    if op.type == "binary_expression":
        o, left, right = text(op.child_by_field_name("operator")), op.child_by_field_name("left"), op.child_by_field_name("right")
        if left is not None and left.type == "call_expression" and callee(left)[1] == "indexOf" and args(left):
            fn = left.child_by_field_name("function")
            if (o in {"===", "=="} and _norm(text(right)) == "-1") or (o == "<" and text(right) == "0"):
                return args(left)[0], fn.child_by_field_name("object")
    return None


def _membership(node: Node, wanted: str):
    if node.type != "comparison_operator":
        return None
    ops = " ".join(text(c) for c in node.children if not c.is_named)
    items = [c for c in node.named_children if c.type != "comment"]
    return (items[0], items[1]) if ops == wanted and len(items) == 2 else None


def allowlist_guard(src: SourceFile, taint: Analyzer, call: Node, arg: Node, strict: bool = True) -> bool:
    """True when every untrusted piece of `arg` was checked against a constant allow-list *and* the
    check stops the program otherwise:

        if sys.argv[1] not in PROJECTS: raise SystemExit(…)      # guard: nothing else can reach the sink
        if (!ALLOWED.includes(name)) return res.sendStatus(400)  # guard (JS)
        if project not in PROJECTS: print("invalid")             # not a guard: execution continues

    The checked value must be the one that reaches the sink (directly, by assignment or by unpacking), and
    must not be reassigned in between. Anything the analysis cannot follow stays reported."""
    fam = src.family
    if fam not in {"py", "js"} or src.tree is None:
        return False
    scope = call.parent
    while scope is not None and scope.type not in FUNCTION_TYPES:
        scope = scope.parent
    root = scope if scope is not None else src.tree.root_node
    source_types = SOURCE_NODES[fam]

    pieces: list[tuple[str, Node]] = []  # (text that identifies the untrusted value, node)
    for n in walk(arg):
        if n.type == "identifier" and taint.tainted_by(n):
            parent = n.parent
            if parent is not None and parent.type in {"attribute", "member_expression"} and \
                    (parent.child_by_field_name("object") is not n):
                continue
            if parent is not None and parent.type in CALLS and parent.child_by_field_name("function") is n:
                continue
            pieces.append((text(n), n))
        elif n.type in source_types and taint.is_source(n):
            pieces.append((_norm(text(n)), n))
    # a name inside a source expression (`sys` in `sys.argv[1]`) is part of that source, not a second value
    covered_sources = [p for p in pieces if p[1].type in source_types]
    # `req.query` inside `req.query.name` is the same value seen from a shorter prefix: keep the outermost
    pieces = [p for p in pieces if not any(c[1].id != p[1].id and p[1].type in source_types
                                           and c[1].start_byte <= p[1].start_byte and p[1].end_byte <= c[1].end_byte
                                           for c in covered_sources)]
    pieces = [p for p in pieces if p[1].type != "identifier"
              or not any(c.start_byte <= p[1].start_byte and p[1].end_byte <= c.end_byte for _, c in covered_sources)]
    if not pieces:
        return False

    guards = []
    for node in walk(root):
        if node.type != "if_statement" or node.end_byte > call.start_byte:
            continue
        holder = node.parent
        if holder is None or not (holder.start_byte <= call.start_byte < holder.end_byte):
            continue  # the check sits in a branch the call is not inside of
        if node.child_by_field_name("alternative") is not None or not _terminates(node.child_by_field_name("consequence"), fam):
            continue
        guards.append(node)

    def assigned(name: str, lo: int, hi: int) -> int:
        """How many times `name` is (re)bound between two byte offsets."""
        count = 0
        for a in walk(root):
            if a.type not in REBIND[fam] or not (lo <= a.start_byte < hi):
                continue
            target = a.child_by_field_name("left") or a.child_by_field_name("name")
            if target is not None and name in {text(x) for x in walk(target) if x.type == "identifier"}:
                count += 1
        return count

    for piece_text, piece in pieces:
        proved = False
        spellings = {_norm(x) for x in _aliases(piece_text, root, call.start_byte, fam)} | {_norm(piece_text)}
        for guard in guards:
            for op in _or_operands(guard.child_by_field_name("condition"), fam):
                hit = _rejects_unlisted(op, fam)
                if not hit or _norm(text(hit[0])) not in spellings or not _constant_members(src, taint, hit[1], strict):
                    continue
                checked = text(hit[0])
                if piece.type == "identifier":
                    if checked == piece_text:
                        # the name itself was checked: it must keep that value until the sink
                        if assigned(piece_text, guard.end_byte, call.start_byte):
                            continue
                    elif assigned(piece_text, 0, call.start_byte) != 1:
                        # an alias was checked (`sys.argv[1]`): the name must come from it, and only from it
                        continue
                if hit[0].type == "identifier" and assigned(checked, guard.end_byte, call.start_byte):
                    continue
                proved = True
                break
            if proved:
                break
        if not proved:
            return False
    return True


def finding(
    rule: Rule,
    src: SourceFile,
    node: Node,
    severity: Severity,
    message: str,
    fix: str,
    taint: Analyzer | None = None,
    via: str | None = None,
) -> Finding:
    line = line_of(node)
    trace: list[TraceStep] = []
    if taint is not None and via:
        chain = taint.origin_chain(via)
        for i, origin in enumerate(chain):
            if origin.line != line:
                trace.append(TraceStep(origin.line, origin.code, "source" if i == 0 else "flows"))
        if trace:
            trace.append(TraceStep(line, src.line(line), "sink"))
    data = {"source": taint.root(via)} if taint is not None and via else {}
    return Finding(
        data=data,
        confidence="high" if (taint is not None and via) else "medium",
        rule_id=rule.id,
        cwe=rule.cwe,
        severity=severity,
        title=rule.title,
        message=message,
        fix=fix,
        file=src.rel,
        line=line,
        column=node.start_point[1] + 1,
        snippet=src.line(line),
        trace=trace,
    )


class CallSinkRule(Rule):
    """A call whose argument must not carry untrusted (or dynamically built) data.

    Subclasses fill in:
      sinks        {family: {(object, name), …}}; object None matches any receiver
      sanitizers   substrings that make an argument safe (`basename`, `DOMPurify` …)
      tainted / dynamic   severity for a proven source → sink path / a merely non-constant argument
                          (dynamic None = only report proven taint)
    """

    sinks: dict[str, set[tuple[str | None, str]]] = {}
    arg_index = 0
    sanitizers: tuple[str, ...] = ()
    tainted: Severity = Severity.HIGH
    dynamic: Severity | None = None
    msg_tainted = "Untrusted input `{src}` reaches `{name}`."
    msg_dynamic = "`{name}` receives a non-constant value."
    fix: dict[str, str] = {}

    def matches(self, src: SourceFile, call: Node) -> bool:
        obj, name = callee(call)
        return any(n == name and (o is None or o == obj) for o, n in self.sinks.get(src.family, ()))

    def target(self, call: Node) -> Node | None:
        a = args(call)
        return a[self.arg_index] if len(a) > self.arg_index else None

    guards: tuple[str, ...] = ()  # validation calls that, if present in the enclosing function, count as a check

    def skip(self, src: SourceFile, call: Node, arg: Node) -> bool:
        return False

    def allowlisted(self, src: SourceFile, taint: Analyzer, call: Node, arg: Node) -> bool:
        """The value was checked against a constant allow-list that stops the program on a miss."""
        return False

    def weak(self, taint: Analyzer, arg: Node) -> bool:
        """An untainted argument that is not worth a lower-confidence finding."""
        return False

    def guarded(self, call: Node, arg: Node | None = None) -> bool:
        """A check written in the same function — on a line that is about this value.

        Matching the guard anywhere in the function made `content.startswith("<!DOCTYPE")` count as
        validating an unrelated `open(params["path"])` three branches away."""
        if not self.guards:
            return False
        node = call.parent
        while node is not None and node.type not in FUNCTION_TYPES:
            node = node.parent
        body = text(node) if node is not None else ""
        names = self._value_names(arg) if arg is not None else set()
        mentions = lambda t: not names or any(re.search(rf"(?<![\w.$]){re.escape(n)}\b", t) for n in names)  # noqa: E731
        for g in self.guards:
            if hasattr(g, "search"):
                if any(mentions(line) for line in body.splitlines() if g.search(line)):
                    return True
            elif g.startswith("."):
                # `full.startswith(base)`: the value being checked is the receiver, right before the dot
                for m in re.finditer(r"([\w$.\[\]'\"()]{1,80})" + re.escape(g), body):
                    if mentions(m.group(1)):
                        return True
            else:
                for line in body.splitlines():
                    if g in line and mentions(line):
                        return True
        return False

    @staticmethod
    def _value_names(arg: Node) -> set[str]:
        """Variables the argument is built from — not attribute or function names (`os`, `path`, `abspath`)."""
        out = set()
        for n in walk(arg):
            if n.type not in {"identifier", "variable_name"}:
                continue
            parent = n.parent
            if parent is not None and parent.type in {"attribute", "member_expression"} and \
                    parent.child_by_field_name("object") is not n:
                continue  # .abspath, .path — a property, not a value
            if parent is not None and parent.type in {"call", "call_expression"} and parent.child_by_field_name("function") is n:
                continue  # open(…), FETCH(…) — the function, not the value
            out.add(text(n))
        out -= {"os", "sys", "io", "path", "shutil", "fs", "Path", "this", "self"}
        return out

    def check(self, src, taint):
        out = []
        for call in calls(src):
            if not self.matches(src, call):
                continue
            arg = self.target(call)
            if arg is None or taint.is_literal(arg) or self.skip(src, call, arg):
                continue
            if sanitizer_call(arg, self.sanitizers, src) is not None or self.guarded(call, arg) \
                    or self.allowlisted(src, taint, call, arg):
                continue
            name = callee(call)[1]
            fix = self.fix.get(src.family, "")
            via = taint.tainted_by(arg)
            if via:
                out.append(finding(self, src, call, self.tainted,
                                   self.msg_tainted.format(src=taint.root(via), name=name), fix, taint, via))
            elif self.dynamic is not None and not self.weak(taint, arg) and arg.type not in {"arrow_function", "function_expression", "lambda", "number", "true", "false"}:
                out.append(finding(self, src, call, self.dynamic, self.msg_dynamic.format(name=name), fix))
        return out
