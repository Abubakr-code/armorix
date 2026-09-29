"""Shared helpers for AST rules: call inspection and finding construction."""

from __future__ import annotations

from tree_sitter import Node

from ..finding import Finding, Severity, TraceStep
from ..parsing import SourceFile, line_of, text
from ..taint import Analyzer

CALLS = {"call_expression", "call", "new_expression"}
FUNCTION_TYPES = {"function_declaration", "function_expression", "arrow_function", "method_definition", "function_definition"}


class Rule:
    id: str = ""
    cwe: str = ""
    title: str = ""
    description: str = ""
    families: tuple[str, ...] = ("js", "py")

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

    def guarded(self, call: Node) -> bool:
        if not self.guards:
            return False
        node = call.parent
        while node is not None and node.type not in FUNCTION_TYPES:
            node = node.parent
        body = text(node) if node is not None else ""
        return any(g.search(body) if hasattr(g, "search") else g in body for g in self.guards)

    def check(self, src, taint):
        out = []
        for call in calls(src):
            if not self.matches(src, call):
                continue
            arg = self.target(call)
            if arg is None or taint.is_literal(arg) or self.skip(src, call, arg):
                continue
            if any(s in text(arg) for s in self.sanitizers) or self.guarded(call):
                continue
            name = callee(call)[1]
            fix = self.fix.get(src.family, "")
            via = taint.tainted_by(arg)
            if via:
                out.append(finding(self, src, call, self.tainted,
                                   self.msg_tainted.format(src=taint.root(via), name=name), fix, taint, via))
            elif self.dynamic is not None and arg.type not in {"arrow_function", "function_expression", "lambda", "number", "true", "false"}:
                out.append(finding(self, src, call, self.dynamic, self.msg_dynamic.format(name=name), fix))
        return out
