"""Lightweight, file-level taint tracking.

Answers two questions for the rules:
  * is this expression attacker-controlled?  (reaches back to an HTTP/CLI source)
  * is this expression a *dynamically built* string?  (concatenation, template, f-string …)

It is intentionally simple — one pass over assignments in source order, repeated
until nothing changes, no inter-procedural flow. Rules use "tainted" for
critical findings and "dynamic but untainted" for lower-confidence ones, so a
miss here lowers severity instead of hiding the bug.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from tree_sitter import Node

from .parsing import SourceFile, line_of, text, walk

# Attacker-controlled entry points, matched against the source text of a node.
JS_SOURCE = re.compile(
    r"^(?:req|request|ctx(?:\.request)?)\.(?:query|body|params|headers|cookies|files)\b"
    r"|^process\.argv\b"
    r"|^(?:window\.)?location\.(?:search|hash|href)\b"
)
PY_SOURCE = re.compile(
    r"^request\.(?:args|form|values|json|files|cookies|headers|data|GET|POST|query_params)\b"
    r"|^request\.(?:get_json|get_data)\("
    r"|^request\.stream\b"
    r"|^sys\.argv\b"
    r"|^input\("
)

JS_ASSIGN = {"variable_declarator": ("name", "value"), "assignment_expression": ("left", "right")}
PY_ASSIGN = {"assignment": ("left", "right")}
NAME_TYPES = {"identifier", "shorthand_property_identifier_pattern"}


@dataclass
class Origin:
    """Where a variable picked up its taint — used to print the source → sink path."""

    line: int
    code: str
    via: str | None = None  # another tainted variable it came from
    source: str | None = None  # the entry point text, when taken directly from one


@dataclass
class TaintInfo:
    tainted: dict[str, Origin] = field(default_factory=dict)
    dynamic: dict[str, Node] = field(default_factory=dict)  # names holding built strings


class Analyzer:
    def __init__(self, src: SourceFile):
        self.src = src
        self.family = src.family
        self.source_re = JS_SOURCE if self.family == "js" else PY_SOURCE
        self.assign_types = JS_ASSIGN if self.family == "js" else PY_ASSIGN
        self.info = TaintInfo()
        self._propagate()

    # ── sources & taint ─────────────────────────────────────────
    def is_source(self, node: Node) -> bool:
        if node.type not in {"member_expression", "attribute", "call", "call_expression", "subscript", "subscript_expression"}:
            return False
        return bool(self.source_re.match(text(node)))

    def tainted_by(self, node: Node | None) -> str | None:
        """Returns the source text or tainted variable name that `node` depends on."""
        if node is None:
            return None
        for n in walk(node):
            if self.is_source(n):
                return text(n)
            if n.type == "identifier" and text(n) in self.info.tainted:
                return text(n)
        return None

    # ── dynamic strings ─────────────────────────────────────────
    def is_literal(self, node: Node | None) -> bool:
        if node is None:
            return False
        if node.type == "string":
            return not any(c.type in {"interpolation", "template_substitution"} for c in node.children)
        if node.type == "template_string":
            return not any(c.type == "template_substitution" for c in node.children)
        return False

    def is_dynamic_string(self, node: Node | None) -> bool:
        if node is None:
            return False
        t = node.type
        if t in {"string", "template_string"}:
            return not self.is_literal(node)
        if t == "identifier":
            return text(node) in self.info.dynamic
        if t == "parenthesized_expression":
            return any(self.is_dynamic_string(c) for c in node.named_children)
        if t in {"binary_expression", "binary_operator"}:
            op = text(node.child_by_field_name("operator"))
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if op == "+":
                stringy = any(self._stringy(side) for side in (left, right))
                return stringy and not (self.is_literal(left) and self.is_literal(right))
            if op == "%" and self.family == "py":  # "... %s" % value
                return self._stringy(left)
        if t in {"call", "call_expression"}:  # "...".format(x)  /  "".concat(x)
            fn = node.child_by_field_name("function")
            if fn is not None and fn.type in {"attribute", "member_expression"}:
                prop = fn.child_by_field_name("attribute") or fn.child_by_field_name("property")
                obj = fn.child_by_field_name("object")
                if text(prop) in {"format", "concat", "join"} and self._stringy(obj):
                    return True
        return False

    def _stringy(self, node: Node | None) -> bool:
        return node is not None and (node.type in {"string", "template_string"} or self.is_dynamic_string(node))

    def string_value(self, node: Node | None) -> str:
        """Best-effort text of a string expression, following one variable hop."""
        if node is not None and node.type == "identifier" and text(node) in self.info.dynamic:
            return text(self.info.dynamic[text(node)])
        return text(node)

    # ── propagation ─────────────────────────────────────────────
    def _assignments(self):
        for node in self.src.nodes:
            fields = self.assign_types.get(node.type)
            if not fields:
                continue
            target, value = (node.child_by_field_name(f) for f in fields)
            if target is None or value is None:
                continue
            names = [text(n) for n in walk(target) if n.type in NAME_TYPES]
            yield names, value

    def _propagate(self) -> None:
        assignments = list(self._assignments())
        changed = True
        while changed:
            changed = False
            for names, value in assignments:
                via = self.tainted_by(value)
                dynamic = self.is_dynamic_string(value)
                for name in names:
                    if via and name not in self.info.tainted and name != via:
                        from_var = via in self.info.tainted
                        self.info.tainted[name] = Origin(
                            line_of(value), self.src.line(line_of(value)),
                            via=via if from_var else None, source=None if from_var else via,
                        )
                        changed = True
                    if dynamic and name not in self.info.dynamic:
                        self.info.dynamic[name] = value
                        changed = True

    def root(self, via: str) -> str:
        """The original entry point behind a tainted name: `sql` → `req.query.id`."""
        chain = self.origin_chain(via)
        return chain[0].source if chain and chain[0].source else via

    def origin_chain(self, name: str) -> list[Origin]:
        """Follows `a = b; b = req.query.x` back to the original source, oldest first."""
        chain, seen = [], set()
        while name in self.info.tainted and name not in seen:
            seen.add(name)
            origin = self.info.tainted[name]
            chain.append(origin)
            name = origin.via or ""
        return list(reversed(chain))
