"""tree-sitter setup and small AST helpers shared by the rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Iterator

import tree_sitter_c as ts_c
import tree_sitter_cpp as ts_cpp
import tree_sitter_javascript as ts_javascript
import tree_sitter_python as ts_python
import tree_sitter_typescript as ts_typescript
from tree_sitter import Language, Node, Parser, Tree

# extension → tree-sitter grammar
GRAMMARS = {
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
    ".py": "python",
    ".c": "c",
    ".h": "cpp",  # headers are usually shared with C++; the C++ grammar parses plain C too
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
}

# grammar → rule family (JS and TS share node types for everything the rules touch)
FAMILY = {"javascript": "js", "typescript": "js", "tsx": "js", "python": "py", "c": "c", "cpp": "c"}


@lru_cache(maxsize=None)
def _language(grammar: str) -> Language:
    raw = {
        "javascript": ts_javascript.language,
        "typescript": ts_typescript.language_typescript,
        "tsx": ts_typescript.language_tsx,
        "python": ts_python.language,
        "c": ts_c.language,
        "cpp": ts_cpp.language,
    }[grammar]()
    return Language(raw)


@lru_cache(maxsize=None)
def _parser(grammar: str) -> Parser:
    return Parser(_language(grammar))


@dataclass
class SourceFile:
    path: Path
    rel: str
    text: str
    grammar: str | None = None  # None → not parsed (config files, .env …)
    tree: Tree | None = None
    lines: list[str] = field(default_factory=list)

    @cached_property
    def nodes(self) -> list[Node]:
        """Every AST node in pre-order, computed once and shared by all rules."""
        return list(walk(self.tree.root_node)) if self.tree is not None else []

    @cached_property
    def call_nodes(self) -> list[Node]:
        return [n for n in self.nodes if n.type in {"call_expression", "call", "new_expression"}]

    @property
    def family(self) -> str | None:
        return FAMILY.get(self.grammar) if self.grammar else None

    def line(self, n: int) -> str:
        """1-based source line, stripped."""
        return self.lines[n - 1].strip() if 0 < n <= len(self.lines) else ""


def load(path: Path, rel: str) -> SourceFile:
    text = path.read_text(encoding="utf-8", errors="replace")
    grammar = GRAMMARS.get(path.suffix.lower())
    tree = _parser(grammar).parse(text.encode("utf-8")) if grammar else None
    return SourceFile(path=path, rel=rel, text=text, grammar=grammar, tree=tree, lines=text.splitlines())


def walk(node: Node) -> Iterator[Node]:
    """Pre-order traversal without recursion (deep ASTs are common in bundles)."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def text(node: Node | None) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


def line_of(node: Node) -> int:
    return node.start_point[0] + 1
