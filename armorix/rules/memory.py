"""C / C++ memory-safety rules: buffer overflows, use-after-free, double free, format strings.

Analysis is per function and flow-insensitive except for use-after-free, which walks
events in source order and ignores frees that sit in a block ending in return/break/
goto/exit (the classic `if (err) { free(p); return; }` pattern).
Taint sources: argv, getenv(), and buffers filled by fgets/read/recv/scanf/gets/fread.
"""

from __future__ import annotations

import re

from tree_sitter import Node

from ..finding import Finding, Severity, TraceStep
from ..parsing import SourceFile, line_of, text, walk
from .base import Rule

FUNC = "function_definition"
UNBOUNDED_COPY = {"strcpy": 1, "strcat": 1, "wcscpy": 1, "wcscat": 1, "stpcpy": 1, "sprintf": None, "vsprintf": None}
SIZED_COPY = {"memcpy": 2, "memmove": 2, "strncpy": 2, "strncat": 2, "memset": 2, "wmemcpy": 2, "read": 2, "fgets": 1, "recv": 2}
SCANF = {"scanf": 0, "sscanf": 1, "fscanf": 1}
FORMAT_ARG = {"printf": 0, "fprintf": 1, "dprintf": 1, "sprintf": 1, "snprintf": 2, "syslog": 1, "wprintf": 0}
FREE = {"free", "cfree", "kfree", "g_free"}
ALLOC = {"malloc": 0, "alloca": 0, "realloc": 1}
SHELL = {"system": 0, "popen": 0}
# call → index of the buffer it fills with outside data (None: every argument after the format)
FILLS = {"fgets": 0, "gets": 0, "read": 1, "recv": 1, "recvfrom": 1, "fread": 0, "getline": 0, "scanf": "fmt0", "sscanf": "fmt1", "fscanf": "fmt1"}
UNBOUNDED_S = re.compile(r"%(?!\d)(?:l?s|\[)")
JUMPS = {"return_statement", "break_statement", "continue_statement", "goto_statement", "throw_statement"}
EXITS = {"exit", "abort", "_exit", "longjmp", "err", "errx"}
BYTE_TYPES = {"char", "unsigned char", "signed char", "uint8_t", "int8_t", "u_char", "u8", "BYTE", "gchar", "guchar"}
BRANCHES = {"preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif", "preproc_elifdef"}


def _byte_array(decl_type: Node | None, arr: Node) -> bool:
    """`char buf[64]` yes; `int v[16]` / `char *keys[16]` (array of pointers) no."""
    t = " ".join(text(decl_type).split()) if decl_type is not None else ""
    return t in BYTE_TYPES and arr.parent is not None and arr.parent.type != "pointer_declarator"


def _declared_arrays(root: Node) -> dict[str, int]:
    sizes = {}
    for n in walk(root):
        if n.type == "array_declarator":
            decl = n.parent
            while decl is not None and decl.type not in {"declaration", "field_declaration", "parameter_declaration"}:
                decl = decl.parent
            name, size = n.child_by_field_name("declarator"), literal_int(n.child_by_field_name("size"))
            if decl is not None and decl.type == "declaration" and name is not None and name.type == "identifier" and size \
                    and _byte_array(decl.child_by_field_name("type"), n):
                sizes[text(name)] = size
    return sizes

FIX = {
    "copy": "Bound every copy by the destination size: snprintf(buf, sizeof(buf), \"%s\", src) or strlcpy; validate input length first.",
    "sized": "Never copy more than sizeof(destination): use min(len, sizeof(buf)) and check the length before copying.",
    "gets": "gets() cannot be used safely — replace it with fgets(buf, sizeof(buf), stdin).",
    "scanf": "Give every %s a width (\"%63s\" for char buf[64]) or read with fgets.",
    "uaf": "Do not touch memory after free/delete: move the use before the free and set the pointer to NULL / nullptr right after freeing.",
    "dfree": "Set the pointer to NULL after free so a second free becomes a no-op; keep ownership in one place.",
    "fmt": "Use a constant format string: printf(\"%s\", msg) instead of printf(msg).",
    "alloc": "Check the multiplication for overflow (or use calloc / reallocarray) before allocating.",
    "shell": "Avoid system()/popen(): call execve with an argument array and allow-list every user-supplied value.",
}


def callee_name(call: Node) -> str:
    fn = call.child_by_field_name("function")
    if fn is None:
        return ""
    if fn.type in {"field_expression", "qualified_identifier"}:  # obj.f / std::f
        fn = fn.child_by_field_name("field") or fn.child_by_field_name("name") or fn
    return text(fn)


def call_args(call: Node) -> list[Node]:
    a = call.child_by_field_name("arguments")
    return [c for c in a.named_children if c.type != "comment"] if a is not None else []


def literal_text(node: Node | None) -> str | None:
    """Value of a string literal (or adjacent literals), else None."""
    if node is None:
        return None
    if node.type == "string_literal":
        return "".join(text(c) for c in node.named_children if c.type in {"string_content", "escape_sequence"})
    if node.type == "concatenated_string":
        parts = [literal_text(c) for c in node.named_children]
        return None if any(p is None for p in parts) else "".join(parts)
    return None


def literal_int(node: Node | None) -> int | None:
    if node is None or node.type != "number_literal":
        return None
    try:
        return int(text(node).rstrip("uUlL"), 0)
    except ValueError:
        return None


class FunctionFacts:
    """Array sizes and tainted names for one function (plus globals)."""

    def __init__(self, src: SourceFile, fn: Node, global_arrays: dict[str, int]):
        self.src, self.fn = src, fn
        self.arrays = {**global_arrays, **_declared_arrays(fn)}
        self.tainted: dict[str, int] = {}  # name → line where it became attacker-controlled
        body_nodes = list(walk(fn))
        decl = fn.child_by_field_name("declarator")
        if decl is not None and "main" in text(decl.child_by_field_name("declarator") or decl):
            for p in walk(decl):
                if p.type == "identifier" and text(p) in {"argv", "envp"}:
                    self.tainted[text(p)] = line_of(p)
        for _ in range(2):  # a second pass lets `p = argv[1]; q = p;` propagate
            for n in body_nodes:
                if n.type == "call_expression":
                    self._fills(n)
                elif n.type in {"init_declarator", "assignment_expression"}:
                    target = n.child_by_field_name("declarator") or n.child_by_field_name("left")
                    value = n.child_by_field_name("value") or n.child_by_field_name("right")
                    name = self._base_name(target)
                    if name and value is not None and self.is_tainted(value) and name not in self.tainted:
                        self.tainted[name] = line_of(n)

    @staticmethod
    def _base_name(node: Node | None) -> str | None:
        while node is not None and node.type in {"pointer_declarator", "array_declarator", "parenthesized_declarator", "subscript_expression", "pointer_expression"}:
            node = node.child_by_field_name("declarator") or node.child_by_field_name("argument") or (node.named_children[0] if node.named_children else None)
        return text(node) if node is not None and node.type == "identifier" else None

    def _fills(self, call: Node) -> None:
        name = callee_name(call)
        args = call_args(call)
        # copies carry taint into their destination: snprintf(cmd, …, "ping %s", host)
        if name in {"strcpy", "strcat", "strncpy", "strncat", "sprintf", "snprintf", "memcpy", "memmove", "stpcpy"} and args:
            dest = self._base_name(args[0])
            if dest and any(self.is_tainted(a) for a in args[1:]):
                self.tainted.setdefault(dest, line_of(call))
            return
        kind = FILLS.get(name)
        if kind is None:
            return
        targets = args[int(kind[3]) + 1:] if isinstance(kind, str) else args[kind:kind + 1]
        for t in targets:
            name = self._base_name(t.child_by_field_name("argument") if t.type == "pointer_expression" else t)
            if name:
                self.tainted.setdefault(name, line_of(call))

    def is_tainted(self, node: Node | None) -> bool:
        if node is None:
            return False
        for n in walk(node):
            if n.type == "identifier" and text(n) in self.tainted:
                return True
            if n.type == "call_expression" and callee_name(n) == "getenv":
                return True
        return False

    def origin(self, node: Node) -> str | None:
        for n in walk(node):
            if n.type == "identifier" and text(n) in self.tainted:
                return text(n)
            if n.type == "call_expression" and callee_name(n) == "getenv":
                return text(n)
        return None


def _finding(rule, src, node, sev, message, fix, facts=None, via=None, extra_trace=None) -> Finding:
    line = line_of(node)
    trace = list(extra_trace or [])
    if facts is not None and via in facts.tainted and facts.tainted[via] != line:
        trace = [TraceStep(facts.tainted[via], src.line(facts.tainted[via]), "source"), TraceStep(line, src.line(line), "sink")]
    return Finding(rule_id=rule.id, cwe=rule.cwe, severity=sev, title=rule.title, message=message, fix=fix, file=src.rel,
                   line=line, column=node.start_point[1] + 1, snippet=src.line(line), trace=trace,
                   data={"source": via} if via else {})


def _functions(src: SourceFile):
    global_arrays = {}
    for n in src.tree.root_node.named_children:
        if n.type == "declaration":
            global_arrays.update(_declared_arrays(n))
    for n in src.nodes:
        if n.type == FUNC:
            yield FunctionFacts(src, n, global_arrays)


class MemoryRule(Rule):
    families = ("c",)

    def check(self, src, taint):
        out = []
        for facts in _functions(src):
            out += self.check_function(src, facts)
        return out

    def check_function(self, src, facts):  # pragma: no cover - overridden
        return []


class BufferOverflow(MemoryRule):
    id = "ARX-C-BOF"
    cwe = "CWE-120"
    title = "Buffer overflow"
    description = "Data is copied into a fixed-size buffer without a bound, overwriting the stack or heap (CWE-120/121/787)."

    def check_function(self, src, facts):
        out = []
        for call in (n for n in walk(facts.fn) if n.type == "call_expression"):
            name, args = callee_name(call), call_args(call)
            if not args:
                continue
            dest = FunctionFacts._base_name(args[0])
            # the array itself (`buf`), not an element or member (`keys[i]`, `s->buf`)
            size = facts.arrays.get(dest or "") if args[0].type == "identifier" else None
            if name in UNBOUNDED_COPY:
                sources = args[1:] if UNBOUNDED_COPY[name] is None else args[UNBOUNDED_COPY[name]:UNBOUNDED_COPY[name] + 1]
                if name in {"sprintf", "vsprintf"}:
                    fmt = literal_text(args[1]) if len(args) > 1 else None
                    if fmt is not None and not UNBOUNDED_S.search(fmt):
                        continue  # numbers only — bounded output
                    sources = args[2:]
                lits = [literal_text(s) for s in sources]
                if sources and all(v is not None for v in lits):
                    need = sum(len(v) for v in lits) + 1
                    if size and need > size:
                        out.append(_finding(self, src, call, Severity.CRITICAL,
                                            f"`{name}` writes {need} bytes into `{dest}[{size}]` — a guaranteed overflow.", FIX["copy"]))
                    continue
                via = next((facts.origin(s) for s in sources if facts.is_tainted(s)), None)
                if via:
                    where = f"`{dest}[{size}]`" if size else f"`{dest or text(args[0])}`"
                    out.append(_finding(self, src, call, Severity.CRITICAL,
                                        f"Untrusted input `{via}` is copied into {where} by `{name}` with no length limit — stack/heap overflow.",
                                        FIX["copy"], facts, via))
                elif size:
                    out.append(_finding(self, src, call, Severity.HIGH,
                                        f"`{name}` copies into the fixed buffer `{dest}[{size}]` without checking the source length.", FIX["copy"]))
            elif name in SIZED_COPY and len(args) > SIZED_COPY[name] and size:
                length = args[SIZED_COPY[name]]
                n = literal_int(length)
                if n is not None and n > size:
                    out.append(_finding(self, src, call, Severity.CRITICAL,
                                        f"`{name}` writes {n} bytes into `{dest}[{size}]` — out-of-bounds write (CWE-787).", FIX["sized"]))
                elif n is None and facts.is_tainted(length) and "sizeof" not in text(length):
                    via = facts.origin(length)
                    out.append(_finding(self, src, call, Severity.HIGH,
                                        f"The length passed to `{name}` comes from `{via}` and is never compared with sizeof({dest}).",
                                        FIX["sized"], facts, via))
            elif name == "gets":
                out.append(Finding(rule_id="ARX-C-GETS", cwe="CWE-242", severity=Severity.CRITICAL, title="Inherently dangerous function",
                                   message="`gets` reads an unlimited line into a fixed buffer — every call is an overflow waiting to happen.",
                                   fix=FIX["gets"], file=src.rel, line=line_of(call), column=call.start_point[1] + 1, snippet=src.line(line_of(call))))
            elif name in SCANF and len(args) > SCANF[name]:
                fmt = literal_text(args[SCANF[name]])
                if fmt and UNBOUNDED_S.search(fmt):
                    out.append(_finding(self, src, call, Severity.HIGH,
                                        f"`{name}` uses \"%s\" without a width — input longer than the buffer overflows it.", FIX["scanf"]))
        return out


class UseAfterFree(MemoryRule):
    id = "ARX-C-UAF"
    cwe = "CWE-416"
    title = "Use after free"
    description = "Memory is read or written after free/delete, or freed twice (CWE-416 / CWE-415)."

    @staticmethod
    def _terminal(free_node: Node, fn: Node) -> bool:
        """free/delete inside a block that ends the path (return / break / exit) right after."""
        block = free_node.parent
        while block is not None and block.type != "compound_statement":
            block = block.parent
        if block is None or block.parent is fn:
            return False
        for n in walk(block):
            if n.start_byte <= free_node.end_byte:
                continue
            if n.type in JUMPS or (n.type == "call_expression" and callee_name(n) in EXITS):
                return True
        return False

    @staticmethod
    def _exclusive(a: Node, b: Node) -> bool:
        """True when a and b sit in different arms of the same if/else, switch case or #if/#else."""
        node = a.parent
        while node is not None:
            if node.type == "if_statement":
                cons, alt = node.child_by_field_name("consequence"), node.child_by_field_name("alternative")
                arms = [x for x in (cons, alt) if x is not None]
                ia = next((i for i, x in enumerate(arms) if x.start_byte <= a.start_byte < x.end_byte), None)
                ib = next((i for i, x in enumerate(arms) if x.start_byte <= b.start_byte < x.end_byte), None)
                if ia is not None and ib is not None and ia != ib:
                    return True
            if node.type in BRANCHES:
                # #if/#elif/#else chains nest the next branch as `alternative`
                alt = node.child_by_field_name("alternative")
                if alt is not None and (alt.start_byte <= a.start_byte < alt.end_byte) != (alt.start_byte <= b.start_byte < alt.end_byte):
                    return True
            if node.type in BRANCHES | {"case_statement"}:
                if not (node.start_byte <= b.start_byte < node.end_byte):
                    parent = node.parent
                    # sibling branch of the same conditional
                    if parent is not None and parent.start_byte <= b.start_byte < parent.end_byte:
                        return True
            node = node.parent
        return False

    def check_function(self, src, facts):
        fn, out = facts.fn, []
        freed: dict[str, Node] = {}
        reported = set()
        for n in walk(fn):
            key = None
            if n.type == "call_expression" and callee_name(n) in FREE and call_args(n):
                key = text(call_args(n)[0])
            elif n.type == "delete_expression" and n.named_children:
                key = text(n.named_children[-1])
            if key is not None:
                if key in freed and key not in reported:
                    first = freed[key]
                    out.append(Finding(rule_id="ARX-C-DFREE", cwe="CWE-415", severity=Severity.HIGH, title="Double free",
                                       message=f"`{key}` is freed again (first on line {line_of(first)}) — heap corruption.",
                                       fix=FIX["dfree"], file=src.rel, line=line_of(n), column=n.start_point[1] + 1, snippet=src.line(line_of(n)),
                                       trace=[TraceStep(line_of(first), src.line(line_of(first)), "source"), TraceStep(line_of(n), src.line(line_of(n)), "sink")]))
                    reported.add(key)
                elif not self._terminal(n, fn):
                    freed[key] = n
                continue
            if n.type == "init_declarator" and text(n.child_by_field_name("declarator")).lstrip("*& ") in freed:
                freed.pop(text(n.child_by_field_name("declarator")).lstrip("*& "))  # a new variable with the same name
                continue
            if n.type == "pointer_expression" and text(n).startswith("&") and text(n.child_by_field_name("argument")) in freed:
                freed.pop(text(n.child_by_field_name("argument")))  # &p handed to a function that fills it
                continue
            if n.type == "assignment_expression":
                left = text(n.child_by_field_name("left"))
                if left in freed:
                    right = n.child_by_field_name("right")
                    if right is not None and n.start_byte > freed[left].end_byte and left not in text(right):
                        freed.pop(left)
                continue
            if n.type in {"identifier", "field_expression"} and freed:
                t = text(n)
                for key, free_node in list(freed.items()):
                    if key in reported or n.start_byte <= free_node.end_byte:
                        continue
                    if t == key or t.startswith(key + "->") or t.startswith(key + "."):
                        parent = n.parent
                        # `p = …` (reassignment) and sizeof(p) are not uses
                        if parent is not None and parent.type == "assignment_expression" and parent.child_by_field_name("left") == n:
                            continue
                        if parent is not None and parent.type in {"sizeof_expression", "init_declarator", "pointer_expression"} and parent.child_by_field_name("declarator") in (n, None) and parent.type != "pointer_expression":
                            continue
                        if parent is not None and parent.type == "sizeof_expression":
                            continue
                        if self._exclusive(free_node, n):
                            continue
                        fl, ul = line_of(free_node), line_of(n)
                        out.append(Finding(rule_id=self.id, cwe=self.cwe, severity=Severity.HIGH, title=self.title,
                                           message=f"`{key}` is used after it was freed on line {fl} — attacker-influenced heap memory may be read or written.",
                                           fix=FIX["uaf"], file=src.rel, line=ul, column=n.start_point[1] + 1, snippet=src.line(ul),
                                           trace=[TraceStep(fl, src.line(fl), "source"), TraceStep(ul, src.line(ul), "sink")]))
                        reported.add(key)
        return out


class FormatString(MemoryRule):
    id = "ARX-C-FMT"
    cwe = "CWE-134"
    title = "Format string vulnerability"
    description = "A non-constant format string lets %n / %x in input read or write memory."

    def check_function(self, src, facts):
        out = []
        for call in (n for n in walk(facts.fn) if n.type == "call_expression"):
            name, args = callee_name(call), call_args(call)
            idx = FORMAT_ARG.get(name)
            if idx is None or len(args) <= idx:
                continue
            fmt = args[idx]
            if literal_text(fmt) is not None:
                continue
            if facts.is_tainted(fmt):
                via = facts.origin(fmt)
                out.append(_finding(self, src, call, Severity.CRITICAL,
                                    f"Untrusted input `{via}` is used as the format string of `{name}` — %n / %x leak or overwrite memory.",
                                    FIX["fmt"], facts, via))
            # A merely non-constant format (macros, wrappers, locals set from literals) is too noisy to report.
        return out


class AllocOverflow(MemoryRule):
    id = "ARX-C-INTOVF"
    cwe = "CWE-190"
    title = "Integer overflow in allocation size"
    description = "An attacker-controlled size is multiplied before malloc; the product wraps and a too-small buffer is allocated."

    def check_function(self, src, facts):
        out = []
        for call in (n for n in walk(facts.fn) if n.type == "call_expression"):
            idx = ALLOC.get(callee_name(call))
            args = call_args(call)
            if idx is None or len(args) <= idx:
                continue
            size = args[idx]
            if any(b.type == "binary_expression" and text(b.child_by_field_name("operator")) in {"*", "+"} for b in walk(size)) and facts.is_tainted(size):
                via = facts.origin(size)
                out.append(_finding(self, src, call, Severity.HIGH,
                                    f"The allocation size is computed from `{via}` without an overflow check — a wrapped size gives a buffer that is too small.",
                                    FIX["alloc"], facts, via))
        return out


class ShellCommandC(MemoryRule):
    id = "ARX-C-CMDI"
    cwe = "CWE-78"
    title = "OS command injection"
    description = "system()/popen() run a command string built from input."

    def check_function(self, src, facts):
        out = []
        for call in (n for n in walk(facts.fn) if n.type == "call_expression"):
            idx = SHELL.get(callee_name(call))
            args = call_args(call)
            if idx is None or len(args) <= idx or literal_text(args[idx]) is not None:
                continue
            cmd = args[idx]
            # a buffer that snprintf/sprintf filled from tainted data counts as tainted
            if facts.is_tainted(cmd):
                via = facts.origin(cmd)
                out.append(_finding(self, src, call, Severity.CRITICAL,
                                    f"Untrusted input `{via}` reaches `{callee_name(call)}` — an attacker can run any shell command.",
                                    FIX["shell"], facts, via))
            else:
                out.append(_finding(self, src, call, Severity.HIGH, f"`{callee_name(call)}` runs a non-constant command string.", FIX["shell"]))
        return out
