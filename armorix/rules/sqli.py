"""CWE-89 — SQL built from strings instead of bound parameters."""

from __future__ import annotations

import re

from ..finding import Severity
from .base import Rule, args, callee, calls, finding

SQL = re.compile(
    r"\b(select\b[\s\S]*\bfrom|insert\s+into|update\s+[\w.`\"\[\]]+\s+set|delete\s+from|drop\s+table|where\b)",
    re.IGNORECASE,
)
JS_SINKS = {"query", "execute", "raw", "unsafe", "$queryRawUnsafe", "$executeRawUnsafe", "run", "all", "get", "prepare", "exec"}
PY_SINKS = {"execute", "executemany", "executescript", "raw", "extra", "read_sql", "read_sql_query", "text"}

FIX = {
    "js": 'Pass values as bound parameters: db.query("SELECT * FROM users WHERE id = ?", [id])',
    "py": 'Pass values as bound parameters: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
}


class SqlInjection(Rule):
    id = "ARX-SQLI"
    cwe = "CWE-89"
    title = "SQL injection"
    description = "A SQL statement is built from strings, so input can change the query itself."

    def check(self, src, taint):
        sinks = JS_SINKS if src.family == "js" else PY_SINKS
        out = []
        for call in calls(src):
            _, name = callee(call)
            if name not in sinks:
                continue
            a = args(call)
            if not a:
                continue
            query = a[0]
            if not taint.is_dynamic_string(query) or not SQL.search(taint.string_value(query)):
                continue
            via = taint.tainted_by(query)
            if via:
                out.append(finding(self, src, call, Severity.CRITICAL,
                                   f"Untrusted input `{taint.root(via)}` is concatenated into a SQL query — an attacker can read or rewrite the database.",
                                   FIX[src.family], taint, via))
            else:
                out.append(finding(self, src, call, Severity.MEDIUM,
                                   "SQL query is assembled from strings. Safe only if every piece is trusted — use bound parameters instead.",
                                   FIX[src.family]))
        return out
