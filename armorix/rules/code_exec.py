"""CWE-95 (eval-style code injection) and CWE-78 (OS command injection)."""

from __future__ import annotations

from ..finding import Severity
from ..parsing import text
from .base import Rule, args, callee, calls, finding, kwarg

JS_EVAL = {("", "eval"), ("", "Function"), ("vm", "runInNewContext"), ("vm", "runInThisContext"), ("vm", "runInContext"),
           ("vm", "compileFunction"),
           # expression evaluators that have shipped sandbox escapes (mathjs CVE-2017-1001002, safe-eval, vm2)
           ("mathjs", "eval"), ("mathjs", "evaluate"), ("math", "eval"), ("math", "evaluate"), ("", "safeEval"),
           ("vm2", "run"), ("", "setTimeout"), ("", "setInterval")}
PY_EVAL = {("", "eval"), ("", "exec"), ("", "compile")}
STRING_ONLY = {"setTimeout", "setInterval"}

JS_CP_OBJECTS = {"child_process", "cp", "childProcess", "require('child_process')", 'require("child_process")'}
JS_SHELL = {"exec", "execSync"}
JS_SPAWN = {"spawn", "spawnSync", "execFile", "execFileSync"}
PY_SHELL = {("os", "system"), ("os", "popen"), ("commands", "getoutput"), ("subprocess", "getoutput"), ("subprocess", "getstatusoutput"),
            ("asyncio", "create_subprocess_shell")}
PY_SUBPROCESS = {"run", "call", "check_call", "check_output", "Popen"}


def _dangerous_arg(taint, node):
    """(via, dynamic) for the first argument; literals are never reported."""
    if node is None or taint.is_literal(node):
        return None, False
    via = taint.tainted_by(node)
    dynamic = node.type not in {"arrow_function", "function_expression", "function", "lambda"}
    return via, dynamic


class CodeInjection(Rule):
    id = "ARX-EVAL"
    cwe = "CWE-95"
    title = "Code injection via eval"
    description = "Strings are executed as code with eval / new Function / exec."

    def check(self, src, taint):
        sinks = JS_EVAL if src.family == "js" else PY_EVAL
        out = []
        for call in calls(src):
            obj, name = callee(call)
            if (obj, name) not in sinks:
                continue
            a = args(call)
            if name in STRING_ONLY and not (a and (a[0].type in {"string", "template_string", "binary_expression"}
                                                   or taint.is_dynamic_string(a[0]))):
                continue  # setTimeout(tick, 100) schedules a function; only setTimeout("code", …) evaluates
            if name == "compile" and len(a) >= 3 and "exec" not in text(a[2]) and "eval" not in text(a[2]) \
                    and "single" not in text(a[2]):
                continue
            via, dynamic = _dangerous_arg(taint, a[-1] if (name == "Function" and a) else (a[0] if a else None))
            fix = "Never evaluate strings as code. Parse data with JSON.parse / ast.literal_eval, or map allowed actions to functions."
            if via:
                out.append(finding(self, src, call, Severity.CRITICAL,
                                   f"Untrusted input `{taint.root(via)}` is executed as code — remote code execution.", fix, taint, via))
            elif dynamic:
                out.append(finding(self, src, call, Severity.HIGH,
                                   f"`{name}` runs a non-constant string as code.", fix))
        return out


class CommandInjection(Rule):
    id = "ARX-CMDI"
    cwe = "CWE-78"
    title = "OS command injection"
    description = "A shell command is built from input, so `; rm -rf /` style payloads run on the server."

    def _is_sink(self, src, call):
        obj, name = callee(call)
        if src.family == "js":
            if name in JS_SHELL and (obj in JS_CP_OBJECTS or obj == ""):
                return True
            shell = kwarg(call, "shell")
            return name in JS_SPAWN and shell is not None and text(shell) == "true"
        if (obj, name) in PY_SHELL:
            return True
        shell = kwarg(call, "shell")
        return obj == "subprocess" and name in PY_SUBPROCESS and shell is not None and text(shell) == "True"

    def check(self, src, taint):
        out = []
        for call in calls(src):
            if not self._is_sink(src, call):
                continue
            a = args(call)
            via, dynamic = _dangerous_arg(taint, a[0] if a else None)
            fix = ("Avoid the shell: pass an argument array (execFile / spawn without shell, subprocess.run([...]))"
                   " and allow-list any user-supplied value.")
            if via:
                out.append(finding(self, src, call, Severity.CRITICAL,
                                   f"Untrusted input `{taint.root(via)}` reaches a shell command — an attacker can run any command on the server.",
                                   fix, taint, via))
            elif dynamic:
                out.append(finding(self, src, call, Severity.HIGH,
                                   "Shell command is built from a non-constant string.", fix))
        return out
