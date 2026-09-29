"""Deep scan — the slow, pentester-style pass.

On top of the regular scan:
  1. git history: every commit's added lines are checked for secrets that were
     "deleted" later but still sit in history;
  2. AI review: each HTTP handler (a function that reads request data) is read
     by the local model looking for issues rules can't see — missing auth,
     IDOR, mass assignment, data exposure, brute force, business logic.
AI findings are labelled as unconfirmed: a human should look at them.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from .ai import LocalAI
from .finding import Finding, Severity
from .parsing import load
from .rules.base import FUNCTION_TYPES
from .rules.secrets import mask, match_secret
from .project import assign_fingerprints
from .scanner import ScanResult, discover, scan
from .taint import Analyzer

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")

REVIEW_TYPES = {
    "missing-auth": ("CWE-306", "Missing authentication on a sensitive action"),
    "broken-access": ("CWE-639", "Missing ownership check (IDOR)"),
    "mass-assignment": ("CWE-915", "Mass assignment of request fields"),
    "data-exposure": ("CWE-200", "Sensitive data returned to the client"),
    "brute-force": ("CWE-307", "No brute-force / rate limiting on authentication"),
    "logic": ("CWE-840", "Business logic flaw"),
}
REVIEW_FIX = {
    "missing-auth": "Require an authenticated session (middleware) before this handler runs.",
    "broken-access": "Load the record by id AND the current user's id, or check ownership before returning / changing it.",
    "mass-assignment": "Copy only the allowed fields from the request body (allow-list) instead of passing it whole.",
    "data-exposure": "Return only the fields the client needs; never password hashes, tokens or internal ids.",
    "brute-force": "Add rate limiting / lockout (express-rate-limit, flask-limiter) to login and reset endpoints.",
    "logic": "Re-check the business rule on the server side for every request.",
}


# ── 1. git history ──────────────────────────────────────────────
def git_history_secrets(root: Path, progress=None, cancelled=None) -> list[Finding]:
    probe = subprocess.run(["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"], capture_output=True, text=True)
    if probe.returncode or probe.stdout.strip() != "true":
        return []
    total = int(subprocess.run(["git", "-C", str(root), "rev-list", "--all", "--count"], capture_output=True, text=True).stdout.strip() or 0)
    proc = subprocess.Popen(
        ["git", "-C", str(root), "log", "--all", "-p", "--no-color", "-U0", "--no-ext-diff", "--format=%x00%H%x1f%an%x1f%ad", "--date=short"],
        stdout=subprocess.PIPE, text=True, errors="replace",
    )
    found: dict[str, Finding] = {}
    commit = author = date = path = ""
    line_no = done = 0
    try:
        for raw in proc.stdout:
            if cancelled and cancelled():
                proc.kill()
                break
            if raw.startswith("\x00"):
                commit, author, date = (raw[1:].rstrip("\n").split("\x1f") + ["", ""])[:3]
                done += 1
                if progress and done % 5 == 0:
                    progress("history", done, total, commit[:8])
            elif raw.startswith("+++ "):
                path = raw[6:].rstrip("\n") if raw.startswith("+++ b/") else ""
            elif raw.startswith("@@"):
                m = HUNK.match(raw)
                line_no = int(m.group(1)) if m else 0
            elif raw.startswith("+") and path:
                hit = match_secret(raw[1:].rstrip("\n"), Path(path).name.startswith(".env"))
                if hit:
                    label, secret, severity = hit
                    # newest first: the last write wins, so we keep the oldest commit that introduced it
                    found[secret] = Finding(
                        rule_id="ARX-SECRET-HISTORY", cwe="CWE-798", severity=severity, title="Secret in git history",
                        message=f"{label} was committed in {commit[:8]} ({author}, {date}). Removing it from the file does not remove it from git history.",
                        fix="Rotate the key now, then purge it from history (git filter-repo / BFG) and force-push.",
                        file=path, line=line_no, column=1, snippet=f"{mask(secret)}  @ {commit[:8]}",
                        data={"commit": commit, "author": author, "date": date, "secret": secret},
                    )
                line_no += 1
    finally:
        proc.wait()
    if progress:
        progress("history", total, total, "")
    # Secrets still present in the working tree are already reported by the normal scan.
    out = []
    for secret, f in found.items():
        current = root / f.file
        try:
            still_there = current.is_file() and secret in current.read_text(errors="ignore")
        except OSError:
            still_there = False
        f.data.pop("secret", None)
        if not still_there:
            out.append(f)
    return sorted(out, key=lambda f: (-f.severity, f.file))


# ── 2. AI review of handlers ────────────────────────────────────
def handlers(src) -> list:
    """Outermost functions that read request data, ≤ 80 lines."""
    taint = Analyzer(src)
    picked = []
    for node in src.nodes:
        if node.type not in FUNCTION_TYPES:
            continue
        lines = node.end_point[0] - node.start_point[0] + 1
        if lines > 80 or any(p.start_byte <= node.start_byte and node.end_byte <= p.end_byte for p in picked):
            continue
        if any(taint.is_source(n) for n in _descendants(node)):
            picked.append(node)
    return picked


def _descendants(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _review_prompt(code: str, lang: str) -> str:
    kinds = "\n".join(f'- "{k}": {v[1]}' for k, v in REVIEW_TYPES.items())
    return f"""You are a senior application-security reviewer. Review this {lang} HTTP handler.
Look ONLY for these issue types (static rules already cover injection and secrets):
{kinds}

Code (line numbers on the left):
{code}

Reply with JSON only: {{"issues": [{{"type": "<one of the types>", "line": <line number>, "why": "<one short sentence>", "confidence": <0.0-1.0>}}]}}
Report an issue only if you can point to the exact line. If the handler looks fine, reply {{"issues": []}}."""


def ai_review(ai: LocalAI, result: ScanResult, progress=None, cancelled=None) -> list[Finding]:
    base = result.root if result.root.is_dir() else result.root.parent
    targets = []
    for path in discover(result.root):
        src = load(path, str(path.relative_to(base)))
        if src.tree is not None:
            targets += [(src, fn) for fn in handlers(src)]
    static_lines = {(f.file, f.line) for f in result.findings}
    out = []
    for index, (src, fn) in enumerate(targets, 1):
        if cancelled and cancelled():
            break
        if progress:
            progress("ai", index, len(targets), f"{src.rel}:{fn.start_point[0] + 1}")
        start, end = fn.start_point[0] + 1, fn.end_point[0] + 1
        numbered = "\n".join(f"{n:>4}  {src.lines[n - 1]}" for n in range(start, end + 1))
        try:
            reply = ai.generate(_review_prompt(numbered, "JavaScript" if src.family == "js" else "Python"), max_tokens=400, json_mode=True)
            issues = json.loads(reply).get("issues", [])
        except (ValueError, AttributeError, OSError):
            continue
        for issue in issues if isinstance(issues, list) else []:
            if not isinstance(issue, dict):
                continue
            kind, why = str(issue.get("type", "")), str(issue.get("why", "")).strip()
            try:
                line, confidence = int(issue.get("line", 0)), float(issue.get("confidence", 0))
            except (TypeError, ValueError):
                continue
            # Hallucination filters: known type, a line inside this handler, some confidence, not a duplicate.
            if kind not in REVIEW_TYPES or not (start <= line <= end) or confidence < 0.6 or not why or (src.rel, line) in static_lines:
                continue
            cwe, title = REVIEW_TYPES[kind]
            static_lines.add((src.rel, line))
            out.append(Finding(
                rule_id=f"ARX-AI-{kind.upper()}", cwe=cwe, severity=Severity.MEDIUM if confidence >= 0.75 else Severity.LOW,
                title=title, message=f"{why[:240]} (AI review — unconfirmed, verify manually)", fix=REVIEW_FIX[kind],
                file=src.rel, line=line, column=1, snippet=src.line(line), data={"ai": True, "confidence": round(confidence, 2), "kind": kind},
            ))
    return out


AUTH_MARKERS = re.compile(
    r"passport|jwt\.verify|jsonwebtoken|express-session|req\.session|req\.user|isAuthenticated|requireAuth|authenticate\(|"
    r"login_required|@auth|current_user|flask_login|get_current_user|Depends\(|permission_classes|@jwt_required|auth\(",
)
# ORM "load one record" calls whose argument is an id straight from the request
ID_LOOKUP = re.compile(
    r"\b(?:findById|findByPk|findOne|findByIdAndUpdate|findByIdAndDelete|findUnique|get_object_or_404|get_or_404|query\.get)\s*\("
    r"[^)]*?(?:req\.params|req\.query|request\.args|request\.view_args|\bpk\b|\b\w*_?id\b)"
)
OWNER_HINT = re.compile(r"req\.user|session|current_user|owner|userId|user_id|author|request\.user", re.IGNORECASE)


def auth_overview(result: ScanResult) -> tuple[bool, list[Finding]]:
    """(project has any auth, findings). No auth anywhere → one project-level finding instead of one per handler."""
    base = result.root if result.root.is_dir() else result.root.parent
    handler_count, has_auth, first = 0, False, None
    for path in discover(result.root):
        src = load(path, str(path.relative_to(base)))
        if src.tree is None:
            continue
        if AUTH_MARKERS.search(src.text):
            has_auth = True
        found = handlers(src)
        handler_count += len(found)
        if found and first is None:
            first = (src, found[0])
    if has_auth or not handler_count:
        return has_auth, []
    src, fn = first
    line = fn.start_point[0] + 1
    return False, [Finding(
        rule_id="ARX-NOAUTH", cwe="CWE-306", severity=Severity.HIGH, title="No authentication in the project",
        message=f"None of the {handler_count} request handlers use any authentication (no session, JWT, passport or login_required found) — every endpoint is public.",
        fix="Add an authentication layer (session / JWT middleware) and apply it to every non-public route.",
        file=src.rel, line=line, column=1, snippet=src.line(line), data={"handlers": handler_count},
    )]


def idor_candidates(result: ScanResult) -> list[Finding]:
    """A record fetched by a client-supplied id with no sign of an ownership check in the same handler."""
    base = result.root if result.root.is_dir() else result.root.parent
    out = []
    for path in discover(result.root):
        src = load(path, str(path.relative_to(base)))
        if src.tree is None:
            continue
        for fn in handlers(src):
            body = fn.text.decode(errors="replace")
            m = ID_LOOKUP.search(body)
            if not m or OWNER_HINT.search(body):
                continue
            line = fn.start_point[0] + 1 + body[: m.start()].count("\n")
            out.append(Finding(
                rule_id="ARX-IDOR", cwe="CWE-639", severity=Severity.MEDIUM, title="Possible IDOR (missing ownership check)",
                message="A record is loaded by an id taken from the request, and the handler never compares it with the current user — any user can read or change anyone's data by changing the id.",
                fix=REVIEW_FIX["broken-access"], file=src.rel, line=line, column=1, snippet=src.line(line), data={"heuristic": True},
            ))
    return out


def deep_scan(target, ai: LocalAI | None = None, progress=None, cancelled=None, config=None) -> ScanResult:
    result = scan(target, progress=progress, cancelled=cancelled, config=config)
    root = result.root if result.root.is_dir() else result.root.parent
    result.findings += git_history_secrets(root, progress, cancelled)
    has_auth, noauth = auth_overview(result)
    result.findings += noauth + idor_candidates(result)
    if ai is not None and not (cancelled and cancelled()):
        result.findings += [f for f in ai_review(ai, result, progress, cancelled)
                            # Without any auth system, per-handler "missing auth" only repeats ARX-NOAUTH.
                            if has_auth or f.data.get("kind") != "missing-auth"]
    assign_fingerprints(result.findings)
    result.findings.sort(key=lambda f: (-f.severity, f.file, f.line))
    return result

