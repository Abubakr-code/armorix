"""CWE-798 — credentials committed to source or config files (text based, all files)."""

from __future__ import annotations

import math
import re

from ..finding import Finding, Severity
from .base import Rule

# (name, pattern, severity) — the secret itself is capture group "s".
KNOWN = [
    ("AWS access key", re.compile(r"(?P<s>\b(?:AKIA|ASIA)[0-9A-Z]{16}\b)"), Severity.CRITICAL),
    ("GitHub token", re.compile(r"(?P<s>\bgh[pousr]_[A-Za-z0-9]{36,}\b)"), Severity.CRITICAL),
    ("Stripe live key", re.compile(r"(?P<s>\b[sr]k_live_[0-9a-zA-Z]{20,}\b)"), Severity.CRITICAL),
    ("Slack token", re.compile(r"(?P<s>\bxox[abprs]-[0-9A-Za-z-]{10,}\b)"), Severity.HIGH),
    ("Google API key", re.compile(r"(?P<s>\bAIza[0-9A-Za-z_\-]{35}\b)"), Severity.HIGH),
    ("OpenAI API key", re.compile(r"(?P<s>\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b)"), Severity.CRITICAL),
    ("Private key", re.compile(r"(?P<s>-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)"), Severity.CRITICAL),
]
# `password = "…"`, `apiKey: '…'`, `JWT_SECRET="…"` — kept only when the value looks random.
SECRET_KEY = r"(?P<k>[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token|private[_-]?key)[\w.-]*)"
GENERIC = re.compile(
    rf"(?i){SECRET_KEY}[\"']?\s*(?:=|:|=>)\s*"
    # optional env lookup with a hard-coded fallback: process.env.X || "…", os.environ.get("X") or "…"
    r"(?:[\w.\[\]'\"()]+\s*(?:\|\||\?\?|\bor\b)\s*)?"
    r"[\"'](?P<s>[^\"'\s]{8,})[\"']"
)
# os.getenv("DB_PASSWORD", "fallback") / os.environ.get("API_KEY", "fallback")
ENV_DEFAULT = re.compile(
    r"(?i)(?:getenv|environ\.get)\(\s*[\"'](?P<k>[\w.-]*(?:password|passwd|secret|key|token)[\w.-]*)[\"']\s*,\s*[\"'](?P<s>[^\"'\s]{8,})[\"']"
)
DOTENV = re.compile(
    r"^\s*(?:export\s+)?(?P<k>[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|PRIVATE_KEY|AUTH)[A-Z0-9_]*)"
    r"\s*=\s*[\"']?(?P<s>[^\"'\s#]{8,})"
)
PLACEHOLDER = re.compile(
    r"(?i)(change.?me|your[_-]|example|placeholder|dummy|sample|redacted|todo|xxx|\*{3}|<[^>]+>|\$\{|%\(|\{\{|process\.env|os\.environ|getenv)"
)


def entropy(s: str) -> float:
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def mask(secret: str) -> str:
    return secret[:4] + "•" * min(12, max(4, len(secret) - 4))


def match_secret(raw: str, is_dotenv: bool = False) -> tuple[str, str, Severity] | None:
    """(label, secret, severity) for one line of text, or None. Shared with the git-history scan."""
    if len(raw) > 2000:  # minified or data blob
        return None
    for label, pattern, severity in KNOWN:
        m = pattern.search(raw)
        if m:
            return label, m.group("s"), severity
    m = DOTENV.search(raw) if is_dotenv else (GENERIC.search(raw) or ENV_DEFAULT.search(raw))
    if m and not PLACEHOLDER.search(m.group("s")) and (is_dotenv or entropy(m.group("s")) >= 3.0):
        return f"Secret in `{m.group('k')}`", m.group("s"), Severity.HIGH
    return None


class HardcodedSecret(Rule):
    id = "ARX-SECRET"
    cwe = "CWE-798"
    title = "Hard-coded secret"
    description = "API keys, passwords or private keys are committed to the repository."
    families = ("*",)  # every text file, parsed or not

    def check(self, src, taint):
        name = src.path.name.lower()
        if name.endswith((".example", ".sample", ".template", ".dist")):
            return []
        is_dotenv = name.startswith(".env")
        out: dict[int, Finding] = {}
        for i, raw in enumerate(src.lines, start=1):
            hit = match_secret(raw, is_dotenv)
            if hit is None or i in out:
                continue
            label, secret, severity = hit
            where = "a committed .env file" if is_dotenv else "source code"
            out[i] = Finding(
                rule_id=self.id,
                cwe=self.cwe,
                severity=severity,
                title=self.title,
                message=f"{label} is stored in {where}. Anyone with access to the repository (or its git history) can use it.",
                fix="Load it from an environment variable or secret store, add the file to .gitignore, and rotate the key — it is already exposed in history.",
                file=src.rel,
                line=i,
                column=raw.find(secret) + 1,
                snippet=raw.strip().replace(secret, mask(secret)),
            )
        return list(out.values())
