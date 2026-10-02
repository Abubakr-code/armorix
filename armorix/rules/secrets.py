"""CWE-798 — credentials committed to source or config files (text based, all files)."""

from __future__ import annotations

import math
import re

from ..finding import Finding, Severity
from .base import Rule

# (name, pattern, severity) — the secret itself is capture group "s".
KNOWN = [
    ("AWS access key", re.compile(r"(?P<s>\b(?:AKIA|ASIA)[0-9A-Z]{16}\b)"), Severity.CRITICAL),
    ("GitHub token", re.compile(r"(?P<s>\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b)"), Severity.CRITICAL),
    ("GitLab token", re.compile(r"(?P<s>\bglpat-[A-Za-z0-9_\-]{20,}\b)"), Severity.CRITICAL),
    ("Stripe live key", re.compile(r"(?P<s>\b[sr]k_live_[0-9a-zA-Z]{20,}\b)"), Severity.CRITICAL),
    ("Anthropic API key", re.compile(r"(?P<s>\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}\b)"), Severity.CRITICAL),
    ("OpenAI API key", re.compile(r"(?P<s>\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}\b)"), Severity.CRITICAL),
    ("Telegram bot token", re.compile(r"(?P<s>\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b)"), Severity.CRITICAL),
    ("Slack token", re.compile(r"(?P<s>\bxox[abprs]-[0-9A-Za-z-]{10,}\b)"), Severity.HIGH),
    ("Slack webhook", re.compile(r"(?P<s>https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})"), Severity.HIGH),
    ("Discord webhook", re.compile(r"(?P<s>https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{60,})"), Severity.HIGH),
    ("Google API key", re.compile(r"(?P<s>\bAIza[0-9A-Za-z_\-]{35}\b)"), Severity.HIGH),
    ("Google OAuth client secret", re.compile(r"(?P<s>\bGOCSPX-[A-Za-z0-9_\-]{28}\b)"), Severity.HIGH),
    ("SendGrid API key", re.compile(r"(?P<s>\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b)"), Severity.HIGH),
    ("Twilio API key", re.compile(r"(?P<s>\bSK[0-9a-f]{32}\b)"), Severity.HIGH),
    ("npm token", re.compile(r"(?P<s>\bnpm_[A-Za-z0-9]{36}\b)"), Severity.CRITICAL),
    ("PyPI token", re.compile(r"(?P<s>\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b)"), Severity.CRITICAL),
    ("Hugging Face token", re.compile(r"(?P<s>\bhf_[A-Za-z0-9]{34,}\b)"), Severity.HIGH),
    ("DigitalOcean token", re.compile(r"(?P<s>\bdo[por]_v1_[a-f0-9]{64}\b)"), Severity.CRITICAL),
    ("Shopify token", re.compile(r"(?P<s>\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b)"), Severity.HIGH),
    ("Azure storage key", re.compile(r"AccountKey=(?P<s>[A-Za-z0-9+/]{86}==)"), Severity.CRITICAL),
    ("Private key", re.compile(r"(?P<s>-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"), Severity.CRITICAL),
]
# postgres://user:PASSWORD@host/db — the password is the secret; well-known local defaults are ignored.
DB_URL = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver)://[^:@\s/'\"]+:(?P<s>[^@\s'\"/]{4,})@(?P<host>[^\s'\"/:]+)"
)
DEV_PASSWORDS = {"password", "postgres", "root", "admin", "secret", "example", "test", "pass", "mysql", "changeme", "guest", "redis",
                 "mongo", "mongodb", "user", "dev", "local", "docker", "passw0rd", "password123", "123456"}
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


NOT_SECRET = re.compile(r"^(?:https?://|/|\./|\.\./|~/)|\.(?:pem|key|json|crt|cer|txt|ya?ml|env|p12|pfx|js|ts|py)$", re.IGNORECASE)
# `userid:2`, `role:admin`, `v1:beta` — a field:value pair carries data, not a credential.
FIELD_PAIR = re.compile(r"^[a-z][a-z_-]{1,14}:[a-z0-9_.-]{1,6}$", re.IGNORECASE)


HASHED = re.compile(r"^(?:\$2[abxy]?\$|\$argon2|\$scrypt\$|\$pbkdf2|pbkdf2_sha|\$[156]\$|\$y\$|sha256\$|bcrypt\$)")


def looks_random(value: str) -> bool:
    """Real keys and passwords mix character classes; identifiers, command names, prose and paths do not."""
    if not value.isascii() or NOT_SECRET.search(value) or value.isdigit() or HASHED.match(value):
        return False
    if FIELD_PAIR.match(value):
        return False
    if any(c.isdigit() for c in value) and any(c.isalpha() for c in value):
        return entropy(value) >= 3.0
    return len(value) >= 24 and entropy(value) >= 4.0  # long base64-ish strings without digits


def _inside_prose(raw: str, start: int) -> bool:
    """True when the key sits in the middle of a quoted string (a sentence), not at its start."""
    prefix = raw[:start]
    for quote in "\"'":
        if prefix.count(quote) % 2 == 1 and not prefix.endswith(quote):
            return True
    return False


def match_secret(raw: str, is_dotenv: bool = False) -> tuple[str, str, Severity] | None:
    """(label, secret, severity) for one line of text, or None. Shared with the git-history scan."""
    if len(raw) > 2000:  # minified or data blob
        return None
    for label, pattern, severity in KNOWN:
        m = pattern.search(raw)
        if m:
            return label, m.group("s"), severity
    m = DB_URL.search(raw)
    if m and m.group("s").lower() not in DEV_PASSWORDS and not PLACEHOLDER.search(m.group("s")):
        return "Database password in a connection URL", m.group("s"), Severity.HIGH
    m = DOTENV.search(raw) if is_dotenv else (GENERIC.search(raw) or ENV_DEFAULT.search(raw))
    if m and ("hash" in m.group("k").lower() or _inside_prose(raw, m.start("k"))):
        return None  # hashed_password holds a hash; "…the correct password.": "…" is a sentence, not a key
    if m and not PLACEHOLDER.search(m.group("s")) and (is_dotenv or looks_random(m.group("s"))):
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
