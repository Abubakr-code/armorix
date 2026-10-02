"""Configuration & API-misuse rules: weak hashing, CORS, JWT, deserialization, debug mode, TLS."""

from __future__ import annotations

import re

from ..finding import Severity
from ..parsing import text
from .base import CallSinkRule, Rule, args, callee, calls, finding, kwarg
from .infra import line_finding


class WeakHash(Rule):
    id = "ARX-WEAKHASH"
    cwe = "CWE-328"
    title = "Weak hash algorithm"
    description = "MD5 / SHA-1 are broken for passwords, signatures and tokens."
    WEAK = re.compile(r"^['\"`](md5|sha1|md4)['\"`]$", re.IGNORECASE)
    FIX = "Use bcrypt / argon2 for passwords and SHA-256+ (or HMAC-SHA-256) for integrity; MD5/SHA-1 are fine only for non-security checksums."

    def check(self, src, taint):
        out = []
        for call in calls(src):
            obj, name = callee(call)
            a = args(call)
            weak = False
            if src.family == "js" and name in {"createHash", "createHmac"} and a:
                weak = bool(self.WEAK.match(text(a[0])))
            elif src.family == "py":
                weak = (obj == "hashlib" and name in {"md5", "sha1"}) or (obj == "hashlib" and name == "new" and a and self.WEAK.match(text(a[0])))
            if weak and not any(k in text(call) for k in ("usedforsecurity=False",)):
                out.append(finding(self, src, call, Severity.LOW, "MD5 / SHA-1 hash — collisions are practical.", self.FIX))
        return out


class InsecureCors(Rule):
    id = "ARX-CORS"
    cwe = "CWE-942"
    title = "Permissive CORS with credentials"
    description = "Any website can make authenticated requests on behalf of your users."
    FIX = "List the exact allowed origins; never combine a wildcard or reflected origin with credentials."

    def check(self, src, taint):
        out = []
        for call in calls(src):
            obj, name = callee(call)
            if src.family == "js" and name == "cors":
                origin, creds = kwarg(call, "origin"), kwarg(call, "credentials")
                if creds is not None and text(creds) == "true" and origin is not None and text(origin) in {"true", "'*'", '"*"'}:
                    out.append(finding(self, src, call, Severity.HIGH,
                                       "CORS allows every origin *and* sends cookies — any site can act as the logged-in user.", self.FIX))
            elif src.family == "js" and name in {"setHeader", "header", "set"}:
                a = args(call)
                if len(a) > 1 and "access-control-allow-origin" in text(a[0]).lower():
                    via = taint.tainted_by(a[1])
                    if via:
                        out.append(finding(self, src, call, Severity.HIGH,
                                           f"The request's own origin (`{taint.root(via)}`) is reflected into Access-Control-Allow-Origin.",
                                           self.FIX, taint, via))
            elif src.family == "py" and name == "CORS":
                creds, origins = kwarg(call, "supports_credentials"), kwarg(call, "origins") or kwarg(call, "resources")
                if creds is not None and text(creds) == "True" and (origins is None or "*" in text(origins)):
                    out.append(finding(self, src, call, Severity.HIGH,
                                       "flask-cors allows every origin with credentials.", self.FIX))
        return out


class JwtNoVerify(Rule):
    id = "ARX-JWT"
    cwe = "CWE-347"
    title = "JWT signature not verified"
    description = "Tokens are accepted without checking their signature, so anyone can forge a login."
    NONE = re.compile(r"""['"]none['"]""", re.IGNORECASE)
    FIX = "Always verify with an explicit algorithm allow-list, e.g. jwt.verify(token, key, { algorithms: ['HS256'] })."

    def check(self, src, taint):
        out = []
        for call in calls(src):
            obj, name = callee(call)
            if obj not in {"jwt", "jose", "jsonwebtoken", "PyJWT"} or name not in {"verify", "decode", "sign", "encode"}:
                continue
            body = text(call.child_by_field_name("arguments"))
            no_verify = re.search(r"verify_signature['\"]?\s*:\s*False", body) or re.search(r"verify\s*=\s*False", body)
            if self.NONE.search(body) or no_verify:
                out.append(finding(self, src, call, Severity.HIGH,
                                   "JWT is accepted with algorithm `none` or with signature verification disabled.", self.FIX))
        return out


class UnsafeDeserialization(CallSinkRule):
    id = "ARX-DESER"
    cwe = "CWE-502"
    title = "Unsafe deserialization"
    description = "Deserializing untrusted data with pickle / yaml.load / node-serialize executes attacker code."
    sinks = {
        "py": {("pickle", "loads"), ("pickle", "load"), ("cPickle", "loads"), ("dill", "loads"), ("marshal", "loads"),
               ("shelve", "open"), ("yaml", "unsafe_load"), ("jsonpickle", "decode")},
        "js": {("serialize", "unserialize"), ("", "unserialize")},
    }
    tainted = Severity.CRITICAL
    dynamic = Severity.LOW
    msg_tainted = "Untrusted input `{src}` is deserialized with `{name}` — remote code execution."
    msg_dynamic = "`{name}` can execute code while loading — only use it on data you created yourself."
    fix = {"py": "Use json for untrusted data; for YAML use yaml.safe_load.", "js": "Use JSON.parse; never node-serialize on user data."}

    def check(self, src, taint):
        out = super().check(src, taint)
        if src.family == "py":  # yaml.load without a safe Loader
            for call in calls(src):
                if callee(call) == ("yaml", "load"):
                    loader = kwarg(call, "Loader")
                    if loader is None or "Safe" not in text(loader):
                        a = args(call)
                        via = taint.tainted_by(a[0]) if a else None
                        out.append(finding(self, src, call, Severity.CRITICAL if via else Severity.MEDIUM,
                                           "yaml.load without SafeLoader can construct arbitrary Python objects.",
                                           "Use yaml.safe_load(...) (or Loader=yaml.SafeLoader).", taint, via))
        return out


class DebugEnabled(Rule):
    id = "ARX-DEBUG"
    cwe = "CWE-489"
    title = "Debug mode enabled"
    description = "Debug servers expose stack traces and, in Flask/Werkzeug, an interactive code console."

    def check(self, src, taint):
        out = []
        if src.family != "py":
            return out
        for call in calls(src):
            obj, name = callee(call)
            debug = kwarg(call, "debug")
            if name == "run" and debug is not None and text(debug) == "True":
                out.append(finding(self, src, call, Severity.HIGH,
                                   "`app.run(debug=True)` exposes the Werkzeug debugger — a remote Python console if reachable.",
                                   "Read debug from an environment variable and keep it off in production."))
        if src.path.name == "settings.py":
            for node in src.nodes:
                if node.type == "assignment" and text(node.child_by_field_name("left")) == "DEBUG" and text(node.child_by_field_name("right")) == "True":
                    out.append(finding(self, src, node, Severity.MEDIUM, "Django `DEBUG = True` leaks settings and stack traces.",
                                       "DEBUG = os.environ.get('DJANGO_DEBUG') == '1'"))
        return out


class TlsVerifyDisabled(Rule):
    id = "ARX-TLS"
    cwe = "CWE-295"
    title = "TLS certificate verification disabled"
    description = "HTTPS certificates are not checked, allowing man-in-the-middle attacks."
    FIX = "Keep certificate verification on; for self-signed internal services pass the CA bundle instead."

    def check(self, src, taint):
        out = []
        for node in src.nodes:
            hit = None
            if src.family == "js":
                if node.type == "pair" and text(node.child_by_field_name("key")) == "rejectUnauthorized" and text(node.child_by_field_name("value")) == "false":
                    hit = "`rejectUnauthorized: false` accepts any certificate."
                elif node.type == "assignment_expression" and "NODE_TLS_REJECT_UNAUTHORIZED" in text(node.child_by_field_name("left")) \
                        and text(node.child_by_field_name("right")).strip("'\"") == "0":
                    hit = "NODE_TLS_REJECT_UNAUTHORIZED=0 disables certificate checks for the whole process."
            elif node.type == "keyword_argument" and text(node.child_by_field_name("name")) == "verify" \
                    and text(node.child_by_field_name("value")) == "False":
                hit = "`verify=False` accepts any certificate."
            if hit:
                out.append(finding(self, src, node, Severity.MEDIUM, hit, self.FIX))
        return out



class WeakCsp(Rule):
    id = "ARX-CSP"
    cwe = "CWE-693"
    title = "Content-Security-Policy that does not stop XSS"
    description = "A CSP that allows inline scripts, eval, or any origin gives an attacker's script the same freedom as yours."
    families = ("*",)  # the header is written from PHP, Node, nginx config, a <meta> tag …

    POLICY = re.compile(r"(?i)content-security-policy(?:-report-only)?\b[^\n]{0,400}")
    WEAK = (
        ("'unsafe-inline'", "'unsafe-inline' lets any injected <script> run — the one thing CSP exists to stop"),
        ("'unsafe-eval'", "'unsafe-eval' keeps eval() and new Function() working for injected code"),
    )
    WILDCARD = re.compile(r"(?i)(?:script-src|default-src)[^;]*?(?<![\w'-])\*(?![\w.-])")
    DATA_SCRIPT = re.compile(r"(?i)script-src[^;]*\bdata:")
    XSS_HEADER = re.compile(r"(?i)x-xss-protection\s*:\s*0\b")
    FIX = ("Drop 'unsafe-inline' and 'unsafe-eval'; give each <script> a per-response nonce "
           "(script-src 'nonce-...' 'strict-dynamic') and name real origins instead of *.")

    def check(self, src, taint):
        out = []
        for i, raw in enumerate(src.lines, start=1):
            if len(raw) > 2000:
                continue
            policy = self.POLICY.search(raw)
            if policy:
                body = policy.group(0)
                # A report-only policy enforces nothing, so a weak value in it is not the finding.
                report_only = "report-only" in body.lower()
                for token, why in self.WEAK:
                    if token in body.lower() and not report_only:
                        out.append(line_finding(self, src, i, Severity.MEDIUM, f"CSP allows {why}.", self.FIX))
                        break
                else:
                    if not report_only and (self.WILDCARD.search(body) or self.DATA_SCRIPT.search(body)):
                        out.append(line_finding(self, src, i, Severity.MEDIUM,
                                                "CSP lets scripts load from any origin, so it blocks nothing.", self.FIX))
            if self.XSS_HEADER.search(raw):
                out.append(line_finding(self, src, i, Severity.LOW,
                                        "`X-XSS-Protection: 0` switches the browser's own reflected-XSS filter off.",
                                        "Remove the header (modern browsers ignore it) and rely on escaping plus a real CSP.",
                                        fix_key="xss_header"))
        return out


class WeakCipher(Rule):
    id = "ARX-CRYPTO"
    cwe = "CWE-327"
    title = "Broken or misused cipher"
    description = "ECB mode, DES, RC4 and friends are broken: identical plaintext blocks give identical ciphertext, and the keys are too short."
    families = ("*",)  # cipher names are strings, and look the same in every language

    # A cipher is named by a whole quoted token — 'aes-128-ecb', "AES/ECB/PKCS5Padding", 'des-ede3-cbc'.
    # Matching anywhere in the line instead would hit the URL .../aes-ecb-padding-attack and any prose.
    QUOTED = re.compile(r"""['"]([^'"\n]{2,40})['"]""")
    CONSTANT = re.compile(r"\bMODE_ECB\b|\b(?:ARC4|DES3?|Blowfish|RC2)\.new\b|\bDES_ECB\b")
    BROKEN_HEAD = {"des", "des3", "desede", "3des", "tripledes", "triple-des", "rc2", "rc4", "arc4", "bf", "blowfish"}
    MODES = {"ECB": ("ECB mode encrypts every block on its own, so repeated plaintext stays visible in the ciphertext.",
                     "Use an authenticated mode: AES-GCM (aes-256-gcm, AES/GCM/NoPadding) or ChaCha20-Poly1305."),
             "BROKEN": ("DES, 3DES, RC2, RC4 and Blowfish are broken or have keys short enough to brute-force.",
                        "Use AES-256-GCM or ChaCha20-Poly1305 with a key from a KDF, never a password directly.")}

    def _kind(self, token: str) -> str | None:
        if " " in token or "://" in token or "." in token:
            return None  # a sentence, a URL or a filename — not a cipher spec
        parts = [p.lower() for p in re.split(r"[-/]", token) if p]
        if not parts:
            return None
        if "ecb" in parts:
            return "ECB"
        if parts[0] in self.BROKEN_HEAD:
            return "BROKEN"
        return None

    def check(self, src, taint):
        out = []
        for i, raw in enumerate(src.lines, start=1):
            if len(raw) > 2000 or raw.lstrip().startswith(("#", "//", "*")):
                continue
            kind = next((k for m in self.QUOTED.finditer(raw) if (k := self._kind(m.group(1)))), None)
            if kind is None and self.CONSTANT.search(raw):
                kind = "ECB" if "ECB" in raw else "BROKEN"
            if kind:
                message, fix = self.MODES[kind]
                out.append(line_finding(self, src, i, Severity.MEDIUM, message, fix))
        return out
