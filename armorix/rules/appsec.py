"""Application-logic rules developers hit every day: mass assignment, prototype pollution, regex injection,
cookie flags, predictable tokens, hard-coded signing keys, XXE, disabled auto-escaping and CSRF exemptions."""

from __future__ import annotations

import re

from ..finding import Severity
from ..parsing import text
from .base import FUNCTION_TYPES, CallSinkRule, Rule, args, callee, calls, finding, kwarg

JS_BODY = re.compile(r"^(?:req|request|ctx(?:\.request)?)\.body$")
PY_BODY = re.compile(r"^request\.(?:json|form|data|POST|get_json\(\s*\)|values)$")
SENSITIVE_NAME = re.compile(
    r"(?i)(token|secret|passw|otp|nonce|salt|api_?key|session_?id|sessid|reset|verif|invite|csrf|pin_?code|captcha|recovery|activation)"
)


class MassAssignment(Rule):
    id = "ARX-MASS"
    cwe = "CWE-915"
    title = "Mass assignment"
    description = "The whole request body is written into a database model, so users can set fields like isAdmin or balance."
    JS_WRITES = {"create", "insertOne", "insertMany", "update", "updateOne", "updateMany", "findByIdAndUpdate",
                 "findOneAndUpdate", "build", "upsert", "bulkCreate", "replaceOne"}
    PY_WRITES = {"create", "update", "update_or_create", "get_or_create", "insert_one", "update_one", "filter_by"}
    FIX = "Copy only the fields a user may change (an allow-list or a validation schema such as zod / pydantic) before saving."

    def check(self, src, taint):
        out = []
        for call in calls(src):
            obj, name = callee(call)
            a = args(call)
            if src.family == "js":
                is_new = call.type == "new_expression" and name[:1].isupper()
                if not (name in self.JS_WRITES or is_new or (obj, name) == ("Object", "assign")):
                    continue
                body = next((x for x in a if JS_BODY.match(text(x)) or (x.type == "object" and any(
                    c.type == "spread_element" and JS_BODY.match(text(c.named_children[0])) for c in x.named_children))), None)
                if body is None or ((obj, name) == ("Object", "assign") and a and a[0] is body):
                    continue
            else:
                if not (name in self.PY_WRITES or name[:1].isupper()):
                    continue
                box = call.child_by_field_name("arguments")
                body = next((c for c in (box.named_children if box is not None else [])
                             if c.type == "dictionary_splat" and PY_BODY.match(text(c.named_children[0]) if c.named_children else "")), None)
                if body is None:
                    continue
            out.append(finding(self, src, call, Severity.MEDIUM,
                               f"`{text(body)}` is saved as a whole by `{name}` — a user can add fields like isAdmin, role or balance.", self.FIX))
        return out


class PrototypePollution(Rule):
    id = "ARX-PROTO"
    cwe = "CWE-1321"
    title = "Prototype pollution"
    description = "Untrusted keys are merged into objects, so `__proto__` can change every object in the process."
    families = ("js",)
    MERGES = {"merge", "mergeWith", "defaultsDeep", "set", "setWith", "zipObjectDeep", "deepmerge", "extend", "deepExtend", "assignDeep"}
    FIX = "Merge only known keys (or use Object.create(null) / Map), reject __proto__ / constructor / prototype, and keep lodash ≥ 4.17.21."

    def check(self, src, taint):
        out = []
        for call in calls(src):
            obj, name = callee(call)
            if name not in self.MERGES:
                continue
            if obj in {"$", "jQuery"} and not (name == "extend" and args(call) and text(args(call)[0]) == "true"):
                continue  # only a *deep* jQuery.extend(true, …) walks nested keys; $.merge concatenates arrays
            if name in {"set", "setWith", "merge", "mergeWith"} and obj not in {"_", "lodash", "dot", "objectPath", "R", ""}:
                continue
            via = next((v for v in (taint.tainted_by(x) for x in args(call)) if v), None)
            if via:
                out.append(finding(self, src, call, Severity.HIGH,
                                   f"Untrusted data `{taint.root(via)}` is deep-merged by `{name}` — a `__proto__` key pollutes every object.",
                                   self.FIX, taint, via))
        for node in src.nodes:  # obj[a][b] = value with an untrusted a
            if node.type != "assignment_expression":
                continue
            left = node.child_by_field_name("left")
            if left is None or left.type != "subscript_expression":
                continue
            inner = left.child_by_field_name("object")
            if inner is None or inner.type != "subscript_expression":
                continue
            key = inner.child_by_field_name("index")
            via = taint.tainted_by(key)
            if via and "__proto__" not in text(node.parent.parent if node.parent and node.parent.parent else node):
                out.append(finding(self, src, node, Severity.HIGH,
                                   f"Nested assignment with an untrusted key `{taint.root(via)}` — `__proto__` pollutes Object.prototype.",
                                   self.FIX, taint, via))
        return out


class RegexInjection(CallSinkRule):
    id = "ARX-REGEX"
    cwe = "CWE-1333"
    title = "Regular expression injection (ReDoS)"
    description = "A regular expression is built from user input, so a crafted pattern can freeze the server."
    sinks = {"js": {("", "RegExp")},
             "py": {("re", m) for m in ("compile", "search", "match", "fullmatch", "findall", "finditer", "sub", "split")}}
    sanitizers = ("escape", "escapeRegExp", "quote")
    tainted = Severity.MEDIUM
    msg_tainted = "User input `{src}` becomes a regular expression — a pattern like (a+)+$ blocks the event loop / worker."
    fix = {"js": "Escape the input (_.escapeRegExp) or match it as plain text with includes() / indexOf().",
           "py": "Escape the input with re.escape() or compare as plain text."}


class InsecureCookie(Rule):
    id = "ARX-COOKIE"
    cwe = "CWE-1004"
    title = "Session cookie without HttpOnly / Secure"
    description = "A session or auth cookie can be read by JavaScript (stolen via XSS) or sent over plain HTTP."
    FIX = "Set httpOnly: true, secure: true and sameSite: 'lax' (or 'strict') on session and token cookies."
    SESSIONISH = re.compile(r"(?i)sess|token|auth|jwt|sid\b|remember|login")
    COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)

    def check(self, src, taint):
        out = []
        for call in calls(src):
            obj, name = callee(call)
            a = args(call)
            if src.family == "js" and name == "cookie" and obj in {"res", "response", "reply", "ctx.cookies"} and a:
                if not self.SESSIONISH.search(text(a[0])):
                    continue
                opts = text(a[2]) if len(a) > 2 else ""
                missing = [flag for flag in ("httpOnly", "secure") if not re.search(rf"{flag}\s*:\s*true", opts)]
                if missing:
                    out.append(finding(self, src, call, Severity.MEDIUM,
                                       f"Cookie {text(a[0])} is set without {' and '.join(missing)}.", self.FIX))
            elif src.family == "js" and name in {"session", "cookieSession", "expressSession"}:
                # A commented-out `httpOnly: true` is the single most common thing inside a session config.
                body = self.COMMENT.sub(" ", text(call))
                bad = [m.group(1) for m in re.finditer(r"\b(httpOnly|secure)\s*:\s*false", body)]
                if bad:
                    out.append(finding(self, src, call, Severity.MEDIUM, f"Session cookie has {', '.join(b + ': false' for b in bad)}.", self.FIX))
                elif a and a[0].type in {"object", "dictionary"}:
                    # The default is an insecure cookie, so leaving the flags out is the same bug as writing false.
                    # Any value counts as set: `secure: process.env.NODE_ENV === "production"` is the normal idiom.
                    absent = [flag for flag in ("httpOnly", "secure") if not re.search(rf"\b{flag}\s*:", body)]
                    if absent:
                        out.append(finding(self, src, call, Severity.MEDIUM,
                                           f"Session cookie never sets {' or '.join(absent)} — Express defaults to a cookie "
                                           "readable by JavaScript and sent over plain HTTP.", self.FIX))
            elif src.family == "py" and name == "set_cookie" and a:
                if not self.SESSIONISH.search(text(a[0])):
                    continue
                missing = [flag for flag in ("httponly", "secure") if (kwarg(call, flag) is None or text(kwarg(call, flag)) != "True")]
                if missing:
                    out.append(finding(self, src, call, Severity.MEDIUM,
                                       f"Cookie {text(a[0])} is set without {' and '.join(missing)}=True.",
                                       "Pass httponly=True, secure=True, samesite='Lax' to set_cookie()."))
        if src.family == "py":
            for node in src.nodes:
                if node.type == "assignment" or (node.type == "pair"):
                    left = text(node.child_by_field_name("left") or node.child_by_field_name("key")).strip("'\"")
                    right = text(node.child_by_field_name("right") or node.child_by_field_name("value"))
                    if re.fullmatch(r"(?:\w+\.config\[['\"])?(SESSION_COOKIE_(?:SECURE|HTTPONLY)|CSRF_COOKIE_SECURE)(?:['\"]\])?", left) and right == "False":
                        setting = re.search(r"[A-Z_]{8,}", left).group(0)
                        out.append(finding(self, src, node, Severity.LOW, f"`{setting} = False` sends the cookie without protection.",
                                           f"Set {setting} = True in production settings."))
        return out


class InsecureRandom(Rule):
    id = "ARX-RANDOM"
    cwe = "CWE-338"
    title = "Predictable random value for a secret"
    description = "Tokens, passwords or codes are generated with a non-cryptographic random generator and can be predicted."
    PY_RANDOM = {"random", "randint", "choice", "choices", "randrange", "getrandbits", "sample", "uniform"}
    FIX = {"js": "Use crypto.randomBytes(32).toString('hex') / crypto.randomUUID() / crypto.getRandomValues().",
           "py": "Use the secrets module: secrets.token_urlsafe(32), secrets.choice(), secrets.randbelow()."}

    def _name_of_target(self, node):
        cur, depth = node.parent, 0
        while cur is not None and depth < 8:
            if cur.type in {"variable_declarator", "pair"}:
                return text(cur.child_by_field_name("name") or cur.child_by_field_name("key"))
            if cur.type in {"assignment_expression", "assignment", "augmented_assignment"}:
                return text(cur.child_by_field_name("left"))
            if cur.type == "keyword_argument":
                return text(cur.child_by_field_name("name"))
            if cur.type in FUNCTION_TYPES:
                return text(cur.child_by_field_name("name")) or ""
            if cur.type == "return_statement":
                fn = cur.parent
                while fn is not None and fn.type not in FUNCTION_TYPES:
                    fn = fn.parent
                return text(fn.child_by_field_name("name")) if fn is not None else ""
            cur, depth = cur.parent, depth + 1
        return ""

    def check(self, src, taint):
        out = []
        for call in calls(src):
            obj, name = callee(call)
            weak = (src.family == "js" and (obj, name) == ("Math", "random")) or \
                   (src.family == "py" and obj == "random" and name in self.PY_RANDOM)
            if not weak:
                continue
            target = self._name_of_target(call)
            if target and SENSITIVE_NAME.search(target):
                out.append(finding(self, src, call, Severity.MEDIUM,
                                   f"`{target}` is generated with {obj}.{name}() — its output can be predicted from earlier values.",
                                   self.FIX[src.family]))
        return out


class HardcodedSigningKey(Rule):
    id = "ARX-SIGNKEY"
    cwe = "CWE-321"
    title = "Hard-coded signing key"
    description = "JWTs or session cookies are signed with a key written in the code, so anyone with the code can forge a login."
    FIX = "Read the key from an environment variable or secret store (process.env.JWT_SECRET / os.environ['SECRET_KEY']) and rotate it."

    def _literal(self, node) -> bool:
        return node is not None and node.type in {"string", "template_string"} and not any(
            c.type in {"template_substitution", "interpolation"} for c in node.children) and len(text(node)) > 2

    def check(self, src, taint):
        out = []
        for call in calls(src):
            obj, name = callee(call)
            a = args(call)
            if obj in {"jwt", "jsonwebtoken", "jose", "PyJWT"} and name in {"sign", "verify", "encode", "decode"} and len(a) > 1 \
                    and self._literal(a[1]):
                out.append(finding(self, src, call, Severity.HIGH, f"`{obj}.{name}` uses a hard-coded key — anyone who reads the code can mint valid tokens.", self.FIX))
            elif src.family == "js" and name in {"session", "cookieSession", "expressSession", "cookieParser"}:
                secret = kwarg(call, "secret") if name != "cookieParser" else (a[0] if a else None)
                if self._literal(secret):
                    out.append(finding(self, src, call, Severity.HIGH, "Session cookies are signed with a hard-coded secret — sessions can be forged.", self.FIX))
        if src.family == "py":
            for node in src.nodes:
                if node.type != "assignment":
                    continue
                left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                name = text(left)
                if re.fullmatch(r"\w+\.secret_key|\w+\.config\[['\"](?:SECRET_KEY|JWT_SECRET_KEY)['\"]\]", name) and self._literal(right):
                    out.append(finding(self, src, node, Severity.HIGH, f"`{name}` is hard-coded — Flask session cookies can be forged.", self.FIX))
        return out


class Xxe(Rule):
    id = "ARX-XXE"
    cwe = "CWE-611"
    title = "XML external entities (XXE)"
    description = "The XML parser resolves external entities, so an uploaded XML file can read server files or reach internal URLs."
    FIX = {"js": "Parse without `noent: true` (libxmljs) or use a parser that never resolves entities.",
           "py": "Use defusedxml, or lxml XMLParser(resolve_entities=False, no_network=True)."}

    def check(self, src, taint):
        out = []
        for call in calls(src):
            obj, name = callee(call)
            if src.family == "js" and name in {"parseXml", "parseXmlString", "parseXmlAsync"}:
                noent = kwarg(call, "noent")
                if noent is not None and text(noent) == "true":
                    a = args(call)
                    via = taint.tainted_by(a[0]) if a else None
                    out.append(finding(self, src, call, Severity.CRITICAL if via else Severity.HIGH,
                                       "libxmljs parses with `noent: true` — external entities are resolved (XXE).", self.FIX["js"], taint, via))
            elif src.family == "py" and name == "XMLParser":
                resolve = kwarg(call, "resolve_entities")
                if resolve is not None and text(resolve) == "True":
                    out.append(finding(self, src, call, Severity.HIGH, "lxml parser with resolve_entities=True — external entities are resolved (XXE).", self.FIX["py"]))
            elif src.family == "py" and name == "setFeature":
                a = args(call)
                if len(a) > 1 and "external_ges" in text(a[0]) and text(a[1]) == "True":
                    out.append(finding(self, src, call, Severity.HIGH, "SAX parser enables external general entities (XXE).", self.FIX["py"]))
        return out


class AutoescapeOff(Rule):
    id = "ARX-AUTOESCAPE"
    cwe = "CWE-79"
    title = "Template auto-escaping disabled"
    description = "HTML templates print variables without escaping, so any user value becomes XSS."
    FIX = "Keep auto-escaping on and mark only trusted, sanitized HTML as safe."

    def check(self, src, taint):
        out = []
        for call in calls(src):
            obj, name = callee(call)
            if src.family == "js":
                flag = kwarg(call, "autoescape")
                noescape = kwarg(call, "noEscape")
                if (flag is not None and text(flag) == "false") or (noescape is not None and text(noescape) == "true"):
                    out.append(finding(self, src, call, Severity.MEDIUM, f"`{obj + '.' if obj else ''}{name}` turns HTML escaping off for every template.", self.FIX))
            else:
                flag = kwarg(call, "autoescape")
                if name in {"Environment", "Jinja2Templates"} and flag is not None and text(flag) == "False":
                    out.append(finding(self, src, call, Severity.MEDIUM, "Jinja2 Environment(autoescape=False) prints variables as raw HTML.", self.FIX))
                elif name in {"mark_safe", "Markup", "SafeString"}:
                    a = args(call)
                    if not a or taint.is_literal(a[0]):
                        continue
                    via = taint.tainted_by(a[0])
                    if via:
                        out.append(finding(self, src, call, Severity.HIGH,
                                           f"Untrusted input `{taint.root(via)}` is marked as safe HTML with `{name}` — XSS.",
                                           "Escape the value (django.utils.html.escape / markupsafe.escape) or build HTML with format_html().", taint, via))
        return out


class CsrfExempt(Rule):
    id = "ARX-CSRF"
    cwe = "CWE-352"
    title = "CSRF protection disabled"
    description = "A view that changes state accepts requests from any website, so a malicious page can act as the logged-in user."
    families = ("py", "js")

    def check(self, src, taint):
        out = []
        if src.family == "py":
            for node in src.nodes:
                if node.type == "decorator" and re.match(r"@\s*(?:csrf\.)?csrf_exempt\b|@\s*csrf\.exempt\b", text(node)):
                    out.append(finding(self, src, node, Severity.LOW, "`@csrf_exempt` switches CSRF protection off for this view.",
                                       "Remove @csrf_exempt; for APIs use token auth (Authorization header) instead of cookies."))
        else:
            for call in calls(src):
                obj, name = callee(call)
                if name in {"csurf", "csrf"} and kwarg(call, "ignoreMethods") is not None and "POST" in text(kwarg(call, "ignoreMethods")):
                    out.append(finding(self, src, call, Severity.LOW, "CSRF middleware ignores POST requests.", "Protect every state-changing method."))
        return out


class InsecurePermissions(Rule):
    id = "ARX-PERMS"
    cwe = "CWE-732"
    title = "World-writable file permissions"
    description = "Files are made writable by every user on the machine."
    MODE = re.compile(r"^(?:0o?777|0o?666|'777'|\"777\"|0o?776|511|438)$")

    def check(self, src, taint):
        out = []
        for call in calls(src):
            obj, name = callee(call)
            a = args(call)
            if name in {"chmod", "chmodSync", "fchmod", "fchmodSync"} and len(a) > 1 and self.MODE.match(text(a[1])):
                out.append(finding(self, src, call, Severity.LOW, f"`{name}` sets mode {text(a[1])} — any local user can modify the file.",
                                   "Use the narrowest mode that works (0o600 for secrets, 0o644 for public files, 0o755 for executables)."))
        return out


class TempFileRace(Rule):
    id = "ARX-TMPFILE"
    cwe = "CWE-377"
    title = "Insecure temporary file"
    description = "tempfile.mktemp() returns a name that another process can claim first."
    families = ("py",)

    def check(self, src, taint):
        return [finding(self, src, call, Severity.LOW, "tempfile.mktemp() is race-prone — another process can create the file first.",
                        "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp().")
                for call in calls(src) if callee(call) == ("tempfile", "mktemp")]


class FileInclusion(Rule):
    """PHP include / require with a path from the request. The check itself lives in polyglot.py."""

    id = "ARX-LFI"
    cwe = "CWE-98"
    title = "File inclusion (LFI / RFI)"
    description = "include / require loads a file chosen by the user, so an attacker runs any PHP file or reads server files."
    families = ("php",)

    def check(self, src, taint):
        return []
