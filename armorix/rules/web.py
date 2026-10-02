"""Web-layer rules: XSS, SSTI, path traversal, SSRF, open redirect, NoSQL injection."""

from __future__ import annotations

import re

from ..finding import Severity
from ..parsing import text, walk
from .base import CallSinkRule, Rule, args, callee, calls, finding, kwarg

XSS_SANITIZERS = ("DOMPurify", "sanitize", "escape", "xss(", "encode(", "bleach")
RES = ("res", "response", "reply")
FS_OBJECTS = ("fs", "fsp", "fs.promises", "promises", "fse", "fsPromises")
FS_CALLS = ("readFile", "readFileSync", "createReadStream", "writeFile", "writeFileSync", "appendFile",
            "appendFileSync", "unlink", "unlinkSync", "rm", "rmSync", "readdir", "readdirSync", "createWriteStream")
HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "request")

# A handler that declares a non-HTML content type cannot reflect script into a page.
NON_HTML_CT = re.compile(r"""(?i)['"]?content-type['"]?\s*[:=,]\s*['"](?:application|text)/"""
                         r"""(?:json|plain|csv|xml|octet-stream|javascript|event-stream)""")
HTML_CT = re.compile(r"""(?i)['"]?content-type['"]?\s*[:=,]\s*['"][^'"]*html""")
FUNCTIONS = {"function_declaration", "function_expression", "function", "arrow_function",
             "method_definition", "generator_function_declaration"}


class ReflectedXss(CallSinkRule):
    id = "ARX-XSS"
    cwe = "CWE-79"
    title = "Cross-site scripting (XSS)"
    description = "Untrusted input is written into HTML without escaping."
    sinks = {"js": {(r, m) for r in RES for m in ("send", "write", "end")}}
    sanitizers = XSS_SANITIZERS
    tainted = Severity.HIGH
    msg_tainted = "Untrusted input `{src}` is sent back as HTML — an attacker can run JavaScript in your users' browsers."
    fix = {"js": "Return JSON (res.json) or escape the value before building HTML; render views with an auto-escaping template engine."}

    def skip(self, src, call, arg):
        if arg.type in {"object", "array"}:
            return True  # res.send({...}) → JSON
        # res.writeHead(200, {"Content-Type": "application/json"}) … res.end(body): no HTML, no XSS.
        scope = call
        while scope is not None and scope.type not in FUNCTIONS:
            scope = scope.parent
        body = text(scope) if scope is not None else ""
        return bool(NON_HTML_CT.search(body)) and not HTML_CT.search(body)

    def check(self, src, taint):
        out = super().check(src, taint)
        if src.family == "js":
            out += self._dom(src, taint)
        else:
            out += self._py_return(src, taint)
        return out

    def _dom(self, src, taint):
        """innerHTML / outerHTML / document.write / insertAdjacentHTML / dangerouslySetInnerHTML."""
        out = []
        fix = "Use textContent, or sanitize with DOMPurify.sanitize() before inserting HTML."
        for node in src.nodes:
            value = None
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                if left is not None and left.type == "member_expression" and text(left.child_by_field_name("property")) in {"innerHTML", "outerHTML"}:
                    value = node.child_by_field_name("right")
            elif node.type == "call_expression":
                obj, name = callee(node)
                a = args(node)
                if (obj, name) in {("document", "write"), ("document", "writeln")} and a:
                    value = a[0]
                elif name == "insertAdjacentHTML" and len(a) > 1:
                    value = a[1]
            elif node.type == "jsx_attribute" and text(node.named_children[0]) == "dangerouslySetInnerHTML":
                value = node
            if value is None or taint.is_literal(value) or any(s in text(value) for s in XSS_SANITIZERS):
                continue
            if value.type == "call_expression" and all(taint.is_literal(a) for a in args(value)):
                continue  # __('Hide'), t('label') — translations of fixed strings
            if node.type == "jsx_attribute" and not any(n.type in {"identifier", "member_expression", "template_substitution"} for n in walk(value)):
                continue
            via = taint.tainted_by(value)
            if via:
                out.append(finding(self, src, node, Severity.HIGH,
                                   f"Untrusted input `{taint.root(via)}` is inserted as HTML (DOM XSS).", fix, taint, via))
            elif value.type not in {"number", "true", "false"}:
                out.append(finding(self, src, node, Severity.MEDIUM,
                                   "A non-constant value is inserted as raw HTML — safe only if it can never contain user data.", fix))
        return out

    def _py_return(self, src, taint):
        """Flask/Django view returning an f-string or concatenation of HTML with user input."""
        out = []
        for node in src.nodes:
            if node.type != "return_statement" or not node.named_children:
                continue
            value = node.named_children[0]
            if not taint.is_dynamic_string(value) or "<" not in taint.string_value(value):
                continue
            if any(s in text(value) for s in XSS_SANITIZERS):
                continue
            via = taint.tainted_by(value)
            if via:
                out.append(finding(self, src, node, Severity.HIGH,
                                   f"Untrusted input `{taint.root(via)}` is returned inside HTML without escaping.",
                                   "Render a template (Jinja2 auto-escapes) or wrap the value in markupsafe.escape().", taint, via))
        return out


class TemplateInjection(CallSinkRule):
    id = "ARX-SSTI"
    cwe = "CWE-1336"
    title = "Server-side template injection"
    description = "A template is compiled from untrusted input, giving code execution on the server."
    sinks = {"py": {(None, "render_template_string"), ("jinja2", "Template"), ("", "Template"), (None, "from_string")},
             "js": {(None, "compile"), ("ejs", "render"), ("pug", "render"), ("handlebars", "compile"), ("Handlebars", "compile")}}
    tainted = Severity.CRITICAL
    dynamic = Severity.HIGH
    msg_tainted = "Untrusted input `{src}` is compiled as a template — server-side code execution."
    msg_dynamic = "`{name}` compiles a template from a non-constant string."
    fix = {"py": "Keep templates in files (render_template) and pass user data as variables.",
           "js": "Compile only fixed template files and pass user data as render context."}

    def weak(self, taint, arg):
        return not taint.is_dynamic_string(arg)  # a template read from a file / setting is normal; one built from strings is not

    def matches(self, src, call):
        obj, name = callee(call)
        if src.family == "js" and name == "compile" and obj not in {"handlebars", "Handlebars", "ejs", "pug", "_"}:
            return False  # regex / webpack compile etc.
        return super().matches(src, call)


class PathTraversal(CallSinkRule):
    id = "ARX-PATH"
    cwe = "CWE-22"
    title = "Path traversal"
    description = "A file path is built from untrusted input, allowing ../ to escape the intended folder."
    sinks = {
        "js": {(o, m) for o in FS_OBJECTS for m in FS_CALLS} | {(r, m) for r in RES for m in ("sendFile", "download")},
        "py": {(None, "open"), (None, "send_file"), ("os", "remove"), ("os", "unlink"), ("shutil", "rmtree"),
               ("io", "open"), ("codecs", "open")},
    }
    sanitizers = ("basename", "secure_filename", "sanitize")
    # resolve + prefix check written inside the handler
    guards = (".startsWith(", ".startswith(", "is_relative_to(", "commonpath(", "path.relative(")
    tainted = Severity.HIGH
    msg_tainted = "Untrusted input `{src}` is used as a file path — `../` lets an attacker read or overwrite any file."
    fix = {"js": "Resolve the path, then check it stays inside the allowed folder (path.resolve + startsWith), or use path.basename().",
           "py": "Use werkzeug.utils.secure_filename / os.path.basename, or send_from_directory() with a fixed folder."}

    def matches(self, src, call):
        obj, name = callee(call)
        if src.family == "py" and name == "open" and obj not in {"", "io", "codecs"}:
            return False  # webbrowser.open, Image.open …
        return super().matches(src, call)

    def skip(self, src, call, arg):
        return kwarg(call, "root") is not None  # res.sendFile(name, { root }) is contained


class Ssrf(CallSinkRule):
    id = "ARX-SSRF"
    cwe = "CWE-918"
    title = "Server-side request forgery (SSRF)"
    description = "The server fetches a URL chosen by the user, reaching internal services or cloud metadata."
    sinks = {
        "js": {("", "fetch"), ("", "axios"), ("", "got"), ("", "needle")}
        | {(o, v) for o in ("axios", "got", "needle", "superagent", "http", "https") for v in HTTP_VERBS},
        "py": {(o, v) for o in ("requests", "httpx", "session", "client") for v in HTTP_VERBS}
        | {("urllib.request", "urlopen"), ("", "urlopen"), ("request", "urlopen")},
    }
    # host allow-list check written inside the handler
    guards = (re.compile(r"\.(?:includes|has)\(\s*[\w.]*(?:hostname|host)\s*\)|\b(?:hostname|netloc|host)\s+(?:not\s+)?in\s"),)
    tainted = Severity.HIGH
    msg_tainted = "The server makes a request to a URL built from `{src}` — an attacker can reach internal services or cloud metadata."
    fix = {"js": "Allow-list hosts (new URL(value).hostname) and block private IP ranges before fetching.",
           "py": "Allow-list hosts (urllib.parse.urlparse(value).hostname) and block private IP ranges before requesting."}


class OpenRedirect(CallSinkRule):
    id = "ARX-REDIRECT"
    cwe = "CWE-601"
    title = "Open redirect"
    description = "Users are redirected to a URL taken from the request, enabling phishing."
    sinks = {"js": {(r, "redirect") for r in RES}, "py": {("", "redirect"), ("flask", "redirect"), ("", "HttpResponseRedirect")}}
    tainted = Severity.MEDIUM
    sanitizers = ("url_for", "is_safe_url", "url_has_allowed_host_and_scheme")
    msg_tainted = "Redirect target comes from `{src}` — attackers can send victims to a phishing site via your domain."
    fix = {"js": "Redirect only to relative paths or an allow-list of URLs.",
           "py": "Validate with url_has_allowed_host_and_scheme() or redirect to url_for(...) routes only."}
    # "/pet/" + id stays on this host whatever id is; only a bare "/" + id could become "//evil.com".
    SAME_ORIGIN = re.compile(r"^/[^/\\]")

    def skip(self, src, call, arg):
        return bool(self.SAME_ORIGIN.match(self._literal_prefix(arg)))

    @staticmethod
    def _literal_prefix(node) -> str:
        """The fixed text the target starts with, for `"/a/" + x` and `` `/a/${x}` ``."""
        while node is not None:
            if node.type in {"string", "template_string"}:
                raw = text(node)
                head = raw[1:]
                for mark in ("${", "{"):
                    if mark in head:
                        head = head.split(mark, 1)[0]
                return head.rstrip("'\"`")
            if node.type in {"binary_expression", "binary_operator", "parenthesized_expression"}:
                node = node.child_by_field_name("left") or (node.named_children[0] if node.named_children else None)
                continue
            return ""
        return ""


class NoSqlInjection(Rule):
    id = "ARX-NOSQL"
    cwe = "CWE-943"
    title = "NoSQL injection"
    description = "Request data is used directly as a MongoDB query, so {$ne: null} style operators bypass checks."
    families = ("js",)
    METHODS = {"find", "findOne", "findOneAndUpdate", "findOneAndDelete", "updateOne", "updateMany",
               "deleteOne", "deleteMany", "countDocuments", "exists", "findById"}
    FIX = "Cast every field to the expected type (String(req.body.user)) or validate with a schema (zod / joi); never pass req.body as a query."

    def check(self, src, taint):
        out = []
        for call in calls(src):
            if callee(call)[1] not in self.METHODS:
                continue
            a = args(call)
            if not a:
                continue
            query = a[0]
            if query.type == "object":
                for pair in query.named_children:
                    if pair.type != "pair":
                        continue
                    key, value = text(pair.child_by_field_name("key")).strip("'\""), pair.child_by_field_name("value")
                    if key == "$where":
                        continue  # handled below, where the severity follows the taint
                    if value is not None and taint.is_source(value):
                        out.append(finding(self, src, call, Severity.HIGH,
                                           f"`{text(value)}` is used as a query value without type casting — an object like "
                                           '{"$ne": null} bypasses the check.', self.FIX))
                        break
            elif taint.is_source(query) or (query.type == "identifier" and taint.tainted_by(query)
                                            and taint.root(taint.tainted_by(query)) in {"req.body", "req.query"}):
                out.append(finding(self, src, call, Severity.HIGH,
                                   f"The whole request object `{text(query)}` is used as a database query.", self.FIX))
        # `$where` built anywhere (a query helper, a criteria function) — not only inline in find()
        reported = {f.line for f in out}
        for node in src.nodes:
            if node.type != "pair" or text(node.child_by_field_name("key")).strip("'\"") != "$where":
                continue
            value = node.child_by_field_name("value")
            if value is None or taint.is_literal(value) or value.type in {"function_expression", "arrow_function"} \
                    or node.start_point[0] + 1 in reported or taint.provably_safe(value):
                continue
            via = taint.tainted_by(value)
            out.append(finding(self, src, node, Severity.CRITICAL if via else Severity.HIGH,
                               f"`$where` runs JavaScript inside MongoDB with {'untrusted input `' + taint.root(via) + '`' if via else 'a string built at runtime'}.",
                               self.FIX, taint, via))
        return out

