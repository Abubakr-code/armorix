"""PHP, Go and Java: taint sources, sinks and the checks that tie them together.

The same taint engine as JS / Python (scopes, helper parameters, return values), fed with each language's
syntax and frameworks: PHP ($_GET, Laravel, CodeIgniter), Go (net/http, gin, echo, fiber, chi, gorilla/mux)
and Java (Servlets, Spring, JAX-RS). Findings reuse the rule ids of the JS / Python rules (ARX-SQLI, ARX-CMDI …),
so reports, translations, suppressions and baselines work the same way.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from tree_sitter import Node

from .finding import Finding, Severity
from .parsing import SourceFile, line_of, text, walk
from .rules import ALL_RULES
from .rules.base import finding
from .taint import Analyzer, Origin, Var

POLY_FAMILIES = {"php", "go", "java"}

SOURCES = {
    "php": re.compile(
        r"^\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b"
        r"|^\$_SERVER\[\s*['\"](?:REQUEST_URI|PHP_SELF|QUERY_STRING|PATH_INFO|HTTP_\w+)['\"]"
        r"|^\$(?:request|req)->(?:input|get|query|post|all|header|cookie|file|route|json|string|only|except|getContent)\b"
        r"|^request\(\s*['\"]|^request\(\)->(?:input|get|query|post|all|header|cookie|file|route|json)\b"
        r"|^\\?(?:Input|Request)::(?:get|input|all|query|post)\b"
        r"|^\$this->request->(?:getVar|getPost|getGet|getJSON|getRawInput|input|post|get)\b"
        r"|^file_get_contents\(\s*['\"]php://input|^\$argv\b"
    ),
    "go": re.compile(
        r"^(?:r|req|request|httpReq)\.(?:URL\.(?:Query\(\)(?:\.Get)?|RawQuery|Path)|FormValue|PostFormValue|Form|PostForm|MultipartForm"
        r"|Header\.Get|Header|Body|Cookie|Cookies|FormFile|RequestURI|Referer|UserAgent)\b"
        r"|^(?:c|ctx)\.(?:Query|DefaultQuery|QueryArray|QueryMap|Param|Params|PostForm|DefaultPostForm|PostFormArray|FormValue|QueryParam"
        r"|QueryParams|FormParams|PathParam|GetHeader|Cookie|Body|FormFile|GetRawData)\b"
        r"|^(?:c|ctx)\.Request(?:\(\))?\.(?:URL|Form|PostForm|Body|Header)\b"
        r"|^mux\.Vars\(|^chi\.URLParam\(|^os\.Args\b|^flag\.Args?\("
    ),
    "java": re.compile(
        r"^(?:req|request|httpRequest|servletRequest|httpServletRequest)\.get(?:Parameter\w*|Header\w*|QueryString|Cookies|InputStream"
        r"|Reader|RequestURI|RequestURL|PathInfo|Part\w*)\("
        r"|^(?:ctx|context)\.(?:queryParam|pathParam|formParam|body|header)\("
    ),
}
SOURCE_TYPES = {
    "php": {"variable_name", "subscript_expression", "member_call_expression", "function_call_expression", "scoped_call_expression"},
    "go": {"call_expression", "selector_expression", "index_expression"},
    "java": {"method_invocation"},
}
ASSIGN = {
    "php": {"assignment_expression": ("left", "right"), "augmented_assignment_expression": ("left", "right")},
    "go": {"short_var_declaration": ("left", "right"), "assignment_statement": ("left", "right"), "var_spec": ("name", "value"),
           "range_clause": ("left", "right")},
    "java": {"variable_declarator": ("name", "value"), "assignment_expression": ("left", "right"), "enhanced_for_statement": ("name", "value")},
}
DECLARES = {"php": {"assignment_expression", "augmented_assignment_expression"},  # PHP functions never see outer variables
            "go": {"short_var_declaration", "var_spec", "range_clause"}, "java": {"variable_declarator", "enhanced_for_statement"}}
NAMES = {"php": {"variable_name"}, "go": {"identifier"}, "java": {"identifier"}}
FUNCTIONS = {
    "php": {"function_definition", "method_declaration", "anonymous_function", "anonymous_function_creation_expression", "arrow_function"},
    "go": {"function_declaration", "method_declaration", "func_literal"},
    "java": {"method_declaration", "constructor_declaration", "lambda_expression"},
}
RECEIVERS = {"php": {"", "$this", "self", "static"}, "go": {""}, "java": {"", "this"}}
CALLS = {"function_call_expression", "member_call_expression", "scoped_call_expression", "nullsafe_member_call_expression",
         "object_creation_expression", "method_invocation", "call_expression"}
SAFE = {"intval", "floatval", "boolval", "abs", "count", "strlen", "Atoi", "ParseInt", "ParseUint", "ParseFloat", "ParseBool", "Itoa",
        "parseInt", "parseLong", "parseDouble", "parseBoolean", "fromString", "ctype_digit", "is_numeric", "uuid.Parse",
        # PHP / WordPress escaping and sanitizing helpers: their output is safe to print or to use as a value
        "absint", "esc_html", "esc_attr", "esc_url", "esc_url_raw", "esc_js", "esc_textarea", "esc_sql", "esc_html__", "esc_attr__",
        "esc_html_e", "esc_attr_e", "sanitize_key", "sanitize_title", "sanitize_text_field", "sanitize_textarea_field", "sanitize_email",
        "sanitize_file_name", "sanitize_user", "sanitize_html_class", "sanitize_mime_type", "sanitize_sql_orderby", "wp_kses", "wp_kses_post",
        "wp_kses_data", "number_format", "number_format_i18n", "htmlspecialchars", "htmlentities", "md5", "sha1", "hash", "password_hash",
        "urlencode", "rawurlencode", "http_build_query", "json_encode", "wp_json_encode", "filter_var", "filter_input", "e", "__", "_e",
        "html.EscapeString", "HtmlUtils.htmlEscape", "escapeHtml", "encodeForHTML",
        # checks that return booleans / positions, not the input
        # SQL escaping: the value can still be printed unsafely, but it no longer changes a quoted SQL literal
        "mysqli_real_escape_string", "mysql_real_escape_string", "real_escape_string", "pg_escape_string", "pg_escape_literal",
        "sqlite_escape_string", "addslashes",
        "isset", "empty", "is_array", "is_string", "is_null", "in_array", "array_key_exists", "preg_match", "strpos", "stripos", "strcmp",
        "hash_equals", "wp_validate_redirect", "wp_sanitize_redirect", "current_user_can", "wp_verify_nonce", "check_admin_referer"}
NUMERIC_WRAPPERS = {"Integer", "Long", "Double", "Float", "Short", "Boolean", "UUID", "strconv"}
JAVA_REQUEST_ANNOTATIONS = {"RequestParam", "PathVariable", "RequestBody", "RequestHeader", "CookieValue", "ModelAttribute", "RequestPart",
                            "QueryParam", "PathParam", "FormParam", "HeaderParam", "CookieParam", "MatrixParam"}
JAVA_SAFE_TYPES = re.compile(r"^(?:int|long|short|byte|double|float|boolean|Integer|Long|Short|Double|Float|Boolean|UUID|LocalDate|LocalDateTime)$")
GO_BIND = re.compile(r"^(?:ShouldBind\w*|Bind\w*|BodyParser|QueryParser|ParamsParser|Decode|Unmarshal)$")


def call_parts(node: Node) -> tuple[str, str, list[Node]]:
    """(receiver, name, arguments) of any PHP / Go / Java call node."""
    t = node.type
    obj, name = "", ""
    if t == "function_call_expression":
        name = text(node.child_by_field_name("function")).lstrip("\\")
    elif t in {"member_call_expression", "nullsafe_member_call_expression"}:
        obj, name = text(node.child_by_field_name("object")), text(node.child_by_field_name("name"))
    elif t == "scoped_call_expression":
        obj, name = text(node.child_by_field_name("scope")).lstrip("\\"), text(node.child_by_field_name("name"))
    elif t == "method_invocation":
        obj, name = text(node.child_by_field_name("object")), text(node.child_by_field_name("name"))
    elif t == "object_creation_expression":
        type_node = node.child_by_field_name("type") or next((c for c in node.named_children if c.type in {"name", "qualified_name"}), None)
        name = text(type_node).lstrip("\\").split("<")[0].split(".")[-1]
    elif t == "call_expression":
        fn = node.child_by_field_name("function")
        if fn is not None and fn.type == "selector_expression":
            obj, name = text(fn.child_by_field_name("operand")), text(fn.child_by_field_name("field"))
        else:
            name = text(fn)
    box = node.child_by_field_name("arguments") or next((c for c in node.named_children if c.type in {"arguments", "argument_list"}), None)
    args = []
    for a in box.named_children if box is not None else []:
        if a.type == "comment":
            continue
        if a.type == "argument":  # PHP wraps every argument; named arguments keep their value last
            inner = [c for c in a.named_children if c.type != "name"] or a.named_children
            args.append(inner[-1] if inner else a)
        else:
            args.append(a)
    return obj, name, args


class PolyAnalyzer(Analyzer):
    def __init__(self, src: SourceFile):
        fam = src.family
        self.name_types = NAMES[fam]
        self.function_types = FUNCTIONS[fam]
        self.declares = DECLARES[fam]
        self.self_receivers = RECEIVERS[fam]
        self.source_types = SOURCE_TYPES[fam]
        self.call_types = CALLS
        super().__init__(src)

    def source_pattern(self):
        return SOURCES[self.family]

    def assignment_fields(self):
        return ASSIGN[self.family]

    def _callee_name(self, call):
        obj, name, _ = call_parts(call)
        return obj, name

    def call_arguments(self, call):
        return call_parts(call)[2], {}

    def _safe_cast(self, node):
        if node.type == "cast_expression":
            return bool(re.search(r"\b(int|integer|float|double|bool|boolean|long|short)\b", text(node.child_by_field_name("type") or node)))
        if node.type not in CALLS:
            return False
        obj, name, _ = call_parts(node)
        return name in SAFE or (name in {"valueOf", "parseInt", "parseLong", "fromString"} and obj in NUMERIC_WRAPPERS) or f"{obj}.{name}" in SAFE

    # strings
    def is_literal(self, node):
        if node is None:
            return False
        t = node.type
        if t in {"string", "nowdoc", "interpreted_string_literal", "raw_string_literal", "string_literal", "text_block"}:
            return True
        if t in {"encapsed_string", "heredoc"}:
            return all(c.type in {"string_content", "string_value", "escape_sequence", "heredoc_start", "heredoc_end", "heredoc_body"}
                       for c in node.named_children) and not any(c.type == "variable_name" for c in walk(node))
        return False

    def _operator(self, node) -> str:
        op = node.child_by_field_name("operator")
        if op is not None:
            return text(op)
        return next((text(c) for c in node.children if not c.is_named), "")

    def is_dynamic_string(self, node):
        if node is None:
            return False
        t = node.type
        if t in {"encapsed_string", "heredoc", "shell_command_expression"}:
            return not self.is_literal(node)
        if t in self.name_types:
            return self._lookup(self.dynamic, text(node), node) is not None
        if t in {"parenthesized_expression"}:
            return any(self.is_dynamic_string(c) for c in node.named_children)
        if t == "binary_expression":
            op = self._operator(node)
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if op in {".", "+"}:
                return any(self._stringy(side) for side in (left, right)) and not (self.is_literal(left) and self.is_literal(right))
        if t in CALLS:
            obj, name, args = call_parts(node)
            if name in {"sprintf", "vsprintf", "implode", "str_replace", "Sprintf", "Join", "format", "formatted", "concat", "join"}:
                return any(self._stringy(a) for a in args) or self._stringy(node.child_by_field_name("object"))
        return False

    def _stringy(self, node):
        return node is not None and (self.is_literal(node) or self.is_dynamic_string(node))

    # frameworks
    def _framework_sources(self):
        controller = "Controller" in self.src.path.name or "/Controllers/" in self.src.rel
        for fns in self.functions.values():
            for fn in fns:
                if self.family == "java":
                    self._spring_params(fn)
                elif self.family == "php" and controller and fn.type == "method_declaration":
                    self._laravel_params(fn)

    def _spring_params(self, fn):
        box = fn.child_by_field_name("parameters")
        for p in box.named_children if box is not None else []:
            mods = next((c for c in p.named_children if c.type == "modifiers"), None)
            names = {text(a.child_by_field_name("name")) for a in (mods.named_children if mods else []) if "annotation" in a.type}
            if not names & JAVA_REQUEST_ANNOTATIONS:
                continue
            ptype = text(p.child_by_field_name("type"))
            if JAVA_SAFE_TYPES.match(ptype):
                continue
            pname = text(p.child_by_field_name("name"))
            self._taint((fn.id, pname), Origin(line_of(p), self.src.line(line_of(p)), source=f"@{sorted(names & JAVA_REQUEST_ANNOTATIONS)[0]} {pname}"))

    def _laravel_params(self, fn):
        """Route parameters of controller actions: public function show($id) → $id comes from the URL."""
        mods = text(fn)[:60]
        if "public" not in mods.split("function")[0]:
            return
        box = fn.child_by_field_name("parameters")
        for p in box.named_children if box is not None else []:
            ptype = text(p.child_by_field_name("type"))
            if ptype and ptype not in {"string", "?string", "mixed"}:
                continue  # Request $request, int $id, Model $user (route-model binding) are not raw strings
            name = p.child_by_field_name("name")
            if name is not None:
                self._taint((fn.id, text(name)), Origin(line_of(p), self.src.line(line_of(p)), source=f"route parameter {text(name)}"))

    def _call_sites(self):
        changed = super()._call_sites()
        if self.family == "go":  # json.NewDecoder(r.Body).Decode(&v), c.ShouldBindJSON(&v), json.Unmarshal(body, &v)
            for call in self.src.call_nodes:
                obj, name, args = call_parts(call)
                if not GO_BIND.match(name):
                    continue
                from_request = name.startswith(("ShouldBind", "Bind", "BodyParser", "QueryParser", "ParamsParser")) and obj in {"c", "ctx"}
                via = self.tainted_by(call.child_by_field_name("function")) or next((v for v in (self.tainted_by(a) for a in args if not text(a).startswith("&")) if v), None)
                if not (from_request or via):
                    continue
                for a in args:
                    if a.type == "unary_expression" and text(a).startswith("&"):
                        target = next((n for n in walk(a) if n.type == "identifier"), None)
                        if target is not None:
                            key = self._target_key(text(target), target, False)
                            origin = self._origin(call, via) if via else Origin(line_of(call), self.src.line(line_of(call)), source=text(call))
                            changed |= self._taint(key, origin)
        return changed


# ── sinks ───────────────────────────────────────────────────────
@dataclass(frozen=True)
class Sink:
    rule: str
    name: str  # regex, full match on the called name
    obj: str | None = None  # None: any receiver · "": plain function call · otherwise a regex on the receiver text
    arg: int = 0  # the argument that carries the payload (-1: the last one, 99: any)
    sql: bool = False  # an untainted dynamic string counts only when it looks like SQL
    dynamic: bool = True  # report non-constant values at lower severity


SQL = re.compile(r"\b(select\b[\s\S]*\bfrom|insert\s+into|update\s+[\w.`\"\[\]]+\s+set|delete\s+from|drop\s+table|where\b)", re.IGNORECASE)
DB_RECEIVER = r"(?i).*\b(db|tx|conn|con|connection|database|sqlx|pool|stmt|statement|jdbc\w*|jdbcTemplate|template|em|entityManager|session|pdo|mysqli|dbh|wpdb|query|builder|repo\w*)\b.*"

SINKS: dict[str, list[Sink]] = {
    "php": [
        Sink("ARX-SQLI", r"mysqli_query|mysqli_real_query|mysqli_multi_query", "", arg=1, sql=True),
        Sink("ARX-SQLI", r"mysql_query|pg_query|pg_send_query|sqlite_query|mssql_query|odbc_exec|db2_exec|oci_parse", "", arg=-1, sql=True),
        Sink("ARX-SQLI", r"query|exec|prepare|multi_query|real_query|get_results|get_row|get_var|get_col|raw|whereRaw|orWhereRaw|havingRaw|"
             r"orderByRaw|selectRaw|groupByRaw|fromRaw|unprepared", DB_RECEIVER, sql=True),
        Sink("ARX-SQLI", r"select|insert|update|delete|statement|unprepared|raw", r"\\?(?:Illuminate\\Support\\Facades\\)?DB", sql=True),
        Sink("ARX-CMDI", r"system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec", ""),
        Sink("ARX-EVAL", r"eval|create_function|assert", "", arg=-1),
        Sink("ARX-PATH", r"file_get_contents|fopen|readfile|file|unlink|file_put_contents|fpassthru|copy|rename|rmdir|opendir|scandir|"
             r"highlight_file|show_source|parse_ini_file|simplexml_load_file|glob", "", dynamic=False),
        Sink("ARX-PATH", r"move_uploaded_file", "", arg=1, dynamic=False),
        Sink("ARX-SSRF", r"curl_init|fsockopen|get_headers|stream_socket_client", "", dynamic=False),
        Sink("ARX-REDIRECT", r"redirect", "", dynamic=False),
        Sink("ARX-REDIRECT", r"to|away", r"redirect\(\s*\)|\\?Redirect", dynamic=False),
        Sink("ARX-DESER", r"unserialize|yaml_parse", "", dynamic=False),
        Sink("ARX-SSTI", r"createTemplate", r".+", dynamic=False),
        Sink("ARX-SSTI", r"render", r"\\?Blade", dynamic=False),
    ],
    "go": [
        Sink("ARX-SQLI", r"Query|QueryRow|Exec|Prepare|Queryx|QueryRowx|MustExec|NamedExec|NamedQuery|Raw|Where", DB_RECEIVER, sql=True),
        Sink("ARX-SQLI", r"QueryContext|QueryRowContext|ExecContext|PrepareContext|QueryxContext|Select|Get", DB_RECEIVER, arg=1, sql=True),
        Sink("ARX-PATH", r"Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll|ReadDir|Stat|Lstat", r"os|ioutil", dynamic=False),
        Sink("ARX-PATH", r"ServeFile", r"http", arg=2, dynamic=False),
        Sink("ARX-PATH", r"File|FileAttachment|SendFile|Attachment", r"c|ctx", dynamic=False),
        Sink("ARX-SSRF", r"Get|Post|Head|PostForm", r"http|client|httpClient|\w*[Cc]lient", dynamic=False),
        Sink("ARX-SSRF", r"NewRequest", r"http", arg=1, dynamic=False),
        Sink("ARX-SSRF", r"NewRequestWithContext", r"http", arg=2, dynamic=False),
        Sink("ARX-XSS", r"HTML|JS|URL|HTMLAttr|CSS", r"template"),
        Sink("ARX-XSS", r"WriteString", r"io", arg=1, dynamic=False),
        Sink("ARX-XSS", r"Write", r"w|rw|writer|resp|res", dynamic=False),
        Sink("ARX-REDIRECT", r"Redirect", r"http", arg=2, dynamic=False),
        Sink("ARX-REDIRECT", r"Redirect", r"c|ctx", arg=1, dynamic=False),
        Sink("ARX-SSTI", r"Parse", r".*template\.New\(.*", dynamic=False),
    ],
    "java": [
        Sink("ARX-SQLI", r"executeQuery|execute|executeUpdate|executeLargeUpdate|addBatch|prepareStatement|prepareCall|nativeSQL|"
             r"createQuery|createNativeQuery|createSQLQuery|query|queryForObject|queryForList|queryForMap|queryForRowSet|queryForLong|"
             r"queryForInt|update|batchUpdate", DB_RECEIVER, sql=True),
        Sink("ARX-CMDI", r"exec", r".*(?:getRuntime\(\)|runtime|rt)"),
        Sink("ARX-PATH", r"File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter", "", dynamic=False),
        Sink("ARX-PATH", r"get|of", r"Paths|Path", arg=99, dynamic=False),
        Sink("ARX-SSRF", r"URL", "", dynamic=False),
        Sink("ARX-SSRF", r"create", r"URI", dynamic=False),
        Sink("ARX-SSRF", r"getForObject|getForEntity|postForObject|postForEntity|exchange|headForHeaders", r"(?i).*rest.*", dynamic=False),
        Sink("ARX-XSS", r"write|print|println|append|printf", r".*getWriter\(\)|out|writer|pw", dynamic=False),
        Sink("ARX-REDIRECT", r"sendRedirect", None, dynamic=False),
        Sink("ARX-REDIRECT", r"RedirectView", "", dynamic=False),
        Sink("ARX-DESER", r"ObjectInputStream|XMLDecoder", "", dynamic=False),
        Sink("ARX-DESER", r"load|loadAll", r".*Yaml.*|yaml", dynamic=False),
        Sink("ARX-EVAL", r"eval", r"(?i).*engine.*", dynamic=False),
        Sink("ARX-EVAL", r"parseExpression", None, dynamic=False),
    ],
}

def _words(*names: str) -> re.Pattern:
    return re.compile(r"(?<![\w$])(?:" + "|".join(re.escape(n) for n in names) + r")\s*\(")


SANITIZERS = {
    "ARX-XSS": _words("htmlspecialchars", "htmlentities", "e", "esc_html", "esc_attr", "strip_tags", "intval", "html.EscapeString",
                      "template.HTMLEscapeString", "HTMLEscapeString", "HtmlUtils.htmlEscape", "escapeHtml", "escapeHtml4", "Encode.forHtml",
                      "sanitize", "Sanitize", "json_encode", "json.Marshal"),
    "ARX-PATH": _words("basename", "filepath.Base", "path.Base", "FilenameUtils.getName", "realpath", "getFileName"),
    "ARX-CMDI": _words("escapeshellarg", "escapeshellcmd"),
    "ARX-SQLI": _words("prepare", "esc_sql", "mysqli_real_escape_string", "real_escape_string", "pg_escape_string", "pg_escape_literal", "quote"),
    "ARX-REDIRECT": _words("url_for", "route", "isSafe", "is_safe", "isAllowed", "allowed"),
}


def _sanitized(rule: str, node: Node) -> bool:
    pattern = SANITIZERS.get(rule)
    return bool(pattern and pattern.search(text(node)))


GUARDS = {"ARX-PATH": re.compile(r"startsWith\(|strpos\(\s*realpath|str_starts_with\(|HasPrefix\(|filepath\.Rel\(|validate_file\("),
          "ARX-LFI": re.compile(r"validate_file\(|in_array\(|array_key_exists\(|realpath\(|basename\(|preg_match\("),
          "ARX-CMDI": re.compile(r"escapeshellarg\(|escapeshellcmd\("),
          "ARX-SSRF": re.compile(r"(?i)allow(?:ed)?_?(?:hosts|list)|whitelist|allowlist|\.Host\s*(?:==|!=)|getHost\(\)\s*\.equals|parse_url\(.*host")}

IMPACT = {
    "ARX-SQLI": ("is concatenated into a SQL query — an attacker can read or rewrite the database.", "SQL query is assembled from strings."),
    "ARX-CMDI": ("reaches a shell command — an attacker can run any command on the server.", "a shell command is built from a non-constant string."),
    "ARX-EVAL": ("is executed as code — remote code execution.", "a non-constant string is executed as code."),
    "ARX-PATH": ("is used as a file path — `../` lets an attacker read or overwrite any file.", ""),
    "ARX-SSRF": ("becomes the URL the server requests — internal services and cloud metadata are reachable.", ""),
    "ARX-XSS": ("is written into the HTML response without escaping — cross-site scripting.", "a non-constant value is written as raw HTML."),
    "ARX-REDIRECT": ("decides where the user is redirected — phishing through your domain.", ""),
    "ARX-DESER": ("is deserialized — attacker-controlled objects lead to code execution.", ""),
    "ARX-SSTI": ("is compiled as a template — server-side code execution.", ""),
    "ARX-LFI": ("chooses the file that is included and executed — local / remote file inclusion.", "a file is included from a non-constant path."),
}
FIXES = {
    ("ARX-SQLI", "php"): "Use a prepared statement with the driver the code already uses: mysqli_prepare($conn, '… WHERE id = ?') + "
                         "mysqli_stmt_bind_param() / mysqli_stmt_execute(); with PDO $pdo->prepare('… = ?')->execute([$id]); "
                         "Laravel: DB::select('… = ?', [$id]).",
    ("ARX-SQLI", "go"): 'Pass values as arguments: db.Query("SELECT … WHERE id = $1", id) — never fmt.Sprintf or + into SQL.',
    ("ARX-SQLI", "java"): 'Use PreparedStatement with ? placeholders (or JPA :named parameters): ps = conn.prepareStatement("… WHERE id = ?"); ps.setString(1, id).',
    ("ARX-CMDI", "php"): "Avoid the shell: validate against an allow-list and wrap every value in escapeshellarg().",
    ("ARX-CMDI", "go"): 'Call the program directly with separate arguments: exec.Command("ping", "-c", "1", host) — never "sh", "-c".',
    ("ARX-CMDI", "java"): 'Use ProcessBuilder with a fixed program and separate arguments: new ProcessBuilder("ping", "-c", "1", host); allow-list the value.',
    ("ARX-EVAL", "php"): "Never eval user input; map allowed actions to functions.",
    ("ARX-EVAL", "java"): "Never evaluate user-supplied expressions; use a SimpleEvaluationContext or map allowed actions to code.",
    ("ARX-PATH", "php"): "Use basename() and check realpath() stays inside the upload folder before touching the file.",
    ("ARX-PATH", "go"): "Use filepath.Base() or check filepath.Rel / strings.HasPrefix against the allowed folder after filepath.Clean.",
    ("ARX-PATH", "java"): "Normalize the path and check it startsWith() the allowed folder, or keep only FilenameUtils.getName().",
    ("ARX-SSRF", "php"): "Allow-list hosts (parse_url($url, PHP_URL_HOST)) and block private IP ranges before requesting.",
    ("ARX-SSRF", "go"): "Allow-list hosts (url.Parse(u).Hostname()) and block private IP ranges (a custom Dialer) before requesting.",
    ("ARX-SSRF", "java"): "Allow-list hosts (new URI(u).getHost()) and block private IP ranges before requesting.",
    ("ARX-XSS", "php"): "Escape output: echo htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); in Blade use {{ }} not {!! !!}.",
    ("ARX-XSS", "go"): "Render with html/template (it escapes), never wrap user data in template.HTML / write it raw to the ResponseWriter.",
    ("ARX-XSS", "java"): "Escape with HtmlUtils.htmlEscape / OWASP Encoder, or render through a template engine that escapes (Thymeleaf th:text).",
    ("ARX-REDIRECT", "php"): "Redirect only to relative paths or named routes (redirect()->route('home')).",
    ("ARX-REDIRECT", "go"): "Redirect only to relative paths or an allow-list of URLs.",
    ("ARX-REDIRECT", "java"): "Redirect only to relative paths or an allow-list of URLs.",
    ("ARX-DESER", "php"): "Use json_decode for untrusted data; if you must unserialize, pass ['allowed_classes' => false].",
    ("ARX-DESER", "java"): "Never deserialize untrusted bytes with ObjectInputStream / XMLDecoder; use JSON with explicit types (or an ObjectInputFilter).",
    ("ARX-SSTI", "php"): "Render template files only and pass user data as variables.",
    ("ARX-SSTI", "go"): "Parse templates from files at startup; pass user data only as template data.",
    ("ARX-LFI", "php"): "Include only fixed files: map the user's choice to an allow-list (['home' => 'home.php']) instead of building the path.",
}
RULES = {r.id: r for r in ALL_RULES}

# A tainted value that an enclosing (or earlier, bail-out) `if` validates is not reported: is_numeric, allow-lists, regexes …
VALIDATOR = re.compile(r"is_numeric\(|is_int\(|ctype_digit\(|ctype_alnum\(|filter_var\(|preg_match\(|in_array\(|"
                       r"===?\s*['\"]|['\"]\s*===?|\.matches\(|Pattern\.matches|MatchString\(|\.Match\(|strconv\.Atoi|net\.ParseIP\(|"
                       r"InetAddress|isValid\w*\(|validate\w*\(")
VALIDATED_RULES = {"ARX-SQLI", "ARX-CMDI", "ARX-PATH", "ARX-LFI", "ARX-SSRF", "ARX-REDIRECT", "ARX-EVAL", "ARX-XSS"}
BAIL = re.compile(r"\b(?:exit|die|return|throw|break|continue|panic)\b|http\.Error\(")


def _names(taint, via) -> set[str]:
    """The tainted variable and every variable it was derived from."""
    names, key, seen = set(), getattr(via, "key", None), set()
    while key is not None and key in taint.tainted and key not in seen:
        seen.add(key)
        names.add(str(key[1]))
        key = taint.tainted[key].via
    return {n for n in names if n and not n.startswith("<")}


def _reaching_names(taint, names: set[str], at: Node) -> set[str]:
    """Variables the latest assignment (before `at`) of each name was built from: `$t = $octet[0] . '.' . $octet[1]` → $octet."""
    out = set()
    for key, defs in getattr(taint, "_defs", {}).items():
        if str(key[1]) not in names:
            continue
        prior = [d for d in defs if d[0] < at.start_byte and (d[1] is None or d[1].start_byte <= at.start_byte < d[1].end_byte)]
        if prior:
            out |= {text(n) for n in walk(prior[-1][2]) if n.type in taint.name_types and not text(n).startswith(("$_", "$GLOBALS"))}
    return out


def _validated(node: Node, taint, via) -> bool:
    names = _names(taint, via)
    if not names:
        return False
    names |= _reaching_names(taint, names, node)

    def checks(cond: Node | None) -> bool:
        t = text(cond)
        return bool(cond is not None and VALIDATOR.search(t) and any(re.search(rf"(?<![\w$]){re.escape(n)}(?!\w)", t) for n in names))

    cur = node.parent
    while cur is not None and cur.type not in taint.function_types:
        if cur.type == "if_statement" and checks(cur.child_by_field_name("condition")):
            return True  # the sink sits inside `if (is_numeric($x)) { … }`
        parent = cur.parent
        if parent is not None:  # an earlier `if (!valid($x)) { exit; }` in the same block
            for sib in parent.named_children:
                if sib.start_byte >= cur.start_byte:
                    break
                if sib.type == "if_statement" and checks(sib.child_by_field_name("condition")) and BAIL.search(text(sib)):
                    return True
        cur = parent
    return False


def _pick(args: list[Node], index: int) -> list[Node]:
    if not args:
        return []
    if index == 99:
        return args
    if index == -1:
        return [args[-1]]
    return [args[index]] if index < len(args) else []


def _matches(sink: Sink, obj: str, name: str) -> bool:
    if not re.fullmatch(sink.name, name):
        return False
    if sink.obj is None:
        return True
    if sink.obj == "":
        return obj == ""
    return bool(obj) and re.fullmatch(sink.obj, obj) is not None


SCHEMA = re.compile(r"(?i)^(?:\$wpdb(?:->\w+)?|\$this->(?:\w*(?:table|prefix|tbl|column)\w*)|\$\w*(?:table|prefix|tbl|schema|column|col_name)\w*"
                    r"|\$wpdb->get_blog_prefix.*|\w*(?:table|prefix|column)\w*)$")


def _schema_only(taint, arg: Node) -> bool:
    """Dynamic SQL whose only variable parts are table names / prefixes ($wpdb->posts, $this->table) — not a value an attacker sets."""
    expr = arg
    if arg.type in taint.name_types:
        key = taint._lookup(taint.dynamic, text(arg), arg)
        expr = taint.dynamic.get(key, arg) if key else arg
    parts = []
    for n in walk(expr):
        if n.type in {"variable_name", "identifier"} and n.parent is not None and n.parent.type not in {"member_access_expression"}:
            parts.append(text(n))
        elif n.type in {"member_access_expression", "field_access", "selector_expression"}:
            parts.append(text(n))
    values = [p for p in parts if not SCHEMA.match(p)]
    return bool(parts) and not values


def _guarded(node: Node, rule: str, types: set[str]) -> bool:
    """A validation call in the enclosing function (or the whole script for top-level PHP code)."""
    guard = GUARDS.get(rule)
    if guard is None:
        return False
    cur = node.parent
    while cur is not None and cur.type not in types:
        if cur.parent is None:
            break
        cur = cur.parent
    return bool(guard.search(text(cur))) if cur is not None else False


def _report(src, taint, node, rule_id, name, via, dynamic_msg=None, severity=None) -> Finding:
    rule = RULES[rule_id]
    impact_t, impact_d = IMPACT.get(rule_id, ("", ""))
    fix = FIXES.get((rule_id, src.family), "")
    if via and rule_id in VALIDATED_RULES and _validated(node, taint, via):
        return None
    if via:
        sev = severity or (Severity.CRITICAL if rule_id in {"ARX-SQLI", "ARX-CMDI", "ARX-EVAL", "ARX-DESER", "ARX-SSTI", "ARX-LFI"}
                           else Severity.MEDIUM if rule_id == "ARX-REDIRECT" else Severity.HIGH)
        return finding(rule, src, node, sev, f"Untrusted input `{taint.root(via)}` {impact_t}", fix, taint, via)
    sev = severity or (Severity.MEDIUM if rule_id in {"ARX-SQLI", "ARX-XSS", "ARX-LFI"} else Severity.HIGH)
    return finding(rule, src, node, sev, dynamic_msg or f"`{name}`: {impact_d}", fix)


def check(src: SourceFile, taint: PolyAnalyzer, disabled: frozenset[str] = frozenset()) -> list[Finding]:
    fam = src.family
    out: list[Finding] = []
    seen = set()

    def add(f: Finding | None):
        if f is not None and f.rule_id not in disabled and f.key not in seen:
            seen.add(f.key)
            out.append(f)

    for call in src.call_nodes:
        obj, name, args = call_parts(call)
        if not name:
            continue
        for sink in SINKS[fam]:
            if not _matches(sink, obj, name):
                continue
            for arg in _pick(args, sink.arg):
                if taint.is_literal(arg) or _sanitized(sink.rule, arg) or (arg.type in taint.name_types and SANITIZERS.get(sink.rule)
                                                                             and SANITIZERS[sink.rule].search(taint.string_value(arg))):
                    continue
                if _guarded(call, sink.rule, taint.function_types):
                    continue
                via = taint.tainted_by(arg)
                if via:
                    add(_report(src, taint, call, sink.rule, name, via))
                    break
                if sink.dynamic and taint.is_dynamic_string(arg) and (not sink.sql or SQL.search(taint.string_value(arg))) \
                        and not (sink.sql and _schema_only(taint, arg)):
                    add(_report(src, taint, call, sink.rule, name, None))
                    break
            break  # one sink per call
        add(_special_call(src, taint, call, obj, name, args))

    for node in src.nodes:
        add(_special_node(src, taint, node))
    out.extend(_file_checks(src, disabled, seen))
    return out


def _special_call(src, taint, call, obj, name, args) -> Finding | None:
    fam = src.family
    if fam == "go" and name in {"Command", "CommandContext"} and obj == "exec":
        rest = args[1:] if name == "CommandContext" else args
        if not rest:
            return None
        prog = text(rest[0]).strip('"`')
        payload = rest[2] if prog.split("/")[-1] in {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"} and len(rest) > 2 else rest[0]
        via = taint.tainted_by(payload)
        if via:
            return _report(src, taint, call, "ARX-CMDI", name, via)
        if payload is not rest[0] and taint.is_dynamic_string(payload):
            return _report(src, taint, call, "ARX-CMDI", name, None)
    if fam == "java" and name == "ProcessBuilder":
        via = next((v for v in (taint.tainted_by(a) for a in args) if v), None)
        if via:
            return _report(src, taint, call, "ARX-CMDI", name, via)
    if fam == "php" and name == "header" and args and re.match(r"""^["']\s*Location\s*:""", text(args[0]), re.IGNORECASE):
        via = taint.tainted_by(args[0])
        if via and not _sanitized("ARX-REDIRECT", args[0]):
            return _report(src, taint, call, "ARX-REDIRECT", name, via)
    if fam == "php" and name == "curl_setopt" and len(args) > 2:
        opt = text(args[1])
        if opt == "CURLOPT_URL":
            via = taint.tainted_by(args[2])
            if via and not _guarded(call, "ARX-SSRF", taint.function_types):
                return _report(src, taint, call, "ARX-SSRF", name, via)
        if opt in {"CURLOPT_SSL_VERIFYPEER", "CURLOPT_SSL_VERIFYHOST"} and text(args[2]).lower() in {"false", "0"}:
            return finding(RULES["ARX-TLS"], src, call, Severity.MEDIUM, f"`{opt}` is turned off — any certificate is accepted.",
                           "Keep certificate verification on; point CURLOPT_CAINFO at your CA bundle for internal services.")
    if fam == "php" and name in {"md5", "sha1"} and args and re.search(r"(?i)pass|pwd|secret|token", text(args[0])):
        return finding(RULES["ARX-WEAKHASH"], src, call, Severity.MEDIUM, f"`{name}()` is used for a password or token — cracked in seconds.",
                       "Use password_hash($password, PASSWORD_DEFAULT) / password_verify(); random_bytes() for tokens.")
    if fam == "java" and name == "getInstance" and obj == "MessageDigest" and args and re.match(r'^"(MD5|MD2|SHA-?1)"$', text(args[0]), re.IGNORECASE):
        return finding(RULES["ARX-WEAKHASH"], src, call, Severity.LOW, f"MessageDigest {text(args[0])} — collisions are practical.",
                       "Use SHA-256+ for integrity and BCrypt / Argon2 (Spring Security PasswordEncoder) for passwords.")
    if fam == "go" and obj in {"md5", "sha1"} and name in {"New", "Sum"}:
        return finding(RULES["ARX-WEAKHASH"], src, call, Severity.LOW, f"{obj}.{name} — collisions are practical.",
                       "Use sha256 for integrity and bcrypt / argon2 for passwords.")
    if fam == "php" and name in {"rand", "mt_rand", "uniqid", "lcg_value", "str_shuffle"} and _sensitive_target(call, taint):
        return finding(RULES["ARX-RANDOM"], src, call, Severity.MEDIUM, f"`{name}()` generates a secret value — it is predictable.",
                       "Use random_bytes() / random_int() / bin2hex(random_bytes(32)).")
    if fam == "java" and (name == "Random" and call.type == "object_creation_expression" or (obj, name) == ("Math", "random")) and _sensitive_target(call, taint):
        return finding(RULES["ARX-RANDOM"], src, call, Severity.MEDIUM, "java.util.Random generates a secret value — it is predictable.",
                       "Use java.security.SecureRandom.")
    if fam == "go" and obj == "rand" and name in {"Intn", "Int", "Int63", "Int31", "Read", "Uint32", "Uint64"} \
            and '"math/rand' in src.text and '"crypto/rand"' not in src.text and _sensitive_target(call, taint):
        return finding(RULES["ARX-RANDOM"], src, call, Severity.MEDIUM, "math/rand generates a secret value — it is predictable.",
                       "Use crypto/rand (rand.Read / rand.Int with crypto/rand).")
    if fam == "java" and name == "setHostnameVerifier" and args and re.search(r"->\s*true|NoopHostnameVerifier|ALLOW_ALL", text(args[0])):
        return finding(RULES["ARX-TLS"], src, call, Severity.MEDIUM, "The hostname verifier accepts every host.",
                       "Keep the default hostname verification.")
    return None


def _sensitive_target(call: Node, taint) -> bool:
    from .rules.appsec import SENSITIVE_NAME

    cur, depth = call.parent, 0
    while cur is not None and depth < 8:
        if cur.type in {"assignment_expression", "variable_declarator", "short_var_declaration", "assignment_statement", "var_spec"}:
            target = cur.child_by_field_name("left") or cur.child_by_field_name("name")
            return bool(SENSITIVE_NAME.search(text(target)))
        if cur.type in taint.function_types:
            return bool(SENSITIVE_NAME.search(text(cur.child_by_field_name("name"))))
        cur, depth = cur.parent, depth + 1
    return False


HTML_TAG = re.compile(r"""['"][^'"]*<\s*/?\s*[a-zA-Z][\w-]*[^'"]*['"]""")  # a string literal that contains a tag


def _special_node(src, taint, node) -> Finding | None:
    fam, t = src.family, node.type
    if fam == "php" and t in {"echo_statement", "print_intrinsic", "exit_statement"}:
        for value in node.named_children:
            if taint.is_literal(value) or _sanitized("ARX-XSS", value):
                continue
            via = taint.tainted_by(value)
            if via:
                return _report(src, taint, node, "ARX-XSS", "echo", via)
    if fam == "php" and t in {"assignment_expression", "augmented_assignment_expression"}:
        # $html .= '<pre>Hello ' . $_GET['name'] . '</pre>';  — markup built from input, printed later (often in another file)
        value = node.child_by_field_name("right")
        if value is not None and taint.is_dynamic_string(value) and HTML_TAG.search(text(value)) and not _sanitized("ARX-XSS", value):
            via = taint.tainted_by(value)
            if via:
                return _report(src, taint, node, "ARX-XSS", "HTML", via)
    if fam == "php" and t in {"include_expression", "include_once_expression", "require_expression", "require_once_expression"}:
        value = node.named_children[0] if node.named_children else None
        if value is None or taint.is_literal(value):
            return None
        via = taint.tainted_by(value)
        if via and not _guarded(node, "ARX-LFI", taint.function_types):
            return _report(src, taint, node, "ARX-LFI", t.split("_")[0], via)
    if fam == "php" and t == "shell_command_expression":
        via = taint.tainted_by(node)
        if via:
            return _report(src, taint, node, "ARX-CMDI", "backticks", via)
        if taint.is_dynamic_string(node):
            return _report(src, taint, node, "ARX-CMDI", "backticks", None)
    if fam == "go" and t == "keyed_element" and re.match(r"^InsecureSkipVerify\s*:\s*true$", text(node)):
        return finding(RULES["ARX-TLS"], src, node, Severity.MEDIUM, "`InsecureSkipVerify: true` accepts any TLS certificate.",
                       "Remove InsecureSkipVerify; add your CA to RootCAs for internal services.")
    if fam == "java" and t == "method_declaration" and text(node.child_by_field_name("name")) in {"checkServerTrusted", "checkClientTrusted"}:
        body = node.child_by_field_name("body")
        if body is not None and not [c for c in body.named_children if c.type != "comment"]:
            return finding(RULES["ARX-TLS"], src, node, Severity.HIGH, "A TrustManager with an empty check trusts every certificate (MITM).",
                           "Delete the custom TrustManager and use the default trust store (or add your CA to it).")
    return None


XXE_FACTORY = re.compile(r"\b(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|SAXReader|SAXBuilder)\.newInstance\(|new\s+(SAXReader|SAXBuilder)\(")
XXE_HARDENED = re.compile(r"disallow-doctype-decl|FEATURE_SECURE_PROCESSING|external-general-entities|IS_SUPPORTING_EXTERNAL_ENTITIES|"
                          r"ACCESS_EXTERNAL_DTD|SUPPORT_DTD|setExpandEntityReferences\(\s*false")


def _file_checks(src, disabled, seen) -> list[Finding]:
    out = []
    if src.family == "java" and "ARX-XXE" not in disabled:
        m = XXE_FACTORY.search(src.text)
        if m and not XXE_HARDENED.search(src.text):
            line = src.text[: m.start()].count("\n") + 1
            out.append(Finding(rule_id="ARX-XXE", cwe="CWE-611", severity=Severity.MEDIUM, title=RULES["ARX-XXE"].title,
                               message=f"{m.group(1) or m.group(2)} is created without disabling DTDs — an uploaded XML file can read local files (XXE).",
                               fix='factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
                               file=src.rel, line=line, column=1, snippet=src.line(line)))
    if src.family == "php" and "ARX-XXE" not in disabled:
        for i, raw in enumerate(src.lines, 1):
            if re.search(r"LIBXML_NOENT|libxml_disable_entity_loader\(\s*false\s*\)", raw):
                out.append(Finding(rule_id="ARX-XXE", cwe="CWE-611", severity=Severity.HIGH, title=RULES["ARX-XXE"].title,
                                   message="XML is parsed with external entities enabled (LIBXML_NOENT) — XXE.",
                                   fix="Drop LIBXML_NOENT; never re-enable the entity loader.", file=src.rel, line=i, column=1, snippet=src.line(i)))
                break
    return [f for f in out if f.key not in seen]


__all__ = ["POLY_FAMILIES", "PolyAnalyzer", "check", "call_parts", "Var"]
