"""Regressions from the v0.3.15 false-positive report (A-01 … A-06).

Every fix is a pair: the safe shape stops being reported, and the near-miss that is still dangerous keeps
its finding. Making the safe case quiet by switching a rule off would break the second half of each pair."""

import json
import textwrap

import pytest

from armorix.cli import main, to_json
from armorix.finding import Severity
from armorix.scanner import scan

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW


def findings(tmp_path, name, code, rule=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(textwrap.dedent(code).lstrip())
    found = scan(tmp_path, deps=False).findings
    return sorted((f.rule_id, f.severity) for f in found if rule is None or f.rule_id == rule)


# ── A-01: allow-list + terminating guard ─────────────────────────────────────
ALLOWLIST_SAFE = [
    # the report's case: tuple unpacking after a check that raises
    """
    import sys
    PROJECTS = {"alpha": {}, "beta": {}}
    def main():
        if len(sys.argv) != 3 or sys.argv[1] not in PROJECTS:
            raise SystemExit("invalid project")
        project, target = sys.argv[1:]
        with open("/tmp/" + project + "-deploy.lock", "w") as lock:
            pass
    """,
    # the name itself is checked, and the branch returns
    """
    import sys
    PROJECTS = ("alpha", "beta")
    def main():
        project = sys.argv[1]
        if project not in PROJECTS:
            return
        open("/tmp/" + project + ".lock", "w")
    """,
    # sys.exit() ends the program
    """
    import sys
    NAMES = {"a", "b"}
    def main():
        name = sys.argv[1]
        if name not in NAMES:
            sys.exit(2)
        open("/tmp/" + name, "w")
    """,
]
ALLOWLIST_UNSAFE = [
    # no check at all
    "import sys\ndef main():\n    project = sys.argv[1]\n    open('/tmp/' + project, 'w')\n",
    # the check only prints; execution continues into the sink
    "import sys\nPROJECTS = {'a': 1}\ndef main():\n    project = sys.argv[1]\n    if project not in PROJECTS:\n"
    "        print('invalid')\n    open('/tmp/' + project, 'w')\n",
    # a different variable was checked
    "import sys\nPROJECTS = {'a': 1}\ndef main():\n    other = sys.argv[2]\n    project = sys.argv[1]\n    if other not in PROJECTS:\n"
    "        raise SystemExit(1)\n    open('/tmp/' + project, 'w')\n",
    # the value is replaced after the check
    "import sys\nPROJECTS = {'a': 1}\ndef main():\n    project = sys.argv[1]\n    if project not in PROJECTS:\n"
    "        raise SystemExit(1)\n    project = sys.argv[2]\n    open('/tmp/' + project, 'w')\n",
    # the allow-list can be extended at run time
    "import sys\nPROJECTS = {'a': 1}\nPROJECTS[sys.argv[1]] = 1\ndef main():\n    project = sys.argv[1]\n"
    "    if project not in PROJECTS:\n        raise SystemExit(1)\n    open('/tmp/' + project, 'w')\n",
    # an allowed entry that is itself a traversal
    "import sys\nPROJECTS = {'../etc/passwd': 1}\ndef main():\n    project = sys.argv[1]\n    if project not in PROJECTS:\n"
    "        raise SystemExit(1)\n    open('/tmp/' + project, 'w')\n",
    # `and` only rejects when both halves hold, so the check does not guarantee anything
    "import sys\nPROJECTS = {'a': 1}\ndef main():\n    project = sys.argv[1]\n    if len(sys.argv) > 5 and project not in PROJECTS:\n"
    "        raise SystemExit(1)\n    open('/tmp/' + project, 'w')\n",
    # the check is inside a branch the sink is not in
    "import sys\nPROJECTS = {'a': 1}\ndef main(flag):\n    project = sys.argv[1]\n    if flag:\n        if project not in PROJECTS:\n"
    "            raise SystemExit(1)\n    open('/tmp/' + project, 'w')\n",
    # a list the program does not define: nothing says what it holds
    "import sys\nfrom cfg import PROJECTS\ndef main():\n    project = sys.argv[1]\n    if project not in PROJECTS:\n"
    "        raise SystemExit(1)\n    open('/tmp/' + project, 'w')\n",
]


@pytest.mark.parametrize("code", ALLOWLIST_SAFE)
def test_allowlist_with_terminating_guard_is_not_traversal(tmp_path, code):
    assert findings(tmp_path, "a.py", code, "ARX-PATH") == []


@pytest.mark.parametrize("code", ALLOWLIST_UNSAFE)
def test_allowlist_that_does_not_hold_is_still_traversal(tmp_path, code):
    assert findings(tmp_path, "a.py", code, "ARX-PATH") == [("ARX-PATH", H)]


# ── A-04: sanitizer is a call, not a substring ───────────────────────────────
def test_variable_named_unsanitized_is_not_a_sanitizer(tmp_path):
    named = ("export function U({unsanitized}: {unsanitized: string}) {\n"
             "  return <div dangerouslySetInnerHTML={{__html: unsanitized}} />;\n}\n")
    plain = named.replace("unsanitized", "html")
    assert findings(tmp_path / "a", "x.tsx", named, "ARX-XSS") == findings(tmp_path / "b", "x.tsx", plain, "ARX-XSS") == [("ARX-XSS", M)]


def test_misleading_names_do_not_hide_server_xss(tmp_path):
    code = """
    app.get('/', (req, res) => {
      const unsanitized = req.query.q;
      res.send('<p>' + unsanitized + '</p>');
    });
    """
    assert findings(tmp_path, "a.js", code, "ARX-XSS") == [("ARX-XSS", H)]


def test_comment_or_string_naming_a_sanitizer_proves_nothing(tmp_path):
    code = """
    el.innerHTML = location.hash + '/* DOMPurify.sanitize */';
    """
    assert findings(tmp_path, "a.js", code, "ARX-XSS") == [("ARX-XSS", H)]


@pytest.mark.parametrize("html", [
    "DOMPurify.sanitize(html)",
    "DOMPurify.sanitize(html, {ALLOWED_TAGS: ['b']})",
])
def test_real_sanitizer_call_is_accepted(tmp_path, html):
    code = ('import DOMPurify from "dompurify";\n'
            f"export const S = ({{html}}: {{html: string}}) => <div dangerouslySetInnerHTML={{{{__html: {html}}}}} />;\n")
    assert findings(tmp_path, "x.tsx", code, "ARX-XSS") == []


@pytest.mark.parametrize("html", [
    "DOMPurify.sanitize(html) + extra",       # raw text appended after the sanitizer
    "html + DOMPurify.sanitize(extra)",
    "cond ? DOMPurify.sanitize(html) : html",
])
def test_raw_data_next_to_a_sanitizer_is_still_reported(tmp_path, html):
    code = ('import DOMPurify from "dompurify";\n'
            f"export const S = ({{html, extra, cond}}: any) => <div dangerouslySetInnerHTML={{{{__html: {html}}}}} />;\n")
    assert findings(tmp_path, "x.tsx", code, "ARX-XSS") == [("ARX-XSS", M)]


def test_local_stand_in_named_dompurify_is_not_the_library(tmp_path):
    code = ("const DOMPurify = { sanitize: (x: string) => x };\n"
            "export const S = ({html}: {html: string}) => <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(html)}} />;\n")
    assert findings(tmp_path, "x.tsx", code, "ARX-XSS") == [("ARX-XSS", M)]


def test_variable_assigned_from_sanitizer_is_safe_until_reassigned_raw(tmp_path):
    safe = "const clean = DOMPurify.sanitize(location.hash);\nel.innerHTML = clean;\n"
    raw = "let clean = DOMPurify.sanitize(location.hash);\nclean = location.hash;\nel.innerHTML = clean;\n"
    assert findings(tmp_path / "a", "a.js", safe, "ARX-XSS") == []
    assert findings(tmp_path / "b", "a.js", raw, "ARX-XSS") == [("ARX-XSS", H)]


# ── A-03: sanitizer result stored in React state ─────────────────────────────
STATE = """
import DOMPurify from "dompurify";
import {{ useEffect, useState }} from "react";
export function S({{html}}: {{html: string}}) {{
  const [clean, setClean] = useState({{source: "", html: ""}});
  useEffect(() => {{ {writes} }}, [html]);
  return <div dangerouslySetInnerHTML={{{{__html: clean.source === html ? clean.html : ""}}}} />;
}}
"""


def test_sanitized_value_flowing_through_state_is_safe(tmp_path):
    code = STATE.format(writes="setClean({source: html, html: DOMPurify.sanitize(html)});")
    assert findings(tmp_path, "x.tsx", code, "ARX-XSS") == []


@pytest.mark.parametrize("writes", [
    "setClean({source: html, html: DOMPurify.sanitize(html)}); setClean({source: html, html: html});",  # one raw write
    "setClean({source: html, html: html});",
    "setClean(prev => ({...prev, html}));",                                                            # cannot be followed
    "fetch('/x').then(setClean);",                                                                     # setter escapes
    "setClean({source: html, ...JSON.parse(html)});",                                                  # spread can set .html
])
def test_one_unsafe_state_write_breaks_the_proof(tmp_path, writes):
    code = STATE.format(writes=writes)
    assert findings(tmp_path, "x.tsx", code, "ARX-XSS") == [("ARX-XSS", M)]


def test_state_initialised_with_raw_value_is_not_safe(tmp_path):
    code = STATE.format(writes="setClean({source: html, html: DOMPurify.sanitize(html)});").replace(
        'useState({source: "", html: ""})', "useState({source: '', html: html})")
    assert findings(tmp_path, "x.tsx", code, "ARX-XSS") == [("ARX-XSS", M)]


# ── A-02: constant SQL fragments in Java ─────────────────────────────────────
def java(body, params="java.util.UUID userId"):
    return f"class A {{\n  void run({params}) {{\n{textwrap.indent(textwrap.dedent(body).strip(), '    ')}\n  }}\n}}\n"


def test_constant_sql_fragment_is_not_dynamic(tmp_path):
    code = java('''
        String owned = "select id from section where user_id=?";
        jdbc.update("delete from answer where section_id in (" + owned + ")", userId);
    ''')
    assert findings(tmp_path, "A.java", code, "ARX-SQLI") == []


def test_constant_chain_and_final_field_are_constant(tmp_path):
    code = ('class A {\n  private static final String BASE = "select id from t";\n'
            '  void run(java.util.UUID userId) {\n    String q = BASE + " where u=?";\n'
            '    jdbc.query("select * from x where id in (" + q + ")", userId);\n  }\n}\n')
    assert findings(tmp_path, "A.java", code, "ARX-SQLI") == []


@pytest.mark.parametrize("body,params,expected", [
    # request data concatenated directly
    ('String id = request.getParameter("id");\njdbc.update("delete from a where u=" + id);', "HttpServletRequest request", [("ARX-SQLI", C)]),
    # one branch swaps in request data
    ('String owned = "select 1";\nif (flag) { owned = request.getParameter("x"); }\njdbc.update("delete from a where id in (" + owned + ")");',
     "HttpServletRequest request, boolean flag", [("ARX-SQLI", C)]),
    # a parameter has no known value
    ('jdbc.update("delete from a where id in (" + owned + ")");', "String owned", [("ARX-SQLI", M)]),
    # built up in a loop
    ('String owned = "select 1";\nfor (String p : parts) { owned += p; }\njdbc.update("delete from a where id in (" + owned + ")");',
     "java.util.List<String> parts", [("ARX-SQLI", M)]),
])
def test_non_constant_sql_is_still_reported(tmp_path, body, params, expected):
    assert findings(tmp_path, "A.java", java(body, params), "ARX-SQLI") == expected


# ── A-05: MD5 depends on what it protects ────────────────────────────────────
def digest(method, arg):
    return f'import java.security.MessageDigest;\nclass A {{\n  byte[] {method}(String {arg}) throws Exception {{\n' \
           f'    return MessageDigest.getInstance("MD5").digest({arg}.getBytes());\n  }}\n}}\n'


def test_md5_for_a_password_is_more_serious(tmp_path):
    f = scan(_write(tmp_path, "A.java", digest("hashPassword", "password")), deps=False).findings
    assert [(x.rule_id, x.severity, x.data["context"], x.confidence) for x in f] == [("ARX-WEAKHASH", M, "password", "high")]
    assert "BCrypt" in f[0].fix


def test_md5_for_a_protocol_signature_is_a_hotspot_not_a_patch(tmp_path):
    f = scan(_write(tmp_path, "A.java", digest("providerSignature", "signedFields")), deps=False).findings
    assert [(x.severity, x.data["context"], x.confidence) for x in f] == [(L, "protocol", "review")]
    assert "specification" in f[0].fix and "do not switch your side alone" in f[0].fix


def test_md5_hotspot_is_translated(tmp_path):
    from armorix import i18n

    f = scan(_write(tmp_path, "A.java", digest("providerSignature", "signedFields")), deps=False).findings[0]
    for lang in ("uz", "ru"):
        title, why, fix = i18n.localize(f, lang)
        assert title != f.title and "HMAC-SHA-256" in fix


def _write(tmp_path, name, code):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(code)
    return tmp_path


# ── A-06: JSON states what was not checked ───────────────────────────────────
def test_json_reports_coverage_and_errors(tmp_path):
    (tmp_path / "a.py").write_text("print(1)\n")
    doc = json.loads(to_json(scan(tmp_path, deps=False)))
    assert doc["schema_version"] >= 2
    for key in ("errors", "coverage", "languages", "dependencies", "cached", "config"):
        assert key in doc
    cov = doc["coverage"]
    assert cov["code"]["status"] == "completed"
    assert cov["dependencies"]["status"] == "skipped" and cov["dependencies"]["reason"]
    assert cov["history"]["status"] == cov["ai_review"]["status"] == "skipped"


def test_json_never_implies_dependencies_were_checked_when_they_were_not(tmp_path):
    class NoDb:
        available = False

    (tmp_path / "package.json").write_text('{"dependencies": {"left-pad": "1.0.0"}}')
    doc = json.loads(to_json(scan(tmp_path, db=NoDb())))
    assert doc["dependencies"]["database_available"] is False
    assert doc["coverage"]["dependencies"] == {"status": "skipped",
                                               "reason": "offline vulnerability database (OSV) is not installed"}


def test_cli_json_has_confidence_field(tmp_path, capsys):
    (tmp_path / "a.py").write_text("import os\nos.system(input())\n")
    main(["scan", str(tmp_path), "--format", "json", "--no-cache", "--fail-on", "none"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["findings"] and all(f["confidence"] in {"high", "medium", "review"} for f in doc["findings"])


# ── JS/TS allow-lists, SSRF and redirect ─────────────────────────────────────
JS_ALLOW_SAFE = [
    "const ALLOWED = ['a', 'b'];\napp.get('/f', (req, res) => {\n  const name = req.query.name;\n"
    "  if (!ALLOWED.includes(name)) return res.sendStatus(400);\n  fs.readFile('/data/' + name, cb);\n});\n",
    "const ALLOWED = new Set(['a', 'b']);\napp.get('/f', (req, res) => {\n  if (!ALLOWED.has(req.query.name)) { throw new Error('no'); }\n"
    "  fs.readFile('/data/' + req.query.name, cb);\n});\n",
    "const ALLOWED = {a: 1, b: 2};\napp.get('/f', (req, res) => {\n  const n = req.query.n;\n  if (!(n in ALLOWED)) { return; }\n  fs.readFile('/d/' + n, cb);\n});\n",
    "const ALLOWED = ['a'];\napp.get('/f', (req, res) => {\n  if (ALLOWED.indexOf(req.query.n) === -1) { return res.end(); }\n"
    "  const n = req.query.n;\n  fs.readFile('/d/' + n, cb);\n});\n",
]
JS_ALLOW_UNSAFE = [
    # responds but keeps going
    "const ALLOWED = ['a'];\napp.get('/f', (req, res) => {\n  const n = req.query.n;\n  if (!ALLOWED.includes(n)) { res.status(400).send('no'); }\n  fs.readFile('/d/' + n, cb);\n});\n",
    # another value was checked
    "const ALLOWED = ['a'];\napp.get('/f', (req, res) => {\n  const n = req.query.n;\n  if (!ALLOWED.includes(req.query.m)) return;\n  fs.readFile('/d/' + n, cb);\n});\n",
    # the list is extended with request data
    "const ALLOWED = ['a'];\nALLOWED.push(process.argv[2]);\napp.get('/f', (req, res) => {\n  const n = req.query.n;\n  if (!ALLOWED.includes(n)) return;\n  fs.readFile('/d/' + n, cb);\n});\n",
    # reassigned after the check
    "const ALLOWED = ['a'];\napp.get('/f', (req, res) => {\n  let n = req.query.n;\n  if (!ALLOWED.includes(n)) return;\n  n = req.query.other;\n  fs.readFile('/d/' + n, cb);\n});\n",
    # an entry is a traversal
    "const ALLOWED = ['../../etc/passwd'];\napp.get('/f', (req, res) => {\n  const n = req.query.n;\n  if (!ALLOWED.includes(n)) return;\n  fs.readFile('/d/' + n, cb);\n});\n",
    # the list is re-bound elsewhere
    "let ALLOWED = ['a'];\nALLOWED = loadFromDb();\napp.get('/f', (req, res) => {\n  const n = req.query.n;\n  if (!ALLOWED.includes(n)) return;\n  fs.readFile('/d/' + n, cb);\n});\n",
    # `||` right side only: a left-hand true skips the check — here it is the `&&` form
    "const ALLOWED = ['a'];\napp.get('/f', (req, res) => {\n  const n = req.query.n;\n  if (req.query.skip && !ALLOWED.includes(n)) return;\n  fs.readFile('/d/' + n, cb);\n});\n",
]


@pytest.mark.parametrize("code", JS_ALLOW_SAFE)
def test_js_allowlist_with_terminating_guard_is_not_traversal(tmp_path, code):
    assert findings(tmp_path, "a.js", code, "ARX-PATH") == []


@pytest.mark.parametrize("code", JS_ALLOW_UNSAFE)
def test_js_allowlist_that_does_not_hold_is_still_traversal(tmp_path, code):
    assert findings(tmp_path, "a.js", code, "ARX-PATH") == [("ARX-PATH", H)]


def test_whole_url_allowlist_makes_ssrf_and_redirect_safe_but_only_when_it_stops(tmp_path):
    safe = ("import requests, sys\nURLS = {'https://api.example.com/v1'}\ndef main():\n    u = sys.argv[1]\n"
            "    if u not in URLS:\n        raise SystemExit(1)\n    requests.get(u)\n")
    unsafe = safe.replace("raise SystemExit(1)", "print('bad')")
    assert findings(tmp_path / "a", "a.py", safe, "ARX-SSRF") == []
    assert findings(tmp_path / "b", "a.py", unsafe, "ARX-SSRF") == [("ARX-SSRF", H)]
    js = ("const OK = ['/home', '/docs'];\napp.get('/go', (req, res) => {\n  const t = req.query.to;\n"
          "  if (!OK.includes(t)) return res.sendStatus(400);\n  res.redirect(t);\n});\n")
    assert findings(tmp_path / "c", "a.js", js, "ARX-REDIRECT") == []
    assert findings(tmp_path / "d", "a.js", js.replace("return res.sendStatus(400);", "res.sendStatus(400);"), "ARX-REDIRECT") == [("ARX-REDIRECT", M)]


# ── guards must be about the value that reaches the sink ─────────────────────
GO = """package main

import (
	"net/http"
	"os"
	"strings"
)

func h(w http.ResponseWriter, r *http.Request) {
	a := r.URL.Query().Get("a")
	b := r.URL.Query().Get("b")
	if !strings.HasPrefix(%s, "/var") {
		return
	}
	os.Open("/x/" + a)
}
"""


def test_guard_on_an_unrelated_value_does_not_count(tmp_path):
    assert findings(tmp_path / "a", "a.go", GO % "b", "ARX-PATH") == [("ARX-PATH", H)]
    assert findings(tmp_path / "b", "a.go", GO % "a", "ARX-PATH") == []


# ── coverage / confidence in every format ────────────────────────────────────
def _project(tmp_path):
    (tmp_path / "A.java").write_text(digest("providerSignature", "signedFields"))
    (tmp_path / "b.js").write_text("app.get('/', (req, res) => { el.innerHTML = req.query.q; });\n")
    return tmp_path


def test_every_format_says_what_was_not_checked(tmp_path):
    from armorix.report_ci import to_markdown
    from armorix.report_html import to_html
    from armorix.report_sarif import to_sarif

    result = scan(_project(tmp_path), deps=False)
    assert "history: skipped" in to_markdown(result) and "needs review" in to_markdown(result)
    page = to_html(result)
    assert 'class="gaps"' in page and "needs review" in page
    run = json.loads(to_sarif(result))["runs"][0]
    ids = {n["descriptor"]["id"] for n in run["invocations"][0]["toolExecutionNotifications"] if "descriptor" in n}
    assert {"armorix/history", "armorix/ai_review"} <= ids
    assert {r["properties"]["confidence"] for r in run["results"]} >= {"review"}
    assert "coverage" in run["invocations"][0]["properties"]


def test_reports_are_translated(tmp_path):
    from armorix.report_ci import to_markdown

    result = scan(_project(tmp_path), deps=False)
    assert "Не проверено" in to_markdown(result, "ru") and "Tekshirilmadi" in to_markdown(result, "uz")


def test_min_confidence_hides_weak_evidence_and_says_so(tmp_path, capsys):
    _project(tmp_path)
    main(["scan", str(tmp_path), "--format", "json", "--no-cache", "--fail-on", "none", "--min-confidence", "medium"])
    doc = json.loads(capsys.readouterr().out)
    assert all(f["confidence"] != "review" for f in doc["findings"])
    assert doc["coverage"]["confidence_filter"] == {"status": "applied", "minimum": "medium", "hidden": 1}
    main(["scan", str(tmp_path), "--format", "json", "--no-cache", "--fail-on", "none"])
    assert any(f["confidence"] == "review" for f in json.loads(capsys.readouterr().out)["findings"])
