"""PHP, Go and Java: sources, sinks, sanitizers and framework parameters."""

import textwrap

import pytest

from armorix.finding import Severity
from armorix.scanner import scan

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW


def run(tmp_path, name, code):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(textwrap.dedent(code).lstrip())
    return sorted((f.rule_id, f.severity) for f in scan(tmp_path, deps=False).findings)


VULNERABLE = [
    # PHP
    ("a.php", '<?php\n$id = $_GET["id"];\nmysqli_query($conn, "SELECT * FROM u WHERE id=" . $id);', [("ARX-SQLI", C)]),
    ("a.php", '<?php\n$pdo->query("SELECT * FROM t WHERE name = \'{$_POST[\'n\']}\'");', [("ARX-SQLI", C)]),
    ("a.php", '<?php\necho "Hello " . $_GET["name"];', [("ARX-XSS", H)]),
    ("a.php", '<?php\ninclude $_GET["page"] . ".php";', [("ARX-LFI", C)]),
    ("a.php", '<?php\nsystem("ping -c 1 " . $_GET["host"]);', [("ARX-CMDI", C)]),
    ("a.php", "<?php\n$out = `ls {$_GET['dir']}`;", [("ARX-CMDI", C)]),
    ("a.php", '<?php\nheader("Location: " . $_GET["next"]);', [("ARX-REDIRECT", M)]),
    ("a.php", '<?php\n$prefs = unserialize($_COOKIE["prefs"]);', [("ARX-DESER", C)]),
    ("a.php", '<?php\nfunction find($u) { global $db; return $db->query("SELECT * FROM u WHERE name=\'" . $u . "\'"); }\nfind($_REQUEST["u"]);',
     [("ARX-SQLI", C)]),
    ("a.php", '<?php\n$h = md5($password);', [("ARX-WEAKHASH", M)]),
    ("a.php", '<?php\n$ch = curl_init();\ncurl_setopt($ch, CURLOPT_URL, $_GET["url"]);', [("ARX-SSRF", H)]),
    ("UserController.php", """
        <?php
        class UserController {
            public function show($id) { return DB::select("SELECT * FROM users WHERE id = " . $id); }
        }
     """, [("ARX-SQLI", C)]),
    ("a.php", '<?php\n$name = $request->input("name");\n$rows = DB::select("SELECT * FROM t WHERE n = \'$name\'");', [("ARX-SQLI", C)]),
    # Go
    ("main.go", """
        package main
        func h(w http.ResponseWriter, r *http.Request) {
            id := r.URL.Query().Get("id")
            db.Query("SELECT * FROM users WHERE id = " + id)
        }
     """, [("ARX-SQLI", C)]),
    ("main.go", """
        package main
        func h(w http.ResponseWriter, r *http.Request) {
            db.Query(fmt.Sprintf("SELECT * FROM t WHERE n = '%s'", r.FormValue("n")))
        }
     """, [("ARX-SQLI", C)]),
    ("main.go", """
        package main
        func h(w http.ResponseWriter, r *http.Request) {
            exec.Command("sh", "-c", "ping "+r.FormValue("host")).Run()
        }
     """, [("ARX-CMDI", C)]),
    ("main.go", """
        package main
        func h(w http.ResponseWriter, r *http.Request) { f, _ := os.Open(r.FormValue("file")); _ = f }
     """, [("ARX-PATH", H)]),
    ("main.go", """
        package main
        func h(w http.ResponseWriter, r *http.Request) { http.Get(r.URL.Query().Get("url")) }
     """, [("ARX-SSRF", H)]),
    ("main.go", """
        package main
        func h(w http.ResponseWriter, r *http.Request) { w.Write([]byte(r.FormValue("q"))) }
     """, [("ARX-XSS", H)]),
    ("main.go", """
        package main
        func h(c *gin.Context) {
            var in Input
            c.ShouldBindJSON(&in)
            db.Exec("DELETE FROM t WHERE name = '" + in.Name + "'")
        }
     """, [("ARX-SQLI", C)]),
    ("main.go", "package main\nvar cfg = &tls.Config{InsecureSkipVerify: true}\n", [("ARX-TLS", M)]),
    # Java
    ("C.java", """
        class C {
          @GetMapping("/u") String u(@RequestParam String name) {
            return jdbcTemplate.queryForObject("SELECT email FROM users WHERE name = '" + name + "'", String.class);
          }
        }
     """, [("ARX-SQLI", C)]),
    ("C.java", """
        class C { void run(HttpServletRequest req) throws Exception { Runtime.getRuntime().exec(req.getParameter("cmd")); } }
     """, [("ARX-CMDI", C)]),
    ("C.java", """
        class C { void f(HttpServletRequest req) { new File("/data/" + req.getParameter("f")); } }
     """, [("ARX-PATH", H)]),
    ("C.java", """
        class C { void f(HttpServletRequest request, HttpServletResponse resp) throws Exception { resp.sendRedirect(request.getParameter("next")); } }
     """, [("ARX-REDIRECT", M)]),
    ("C.java", """
        class C { Object f(HttpServletRequest req) throws Exception { return new ObjectInputStream(req.getInputStream()).readObject(); } }
     """, [("ARX-DESER", C)]),
    ("C.java", "class C { Object f() { return DocumentBuilderFactory.newInstance(); } }", [("ARX-XXE", M)]),
    ("C.java", 'class C { byte[] f(byte[] b) throws Exception { return MessageDigest.getInstance("MD5").digest(b); } }', [("ARX-WEAKHASH", L)]),
]

SAFE = [
    ("a.php", '<?php\n$id = intval($_GET["id"]);\nmysqli_query($conn, "SELECT * FROM u WHERE id=" . $id);', "ARX-SQLI-CRIT"),
    ("a.php", '<?php\necho htmlspecialchars($_GET["name"], ENT_QUOTES);', "ARX-XSS"),
    ("a.php", '<?php\necho esc_html( $_GET["name"] );', "ARX-XSS"),
    ("a.php", '<?php\n$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $wpdb->posts WHERE ID = %d", $_GET["id"] ) );', "ARX-SQLI"),
    ("a.php", '<?php\n$rows = $wpdb->get_results( "SELECT option_name FROM $wpdb->options" );', "ARX-SQLI"),
    ("a.php", '<?php\n$page = isset( $_GET["p"] ) ? absint( $_GET["p"] ) : 1;\necho "Page $page";', "ARX-XSS"),
    ("a.php", '<?php\n$stmt = $pdo->prepare("SELECT * FROM u WHERE id = ?");\n$stmt->execute([$_GET["id"]]);', "ARX-SQLI"),
    ("a.php", '<?php\n$q->query($args);', "ARX-SQLI"),
    ("main.go", 'package main\nfunc h(r *http.Request) { db.Query("SELECT * FROM t WHERE id = $1", r.FormValue("id")) }\n', "ARX-SQLI"),
    ("main.go", 'package main\nfunc h(r *http.Request) { n, _ := strconv.Atoi(r.FormValue("n")); db.Query(fmt.Sprintf("SELECT * FROM t LIMIT %d", n)) }\n',
     "ARX-SQLI-CRIT"),
    ("main.go", 'package main\nfunc h(r *http.Request) { os.Open(filepath.Base(r.FormValue("f"))) }\n', "ARX-PATH"),
    ("main.go", 'package main\nimport "crypto/rand"\nfunc token() { b := make([]byte, 32); rand.Read(b) }\n', "ARX-RANDOM"),
    ("C.java", 'class C { void f(@PathVariable long id) { jdbcTemplate.queryForObject("SELECT * FROM t WHERE id = ?", String.class, id); } }', "ARX-SQLI"),
    ("C.java", """
        class C { Object f() throws Exception {
          DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
          f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
          return f; } }
     """, "ARX-XXE"),
]


@pytest.mark.parametrize("name, code, expected", VULNERABLE)
def test_detects(tmp_path, name, code, expected):
    assert run(tmp_path, name, code) == sorted(expected)


@pytest.mark.parametrize("name, code, rule", SAFE)
def test_no_false_positive(tmp_path, name, code, rule):
    found = run(tmp_path, name, code)
    if rule.endswith("-CRIT"):
        assert (rule[:-5], C) not in found, found
    else:
        assert all(r != rule for r, _ in found), found


def test_php_trace_through_helper(tmp_path):
    (tmp_path / "a.php").write_text('<?php\nfunction run($cmd) {\n  system("sh -c " . $cmd);\n}\n$c = $_GET["c"];\nrun($c);\n')
    (f,) = scan(tmp_path, deps=False).findings
    assert f.rule_id == "ARX-CMDI" and f.data["source"] == '$_GET["c"]'
    assert [s.line for s in f.trace] == [5, 6, 3]


def test_languages_are_counted(tmp_path):
    (tmp_path / "a.php").write_text("<?php echo 1;")
    (tmp_path / "b.go").write_text("package b")
    (tmp_path / "C.java").write_text("class C {}")
    assert dict(scan(tmp_path, deps=False).languages) == {"php": 1, "go": 1, "java": 1}


def test_php_invented_variable_is_rejected(tmp_path):
    from armorix.fixer import _verify

    old = '<?php\nfunction f($conn) {\n  $id = $_GET["id"];\n  return mysqli_query($conn, "SELECT * FROM u WHERE id = " . $id);\n}\n'
    new = ('<?php\nfunction f($conn) {\n  $id = $_GET["id"];\n  $stmt = $pdo->prepare("SELECT * FROM u WHERE id = ?");\n'
           '  $stmt->execute([$id]);\n  return $stmt;\n}\n')
    path = tmp_path / "a.php"
    path.write_text(old)
    finding = next(f for f in scan(tmp_path, deps=False).findings if f.rule_id == "ARX-SQLI")
    ok, reason = _verify(path, finding, old, new, 4, 6)
    assert not ok and "$pdo" in reason


FLOW = [
    # sanitized later in the same block → the use sees the clean value
    ("a.php", '<?php\n$id = $_GET["id"];\n$id = intval($id);\nmysqli_query($c, "SELECT * FROM t WHERE id = $id");', "ARX-SQLI-CRIT"),
    ("a.js", "let id = req.query.id;\nid = parseInt(id, 10);\ndb.query('SELECT * FROM t WHERE id = ' + id);", "ARX-SQLI-CRIT"),
    ("a.py", 'q = request.args["q"]\nq = int(q)\ncursor.execute("SELECT * FROM t LIMIT %s" % q)', "ARX-SQLI-CRIT"),
    # validated by an enclosing if
    ("a.php", '<?php\n$ip = $_GET["ip"];\n$o = explode(".", $ip);\nif (is_numeric($o[0]) && is_numeric($o[1])) {\n'
              '  $ip = $o[0] . "." . $o[1];\n  shell_exec("ping " . $ip);\n}', "ARX-CMDI"),
    # validated by an earlier bail-out
    ("a.php", '<?php\n$n = $_GET["n"];\nif (!ctype_digit($n)) { die("bad"); }\nsystem("seq " . $n);', "ARX-CMDI"),
]


@pytest.mark.parametrize("name, code, rule", FLOW)
def test_flow_sensitive_safe(tmp_path, name, code, rule):
    found = run(tmp_path, name, code)
    if rule.endswith("-CRIT"):
        assert (rule[:-5], C) not in found, found
    else:
        assert all(r != rule for r, _ in found), found


def test_reassignment_inside_a_branch_keeps_the_taint(tmp_path):
    code = '<?php\n$x = $_GET["x"];\nif ($debug) { $x = "fixed"; }\nsystem("echo " . $x);'
    assert ("ARX-CMDI", C) in run(tmp_path, "a.php", code)


def test_php_html_built_from_input_is_xss(tmp_path):
    code = '<?php\n$name = $_GET["name"];\n$html .= "<pre>Hello {$name}</pre>";'
    assert ("ARX-XSS", H) in run(tmp_path, "a.php", code)
    safe = '<?php\n$name = htmlspecialchars($_GET["name"]);\n$html .= "<pre>Hello {$name}</pre>";'
    assert ("ARX-XSS", H) not in run(tmp_path / "safe", "b.php", safe)
