"""Each case: a tiny file → the (rule, severity) pairs Armorix must report — and nothing else."""

import textwrap

import pytest

from armorix.finding import Severity
from armorix.scanner import scan

C, H, M = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM
# Provider-format fakes are assembled at runtime so repository secret scanners do not flag the source.
FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPL3"
FAKE_STRIPE = "sk_" + "live_51Hx9QeKd8Vt2mZr4Lp7Nw3Yc"


def run(tmp_path, name, code):
    (tmp_path / name).write_text(textwrap.dedent(code))
    return sorted((f.rule_id, f.severity) for f in scan(tmp_path).findings)


VULNERABLE = [
    # ── SQL injection ───────────────────────────────────────
    ("a.js", 'const id = req.query.id;\ndb.query("SELECT * FROM u WHERE id=" + id);', [("ARX-SQLI", C)]),
    ("a.js", "const { id } = req.params;\npool.query(`DELETE FROM u WHERE id = ${id}`);", [("ARX-SQLI", C)]),
    ("a.ts", 'const q: string = "SELECT * FROM t WHERE n = \'" + req.body.n + "\'";\nawait prisma.$queryRawUnsafe(q);', [("ARX-SQLI", C)]),
    ("a.js", 'function f(name) { return db.query("SELECT * FROM t WHERE n = \'" + name + "\'"); }', [("ARX-SQLI", M)]),
    ("a.py", 'uid = request.args["id"]\ncur.execute("SELECT * FROM u WHERE id = %s" % uid)', [("ARX-SQLI", C)]),
    ("a.py", 'q = request.form.get("q")\ncur.execute("SELECT * FROM p WHERE n = \'{}\'".format(q))', [("ARX-SQLI", C)]),
    ("a.py", 'def f(n):\n    cur.execute(f"UPDATE t SET n = \'{n}\'")', [("ARX-SQLI", M)]),
    # ── code / command injection ────────────────────────────
    ("a.js", "const fn = new Function(req.body.code);", [("ARX-EVAL", C)]),
    ("a.js", "function run(s) { return eval(s); }", [("ARX-EVAL", H)]),
    ("a.js", 'const cp = require("child_process");\ncp.execSync("git log " + req.query.ref);', [("ARX-CMDI", C)]),
    ("a.js", 'spawn(cmd, args, { shell: true });', [("ARX-CMDI", H)]),
    ("a.py", 'import os\nos.system("convert " + request.args["f"])', [("ARX-CMDI", C)]),
    ("a.py", 'subprocess.check_output(cmd, shell=True)', [("ARX-CMDI", H)]),
    ("a.py", 'exec(sys.argv[1])', [("ARX-EVAL", C)]),
    # ── secrets ─────────────────────────────────────────────
    ("config.yml", "aws:\n  key: " + FAKE_AWS + "\n", [("ARX-SECRET", C)]),
    ("a.js", 'const token = "ghp_' + "a" * 20 + 'Bc9dE8fG7hI6jK5lM4nO3";', [("ARX-SECRET", C)]),
    ("a.py", 'API_KEY = "q8Zt3LmP0xVw7NcR2yHk"', [("ARX-SECRET", H)]),
    (".env", "SESSION_SECRET=Zx81qLmW9pTr\n", [("ARX-SECRET", H)]),
    ("key.pem.sh", "echo '-----BEGIN RSA " + "PRIVATE KEY-----'", [("ARX-SECRET", C)]),
]

SAFE = [
    ("a.js", 'db.query("SELECT * FROM u WHERE id = ?", [req.query.id]);'),
    ("a.js", "db.query(`SELECT * FROM users`);"),
    ("a.js", 'const v = cache.get("user:" + req.query.id);'),
    ("a.js", 'exec("ls -la"); eval("2 + 2");'),
    ("a.js", 'setTimeout(() => run(), 10); spawn("ls", [dir]);'),
    ("a.js", 'const c = { password: process.env.DB_PASS, apiKey: "your-api-key-here" };'),
    ("a.py", 'cur.execute("SELECT * FROM u WHERE id = %s", (request.args["id"],))'),
    ("a.py", 'subprocess.run(["tar", "-czf", name, path])\nos.system("rm -rf /tmp/cache")'),
    ("a.py", 'password = os.environ["DB_PASSWORD"]\nsecret = "changeme123"'),
    ("a.py", 'msg = "Hello " + request.args["name"]\nprint(msg)'),
    (".env.example", "JWT_SECRET=kD93mZq81LxP0wRt7Yv2\n"),
    (".env", "PORT=3000\nNODE_ENV=production\n"),
]


@pytest.mark.parametrize("name, code, expected", VULNERABLE)
def test_detects(tmp_path, name, code, expected):
    assert run(tmp_path, name, code) == sorted(expected)


@pytest.mark.parametrize("name, code", SAFE)
def test_no_false_positive(tmp_path, name, code):
    assert run(tmp_path, name, code) == []


def test_trace_points_back_to_the_source(tmp_path):
    (tmp_path / "s.js").write_text('const id = req.query.id;\nconst sql = "SELECT * FROM u WHERE id=" + id;\ndb.query(sql);\n')
    (f,) = scan(tmp_path).findings
    assert "req.query.id" in f.message
    assert [s.label for s in f.trace] == ["source", "flows", "sink"]
    assert [s.line for s in f.trace] == [1, 2, 3]


def test_secret_is_masked(tmp_path):
    (tmp_path / "a.py").write_text(f'STRIPE = "{FAKE_STRIPE}"\n')
    (f,) = scan(tmp_path).findings
    assert "51Hx9QeKd8" not in f.snippet


def test_skips_dependencies(tmp_path):
    (tmp_path / "node_modules" / "lib").mkdir(parents=True)
    (tmp_path / "node_modules" / "lib" / "x.js").write_text("eval(req.body.x)")
    assert scan(tmp_path).findings == []


def test_demo_project():
    result = scan("examples/vuln-shop", deps=False)
    assert sorted(f.rule_id for f in result.findings) == sorted(
        ["ARX-SQLI"] * 2 + ["ARX-CMDI"] * 2 + ["ARX-EVAL"] * 2 + ["ARX-SECRET"] * 3
        + ["ARX-XSS"] * 2 + ["ARX-PATH", "ARX-SSRF", "ARX-SSRF", "ARX-NOSQL", "ARX-JWT", "ARX-DEBUG"]
    )
