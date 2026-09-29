"""v0.3: scoped / inter-procedural taint, framework sources, application-logic and infrastructure rules."""

import textwrap

import pytest

from armorix.finding import Severity
from armorix.scanner import scan

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW


def run(tmp_path, name, code):
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(textwrap.dedent(code))
    return sorted((f.rule_id, f.severity) for f in scan(tmp_path, deps=False).findings)


VULNERABLE = [
    # taint through a helper's parameter
    ("a.js", """
        function findUser(id) { return db.query("SELECT * FROM users WHERE id = " + id); }
        app.get('/u', (req, res) => findUser(req.query.id));
     """, [("ARX-SQLI", C)]),
    # taint through a helper's return value
    ("a.py", """
        def term():
            return request.args.get("q")
        def search():
            cursor.execute("SELECT * FROM items WHERE name = '%s'" % term())
     """, [("ARX-SQLI", C)]),
    # Flask route parameter is a source
    ("a.py", """
        @app.route("/files/<name>")
        def download(name):
            return open("/srv/files/" + name).read()
     """, [("ARX-PATH", H)]),
    # FastAPI query parameter is a source
    ("a.py", """
        from fastapi import FastAPI
        app = FastAPI()
        @app.get("/ping")
        def ping(host: str):
            os.system("ping -c 1 " + host)
     """, [("ARX-CMDI", C)]),
    # NestJS @Query() is a source
    ("a.ts", """
        class C {
          @Get() find(@Query('q') q: string) { return this.repo.query(`SELECT * FROM t WHERE a = '${q}'`); }
        }
     """, [("ARX-SQLI", C)]),
    # Next.js route handler
    ("route.ts", """
        export async function GET(request) {
          const url = request.nextUrl.searchParams.get('url');
          return fetch(url);
        }
     """, [("ARX-SSRF", H)]),
    # $where built in a helper
    ("a.js", """
        const criteria = (t) => ({ $where: `this.stocks > '${t}'` });
        col.find(criteria(x));
     """, [("ARX-NOSQL", H)]),
    # mass assignment
    ("a.js", "app.post('/u', async (req, res) => { await User.create(req.body); });", [("ARX-MASS", M)]),
    ("a.py", "user = User(**request.json)", [("ARX-MASS", M)]),
    # prototype pollution
    ("a.js", "_.merge(settings, req.body);", [("ARX-PROTO", H)]),
    # regex injection
    ("a.js", "const re = new RegExp(req.query.q);", [("ARX-REGEX", M)]),
    # cookies
    ("a.js", "res.cookie('session', token);", [("ARX-COOKIE", M)]),
    ("a.py", "resp.set_cookie('auth_token', tok)", [("ARX-COOKIE", M)]),
    # predictable tokens
    ("a.js", "const resetToken = Math.random().toString(36).slice(2);", [("ARX-RANDOM", M)]),
    ("a.py", "otp = random.randint(100000, 999999)", [("ARX-RANDOM", M)]),
    # hard-coded signing keys
    ("a.js", "const t = jwt.sign({ id }, 'supersecret');", [("ARX-SIGNKEY", H)]),
    ("a.js", "app.use(session({ secret: 'keyboard cat', resave: false }));", [("ARX-SIGNKEY", H)]),
    ("a.py", "app.secret_key = 'dev'", [("ARX-SIGNKEY", H)]),
    # XXE
    ("a.js", "const doc = libxml.parseXml(req.body.xml, { noent: true });", [("ARX-XXE", C)]),
    ("a.py", "parser = etree.XMLParser(resolve_entities=True)", [("ARX-XXE", H)]),
    # auto-escaping / mark_safe
    ("a.js", "swig.setDefaults({ autoescape: false });", [("ARX-AUTOESCAPE", M)]),
    ("a.py", "html = mark_safe(request.GET['bio'])", [("ARX-AUTOESCAPE", H)]),
    # CSRF / permissions / temp files
    ("views.py", "@csrf_exempt\ndef pay(request):\n    pass\n", [("ARX-CSRF", L)]),
    ("a.py", "os.chmod(path, 0o777)", [("ARX-PERMS", L)]),
    ("a.py", "name = tempfile.mktemp()", [("ARX-TMPFILE", L)]),
    # new secret formats
    ("a.py", "BOT = '" + "1234567890:AA" + "Hk9f3Jd8s7Kd9sLq2Wm4Xn6Vb8Zc1Qa3E" + "'", [("ARX-SECRET", C)]),
    ("a.js", "const url = 'postgres://app:" + "Zx9kLm2Qw8" + "@db.prod.internal:5432/app';", [("ARX-SECRET", H)]),
    # GitHub Actions
    (".github/workflows/triage.yml", """
        on: issues
        jobs:
          t:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "New issue: ${{ github.event.issue.title }}"
     """, [("ARX-GHA-INJECT", H)]),
    (".github/workflows/pr.yml", """
        on: pull_request_target
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - run: npm test
     """, [("ARX-GHA-PWN", C)]),
    # Dockerfile / compose / Terraform
    ("Dockerfile", """
        FROM node:20
        ENV STRIPE_TOKEN sk_test_abc
        RUN curl -fsSL https://example.com/install.sh | sh
        CMD ["node", "server.js"]
     """, [("ARX-DOCKER", L), ("ARX-DOCKER", M), ("ARX-DOCKER", H)]),
    ("docker-compose.yml", """
        services:
          app:
            image: app
            volumes:
              - /var/run/docker.sock:/var/run/docker.sock
     """, [("ARX-CONTAINER", H)]),
    ("main.tf", """
        resource "aws_security_group" "ssh" {
          ingress {
            from_port   = 22
            to_port     = 22
            cidr_blocks = ["0.0.0.0/0"]
          }
        }
     """, [("ARX-TF", H)]),
]

SAFE = [
    # numeric casts stop taint
    ("a.js", 'const id = parseInt(req.query.id, 10);\ndb.query("SELECT * FROM t WHERE id = " + id);', "ARX-SQLI-CRIT"),
    # server data selected by an untrusted key is not attacker-controlled
    ("a.js", "app.get('/u/:id', (req, res) => res.send(users[req.params.id] || { error: 'none' }));", "ARX-XSS"),
    # same variable name in another handler is a different variable
    ("a.js", """
        app.get('/a', (req, res) => { const q = req.query.q; res.json({ q }); });
        app.get('/b', (req, res) => { const q = 'fixed'; res.send(q); });
     """, "ARX-XSS"),
    # Flask int converter
    ("a.py", '@app.route("/u/<int:uid>")\ndef u(uid):\n    cursor.execute("SELECT * FROM u WHERE id = %s" % uid)\n', "ARX-SQLI-CRIT"),
    # FastAPI: Depends and int params are not sources
    ("a.py", """
        from fastapi import Depends
        @app.get("/x")
        def x(n: int, db: Session = Depends(get_db)):
            os.system("echo " + str(n))
     """, "ARX-CMDI-CRIT"),
    # secrets: prose keys, hashes, command names, dev DB passwords
    ("i18n.json", '{"Use the correct password.": "\\u0412\\u0432\\u0435\\u0434\\u0438\\u0442\\u0435 \\u043f\\u0430\\u0440\\u043e\\u043b\\u044c123"}', "ARX-SECRET"),
    ("a.py", 'USER = {"hashed_password": "$2b$12$KIXQ4rS1D2a5b6c7d8e9f0g1h2i3j4k5l6m7n8o9p0q1r2s3t4u5v"}', "ARX-SECRET"),
    ("cmds.json", '{"token": "WITHSCORES"}', "ARX-SECRET"),
    ("compose.yml", "DATABASE_URL: postgres://postgres:postgres@db:5432/app", "ARX-SECRET"),
    # cookies with flags, crypto randomness, keys from env
    ("a.js", "res.cookie('session', t, { httpOnly: true, secure: true, sameSite: 'lax' });", "ARX-COOKIE"),
    ("a.js", "const resetToken = crypto.randomBytes(32).toString('hex');", "ARX-RANDOM"),
    ("a.js", "const color = Math.floor(Math.random() * 255);", "ARX-RANDOM"),
    ("a.js", "jwt.sign({ id }, process.env.JWT_SECRET);", "ARX-SIGNKEY"),
    # workflow: value passed via env is fine
    (".github/workflows/ok.yml", """
        on: issues
        jobs:
          t:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TITLE: ${{ github.event.issue.title }}
                run: echo "$TITLE"
     """, "ARX-GHA-INJECT"),
    # Dockerfile with a non-root user and pinned image
    ("Dockerfile", "FROM python:3.12-slim\nRUN useradd -r app\nUSER app\nCMD [\"python\", \"app.py\"]\n", "ARX-DOCKER"),
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


def test_interprocedural_trace(tmp_path):
    (tmp_path / "a.js").write_text(
        "function run(cmd) {\n  exec('sh -c ' + cmd);\n}\napp.get('/x', (req, res) => {\n  const c = req.query.c;\n  run(c);\n});\n")
    (f,) = scan(tmp_path, deps=False).findings
    assert f.rule_id == "ARX-CMDI" and f.data["source"] == "req.query.c"
    assert [s.label for s in f.trace] == ["source", "flows", "sink"] and [s.line for s in f.trace] == [5, 6, 2]
