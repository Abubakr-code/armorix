"""Stage-2 rules: web layer and configuration."""

import textwrap

import pytest

from armorix.finding import Severity
from armorix.rules import ALL_RULES
from armorix.scanner import scan

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW


def run(tmp_path, name, code):
    (tmp_path / name).write_text(textwrap.dedent(code))
    return sorted((f.rule_id, f.severity) for f in scan(tmp_path).findings)


VULNERABLE = [
    # XSS
    ("a.js", "app.get('/', (req, res) => res.send('<h1>' + req.query.name + '</h1>'));", [("ARX-XSS", H)]),
    ("a.js", "el.innerHTML = location.hash.slice(1);", [("ARX-XSS", H)]),
    ("a.js", "box.innerHTML = `<b>${msg}</b>`;", [("ARX-XSS", M)]),
    ("a.jsx", "const P = ({ html }) => <div dangerouslySetInnerHTML={{ __html: html }} />;", [("ARX-XSS", M)]),
    ("a.py", 'name = request.args.get("n")\nreturn f"<p>Hello {name}</p>"', [("ARX-XSS", H)]),
    # SSTI
    ("a.py", 'tpl = request.args["t"]\nrender_template_string(tpl)', [("ARX-SSTI", C)]),
    # path traversal
    ("a.js", "fs.readFile(path.join(__dirname, 'files', req.params.name), cb);", [("ARX-PATH", H)]),
    ("a.js", "res.sendFile(req.query.file);", [("ARX-PATH", H)]),
    ("a.py", 'f = request.args["f"]\nreturn open("/srv/data/" + f).read()', [("ARX-PATH", H)]),
    # SSRF
    ("a.js", "const r = await fetch(req.body.url);", [("ARX-SSRF", H)]),
    ("a.js", "axios.get(`http://${req.query.host}/status`);", [("ARX-SSRF", H)]),
    ("a.py", 'requests.get(request.args["url"], timeout=5)', [("ARX-SSRF", H)]),
    # open redirect
    ("a.js", "res.redirect(req.query.next);", [("ARX-REDIRECT", M)]),
    ("a.py", 'return redirect(request.args.get("next"))', [("ARX-REDIRECT", M)]),
    # NoSQL
    ("a.js", "User.findOne({ email: req.body.email, password: req.body.password });", [("ARX-NOSQL", H)]),
    ("a.js", "const q = req.body;\nUsers.find(q);", [("ARX-NOSQL", H)]),
    ("a.js", "db.users.find({ $where: 'this.age > ' + age });", [("ARX-NOSQL", C)]),
    # deserialization
    ("a.py", 'data = request.get_data()\nobj = pickle.loads(data)', [("ARX-DESER", C)]),
    ("a.py", "cfg = yaml.load(open('c.yml'))", [("ARX-DESER", M)]),
    # JWT
    ("a.js", "jwt.verify(token, key, { algorithms: ['none', 'HS256'] });", [("ARX-JWT", H)]),
    ("a.py", 'jwt.decode(tok, options={"verify_signature": False})', [("ARX-JWT", H)]),
    # CORS
    ("a.js", "app.use(cors({ origin: true, credentials: true }));", [("ARX-CORS", H)]),
    ("a.js", "res.setHeader('Access-Control-Allow-Origin', req.headers.origin);", [("ARX-CORS", H)]),
    # TLS / debug / weak hash
    ("a.js", "https.request({ host, rejectUnauthorized: false });", [("ARX-TLS", M)]),
    ("a.py", "requests.post(url, json=d, verify=False)", [("ARX-TLS", M)]),
    ("a.py", "app.run(host='0.0.0.0', debug=True)", [("ARX-DEBUG", H)]),
    ("a.js", "const h = crypto.createHash('md5').update(pw).digest('hex');", [("ARX-WEAKHASH", L)]),
    ("a.py", "digest = hashlib.sha1(password.encode()).hexdigest()", [("ARX-WEAKHASH", L)]),
]

SAFE = [
    ("a.js", "res.send({ ok: true, name: req.query.name });"),
    ("a.js", "res.json(req.body);"),
    ("a.js", "el.textContent = location.hash; el.innerHTML = '';"),
    ("a.js", "el.innerHTML = DOMPurify.sanitize(req.body.html);"),
    ("a.js", "res.sendFile(req.params.name, { root: PUBLIC_DIR });"),
    ("a.js", "fs.readFile(path.join(dir, path.basename(req.params.name)), cb);"),
    ("a.js", "fetch('/api/users'); axios.get(API + '/health');"),
    ("a.js", "res.redirect('/login');"),
    ("a.js", "User.findOne({ email: String(req.body.email) });"),
    ("a.js", "items.find(i => i.id === req.params.id);"),
    ("a.js", "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));"),
    ("a.js", "jwt.verify(token, key, { algorithms: ['HS256'] });"),
    ("a.js", "crypto.createHash('sha256').update(x).digest('hex');"),
    ("a.py", 'return render_template("page.html", name=request.args["n"])'),
    ("a.py", 'return send_from_directory("uploads", secure_filename(request.args["f"]))'),
    ("a.py", "cfg = yaml.safe_load(open('c.yml'))\nx = yaml.load(s, Loader=yaml.SafeLoader)"),
    ("a.py", 'return redirect(url_for("index"))'),
    ("a.py", "app.run(debug=os.environ.get('DEBUG') == '1')"),
    ("a.py", 'img = Image.open(request.files["img"])'),
    ("a.py", 'webbrowser.open(request.args["u"])'),
]


@pytest.mark.parametrize("name, code, expected", VULNERABLE)
def test_detects(tmp_path, name, code, expected):
    assert run(tmp_path, name, code) == sorted(expected)


@pytest.mark.parametrize("name, code", SAFE)
def test_no_false_positive(tmp_path, name, code):
    assert run(tmp_path, name, code) == []


def test_every_rule_is_documented():
    ids = [r.id for r in ALL_RULES]
    assert len(ids) == len(set(ids)) == 37
    for rule in ALL_RULES:
        assert rule.cwe.startswith("CWE-") and rule.title and rule.description, rule.id


def test_ssrf_allow_list_counts_as_guard(tmp_path):
    (tmp_path / "a.js").write_text(
        'app.post("/p", async (req, res) => {\n  const u = new URL(req.body.url);\n'
        '  if (!["api.example.com"].includes(u.hostname)) return res.sendStatus(403);\n  await fetch(u);\n});\n')
    (tmp_path / "b.py").write_text(
        'def f():\n    u = urlparse(request.args["u"])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    requests.get(u.geturl())\n')
    assert scan(tmp_path).findings == []
