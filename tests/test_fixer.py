"""Patch verification with a scripted fake model — no Ollama needed."""

import shutil

import pytest

from armorix import fixer
from armorix.ai import AIUnavailable, LocalAI
from armorix.scanner import scan

APP = """const express = require("express");
const app = express();

app.get("/u", (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM users WHERE id = " + id, (e, rows) => res.json(rows));
});

const cfg = { password: "Sh0p!2026_prod#db" };
"""


class FakeAI:
    def __init__(self, reply):
        self.reply = reply
        self.prompts = []

    def generate(self, prompt, max_tokens=700):
        self.prompts.append(prompt)
        return self.reply


@pytest.fixture
def project(tmp_path):
    (tmp_path / "server.js").write_text(APP)
    return tmp_path


def sqli(project):
    return next(f for f in scan(project, deps=False).findings if f.rule_id == "ARX-SQLI")


def secret(project):
    return next(f for f in scan(project, deps=False).findings if f.rule_id == "ARX-SECRET")


GOOD = """```javascript
app.get("/u", (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM users WHERE id = ?", [id], (e, rows) => res.json(rows));
});
```"""


def test_good_patch_is_verified_and_applied(project):
    patch = fixer.propose(FakeAI(GOOD), project, sqli(project))
    assert patch.verified, patch.reason
    assert (patch.start, patch.end) == (4, 7)  # enclosing arrow function
    assert "+  db.query(\"SELECT * FROM users WHERE id = ?\", [id]" in patch.diff
    applied = fixer.apply(project, [patch])
    assert applied == [patch]
    assert (project / "server.js.armorix.bak").read_text() == APP
    assert not [f for f in scan(project, deps=False).findings if f.rule_id == "ARX-SQLI"]


def test_invented_helper_is_rejected(project):
    reply = GOOD.replace("const id = req.query.id;", "const id = sanitizeSql(req.query.id);")
    patch = fixer.propose(FakeAI(reply), project, sqli(project))
    assert not patch.verified and "sanitizeSql" in patch.reason


def test_still_vulnerable_is_rejected(project):
    reply = GOOD.replace('"SELECT * FROM users WHERE id = ?", [id]', '`SELECT * FROM users WHERE id = ${id}`')
    patch = fixer.propose(FakeAI(reply), project, sqli(project))
    assert not patch.verified and "still detected" in patch.reason


def test_syntax_error_is_rejected(project):
    patch = fixer.propose(FakeAI(GOOD.replace("});\n```", "}\n```")), project, sqli(project))
    assert not patch.verified and "parse" in patch.reason


def test_secret_kept_as_fallback_is_rejected(project):
    reply = '```javascript\nconst cfg = { password: process.env.DB_PASSWORD || "Sh0p!2026_prod#db" };\n```'
    patch = fixer.propose(FakeAI(reply), project, secret(project))
    assert not patch.verified


def test_secret_moved_to_env_is_verified(project):
    reply = "```javascript\nconst cfg = { password: process.env.DB_PASSWORD };\n```"
    patch = fixer.propose(FakeAI(reply), project, secret(project))
    assert patch.verified, patch.reason


def test_prompt_contains_file_context_and_no_invention_rule(project):
    ai = FakeAI(GOOD)
    fixer.propose(ai, project, sqli(project))
    assert 'require("express")' in ai.prompts[0] and "Never invent helpers" in ai.prompts[0]


def test_overlapping_patches_apply_once(project):
    p1 = fixer.propose(FakeAI(GOOD), project, sqli(project))
    p2 = fixer.propose(FakeAI(GOOD), project, sqli(project))
    assert len(fixer.apply(project, [p1, p2])) == 1


def test_remote_model_endpoint_is_refused(monkeypatch):
    monkeypatch.delenv("ARMORIX_ALLOW_REMOTE_AI", raising=False)
    with pytest.raises(AIUnavailable):
        LocalAI(url="https://api.example.com")
    LocalAI(url="http://127.0.0.1:11434")  # loopback is fine


def test_demo_copy_untouched(tmp_path):
    shutil.copytree("examples/vuln-shop", tmp_path / "demo")
    assert scan(tmp_path / "demo", deps=False).findings


class ScriptedAI:
    """Returns replies in order — lets a test drive the retry loop."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.prompts = []

    def generate(self, prompt, max_tokens=700):
        self.prompts.append(prompt)
        return self.replies.pop(0)


def test_rejected_patch_is_retried_with_feedback(project):
    bad = GOOD.replace('"SELECT * FROM users WHERE id = ?", [id]', '`SELECT * FROM users WHERE id = ${id}`')
    ai = ScriptedAI(bad, GOOD)
    patch = fixer.propose(ai, project, sqli(project))
    assert patch.verified
    assert "REJECTED" in ai.prompts[1] and "still detected" in ai.prompts[1]


def test_imports_from_the_reply_are_hoisted(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
        "@app.route('/r')\ndef report():\n    fmt = request.form['format']\n    return str(eval(fmt))\n"
    )
    finding = next(f for f in scan(tmp_path, deps=False).findings if f.rule_id == "ARX-EVAL")
    reply = "```python\nimport json\n\ndef report():\n    fmt = request.form['format']\n    return str(json.loads(fmt))\n```"
    patch = fixer.propose(FakeAI(reply), tmp_path, finding)
    assert patch.verified, patch.reason
    assert patch.imports == ["import json"]
    fixer.apply(tmp_path, [patch])
    code = (tmp_path / "app.py").read_text()
    assert code.startswith("import os\nfrom flask import Flask, request\nimport json\n")
    assert "json.loads(fmt)" in code and "eval(" not in code


def test_validation_in_handler_counts_as_guard(tmp_path):
    (tmp_path / "a.js").write_text(
        "app.get('/f', (req, res) => {\n"
        "  const p = path.resolve(BASE, req.query.file);\n"
        "  if (!p.startsWith(BASE + path.sep)) return res.sendStatus(403);\n"
        "  res.sendFile(p);\n});\n"
    )
    assert [f.rule_id for f in scan(tmp_path, deps=False).findings] == []


def test_echoed_context_is_stripped(project):
    echo = GOOD.replace("```javascript\n", '```javascript\nconst express = require("express");\nconst app = express();\n')
    patch = fixer.propose(FakeAI(echo), project, sqli(project))
    assert patch.verified, patch.reason
    assert "const app = express()" not in patch.fixed


def test_duplicating_vulnerable_code_is_rejected(project):
    dup = GOOD.replace("});\n```", '});\nconst other = { password: "Sh0p!2026_prod#db" };\n```')
    patch = fixer.propose(FakeAI(dup), project, sqli(project))
    assert not patch.verified and "introduced" in patch.reason


def test_execfile_with_array_first_is_rejected(tmp_path):
    (tmp_path / "p.js").write_text('const { exec } = require("child_process");\napp.post("/p", (req, res) => {\n  exec(`ping -c 1 ${req.body.host}`, (e, o) => res.send(o));\n});\n')
    finding = scan(tmp_path, deps=False).findings[0]
    bad = '```javascript\nconst { execFile } = require("child_process");\napp.post("/p", (req, res) => {\n  execFile(["ping", "-c", "1", req.body.host], (e, o) => res.send(o));\n});\n```'
    good = bad.replace('execFile(["ping", "-c", "1", req.body.host]', 'execFile("ping", ["-c", "1", req.body.host]')
    ai = ScriptedAI(bad, good)
    patch = fixer.propose(ai, tmp_path, finding)
    assert patch.verified, patch.reason
    assert "program name first" in ai.prompts[1]
    assert patch.imports == ['const { execFile } = require("child_process");']
