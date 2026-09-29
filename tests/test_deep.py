import os
import subprocess

import pytest

from armorix.deep import ai_review, deep_scan, git_history_secrets
from armorix.scanner import scan

pytestmark = pytest.mark.skipif(subprocess.run(["git", "--version"], capture_output=True).returncode, reason="git missing")
FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPL3"  # assembled at runtime: keeps repository secret scanners quiet
ENV = {**os.environ, "GIT_AUTHOR_NAME": "dev", "GIT_AUTHOR_EMAIL": "d@x", "GIT_COMMITTER_NAME": "dev", "GIT_COMMITTER_EMAIL": "d@x"}


def git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, env=ENV)


def test_deleted_secret_is_found_in_history(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / "config.js").write_text(f'const key = "{FAKE_AWS}";\n')
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "add")
    (tmp_path / "config.js").write_text("const key = process.env.AWS_KEY;\n")
    git(tmp_path, "commit", "-qam", "remove")
    (f,) = git_history_secrets(tmp_path)
    assert f.rule_id == "ARX-SECRET-HISTORY" and f.file == "config.js" and f.line == 1
    assert FAKE_AWS not in f.snippet and "secret" not in f.data


def test_secret_still_in_tree_is_not_duplicated(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / "a.py").write_text(f'KEY = "{FAKE_AWS}"\n')
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "add")
    assert git_history_secrets(tmp_path) == []  # the normal scan reports it


def test_idor_and_noauth(tmp_path):
    (tmp_path / "a.js").write_text(
        "app.get('/orders/:id', async (req, res) => {\n  res.json(await Order.findById(req.params.id));\n});\n"
        "app.get('/me/orders/:id', async (req, res) => {\n  res.json(await Order.findOne({ _id: req.params.id, owner: req.user.id }));\n});\n"
        "app.get('/proxy', async (req, res) => res.json(await axios.get(req.query.url)));\n"
    )
    ids = sorted((f.rule_id, f.line) for f in deep_scan(tmp_path).findings if f.rule_id in {"ARX-IDOR", "ARX-NOAUTH"})
    assert ids == [("ARX-IDOR", 2)]  # req.user exists → project has auth; owner-checked handler is fine


def test_noauth_reported_once(tmp_path):
    (tmp_path / "a.py").write_text("@app.route('/a')\ndef a():\n    return request.args['x']\n\n@app.route('/b')\ndef b():\n    return request.args['y']\n")
    found = [f for f in deep_scan(tmp_path).findings if f.rule_id == "ARX-NOAUTH"]
    assert len(found) == 1 and found[0].data["handlers"] == 2


class FakeAI:
    def __init__(self, reply):
        self.reply = reply

    def generate(self, prompt, max_tokens=0, json_mode=False):
        assert json_mode
        return self.reply


def test_ai_review_filters_hallucinations(tmp_path):
    (tmp_path / "a.js").write_text("app.put('/p', async (req, res) => {\n  await User.update(req.session.uid, req.body);\n  res.sendStatus(204);\n});\n")
    reply = ('{"issues": [{"type": "mass-assignment", "line": 2, "why": "req.body passed whole", "confidence": 0.9},'
             '{"type": "sql-injection", "line": 2, "why": "x", "confidence": 1},'   # not a review type
             '{"type": "logic", "line": 99, "why": "x", "confidence": 1},'          # line outside handler
             '{"type": "data-exposure", "line": 3, "why": "x", "confidence": 0.3}]}')  # low confidence
    (f,) = ai_review(FakeAI(reply), scan(tmp_path, deps=False))
    assert f.rule_id == "ARX-AI-MASS-ASSIGNMENT" and f.line == 2 and f.data["ai"]
    assert ai_review(FakeAI("not json"), scan(tmp_path, deps=False)) == []
