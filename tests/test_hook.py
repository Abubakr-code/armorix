import os
import subprocess
import sys

import pytest

from armorix import fixer
from armorix.cli import main
from armorix.scanner import scan

pytestmark = pytest.mark.skipif(subprocess.run(["git", "--version"], capture_output=True).returncode, reason="git missing")


def git(repo, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, env=env)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    return tmp_path


def test_staged_scans_index_not_working_tree(repo):
    (repo / "a.py").write_text("import os\nos.system('rm ' + input())\n")
    git(repo, "add", "a.py")
    (repo / "a.py").write_text("print('fixed in working tree, not staged')\n")
    (repo / "b.py").write_text("eval(input())\n")  # not staged → ignored
    assert main(["scan", str(repo), "--staged", "--fail-on", "critical"]) == 1
    git(repo, "add", "a.py")
    assert main(["scan", str(repo), "--staged", "--fail-on", "critical"]) == 0


def test_hook_blocks_commit(repo):
    assert main(["hook", "install", str(repo)]) == 0
    hook = repo / ".git" / "hooks" / "pre-commit"
    assert os.access(hook, os.X_OK) and sys.executable in hook.read_text()
    (repo / "s.js").write_text('const key = "AKIA' + 'IOSFODNN7EXAMPL3";\n')
    git(repo, "add", "s.js")
    assert git(repo, "commit", "-qm", "leak").returncode != 0
    (repo / "s.js").write_text("const key = process.env.AWS_KEY;\n")
    git(repo, "add", "s.js")
    assert git(repo, "commit", "-qm", "clean").returncode == 0
    assert main(["hook", "uninstall", str(repo)]) == 0 and not hook.exists()


def test_existing_foreign_hook_is_not_overwritten(repo):
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho mine\n")
    assert main(["hook", "install", str(repo)]) == 1
    assert hook.read_text() == "#!/bin/sh\necho mine\n"


def test_ssrf_fix_allowing_localhost_is_rejected(tmp_path):
    (tmp_path / "a.js").write_text('app.post("/p", async (req, res) => {\n  const r = await fetch(req.body.url);\n  res.json(await r.json());\n});\n')
    finding = scan(tmp_path, deps=False).findings[0]

    class AI:
        def generate(self, prompt, max_tokens=0):
            return ('```javascript\napp.post("/p", async (req, res) => {\n  const u = new URL(req.body.url);\n'
                    '  if (!["api.example.com", "localhost"].includes(u.hostname)) return res.sendStatus(403);\n'
                    '  const r = await fetch(u);\n  res.json(await r.json());\n});\n```')

    patch = fixer.propose(AI(), tmp_path, finding, attempts=1)
    assert not patch.verified and "localhost" in patch.reason
