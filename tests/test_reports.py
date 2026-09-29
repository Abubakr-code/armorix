import json

from armorix.cli import main
from armorix.report_html import to_html
from armorix.report_sarif import to_sarif
from armorix.scanner import scan


def test_sarif_is_valid_and_complete():
    result = scan("examples/vuln-shop", deps=False)
    doc = json.loads(to_sarif(result))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    assert len(run["results"]) == len(result.findings)
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in rule_ids for r in run["results"])
    assert any("codeFlows" in r for r in run["results"])
    assert all(float(r["properties"]["security-severity"]) > 0 for r in run["results"])


def test_html_escapes_code(tmp_path):
    (tmp_path / "x.js").write_text('el.innerHTML = "<img src=x onerror=alert(1)>" + location.hash;\n')
    page = to_html(scan(tmp_path))
    assert "<img src=x" not in page and "&lt;img src=x" in page
    assert "http" not in page.split("<style>")[0].split("<title>")[0]  # no external resources in <head>
    assert "<link" not in page and "<script src" not in page


def test_cli_exit_codes(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("print('hi')\n")
    assert main(["scan", str(tmp_path)]) == 0
    (tmp_path / "bad.py").write_text("import os\nos.system('rm ' + input())\n")
    assert main(["scan", str(tmp_path)]) == 1
    assert main(["scan", str(tmp_path), "--fail-on", "none"]) == 0


def test_cli_writes_files(tmp_path):
    out = tmp_path / "r.sarif"
    main(["scan", "examples/vuln-shop", "--format", "sarif", "-o", str(out), "--fail-on", "none"])
    assert json.loads(out.read_text())["runs"][0]["results"]
