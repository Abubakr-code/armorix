"""SARIF 2.1.0 — understood by GitHub code scanning, GitLab, VS Code SARIF viewer."""

from __future__ import annotations

import json

from . import __version__
from .finding import Severity
from .deps.check import DependencyRule
from .rules import ALL_RULES
from .scanner import ScanResult

LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}
# GitHub maps this 0–10 score to its own critical/high/medium/low badges.
SCORE = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0"}


def _cwe_url(cwe: str) -> str:
    return f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"


def _location(file: str, line: int, column: int = 1, snippet: str = "") -> dict:
    region = {"startLine": line, "startColumn": max(1, column)}
    if snippet:
        region["snippet"] = {"text": snippet}
    return {"physicalLocation": {"artifactLocation": {"uri": file.replace("\\", "/")}, "region": region}}


def to_sarif(result: ScanResult) -> str:
    rules = [
        {
            "id": r.id,
            "name": r.title.title().replace(" ", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.description},
            "helpUri": _cwe_url(r.cwe),
            "properties": {"tags": ["security", r.cwe]},
        }
        for r in [*ALL_RULES, DependencyRule()]
    ]
    index = {r["id"]: i for i, r in enumerate(rules)}
    results = []
    for f in result.findings:
        item = {
            "ruleId": f.rule_id,
            "ruleIndex": index[f.rule_id],
            "level": LEVEL[f.severity],
            "message": {"text": f"{f.message} Fix: {f.fix}"},
            "locations": [_location(f.file, f.line, f.column, f.snippet)],
            "properties": {"security-severity": SCORE[f.severity], "severity": f.severity.name.lower()},
        }
        if f.trace:
            item["codeFlows"] = [{"threadFlows": [{"locations": [
                {"location": {**_location(f.file, s.line), "message": {"text": f"{s.label}: {s.code}"}}} for s in f.trace
            ]}]}]
        results.append(item)
    # Per-rule security-severity: the highest seen, so GitHub can rank rules too.
    for r in rules:
        seen = [f.severity for f in result.findings if f.rule_id == r["id"]]
        r["properties"]["security-severity"] = SCORE[max(seen)] if seen else "5.0"
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Armorix", "version": __version__, "informationUri": "https://armorix.security", "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)
