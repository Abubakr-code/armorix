"""ARX-REDOS: a fixed regular expression that backtracks exponentially.

Found by scanning OWASP NodeGoat, whose profile page validates input with /([0-9]+)+\\#/. The checks are
paired: dangerous nested quantifiers are reported, and ordinary patterns people write every day are not."""

import pytest

from armorix.rules.appsec import catastrophic_pattern
from armorix.scanner import scan


@pytest.mark.parametrize("pattern", [
    r"([0-9]+)+\#", r"(a+)+$", r"(a*)*b", r"(.*)*x", r"(\w+\s*)+$", r"(x+x+)+y", r"(a|aa)+$", r"^(\d+\.?)+$", r"((a+)b?)+",
])
def test_nested_quantifier_is_catastrophic(pattern):
    assert catastrophic_pattern(pattern)


@pytest.mark.parametrize("pattern", [
    r"([0-9]+)\#", r"^\d+$", r"(\w+\s)+", r"(?:[a-z]+,)*[a-z]+", r"(foo|bar)+", r"(a+)b", r"((\w+)\s)+",
    r"^[a-z0-9._-]+@[a-z0-9.-]+\.[a-z]{2,}$", r"(\d{1,3}\.){3}\d{1,3}", r"(a+)++b", r"\((\d+)\)", r"[(a+)+]",
])
def test_ordinary_patterns_are_not_flagged(pattern):
    assert catastrophic_pattern(pattern) is None


def test_rule_reads_regex_literals_and_strings_in_js_and_python(tmp_path):
    (tmp_path / "a.js").write_text("const ok = /^\\d+$/.test(x);\nconst bad = /([0-9]+)+\\#/.test(bank);\nconst b2 = new RegExp('(a+)+$');\n")
    (tmp_path / "b.py").write_text("import re\nre.compile(r'^(\\w+\\s?)*$')\nre.match(r'\\d+', s)\nre.compile(r'(\\w+\\s)+')\n")
    got = sorted((f.file, f.line, f.rule_id) for f in scan(tmp_path, deps=False).findings if f.rule_id == "ARX-REDOS")
    assert got == [("a.js", 2, "ARX-REDOS"), ("a.js", 3, "ARX-REDOS"), ("b.py", 2, "ARX-REDOS")]
