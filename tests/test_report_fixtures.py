"""The 12 fixtures from the v0.3.15 false-positive report, with the outcome each one must keep.

Run before every release: a safe shape that starts to be reported again, or a dangerous shape that goes
quiet, fails here by file name."""

import shutil
from pathlib import Path

import pytest

from armorix.finding import Severity
from armorix.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures" / "report_v0315"
C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

# file → [(rule, severity, confidence)]
EXPECTED = {
    "path_allowlist.py": [],                                    # allow-list + raise: A-01
    "path_unsafe.py": [("ARX-PATH", H, "high")],
    "path_nonblocking_guard.py": [("ARX-PATH", H, "high")],     # the check only prints
    "SqlConstant.java": [],                                     # constant fragment: A-02
    "SqlLiteral.java": [],
    "SqlUnsafe.java": [("ARX-SQLI", C, "high")],
    "xss_state_safe.tsx": [],                                   # sanitizer → state → sink: A-03
    "xss_direct_safe.tsx": [],
    "xss_raw.tsx": [("ARX-XSS", M, "medium")],
    "xss_misleading_name.tsx": [("ARX-XSS", M, "medium")],      # a name proves nothing: A-04
    "Md5Protocol.java": [("ARX-WEAKHASH", L, "review")],        # hotspot, not a patch: A-05
    "Md5Password.java": [("ARX-WEAKHASH", M, "high")],
}


def test_every_fixture_has_an_expectation():
    on_disk = {p.name for p in FIXTURES.iterdir()}
    assert on_disk == set(EXPECTED), on_disk ^ set(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_fixture_keeps_its_outcome(tmp_path, name):
    shutil.copy(FIXTURES / name, tmp_path / name)
    got = [(f.rule_id, f.severity, f.confidence) for f in scan(tmp_path, deps=False, use_cache=False).findings]
    assert got == EXPECTED[name]
