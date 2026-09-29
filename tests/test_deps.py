"""Dependency checks against a tiny synthetic OSV database (no download needed)."""

import io
import json
import sqlite3
import zipfile

import pytest

from armorix.deps import osv
from armorix.deps.manifests import parse
from armorix.deps.versions import cvss3_score, in_ranges, key
from armorix.finding import Severity
from armorix.scanner import scan

ADVISORIES = [
    {"id": "GHSA-aaaa", "aliases": ["CVE-2020-8203"], "summary": "Prototype pollution in lodash",
     "database_specific": {"severity": "HIGH"},
     "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                   "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}]}]},
    {"id": "GHSA-bbbb", "aliases": ["CVE-2021-23337"], "summary": "Command injection in lodash",
     "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
     "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                   "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]},
    {"id": "PYSEC-1", "aliases": ["CVE-2020-14343", "GHSA-cccc"], "summary": "Arbitrary code execution in PyYAML",
     "affected": [{"package": {"ecosystem": "PyPI", "name": "PyYAML"}, "versions": ["5.3", "5.3.1"],
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}]},
    {"id": "GHSA-cccc", "aliases": ["CVE-2020-14343"], "summary": "duplicate of PYSEC-1",
     "database_specific": {"severity": "CRITICAL"},
     "affected": [{"package": {"ecosystem": "PyPI", "name": "pyyaml"},
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}]},
    {"id": "MAL-2025-1", "summary": "Malicious code in event-strem (npm)",
     "affected": [{"package": {"ecosystem": "npm", "name": "event-strem"}}]},
    {"id": "GHSA-old", "withdrawn": "2020-01-01", "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"}}]},
]


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("ARMORIX_HOME", str(tmp_path / "home"))
    for eco in ("npm", "PyPI"):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for adv in ADVISORIES:
                zf.writestr(f"{adv['id']}.json", json.dumps(adv))
        (tmp_path / f"{eco}-all.zip").write_bytes(buf.getvalue())
    osv.update(from_dir=str(tmp_path), log=lambda m: None)
    return osv.OsvDb()


def test_versions_and_cvss():
    assert key("npm", "1.2.3") < key("npm", "1.10.0") < key("npm", "2.0.0-rc.1") < key("npm", "2.0.0")
    assert in_ranges("npm", "4.17.15", [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}], [])
    assert not in_ranges("npm", "4.17.19", [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}], [])
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1


def test_lookup(db):
    assert {a.id for a in db.lookup("npm", "lodash", "4.17.15")} == {"GHSA-aaaa", "GHSA-bbbb"}
    assert {a.id for a in db.lookup("npm", "lodash", "4.17.20")} == {"GHSA-bbbb"}
    assert db.lookup("npm", "lodash", "4.17.21") == []
    assert {a.id for a in db.lookup("PyPI", "pyyaml", "5.3")} == {"PYSEC-1", "GHSA-cccc"}  # name normalised
    assert db.lookup("npm", "event-strem", "1.0.0")[0].malicious
    assert db.lookup("npm", "left-pad", "1.0.0") == []  # withdrawn


def test_scan_reports_dependencies(tmp_path, db):
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "p"},
        "node_modules/lodash": {"version": "4.17.15"},
        "node_modules/event-strem": {"version": "3.3.6"},
        "node_modules/react": {"version": "19.0.0"},
    }}))
    (proj / "requirements.txt").write_text("flask==3.0.0\nPyYAML==5.3  # pinned\nrequests>=2\n")
    result = scan(proj, db=db)
    by_pkg = {f.snippet.split()[0]: f for f in result.findings}
    assert set(by_pkg) == {"lodash", "event-strem", "PyYAML"}
    assert by_pkg["event-strem"].title == "Malicious package" and by_pkg["event-strem"].severity == Severity.CRITICAL
    assert by_pkg["lodash"].severity == Severity.HIGH and "4.17.21" in by_pkg["lodash"].fix
    assert "1 known vulnerability" in by_pkg["PyYAML"].message  # PYSEC + GHSA of one CVE count once
    assert by_pkg["PyYAML"].severity == Severity.CRITICAL
    assert result.dependencies == 5


def test_manifest_parsers(tmp_path):
    (tmp_path / "yarn.lock").write_text('lodash@^4.17.0:\n  version "4.17.15"\n  resolved "x"\n\n"@babel/core@^7.0.0":\n  version "7.1.0"\n')
    assert {(d.name, d.version) for d in parse(tmp_path / "yarn.lock", "yarn.lock")} == {("lodash", "4.17.15"), ("@babel/core", "7.1.0")}
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "django"\nversion = "3.2.0"\n')
    assert [(d.name, d.version) for d in parse(tmp_path / "poetry.lock", "poetry.lock")] == [("django", "3.2.0")]
    # A lockfile wins over package.json ranges …
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "^1.2.3"}}')
    assert parse(tmp_path / "package.json", "package.json") == []
    # … without one, pinned versions and range floors are used.
    solo = tmp_path / "solo"
    solo.mkdir()
    (solo / "package.json").write_text('{"dependencies": {"a": "^1.2.3", "b": "latest", "c": "2.0.0"}}')
    assert [(d.name, d.version) for d in parse(solo / "package.json", "package.json")] == [("a", "1.2.3"), ("c", "2.0.0")]


def test_database_is_read_only_at_scan_time(db):
    with pytest.raises(sqlite3.OperationalError):
        db.con.execute("DELETE FROM advisory")
