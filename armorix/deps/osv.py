"""Local OSV snapshot: download once (or import from USB), query fully offline.

The OSV "all.zip" dumps are flattened into one SQLite file with a row per
(advisory, package). Nothing is fetched at scan time.
"""

from __future__ import annotations

import io
import json
import os
import re
import sqlite3
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..finding import Severity
from .versions import cvss3_score, in_ranges

ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI"}
URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
SCHEMA = """
CREATE TABLE IF NOT EXISTS advisory (
  id TEXT, ecosystem TEXT, package TEXT, aliases TEXT, summary TEXT,
  severity INTEGER, ranges TEXT, versions TEXT, malicious INTEGER
);
CREATE INDEX IF NOT EXISTS advisory_pkg ON advisory (ecosystem, package);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""
GHSA_SEVERITY = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def data_dir() -> Path:
    base = os.environ.get("ARMORIX_HOME") or os.path.join(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"), "armorix")
    return Path(base)


def db_path() -> Path:
    return data_dir() / "osv.sqlite"


def normalize(ecosystem: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name


def _severity(adv: dict, affected: dict) -> Severity:
    label = (affected.get("database_specific") or {}).get("severity") or (adv.get("database_specific") or {}).get("severity")
    if isinstance(label, str) and label.upper() in GHSA_SEVERITY:
        return GHSA_SEVERITY[label.upper()]
    scores = [cvss3_score(s.get("score", "")) for s in adv.get("severity", []) if s.get("type") == "CVSS_V3"]
    scores = [s for s in scores if s is not None]
    if scores:
        s = max(scores)
        return Severity.CRITICAL if s >= 9 else Severity.HIGH if s >= 7 else Severity.MEDIUM if s >= 4 else Severity.LOW
    return Severity.MEDIUM


def _rows(adv: dict, eco: str):
    if adv.get("withdrawn"):
        return
    malicious = adv.get("id", "").startswith("MAL-")
    for affected in adv.get("affected", []):
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != eco or not pkg.get("name"):
            continue
        yield (
            adv["id"],
            eco,
            normalize(eco, pkg["name"]),
            ",".join(a for a in adv.get("aliases", []) if a.startswith(("CVE-", "GHSA-"))),
            (adv.get("summary") or adv.get("details", "")[:160]).strip(),
            int(Severity.CRITICAL if malicious else _severity(adv, affected)),
            json.dumps(affected.get("ranges", []), separators=(",", ":")),
            json.dumps(affected.get("versions", []) if len(affected.get("versions", [])) < 400 else [], separators=(",", ":")),
            int(malicious),
        )


def _load_zip(con: sqlite3.Connection, eco: str, blob: bytes) -> int:
    con.execute("DELETE FROM advisory WHERE ecosystem = ?", (eco,))
    count = 0
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        batch = []
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                adv = json.loads(zf.read(name))
            except ValueError:
                continue
            batch.extend(_rows(adv, eco))
            count += 1
            if len(batch) > 5000:
                con.executemany("INSERT INTO advisory VALUES (?,?,?,?,?,?,?,?,?)", batch)
                batch.clear()
        con.executemany("INSERT INTO advisory VALUES (?,?,?,?,?,?,?,?,?)", batch)
    return count


def update(ecosystems=("npm", "pypi"), from_dir: str | None = None, log=print) -> dict:
    """Download (or read `<from_dir>/<Ecosystem>-all.zip` / `<Ecosystem>/all.zip`) and rebuild the index."""
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    if tmp.exists():
        tmp.unlink()
    if path.exists():
        tmp.write_bytes(path.read_bytes())  # keep other ecosystems when updating one
    con = sqlite3.connect(tmp)
    con.executescript(SCHEMA)
    stats = {}
    for key in ecosystems:
        eco = ECOSYSTEMS[key]
        if from_dir:
            candidates = [Path(from_dir) / f"{eco}-all.zip", Path(from_dir) / eco / "all.zip", Path(from_dir) / f"{eco}.zip"]
            src = next((c for c in candidates if c.exists()), None)
            if src is None:
                raise FileNotFoundError(f"no {eco} archive in {from_dir}")
            log(f"importing {src}")
            blob = src.read_bytes()
        else:
            log(f"downloading OSV {eco} database …")
            with urllib.request.urlopen(URL.format(eco=eco), timeout=120) as resp:
                blob = resp.read()
        stats[eco] = _load_zip(con, eco, blob)
        log(f"  {eco}: {stats[eco]:,} advisories indexed")
    con.execute("INSERT OR REPLACE INTO meta VALUES ('updated', ?)", (datetime.now(timezone.utc).isoformat(timespec="seconds"),))
    con.commit()
    con.execute("VACUUM")
    con.close()
    tmp.replace(path)
    return stats


@dataclass
class Advisory:
    id: str
    aliases: list[str]
    summary: str
    severity: Severity
    malicious: bool
    fixed: list[str]


class OsvDb:
    def __init__(self, path: Path | None = None):
        self.path = path or db_path()
        self.con = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True) if self.path.exists() else None

    @property
    def available(self) -> bool:
        return self.con is not None

    def info(self) -> dict:
        if not self.con:
            return {}
        counts = dict(self.con.execute("SELECT ecosystem, COUNT(DISTINCT id) FROM advisory GROUP BY ecosystem"))
        updated = self.con.execute("SELECT value FROM meta WHERE key='updated'").fetchone()
        return {"advisories": counts, "updated": updated[0] if updated else None, "path": str(self.path)}

    def lookup(self, ecosystem: str, package: str, version: str) -> list[Advisory]:
        if not self.con:
            return []
        rows = self.con.execute(
            "SELECT id, aliases, summary, severity, ranges, versions, malicious FROM advisory WHERE ecosystem=? AND package=?",
            (ecosystem, normalize(ecosystem, package)),
        ).fetchall()
        found = {}
        for vid, aliases, summary, severity, ranges, versions, malicious in rows:
            ranges, versions = json.loads(ranges), json.loads(versions)
            if not (malicious and not ranges and not versions) and not in_ranges(ecosystem, version, ranges, versions):
                continue
            fixed = [e["fixed"] for r in ranges for e in r.get("events", []) if "fixed" in e]
            found[vid] = Advisory(vid, [a for a in aliases.split(",") if a], summary, Severity(severity), bool(malicious), fixed)
        return sorted(found.values(), key=lambda a: (-a.severity, a.id))
