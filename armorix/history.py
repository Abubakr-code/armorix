"""Scan history per project (desktop app): score over time, what is new and what got fixed since the last scan.

Stored in the data dir as SQLite; findings are kept as plain dicts with their fingerprints.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from .deps.osv import data_dir
from .finding import Finding, Severity
from .scanner import ScanResult, severity_counts

WEIGHTS = {"critical": 25, "high": 10, "medium": 3, "low": 1}
SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY, root TEXT, kind TEXT, started REAL, seconds REAL, files INTEGER, lines INTEGER,
  deps INTEGER, score INTEGER, counts TEXT, languages TEXT, findings TEXT
);
CREATE INDEX IF NOT EXISTS scans_root ON scans (root, started);
"""
_lock = threading.Lock()


def score(counts: dict[str, int]) -> int:
    """100 = nothing found. Each open finding costs points by severity; one critical alone drops below 80."""
    return max(0, 100 - sum(WEIGHTS[k] * counts.get(k, 0) for k in WEIGHTS))


def grade(value: int) -> str:
    return "A" if value >= 90 else "B" if value >= 75 else "C" if value >= 60 else "D" if value >= 40 else "F"


def _db() -> sqlite3.Connection:
    path = data_dir() / "history.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=10)
    con.executescript(SCHEMA)
    return con


def record(result: ScanResult, kind: str) -> dict:
    counts = severity_counts(result.findings)
    entry = {
        "id": uuid.uuid4().hex[:12], "root": str(result.root), "kind": kind, "started": time.time(),
        "seconds": round(result.seconds, 2), "files": result.files, "lines": result.lines, "deps": result.dependencies,
        "score": score(counts), "counts": counts, "languages": dict(result.languages),
    }
    previous = latest(str(result.root))
    with _lock, _db() as con:
        con.execute("INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
            entry["id"], entry["root"], kind, entry["started"], entry["seconds"], entry["files"], entry["lines"], entry["deps"],
            entry["score"], json.dumps(counts), json.dumps(entry["languages"]),
            json.dumps([f.to_dict() for f in result.findings], ensure_ascii=False)))
    entry["grade"] = grade(entry["score"])
    entry["diff"] = diff(previous["fingerprints"] if previous else None, result.findings)
    entry["previous_score"] = previous["score"] if previous else None
    return entry


def diff(before: set[str] | None, findings: list[Finding]) -> dict:
    if before is None:
        return {"new": [], "fixed": 0, "first": True}
    now = {f.fingerprint for f in findings}
    return {"new": sorted(now - before), "fixed": len(before - now), "first": False}


def latest(root: str) -> dict | None:
    with _lock, _db() as con:
        row = con.execute("SELECT id, score, findings FROM scans WHERE root=? ORDER BY started DESC LIMIT 1", (root,)).fetchone()
    if not row:
        return None
    return {"id": row[0], "score": row[1], "fingerprints": {f.get("fingerprint", "") for f in json.loads(row[2])}}


def _summary(row) -> dict:
    sid, root, kind, started, seconds, files, lines, deps, value, counts, languages = row
    return {"id": sid, "root": root, "kind": kind, "started": started, "seconds": seconds, "files": files, "lines": lines,
            "deps": deps, "score": value, "grade": grade(value), "counts": json.loads(counts), "languages": json.loads(languages)}


COLUMNS = "id, root, kind, started, seconds, files, lines, deps, score, counts, languages"


def projects() -> list[dict]:
    with _lock, _db() as con:
        rows = con.execute(f"""SELECT {COLUMNS}, n FROM scans JOIN (SELECT root AS r, MAX(started) AS m, COUNT(*) AS n FROM scans GROUP BY root)
                               ON root = r AND started = m ORDER BY started DESC""").fetchall()
    out = []
    for row in rows:
        item = _summary(row[:-1]) | {"scans": row[-1], "name": Path(row[1]).name or row[1], "exists": Path(row[1]).exists()}
        out.append(item)
    return out


def history(root: str, limit: int = 50) -> list[dict]:
    with _lock, _db() as con:
        rows = con.execute(f"SELECT {COLUMNS} FROM scans WHERE root=? ORDER BY started DESC LIMIT ?", (root, limit)).fetchall()
    return [_summary(r) for r in rows]


def load(scan_id: str) -> tuple[dict, list[Finding]] | None:
    with _lock, _db() as con:
        row = con.execute(f"SELECT {COLUMNS}, findings FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return None
    return _summary(row[:-1]), [Finding.from_dict(f) for f in json.loads(row[-1])]


def forget(root: str) -> int:
    with _lock, _db() as con:
        return con.execute("DELETE FROM scans WHERE root=?", (root,)).rowcount


def known_roots() -> set[str]:
    with _lock, _db() as con:
        return {r[0] for r in con.execute("SELECT DISTINCT root FROM scans")}


__all__ = ["record", "projects", "history", "load", "forget", "score", "grade", "known_roots", "Severity"]
