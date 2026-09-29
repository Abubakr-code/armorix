"""Per-file result cache: unchanged files are not re-parsed, so a re-scan of a big project takes a moment.

Keyed by (engine build, file path, content hash, disabled rules). Lives in the data dir next to the OSV
database; delete it at any time. ARMORIX_NO_CACHE=1 turns it off.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from functools import lru_cache
from pathlib import Path

from . import __version__
from .deps.osv import data_dir

KEEP_DAYS = 30


@lru_cache(maxsize=1)
def engine_salt() -> str:
    """Changes whenever the engine code changes (source checkout) or its version does (frozen build)."""
    h = hashlib.sha1(__version__.encode())
    for path in sorted(Path(__file__).parent.rglob("*.py")):
        try:
            h.update(path.read_bytes())
        except OSError:
            pass
    return h.hexdigest()[:16]


def file_key(rel: str, content: bytes, disabled: frozenset[str]) -> str:
    h = hashlib.sha1(engine_salt().encode())
    h.update(rel.replace("\\", "/").encode("utf-8", "replace"))
    h.update(b"\0")
    h.update(content)
    h.update(",".join(sorted(disabled)).encode())
    return h.hexdigest()


class ResultCache:
    def __init__(self, path: Path | None = None):
        self.enabled = os.environ.get("ARMORIX_NO_CACHE") != "1"
        self.path = path or data_dir() / "cache" / "scan.sqlite"
        self.con = None
        self.lock = threading.Lock()
        if not self.enabled:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.con = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
            self.con.execute("PRAGMA journal_mode=WAL")
            self.con.execute("CREATE TABLE IF NOT EXISTS files (key TEXT PRIMARY KEY, payload TEXT, used REAL)")
        except sqlite3.Error:
            self.con = None  # read-only home, locked file …: scan without a cache

    def get_many(self, keys: list[str]) -> dict[str, dict]:
        if not self.con or not keys:
            return {}
        out = {}
        with self.lock:
            try:
                for i in range(0, len(keys), 500):
                    chunk = keys[i:i + 500]
                    rows = self.con.execute(f"SELECT key, payload FROM files WHERE key IN ({','.join('?' * len(chunk))})", chunk)
                    out.update((k, json.loads(p)) for k, p in rows)
                now = time.time()
                self.con.executemany("UPDATE files SET used=? WHERE key=?", [(now, k) for k in out])
                self.con.commit()
            except (sqlite3.Error, ValueError):
                return {}
        return out

    def put_many(self, items: dict[str, dict]) -> None:
        if not self.con or not items:
            return
        now = time.time()
        with self.lock:
            try:
                self.con.executemany("INSERT OR REPLACE INTO files VALUES (?,?,?)",
                                     [(k, json.dumps(v, ensure_ascii=False), now) for k, v in items.items()])
                self.con.execute("DELETE FROM files WHERE used < ?", (now - KEEP_DAYS * 86400,))
                self.con.commit()
            except sqlite3.Error:
                pass

    def clear(self) -> None:
        if self.con:
            with self.lock:
                self.con.execute("DELETE FROM files")
                self.con.commit()
