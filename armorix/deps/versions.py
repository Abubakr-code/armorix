"""Version ordering for npm (semver) and PyPI (PEP 440), plus a CVSS v3 base-score calculator."""

from __future__ import annotations

import math
import re

from packaging.version import InvalidVersion, Version

SEMVER = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def _semver_key(v: str):
    m = SEMVER.match(v.strip())
    if not m:
        return None
    major, minor, patch, pre = m.groups()
    # A release sorts after all of its pre-releases; numeric identifiers sort numerically.
    pre_key = (1,) if pre is None else (0, *[(0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")])
    return (int(major), int(minor or 0), int(patch or 0), pre_key)


def key(ecosystem: str, version: str):
    """Sortable key, or None when the version can't be parsed (the range is then skipped)."""
    if version in {"0", ""}:
        return (-1,)  # OSV uses "0" for "since the beginning"
    if ecosystem == "npm":
        k = _semver_key(version)
        return None if k is None else (0, k)
    try:
        return (0, Version(version))
    except InvalidVersion:
        return None


def in_ranges(ecosystem: str, version: str, ranges: list[dict], versions: list[str]) -> bool:
    """OSV affected-range evaluation (introduced / fixed / last_affected events)."""
    if version in versions:
        return True
    v = key(ecosystem, version)
    if v is None:
        return False
    for r in ranges:
        if r.get("type") not in {"SEMVER", "ECOSYSTEM"}:
            continue
        affected = False
        for event in r.get("events", []):
            if "introduced" in event:
                k = key(ecosystem, event["introduced"])
                if k is not None and v >= k:
                    affected = True
            elif "fixed" in event:
                k = key(ecosystem, event["fixed"])
                if k is not None and v >= k:
                    affected = False
            elif "last_affected" in event:
                k = key(ecosystem, event["last_affected"])
                if k is not None and v > k:
                    affected = False
        if affected:
            return True
    return False


def newest(ecosystem: str, candidates: list[str]) -> str | None:
    parsed = [(key(ecosystem, c), c) for c in candidates if c]
    parsed = [(k, c) for k, c in parsed if k is not None]
    return max(parsed)[1] if parsed else None


# ── CVSS v3.x base score ────────────────────────────────────────
_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    if not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(part.split(":") for part in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        if impact <= 0:
            return 0.0
        exploit = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        total = 1.08 * (impact + exploit) if scope_changed else impact + exploit
        return _roundup(min(total, 10))
    except (KeyError, ValueError):
        return None
