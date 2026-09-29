"""Turns vulnerable / malicious dependencies into findings."""

from __future__ import annotations

from pathlib import Path

from ..finding import Finding
from .manifests import parse
from .osv import OsvDb
from .versions import newest

RULE_ID = "ARX-DEP"
CWE = "CWE-1395"
TITLE = "Vulnerable dependency"
DESCRIPTION = "A third-party package version with known vulnerabilities (OSV / GHSA / CVE) or a known-malicious package."


class DependencyRule:
    """Metadata twin of the AST rules, so reports can describe ARX-DEP."""

    id, cwe, title, description = RULE_ID, CWE, TITLE, DESCRIPTION


def check_manifest(db: OsvDb, path: Path, rel: str) -> list[Finding]:
    out = []
    for dep in parse(path, rel):
        advisories = db.lookup(dep.ecosystem, dep.name, dep.version)
        if not advisories:
            continue
        top = advisories[0]
        if any(a.malicious for a in advisories):
            mal = next(a for a in advisories if a.malicious)
            message = f"{dep.name}@{dep.version} is a known MALICIOUS package ({mal.id}). {mal.summary}".strip()
            fix = f"Remove {dep.name} now, reinstall from a clean lockfile and rotate any secrets on machines where it was installed."
            title = "Malicious package"
        else:
            # GHSA and PYSEC often publish the same CVE — count each vulnerability once.
            ids = list(dict.fromkeys(next((a for a in adv.aliases if a.startswith("CVE-")), adv.id) for adv in advisories))
            shown = ", ".join(ids[:4]) + (f" +{len(ids) - 4} more" if len(ids) > 4 else "")
            message = f"{dep.name}@{dep.version}: {len(ids)} known vulnerabilit{'y' if len(ids) == 1 else 'ies'} ({shown}) — {top.summary}"
            target = newest(dep.ecosystem, [f for a in advisories for f in a.fixed])
            fix = f"Upgrade {dep.name} to {target} or later." if target else f"No fixed release yet — replace {dep.name} or isolate its use."
            title = TITLE
        mal = next((a for a in advisories if a.malicious), None)
        target = None if mal else newest(dep.ecosystem, [f for a in advisories for f in a.fixed])
        ids = list(dict.fromkeys(next((x for x in a.aliases if x.startswith("CVE-")), a.id) for a in advisories))
        data = {"pkg": dep.name, "ver": dep.version, "n": len(ids), "summary": (mal or top).summary, "malicious": bool(mal),
                "id": mal.id if mal else top.id, "target": target,
                "ids": ", ".join(ids[:4]) + (f" +{len(ids) - 4}" if len(ids) > 4 else "")}
        out.append(Finding(
            rule_id=RULE_ID, cwe=CWE, severity=top.severity, title=title, message=message, fix=fix,
            file=dep.file, line=dep.line, column=1, snippet=f"{dep.name} {dep.version}", data=data,
        ))
    return out
