"""Accuracy check on real, publicly known vulnerable applications.

Unit tests prove the rules on small fixtures; this proves the scanner on code nobody wrote for it. Three projects
whose weaknesses are documented, pinned to the exact commits the expectations were verified against:

  OWASP NodeGoat (JS)     every documented injection / redirect / SSRF / ReDoS site must be found
  DVWA (PHP)              every vulnerability module must be found, and the secure `impossible.php`
                          variants must not be reported as injectable
  Vulpy (Flask)           the deliberately vulnerable `bad/` tree must be found; `good/` must not gain SQL injection

Usage:  python tests/benchmark.py DIR      # DIR contains nodegoat/, dvwa/ and vulpy/ checked out at PINS

Exit code 1 on any miss, with the file and line that disappeared. Runs in CI (see .github/workflows/ci.yml).
"""

from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from armorix.scanner import scan

PINS = {
    "nodegoat": ("https://github.com/OWASP/NodeGoat.git", "c5cb68a7084e4ae7dcc60e6a98768720a81841e8"),
    "dvwa": ("https://github.com/digininja/DVWA.git", "068d974487a297c155c48722f9fcf7180a83adc4"),
    "vulpy": ("https://github.com/fportantier/vulpy.git", "5249cc8b05a1c37f6b2f757b1cf16a509c327122"),
}

NODEGOAT = [  # (rule, file, line) — each is a documented NodeGoat weakness
    ("ARX-EVAL", "app/routes/contributions.js", 32), ("ARX-EVAL", "app/routes/contributions.js", 33),
    ("ARX-EVAL", "app/routes/contributions.js", 34),   # A1: server-side JS injection
    ("ARX-NOSQL", "app/data/allocations-dao.js", 78),  # A1: $where built from the query string
    ("ARX-SSRF", "app/routes/research.js", 16),        # SSRF through the "research" page
    ("ARX-REDIRECT", "app/routes/index.js", 72),       # A10: unvalidated redirect
    ("ARX-SECRET", "artifacts/db-reset.js", 18),       # A6: credentials in source
    ("ARX-COOKIE", "server.js", 78),                   # A2: session cookie flags
    ("ARX-AUTOESCAPE", "server.js", 135),              # A3: template escaping switched off
    ("ARX-REDOS", "app/routes/profile.js", 59),        # /([0-9]+)+\#/ — catastrophic backtracking
]
DVWA_MODULES = {  # module → what must be found somewhere inside its folder
    "brute": "ARX-SQLI", "exec": "ARX-CMDI", "csrf": "ARX-CSRF", "fi": "ARX-LFI", "upload": "ARX-PATH",
    "captcha": "ARX-SQLI", "sqli": "ARX-SQLI", "sqli_blind": "ARX-SQLI", "xss_d": "ARX-XSS", "xss_r": "ARX-XSS",
    "xss_s": "ARX-SQLI", "csp": "ARX-CSP", "open_redirect": "ARX-REDIRECT", "cryptography": "ARX-CRYPTO", "weak_id": "ARX-COOKIE",
}
# `impossible.php` is DVWA's fixed version: injection rules must stay quiet there (stored-XSS leads and md5 are fair).
INJECTION = {"ARX-SQLI", "ARX-CMDI", "ARX-PATH", "ARX-LFI", "ARX-EVAL", "ARX-REDIRECT"}


def findings(root: Path):
    return [(f.rule_id, f.file.replace("\\", "/"), f.line) for f in scan(root, deps=False, use_cache=False).findings]


def main(base: Path) -> int:
    failures: list[str] = []

    ng = set(findings(base / "nodegoat"))
    for rule, file, line in NODEGOAT:
        if (rule, file, line) not in ng:
            failures.append(f"NodeGoat: {rule} at {file}:{line} was not found")
    print(f"NodeGoat   {len(ng):3d} findings, {sum(1 for x in NODEGOAT if x in ng)}/{len(NODEGOAT)} documented sites found")

    dv = findings(base / "dvwa")
    by_module: dict[str, set] = defaultdict(set)
    for rule, file, _ in dv:
        m = re.search(r"vulnerabilities/([^/]+)/", file)
        if m:
            by_module[m.group(1)].add(rule)
        if file.endswith("impossible.php") and rule in INJECTION:
            failures.append(f"DVWA: {rule} reported in the secure variant {file}")
    for module, rule in DVWA_MODULES.items():
        if rule not in by_module[module]:
            failures.append(f"DVWA: module '{module}' no longer reports {rule}")
    print(f"DVWA       {len(dv):3d} findings, {sum(1 for m, r in DVWA_MODULES.items() if r in by_module[m])}/{len(DVWA_MODULES)} modules detected")

    vp = findings(base / "vulpy")
    bad = Counter(rule for rule, file, _ in vp if "/bad/" in "/" + file)
    good = Counter(rule for rule, file, _ in vp if "/good/" in "/" + file)
    if bad["ARX-SQLI"] < 5:
        failures.append(f"Vulpy: bad/ reports {bad['ARX-SQLI']} SQL injections, expected at least 5")
    if good["ARX-SQLI"] > 1:
        failures.append(f"Vulpy: good/ reports {good['ARX-SQLI']} SQL injections, expected at most 1 (the one real flaw in libuser.py)")
    print(f"Vulpy      {len(vp):3d} findings, bad/ SQLi {bad['ARX-SQLI']}, good/ SQLi {good['ARX-SQLI']}")

    for line in failures:
        print("FAIL", line)
    print("benchmark:", "FAILED" if failures else "ok")
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(Path(sys.argv[1])))
