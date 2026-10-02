"""CI-friendly outputs: GitHub Actions annotations and a Markdown summary for pull request comments / job summaries."""

from __future__ import annotations

from collections import Counter

from . import __version__, i18n
from .finding import Severity
from .scanner import ScanResult

LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "notice"}
EMOJI = {Severity.CRITICAL: "🟥", Severity.HIGH: "🟧", Severity.MEDIUM: "🟨", Severity.LOW: "🟦"}


def _prop(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C")


def _data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def to_github(result: ScanResult, lang: str = "en") -> str:
    """`::error file=…,line=…::…` lines — GitHub shows them inline on the pull request diff."""
    lines = []
    for f in result.findings:
        title, message, fix = i18n.localize(f, lang)
        head = f"file={_prop(f.file)},line={f.line},col={f.column},title={_prop(f'{f.rule_id} · {f.cwe} · {title}')}"
        lines.append(f"::{LEVEL[f.severity]} {head}::{_data(message + chr(10) + '→ ' + fix)}")
    return "\n".join(lines)


def to_markdown(result: ScanResult, lang: str = "en") -> str:
    t = lambda key, **kw: i18n.ui(lang, key, **kw)  # noqa: E731
    # Dependency CVEs and bugs in the diff are different jobs for the reviewer, and one lockfile
    # can hold hundreds of CVEs — listed together they push the code findings out of the comment.
    code = [f for f in result.findings if f.rule_id != "ARX-DEP"]
    deps = [f for f in result.findings if f.rule_id == "ARX-DEP"]
    counts, dep_counts = Counter(f.severity for f in code), Counter(f.severity for f in deps)
    severities = sorted(Severity, reverse=True)
    out = [f"### 🛡️ Armorix v{__version__}", ""]
    if not result.findings:
        out.append(f"**{t('clean')}** — {result.files} {t('files').strip().lower()}, {result.lines:,} {t('lines')}.")
    else:
        out.append("| | " + " | ".join(f"{EMOJI[s]} {i18n.severity(lang, s)}" for s in severities) + " |")
        out.append("|" + "---|" * (len(Severity) + 1))
        out.append(f"| {t('in_code')} | " + " | ".join(str(counts.get(s, 0)) for s in severities) + " |")
        if deps:
            out.append(f"| {t('in_deps')} | " + " | ".join(str(dep_counts.get(s, 0)) for s in severities) + " |")
        out.append("")
        if code:
            out.append("| | Rule | Location | Finding |")
            out.append("|---|---|---|---|")
            for f in code[:100]:
                title, message, _ = i18n.localize(f, lang)
                out.append(f"| {EMOJI[f.severity]} | `{f.rule_id}` {f.cwe} | `{f.file}:{f.line}` | **{title}** — {message.replace('|', '\\|')} |")
            if len(code) > 100:
                out.append(f"\n… +{len(code) - 100}")
        if deps:
            out.append(f"\n<details><summary>{t('dep_title', n=len(deps))}</summary>\n")
            out.append("| | Package | Fix |")
            out.append("|---|---|---|")
            for f in deps[:60]:
                d = f.data
                out.append(f"| {EMOJI[f.severity]} | `{d['pkg']}@{d['ver']}` ({d['n']} CVE) | {d['target'] or '—'} |")
            if len(deps) > 60:
                out.append(f"\n… +{len(deps) - 60}")
            out.append("\n</details>")
    extra = []
    if result.baselined:
        extra.append(f"{result.baselined} baseline")
    if result.suppressed:
        extra.append(f"{result.suppressed} armorix-ignore")
    if extra:
        out.append(f"\n<sub>Hidden: {', '.join(extra)}.</sub>")
    out.append(f"\n<sub>{t('zero')} · {result.seconds:.1f}s</sub>")
    return "\n".join(out) + "\n"
