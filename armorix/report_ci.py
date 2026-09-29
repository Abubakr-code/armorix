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
    counts = Counter(f.severity for f in result.findings)
    out = [f"### 🛡️ Armorix v{__version__}", ""]
    if not result.findings:
        out.append(f"**{t('clean')}** — {result.files} {t('files').strip().lower()}, {result.lines:,} {t('lines')}.")
    else:
        out.append("| " + " | ".join(f"{EMOJI[s]} {i18n.severity(lang, s)}" for s in sorted(Severity, reverse=True)) + " |")
        out.append("|" + "---|" * len(Severity))
        out.append("| " + " | ".join(str(counts.get(s, 0)) for s in sorted(Severity, reverse=True)) + " |")
        out.append("")
        out.append("| | Rule | Location | Finding |")
        out.append("|---|---|---|---|")
        for f in result.findings[:100]:
            title, message, _ = i18n.localize(f, lang)
            out.append(f"| {EMOJI[f.severity]} | `{f.rule_id}` {f.cwe} | `{f.file}:{f.line}` | **{title}** — {message.replace('|', '\\|')} |")
        if len(result.findings) > 100:
            out.append(f"\n… +{len(result.findings) - 100}")
    extra = []
    if result.baselined:
        extra.append(f"{result.baselined} baseline")
    if result.suppressed:
        extra.append(f"{result.suppressed} armorix-ignore")
    if extra:
        out.append(f"\n<sub>Hidden: {', '.join(extra)}.</sub>")
    out.append(f"\n<sub>{t('zero')} · {result.seconds:.1f}s</sub>")
    return "\n".join(out) + "\n"
