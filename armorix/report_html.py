"""Single-file, fully offline HTML report (no CDN, no fonts, no network)."""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime

from . import __version__, i18n
from .finding import Severity
from .scanner import ScanResult

FAMILY_NAMES = {"js": "JS/TS", "py": "Python", "c": "C/C++", "php": "PHP", "go": "Go", "java": "Java"}

CSS = """
:root{--paper:#f4f4f1;--card:#fff;--ink:#0d0d0f;--muted:#6f6f6a;--line:#dcdcd5;--accent:#2448ff;--code:#0d0d0f;--codeink:#e8e8e4;
--crit:#ff3b5c;--high:#ff7a1a;--med:#e0a100;--low:#3b82f6;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--paper:#0b0c0f;--card:#16171c;--ink:#efefeb;--muted:#8e8f97;--line:#26272e;--accent:#6f86ff;--code:#0f1013;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:40px 24px 80px}
header{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:28px}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:20px;letter-spacing:-.02em}
.logo{width:30px;height:30px;border-radius:8px;background:var(--accent);display:grid;place-items:center;color:#fff;font-size:15px}
h1{font-size:44px;line-height:1;letter-spacing:-.04em;margin:18px 0 8px;font-weight:800}
.meta{color:var(--muted);font-size:13px}.meta b{color:var(--ink);font-weight:600}
.badge{display:inline-flex;gap:6px;align-items:center;font:600 12px/1 ui-monospace,monospace;padding:6px 10px;border-radius:99px;border:1px solid var(--line);color:var(--muted)}
.badge i{width:7px;height:7px;border-radius:50%;background:#19d58a}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:28px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px 20px;cursor:pointer;text-align:left;color:inherit;font:inherit}
.stat b{display:block;font-size:44px;line-height:1;font-weight:800;letter-spacing:-.03em}
.stat span{font:600 11px/1 ui-monospace,monospace;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.stat.off{opacity:.4}.s-CRITICAL b{color:var(--crit)}.s-HIGH b{color:var(--high)}.s-MEDIUM b{color:var(--med)}.s-LOW b{color:var(--low)}
.tools{display:flex;gap:12px;margin-bottom:18px}
.tools input{flex:1;padding:12px 16px;border-radius:12px;border:1px solid var(--line);background:var(--card);color:var(--ink);font:inherit}
.f{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px 22px;margin-bottom:12px}
.f-top{display:flex;flex-wrap:wrap;align-items:center;gap:10px}
.sev{font:700 11px/1 ui-monospace,monospace;letter-spacing:.08em;padding:6px 9px;border-radius:6px;color:#fff}
.sev.CRITICAL{background:var(--crit)}.sev.HIGH{background:var(--high)}.sev.MEDIUM{background:var(--med)}.sev.LOW{background:var(--low)}
.cwe{font:600 12px/1 ui-monospace,monospace;color:var(--accent);text-decoration:none}
.title{font-weight:700;font-size:17px}.loc{margin-left:auto;font:13px ui-monospace,monospace;color:var(--muted)}
.msg{margin:10px 0 12px}
pre{margin:0;background:var(--code);color:var(--codeink);border-radius:12px;padding:14px 16px;overflow-x:auto;font:13px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace}
pre .ln{color:#6b6c75;user-select:none;display:inline-block;width:44px}
pre .lab{display:inline-block;min-width:74px;font-weight:700}.lab.source{color:#19d58a}.lab.flows{color:#8e8f97}.lab.sink{color:#ff5c7a}
.fix{margin-top:12px;padding:12px 14px;border-radius:12px;border:1px dashed var(--line);font-size:14px}.fix b{color:var(--accent)}
.empty{text-align:center;padding:80px 0;color:var(--muted)}.empty b{display:block;font-size:40px;color:#19d58a}
footer{margin-top:40px;color:var(--muted);font-size:12px;text-align:center}
@media (max-width:640px){.stats{grid-template-columns:repeat(2,1fr)}h1{font-size:34px}.loc{margin-left:0;width:100%}}
"""

JS = """
const cards=[...document.querySelectorAll('.f')],off=new Set(),q=document.getElementById('q');
function apply(){const t=q.value.toLowerCase();cards.forEach(c=>{c.hidden=off.has(c.dataset.sev)||(t&&!c.textContent.toLowerCase().includes(t))})}
document.querySelectorAll('.stat').forEach(b=>b.onclick=()=>{const s=b.dataset.sev;off.has(s)?off.delete(s):off.add(s);b.classList.toggle('off');apply()});
q.oninput=apply;
"""


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _code(f, lang: str = "en") -> str:
    if f.trace:
        rows = [f'<span class="lab {s.label}">{_e(i18n.ui(lang, s.label))}</span><span class="ln">{s.line}</span>{_e(s.code)}' for s in f.trace]
    else:
        rows = [f'<span class="ln">{f.line}</span>{_e(f.snippet)}']
    return "<pre>" + "\n".join(rows) + "</pre>"


def _card(f, lang: str) -> str:
    title, message, fix = i18n.localize(f, lang)
    return f"""<article class="f" data-sev="{f.severity.name}">
  <div class="f-top"><span class="sev {f.severity.name}">{_e(i18n.severity(lang, f.severity))}</span>
  <a class="cwe" href="https://cwe.mitre.org/data/definitions/{_e(f.cwe.split('-')[1])}.html">{_e(f.cwe)}</a>
  <span class="title">{_e(title)}</span><span class="loc">{_e(f.file)}:{f.line}</span></div>
  <p class="msg">{_e(message)}</p>{_code(f, lang)}
  <div class="fix"><b>{_e(i18n.ui(lang, "fix").capitalize())}</b> — {_e(fix)}</div>
</article>"""


def to_html(result: ScanResult, lang: str = "en") -> str:
    t = lambda key, **kw: i18n.ui(lang, key, **kw)  # noqa: E731
    counts = Counter(f.severity for f in result.findings)
    langs = ", ".join(f"{FAMILY_NAMES.get(k, k)} {v}" for k, v in result.languages.most_common()) or "—"
    stats = "".join(
        f'<button class="stat s-{s.name}" data-sev="{s.name}"><b>{counts.get(s, 0)}</b><span>{_e(i18n.severity(lang, s))}</span></button>'
        for s in sorted(Severity, reverse=True)
    )
    cards = "".join(_card(f, lang) for f in result.findings) or f'<div class="empty"><b>✓</b>{_e(t("none"))}</div>'
    when = datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"""<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Armorix — {_e(result.root.name)}</title><style>{CSS}</style></head><body><div class="wrap">
<header><div><div class="brand"><span class="logo">◈</span>Armorix</div>
<h1>{_e(t("report"))}</h1>
<div class="meta"><b>{_e(result.root)}</b><br>{result.files} {_e(t("files"))} ({_e(langs)}) · {result.lines:,} {_e(t("lines"))} · {result.seconds * 1000:.0f} ms · {when}</div></div>
<span class="badge"><i></i>{_e(t("offline"))}</span></header>
<section class="stats">{stats}</section>
<div class="tools"><input id="q" type="search" placeholder="{_e(t("filter"))}" aria-label="{_e(t("filter"))}"></div>
<main>{cards}</main>
<footer>{_e(t("footer", v=__version__))}</footer>
</div><script>{JS}</script></body></html>"""
