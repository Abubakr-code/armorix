"""`armorix scan <path>` — terminal, JSON output and CI exit codes."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .finding import Severity
from . import fixer, i18n, runtime
from .ai import AIUnavailable, LocalAI
from .deps import osv
from .report_html import to_html
from .report_sarif import to_sarif
from .rules import ALL_RULES
from .scanner import ScanResult, scan

COLORS = {Severity.CRITICAL: "bold white on red", Severity.HIGH: "bold red", Severity.MEDIUM: "bold yellow", Severity.LOW: "cyan"}
ACCENT = "#7088ff"
FAMILY_NAMES = {"js": "JS/TS", "py": "Python"}


def render(result: ScanResult, console: Console, lang: str = "en") -> None:
    t = lambda key, **kw: i18n.ui(lang, key, **kw)  # noqa: E731
    langs = ", ".join(f"{FAMILY_NAMES.get(k, k)} {v}" for k, v in result.languages.most_common()) or "—"
    header = Text.assemble(
        ("ARMORIX ", f"bold {ACCENT}"), (f"v{__version__}", "dim"), (f"  ·  {t('tagline')}  ·  ", "dim"), (t("network"), "bold green"),
    )
    console.print(Panel(header, border_style=ACCENT, expand=False))
    pad = max(len(t(k)) for k in ("target", "files", "deps")) + 2
    console.print(f"[dim]{t('target'):<{pad}}[/]{escape(str(result.root))}")
    console.print(f"[dim]{t('files'):<{pad}}[/]{result.files} ({langs}) · {result.lines:,} {t('lines')} · {len(ALL_RULES)} {t('rules')}")
    if result.db_available:
        console.print(f"[dim]{t('deps'):<{pad}}[/]{t('deps_ok', n=f'{result.dependencies:,}')}\n")
    else:
        console.print(f"[dim]{t('deps'):<{pad}}[/][yellow]{t('deps_off')}[/]\n")

    width = max(len(t("source")), len(t("flows")), len(t("sink")))
    for f in result.findings:
        title, message, fix = i18n.localize(f, lang)
        sev = Text(f" {i18n.severity(lang, f.severity)} ", style=COLORS[f.severity])
        console.print(Text.assemble(sev, "  ", (f.cwe, f"bold {ACCENT}"), "  ", (title, "bold"), "  ", (f"{f.file}:{f.line}", "dim underline")))
        console.print(f"   {escape(message)}")
        if f.trace:
            colors = {"source": "green", "flows": "dim", "sink": "red"}
            for step in f.trace:
                label = f"[{colors[step.label]}]{t(step.label):<{width}}[/]"
                console.print(f"   {label} [dim]{step.line:>4} │[/] {escape(step.code[:120])}")
        else:
            console.print(f"   {' ' * width} [dim]{f.line:>4} │[/] {escape(f.snippet[:120])}")
        console.print(f"   [{ACCENT}]{t('fix')}[/] {escape(fix)}\n")

    counts = Counter(f.severity for f in result.findings)
    table = Table(show_header=False, box=None, padding=(0, 2))
    for sev in sorted(Severity, reverse=True):
        table.add_row(Text(f" {i18n.severity(lang, sev)} ", style=COLORS[sev]), str(counts.get(sev, 0)))
    console.print(Panel(table, title=t("summary"), title_align="left", border_style="dim", expand=False))
    verdict = f"[bold green]{t('clean')}[/]" if not result.findings else f"[bold]{t('issues', n=len(result.findings))}[/]"
    console.print(f"{verdict} · {t('time', ms=f'{result.seconds * 1000:.0f}')} · [green]{t('zero')}[/]")
    for err in result.errors:
        console.print(f"[yellow]skipped[/] {escape(err)}")


def to_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "tool": "armorix",
            "version": __version__,
            "target": str(result.root),
            "files": result.files,
            "lines": result.lines,
            "seconds": round(result.seconds, 3),
            "findings": [f.to_dict() for f in result.findings],
        },
        indent=2,
        ensure_ascii=False,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="armorix", description="Offline, AST-based vulnerability scanner.")
    parser.add_argument("--version", action="version", version=f"armorix {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    p_scan = sub.add_parser("scan", help="scan a file or project directory")
    p_scan.add_argument("path", nargs="?", default=".")
    p_scan.add_argument("--format", choices=["text", "json", "sarif", "html"], default="text")
    p_scan.add_argument("-o", "--output", help="write the report to a file (html defaults to armorix-report.html)")
    p_scan.add_argument("--staged", action="store_true", help="scan only files staged in git (what the next commit contains)")
    p_scan.add_argument("--lang", choices=list(i18n.LANGS), help="output language (default: $ARMORIX_LANG / $LANG / en)")
    p_scan.add_argument("--fail-on", default="high", choices=[s.name.lower() for s in Severity] + ["none"],
                        help="exit with code 1 when a finding of this severity or higher exists (default: high)")
    p_fix = sub.add_parser("fix", help="let the local AI patch findings; every patch is re-scanned before it counts")
    p_fix.add_argument("path", nargs="?", default=".")
    p_fix.add_argument("--apply", action="store_true", help="write verified patches (a .armorix.bak backup is kept)")
    p_fix.add_argument("--limit", type=int, default=8, help="maximum findings to patch (default 8)")
    p_fix.add_argument("--min-severity", default="high", choices=[s.name.lower() for s in Severity])
    p_fix.add_argument("--lang", choices=list(i18n.LANGS), help="output language")
    p_fix.add_argument("--model", help="Ollama model (default qwen2.5-coder:1.5b or $ARMORIX_MODEL)")

    p_scan.add_argument("--deep", action="store_true", help="pentest-style pass: + git history secrets, auth/IDOR checks, AI handler review (slow)")

    p_ai = sub.add_parser("ai", help="manage the local AI engine (bundled llama.cpp or an existing Ollama)")
    p_ai.add_argument("action", choices=["status", "setup", "import"])
    p_ai.add_argument("file", nargs="?", help="GGUF model file for `import` (air-gapped machines)")

    p_serve = sub.add_parser("serve", help="local JSON API for the desktop app (127.0.0.1 only)")
    p_serve.add_argument("--port", type=int, default=0)

    p_hook = sub.add_parser("hook", help="install a git pre-commit hook that blocks commits with critical findings")
    p_hook.add_argument("action", choices=["install", "uninstall"])
    p_hook.add_argument("path", nargs="?", default=".")
    p_hook.add_argument("--fail-on", default="critical", choices=[s.name.lower() for s in Severity])

    p_db = sub.add_parser("db", help="manage the offline vulnerability database (OSV)")
    p_db.add_argument("action", choices=["update", "status"])
    p_db.add_argument("--from", dest="from_dir", help="import OSV all.zip archives from a folder (USB / air-gapped transfer)")
    p_db.add_argument("--only", choices=list(osv.ECOSYSTEMS), help="update a single ecosystem")
    ns = parser.parse_args(argv)

    if ns.command == "db":
        return _db(ns)
    if ns.command == "fix":
        return _fix(ns)
    if ns.command == "hook":
        return _hook(ns)
    if ns.command == "ai":
        return _ai(ns)
    if ns.command == "serve":
        from .server import serve

        serve(ns.port)
        return 0

    if ns.staged:
        result = _scan_staged(ns.path)
        if result is None:
            print("not a git repository", file=sys.stderr)
            return 2
    elif ns.deep:
        from .deep import deep_scan

        try:
            ai = runtime.start()
        except AIUnavailable as exc:
            print(f"AI review skipped: {exc}", file=sys.stderr)
            ai = None
        with Console(stderr=True).status("deep scan…") as status:
            result = deep_scan(ns.path, ai, lambda ph, d, t, x="": status.update(f"{ph} {d}/{t} {x}"))
    else:
        result = scan(ns.path)
    if ns.format in {"json", "sarif", "html"}:
        lang = i18n.detect(ns.lang)
        payload = to_html(result, lang) if ns.format == "html" else {"json": to_json, "sarif": to_sarif}[ns.format](result)
        output = ns.output or ("armorix-report.html" if ns.format == "html" else None)
        if output:
            with open(output, "w", encoding="utf-8") as fh:
                fh.write(payload)
            print(f"{ns.format.upper()} report → {output}  ({len(result.findings)} findings)", file=sys.stderr)
        else:
            print(payload)
    else:
        console = Console(record=bool(ns.output), highlight=False)
        render(result, console, i18n.detect(ns.lang))
        if ns.output:
            console.save_text(ns.output)

    if ns.fail_on == "none":
        return 0
    threshold = Severity.parse(ns.fail_on)
    return 1 if any(f.severity >= threshold for f in result.findings) else 0


def _print_diff(console: Console, diff: str) -> None:
    for line in diff.splitlines()[2:]:  # drop ---/+++ headers
        style = "green" if line.startswith("+") else "red" if line.startswith("-") else "dim" if line.startswith("@@") else ""
        console.print(Text("   " + line, style=style))


def _fix(ns) -> int:
    lang = i18n.detect(ns.lang)
    t = lambda key, **kw: i18n.ui(lang, key, **kw)  # noqa: E731
    console = Console(highlight=False)
    try:
        if ns.model:
            ai = LocalAI(model=ns.model)
            ai.check()
        else:
            ai = runtime.start()
    except AIUnavailable as exc:
        console.print(f"[red]✗[/] {escape(str(exc))}")
        return 2
    root = Path(ns.path).resolve()
    before = scan(root, deps=False)
    threshold = Severity.parse(ns.min_severity)
    targets = [f for f in before.findings if f.severity >= threshold][: ns.limit]
    console.print(Panel(Text.assemble(("ARMORIX FIX ", f"bold {ACCENT}"), (f"· {ai.model} · ", "dim"), (t("localhost"), "bold green")),
                        border_style=ACCENT, expand=False))
    console.print(f"[dim]{t('to_patch', n=len(targets), sev=i18n.severity(lang, threshold))}[/]\n")

    patches = []
    for i, f in enumerate(targets, 1):
        title, _, _ = i18n.localize(f, lang)
        console.print(Text.assemble((f"[{i}/{len(targets)}] ", "dim"), (f" {i18n.severity(lang, f.severity)} ", COLORS[f.severity]), "  ",
                                    (title, "bold"), "  ", (f"{f.file}:{f.line}", "dim underline")))
        with console.status(f"[dim]{t('writing')}[/]", spinner="dots"):
            patch = fixer.propose(ai, root, f)
        if patch is None:
            console.print(f"   [yellow]{t('skipped')}[/] [dim]{t('skipped_cfg')}[/]\n")
            continue
        patches.append(patch)
        if patch.diff:
            _print_diff(console, patch.diff)
        mark = f"[bold green]{t('verified')}[/]" if patch.verified else f"[bold red]{t('rejected')}[/]"
        console.print(f"   {mark} [dim]{escape(patch.reason)} · {patch.seconds:.1f}s[/]\n")

    ok = [p for p in patches if p.verified]
    console.print(f"[bold]{len(ok)}/{len(patches)}[/] {t('passed')}.")
    if not ns.apply:
        if ok:
            console.print(f"[dim]{t('dry')}[/]")
        return 0
    applied = fixer.apply(root, patches)
    after = scan(root, deps=False)
    console.print(f"[green]{t('applied', n=len(applied))}[/] · [bold]{len(before.findings)} → {len(after.findings)}[/]")
    return 0


def _git(cwd, *args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True)


def _scan_staged(path: str) -> ScanResult | None:
    """Scans the exact staged content (`git show :file`), not the working tree."""
    top = _git(path, "rev-parse", "--show-toplevel")
    if top.returncode:
        return None
    repo = Path(top.stdout.decode().strip())
    names = _git(repo, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").stdout.decode().split("\0")
    with tempfile.TemporaryDirectory(prefix="armorix-staged-") as tmp:
        for name in filter(None, names):
            blob = _git(repo, "show", f":{name}")
            if blob.returncode == 0:
                target = Path(tmp) / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(blob.stdout)
        result = scan(tmp)
    result.root = repo
    return result


HOOK_MARK = "# armorix-pre-commit"


def _hook(ns) -> int:
    top = _git(ns.path, "rev-parse", "--git-path", "hooks")
    if top.returncode:
        print("not a git repository", file=sys.stderr)
        return 2
    hook = (Path(ns.path) / top.stdout.decode().strip()).resolve() / "pre-commit"
    if ns.action == "uninstall":
        if hook.exists() and HOOK_MARK in hook.read_text():
            hook.unlink()
            print(f"removed {hook}")
        return 0
    if hook.exists() and HOOK_MARK not in hook.read_text():
        print(f"{hook} already exists — add this line to it:\n  {sys.executable} -m armorix scan --staged --fail-on {ns.fail_on}", file=sys.stderr)
        return 1
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(f"""#!/bin/sh
{HOOK_MARK}
# Blocks the commit when staged files contain {ns.fail_on} (or worse) findings. Bypass once: git commit --no-verify
exec "{sys.executable}" -m armorix scan --staged --fail-on {ns.fail_on}
""")
    hook.chmod(0o755)
    print(f"installed {hook} (fails on {ns.fail_on})")
    return 0


def _ai(ns) -> int:
    if ns.action == "import":
        if not ns.file:
            print("usage: armorix ai import <model.gguf>", file=sys.stderr)
            return 2
        print(f"imported → {runtime.import_model(ns.file)}")
    elif ns.action == "setup":
        last = [0.0]

        def show(phase, done, total, name=""):
            if time.time() - last[0] > 0.5 or done == total:
                last[0] = time.time()
                pct = f"{done / total * 100:5.1f}%" if total else ""
                print(f"\r{name} {done / 1e6:8.1f} MB {pct}", end="", file=sys.stderr, flush=True)

        runtime.setup(show)
        print(file=sys.stderr)
    st = runtime.status()
    engine = "Ollama" if st["ollama"] else (st["engine"] or "not installed")
    print(f"engine: {engine}\nmodel:  {'ready' if st['model'] or st['ollama'] else 'not downloaded'}\nready:  {st['ready']}")
    return 0 if st["ready"] else 1


def _db(ns) -> int:
    if ns.action == "update":
        ecosystems = (ns.only,) if ns.only else tuple(osv.ECOSYSTEMS)
        osv.update(ecosystems, from_dir=ns.from_dir, log=lambda m: print(m, file=sys.stderr))
    info = osv.OsvDb().info()
    if not info:
        print("No database yet. Run: armorix db update", file=sys.stderr)
        return 1
    for eco, n in info["advisories"].items():
        print(f"{eco:>5}: {n:,} advisories")
    print(f"updated {info['updated']}  ·  {info['path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
