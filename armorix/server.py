"""Local JSON API for the desktop app — 127.0.0.1 only, per-launch token.

The desktop shell starts `armorix serve`, reads the first stdout line
(`ARMORIX_READY {"port": …, "token": …}`) and talks to it with fetch().
Long work (scan / deep scan / AI fix / model download) runs as jobs that the UI polls.
"""

from __future__ import annotations

import json
import re
import secrets
import sys
import threading
import time
import traceback
import uuid
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__, fixer, history, i18n, runtime
from .ai import AIUnavailable
from .deep import deep_scan
from .deps import osv
from .deps.check import DependencyRule
from .finding import Severity
from .project import add_suppression, load_config, write_baseline
from .report_html import to_html
from .report_sarif import to_sarif
from .rules import ALL_RULES
from .scanner import ScanResult, scan

# ── task understanding (keyword based: reliable in uz / ru / en, no model needed) ──
DEEP = re.compile(r"chuqur|to'?liq|toliq|pentest|batafsil|deep|full|thorough|глубок|полн|пентест", re.IGNORECASE)
FIX = re.compile(r"tuzat|to'g'irla|fix|patch|yamoq|исправ|почин|патч", re.IGNORECASE)
PATH = re.compile(r"""["'«]([^"'»]+)["'»]|((?:~|/|[A-Za-z]:\\)[^\s,;]*)|((?:\.{1,2}/)?[\w.-]+/[\w./-]*)""")


def parse_task(text: str, fallback_path: str | None) -> dict:
    m = PATH.search(text)
    path = (m.group(1) or m.group(2) or m.group(3)) if m else None
    path = str(Path(path).expanduser()) if path else fallback_path
    kind = "fix" if FIX.search(text) else "deep" if DEEP.search(text) else "scan"
    return {"kind": kind, "path": path}


REPLY = {
    "uz": {"scan": "Tushundim — {path} papkasini tekshiraman.", "deep": "Tushundim — {path} papkasini chuqur tekshiraman: kod, kutubxonalar, git tarixi va AI tahlili. Katta loyihada bu uzoq davom etishi mumkin.",
           "fix": "Tushundim — {path} dagi muammolarni topib, AI bilan tuzatish takliflarini tayyorlayman. Har bir patch qayta tekshiriladi.",
           "nopath": "Qaysi papkani tekshiray? Chapdagi «Papka tanlash» tugmasini bosing yoki yo'lni yozing, masalan: ~/projects/shop ni tekshir",
           "missing": "Bu papka topilmadi: {path}"},
    "ru": {"scan": "Понял — проверяю папку {path}.", "deep": "Понял — глубокая проверка {path}: код, зависимости, история git и анализ ИИ. Для большого проекта это может занять много времени.",
           "fix": "Понял — найду проблемы в {path} и подготовлю исправления с ИИ. Каждый патч проверяется повторно.",
           "nopath": "Какую папку проверить? Нажмите «Выбрать папку» слева или напишите путь, например: проверь ~/projects/shop",
           "missing": "Папка не найдена: {path}"},
    "en": {"scan": "Got it — scanning {path}.", "deep": "Got it — deep scan of {path}: code, dependencies, git history and AI review. On a large project this can take a long time.",
           "fix": "Got it — I'll find the issues in {path} and prepare AI fixes. Every patch is re-verified.",
           "nopath": "Which folder should I check? Use “Choose folder” on the left or type a path, e.g.: scan ~/projects/shop",
           "missing": "Folder not found: {path}"},
}


# ── jobs ────────────────────────────────────────────────────────
class Job:
    def __init__(self, kind: str, params: dict):
        self.id = uuid.uuid4().hex[:12]
        self.kind, self.params = kind, params
        self.status, self.error = "running", None
        self.phase, self.done, self.total, self.detail = "", 0, 0, ""
        self.started, self.finished = time.time(), None
        self.result: dict | None = None
        self.scan: ScanResult | None = None
        self.patches: list = []
        self._cancel = False

    def progress(self, phase, done, total, detail=""):
        self.phase, self.done, self.total, self.detail = phase, done, total, detail

    def cancelled(self) -> bool:
        return self._cancel

    def view(self) -> dict:
        return {"id": self.id, "kind": self.kind, "status": self.status, "error": self.error, "phase": self.phase,
                "done": self.done, "total": self.total, "detail": self.detail, "elapsed": round((self.finished or time.time()) - self.started, 1),
                "result": self.result}


JOBS: dict[str, Job] = {}


def finding_view(f, lang: str, index: int) -> dict:
    title, message, fix = i18n.localize(f, lang)
    return {"id": index, "rule": f.rule_id, "cwe": f.cwe, "severity": f.severity.name.lower(), "severity_label": i18n.severity(lang, f.severity),
            "title": title, "message": message, "fix": fix, "file": f.file, "line": f.line, "column": f.column, "snippet": f.snippet,
            "fingerprint": f.fingerprint,
            "trace": [{"line": s.line, "code": s.code, "label": i18n.ui(lang, s.label)} for s in f.trace],
            "ai": bool(f.data.get("ai")), "fixable": f.rule_id not in {"ARX-DEP", "ARX-SECRET-HISTORY", "ARX-NOAUTH"} and not f.file.startswith(".env")}


def result_view(result: ScanResult, lang: str) -> dict:
    counts = Counter(f.severity.name.lower() for f in result.findings)
    return {"root": str(result.root), "files": result.files, "lines": result.lines, "dependencies": result.dependencies,
            "db": result.db_available, "seconds": round(result.seconds, 2), "counts": {s.name.lower(): counts.get(s.name.lower(), 0) for s in Severity},
            "languages": dict(result.languages), "suppressed": result.suppressed, "baselined": result.baselined, "cached": result.cached,
            "findings": [finding_view(f, lang, i) for i, f in enumerate(result.findings)]}


def _config(p: dict):
    """Project settings plus the overrides the desktop app sends (disabled rules, tests, extra excludes)."""
    cfg = load_config(Path(p["path"]).resolve())
    cfg.disable |= {str(r).upper() for r in p.get("disable") or []}
    cfg.exclude += [str(x) for x in p.get("exclude") or []]
    cfg.include_tests |= bool(p.get("include_tests"))
    return cfg


def rules_view(lang: str) -> list[dict]:
    out = []
    for rule in [*ALL_RULES, DependencyRule()]:
        title, why, fix = i18n.RULES.get(rule.id, {}).get(lang, ("", "", ""))
        out.append({"id": rule.id, "cwe": rule.cwe, "title": title or rule.title, "description": why or rule.description,
                    "fix": fix, "families": list(getattr(rule, "families", ("*",)))})
    return out


def _within_known_root(path: Path) -> Path | None:
    roots = {Path(r) for r in history.known_roots()} | {Path(j.params["path"]).resolve() for j in JOBS.values() if j.params.get("path")}
    for root in roots:
        base = root if root.is_dir() else root.parent
        try:
            path.relative_to(base)
            return base
        except ValueError:
            continue
    return None


def _run(job: Job) -> None:
    p, lang = job.params, job.params.get("lang", "en")
    try:
        if job.kind in {"scan", "deep"}:
            ai = None
            if job.kind == "deep":
                try:
                    job.progress("ai-start", 0, 0, "")
                    ai = runtime.start()
                except AIUnavailable:
                    ai = None  # deep scan still runs its non-AI parts
            started = time.perf_counter()
            cfg = _config(p)
            result = (deep_scan(p["path"], ai, job.progress, job.cancelled, cfg) if job.kind == "deep"
                      else scan(p["path"], progress=job.progress, cancelled=job.cancelled, config=cfg))
            result.seconds = time.perf_counter() - started
            job.scan = result
            entry = history.record(result, job.kind) if not job.cancelled() else None
            job.result = result_view(result, lang) | {"ai_used": ai is not None, "history": entry}
        elif job.kind == "fix":
            ai = runtime.start()
            root = Path(p["path"]).resolve()
            result = scan(root, deps=False, progress=job.progress, config=_config(p))
            prints = set(p.get("fingerprints") or [])
            wanted = set(p.get("findings") or [])
            if prints:
                targets = [f for f in result.findings if f.fingerprint in prints]
            else:
                targets = [f for i, f in enumerate(result.findings) if (i in wanted if wanted else f.severity >= Severity.HIGH)]
            targets = [f for f in targets if f.rule_id not in {"ARX-DEP", "ARX-SECRET-HISTORY", "ARX-NOAUTH"}][: int(p.get("limit", 8))]
            for i, f in enumerate(targets, 1):
                if job.cancelled():
                    break
                job.progress("fix", i, len(targets), f"{f.file}:{f.line}")
                patch = fixer.propose(ai, root, f)
                if patch is not None:
                    job.patches.append(patch)
            job.scan = result
            job.result = {"root": str(root), "patches": [
                {"id": i, "finding": finding_view(pt.finding, lang, i), "diff": pt.diff, "verified": pt.verified,
                 "reason": pt.reason, "seconds": round(pt.seconds, 1)} for i, pt in enumerate(job.patches)]}
        elif job.kind == "ai-setup":
            job.result = runtime.setup(job.progress)
        elif job.kind == "db-update":
            job.progress("download", 0, 0, "OSV")
            osv.update(log=lambda m: job.progress("download", 0, 0, m))
            job.result = osv.OsvDb().info()
        job.status = "cancelled" if job.cancelled() else "done"
    except Exception as exc:  # surfaced to the UI, never crashes the server
        job.status, job.error = "error", str(exc) or exc.__class__.__name__
        traceback.print_exc(file=sys.stderr)
    finally:
        job.finished = time.time()


def start_job(kind: str, params: dict) -> Job:
    job = Job(kind, params)
    JOBS[job.id] = job
    threading.Thread(target=_run, args=(job,), daemon=True).start()
    return job


# ── HTTP ────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    token = ""
    server_version = "Armorix"

    def log_message(self, *args):  # keep stdout clean for the READY line
        pass

    def _send(self, code: int, payload, content_type="application/json"):
        body = payload.encode() if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        ok = secrets.compare_digest(self.headers.get("X-Armorix-Token", ""), self.token) or \
            secrets.compare_digest(self._query().get("token", ""), self.token)
        if not ok:
            self._send(403, {"error": "forbidden"})
        return ok

    def _query(self) -> dict:
        from urllib.parse import parse_qs, urlparse
        return {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}") if length else {}

    def do_GET(self):
        if not self._authorized():
            return
        path = self.path.split("?")[0]
        if path == "/status":
            info = osv.OsvDb().info()
            return self._send(200, {"version": __version__, "ai": runtime.status(), "db": info, "lang": i18n.detect()})
        m = re.fullmatch(r"/jobs/(\w+)", path)
        if m and m.group(1) in JOBS:
            return self._send(200, JOBS[m.group(1)].view())
        m = re.fullmatch(r"/report/(\w+)\.(html|sarif|json)", path)
        if m and m.group(1) in JOBS and JOBS[m.group(1)].scan is not None:
            job = JOBS[m.group(1)]
            lang = self._query().get("lang") or job.params.get("lang", "en")
            if m.group(2) == "sarif":
                return self._send(200, to_sarif(job.scan), "application/sarif+json")
            if m.group(2) == "json":
                from .cli import to_json
                return self._send(200, to_json(job.scan, lang), "application/json")
            return self._send(200, to_html(job.scan, lang), "text/html")
        q = self._query()
        lang = i18n.detect(q.get("lang"))
        if path == "/projects":
            return self._send(200, {"projects": history.projects()})
        if path == "/history":
            return self._send(200, {"scans": history.history(q.get("root", ""))})
        m = re.fullmatch(r"/scans/(\w+)", path)
        if m:
            loaded = history.load(m.group(1))
            if loaded is None:
                return self._send(404, {"error": "not found"})
            summary, findings = loaded
            return self._send(200, summary | {"findings": [finding_view(f, lang, i) for i, f in enumerate(findings)]})
        if path == "/rules":
            return self._send(200, {"rules": rules_view(lang)})
        if path == "/file":
            target = Path(q.get("path", "")).resolve()
            base = _within_known_root(target)
            if base is None or not target.is_file():
                return self._send(403, {"error": "file is outside the scanned projects"})
            if target.stat().st_size > 2_000_000:
                return self._send(413, {"error": "file too large to preview"})
            return self._send(200, {"path": str(target), "rel": target.relative_to(base).as_posix(),
                                    "text": target.read_text(encoding="utf-8", errors="replace")})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authorized():
            return
        path, body = self.path.split("?")[0], self._body()
        lang = i18n.detect(body.get("lang"))
        if path == "/task":
            intent = parse_task(body.get("text", ""), body.get("path"))
            texts = REPLY[lang]
            if not intent["path"]:
                return self._send(200, {"reply": texts["nopath"], "job": None})
            if not Path(intent["path"]).exists():
                return self._send(200, {"reply": texts["missing"].format(path=intent["path"]), "job": None})
            job = start_job(intent["kind"], {"path": intent["path"], "lang": lang})
            return self._send(200, {"reply": texts[intent["kind"]].format(path=intent["path"]), "job": job.id, "kind": intent["kind"], "path": intent["path"]})
        if path == "/jobs":
            kind = body.get("kind")
            if kind not in {"scan", "deep", "fix", "ai-setup", "db-update"}:
                return self._send(400, {"error": "unknown job kind"})
            job = start_job(kind, {**body, "lang": lang})
            return self._send(200, {"job": job.id})
        if path == "/ai/import":
            try:
                runtime.import_model(body.get("file", ""))
            except AIUnavailable as exc:
                return self._send(400, {"error": str(exc)})
            return self._send(200, runtime.status())
        if path == "/suppress":
            target = Path(body.get("path", "")).resolve()
            if _within_known_root(target) is None or not target.is_file():
                return self._send(403, {"error": "file is outside the scanned projects"})
            ok = add_suppression(target, int(body.get("line", 0)), str(body.get("rule", "")))
            return self._send(200 if ok else 400, {"ok": ok} if ok else {"error": "this file type has no comments — use a baseline instead"})
        if path == "/baseline":
            root = Path(body.get("root", "")).resolve()
            job = next((j for j in reversed(list(JOBS.values())) if j.scan is not None and j.scan.root == root), None)
            if job is None:
                return self._send(400, {"error": "scan the project first"})
            target = root / "armorix-baseline.json"
            n = write_baseline(target, job.scan.findings)
            cfg = root / "armorix.toml"
            if not cfg.exists() and not (root / ".armorix.toml").exists():
                cfg.write_text('[scan]\nbaseline = "armorix-baseline.json"\n', encoding="utf-8")
            return self._send(200, {"ok": True, "count": n, "path": str(target)})
        if path == "/projects/forget":
            return self._send(200, {"removed": history.forget(str(body.get("root", "")))})
        m = re.fullmatch(r"/jobs/(\w+)/cancel", path)
        if m and m.group(1) in JOBS:
            JOBS[m.group(1)]._cancel = True
            return self._send(200, {"ok": True})
        m = re.fullmatch(r"/jobs/(\w+)/apply", path)
        if m and m.group(1) in JOBS:
            job = JOBS[m.group(1)]
            chosen = [job.patches[i] for i in body.get("patches", []) if 0 <= i < len(job.patches) and job.patches[i].verified]
            applied = fixer.apply(Path(job.params["path"]).resolve(), chosen)
            after = scan(job.params["path"], deps=False)
            return self._send(200, {"applied": len(applied), "remaining": len(after.findings)})
        self._send(404, {"error": "not found"})


def make_server(port: int = 0) -> ThreadingHTTPServer:
    Handler.token = secrets.token_urlsafe(24)
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(port: int = 0) -> None:
    import signal

    httpd = make_server(port)
    # The desktop shell sends SIGTERM on quit: stop the AI engine we may have started.
    signal.signal(signal.SIGTERM, lambda *_: (runtime.stop(), sys.exit(0)))
    print("ARMORIX_READY " + json.dumps({"port": httpd.server_address[1], "token": Handler.token, "version": __version__}), flush=True)
    try:
        httpd.serve_forever()
    finally:
        runtime.stop()
