# Armorix Engine

Offline, AST-based vulnerability scanner for web developers. No account, no cloud,
no telemetry — the scan runs entirely on your machine.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

armorix scan examples/vuln-shop --lang uz        # terminal report (uz / ru / en)
armorix scan . --format html                     # → armorix-report.html (offline, single file)
armorix scan . --format sarif -o armorix.sarif   # GitHub code scanning / VS Code SARIF viewer
armorix scan . --fail-on critical                # CI: exit 1 on critical findings

armorix db update                                # one-time OSV download (npm + PyPI, ~250k advisories → 60 MB)
armorix db update --from /media/usb/osv          # air-gapped: import npm-all.zip / PyPI-all.zip from a folder

armorix fix examples/vuln-shop                   # local AI proposes patches, each one re-scanned (dry run)
armorix fix . --apply --limit 5                  # write verified patches (*.armorix.bak backups)

armorix hook install                             # git pre-commit: block commits with critical findings
```

The AI step needs [Ollama](https://ollama.com) and `ollama pull qwen2.5-coder:1.5b`. Armorix only talks to a
loopback endpoint; a remote model URL is refused unless `ARMORIX_ALLOW_REMOTE_AI=1`.

## How it works

1. **Parse** — every JS / TS / Python file is turned into an AST with tree-sitter.
2. **Track taint** — values from HTTP / CLI entry points (`req.query`, `request.args`, `sys.argv` …)
   are followed through assignments to dangerous sinks.
3. **Match rules** — deterministic, CWE-mapped rules decide what is a vulnerability.
   Findings with a proven source → sink path are `critical`; risky patterns without one are lower severity.
4. **Dependencies** — lockfiles (`package-lock.json`, `yarn.lock`, `requirements*.txt`, `poetry.lock`, `uv.lock`,
   `Pipfile.lock`) are matched against a local OSV snapshot: known CVEs and known-malicious packages.
5. **Fix** — the local model rewrites the enclosing function. A patch counts only if it parses, the finding is gone
   on re-scan, no issue count grows, it uses no invented names, and it avoids known self-defeating fixes.
   Rejected patches are retried once with the verifier's reason.
6. **Report** — terminal (uz / ru / en), HTML, SARIF, JSON; exit codes for CI and pre-commit.

## Rules

| ID | CWE | Detects |
|---|---|---|
| ARX-SQLI | CWE-89 | SQL built by concatenation / template / f-string / `%` / `.format` |
| ARX-NOSQL | CWE-943 | `req.body` fields used as MongoDB query values, `$where` with dynamic code |
| ARX-CMDI | CWE-78 | `child_process.exec`, `spawn(…, {shell:true})`, `os.system`, `subprocess(…, shell=True)` |
| ARX-EVAL | CWE-95 | `eval`, `new Function`, `vm.run*`, Python `eval` / `exec` |
| ARX-SSTI | CWE-1336 | `render_template_string`, `Template(…)`, Handlebars/EJS/Pug compile from input |
| ARX-XSS | CWE-79 | `res.send` of HTML with input, `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, Flask f-string HTML |
| ARX-PATH | CWE-22 | `fs.*`, `res.sendFile/download`, `open`, `send_file` with user-controlled paths |
| ARX-SSRF | CWE-918 | `fetch` / `axios` / `got` / `requests` / `httpx` / `urlopen` to user-controlled URLs |
| ARX-REDIRECT | CWE-601 | `res.redirect` / Flask `redirect` to request-supplied URLs |
| ARX-DESER | CWE-502 | `pickle`, `marshal`, `yaml.load` without SafeLoader, `node-serialize` |
| ARX-SECRET | CWE-798 | AWS / GitHub / Stripe / OpenAI / Slack / Google keys, private keys, high-entropy passwords, committed `.env` |
| ARX-JWT | CWE-347 | `alg: none`, `verify_signature: False` |
| ARX-CORS | CWE-942 | wildcard / reflected origin combined with credentials |
| ARX-TLS | CWE-295 | `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `verify=False` |
| ARX-DEBUG | CWE-489 | Flask `app.run(debug=True)`, Django `DEBUG = True` |
| ARX-WEAKHASH | CWE-328 | MD5 / SHA-1 |
| ARX-DEP | CWE-1395 | dependency versions with known CVEs (OSV / GHSA), known-malicious packages |

## Development

```bash
python -m pytest -q
```

## Desktop app

`desktop/` is an Electron shell around the engine: a chat where you give tasks
(“~/projects/shop ni chuqur tekshir”, “fix the issues”), live progress, findings, AI patches with diffs.

```bash
python packaging/prepare.py          # freeze the engine (PyInstaller) + fetch llama.cpp into desktop/vendor/
cd desktop && npm install
npm start                            # run from source
npm run dist:linux                   # → release/Armorix-linux-x86_64.AppImage and .deb
```

The AI engine is bundled (llama.cpp `llama-server`, ~40 MB); on first launch the app offers to download
the 1.1 GB model (or import a `.gguf` from a USB stick). An already-running Ollama is used automatically.

Releases for Linux, Windows and macOS are built by `.github/workflows/release.yml` when a `v*` tag is pushed.

## Deep scan

`armorix scan . --deep` (or “Chuqur tekshiruv” in the app) adds a slow, pentester-style pass:
secrets in the whole git history, project-level authentication check, IDOR heuristics,
and a local-AI review of every HTTP handler (reported as unconfirmed).
