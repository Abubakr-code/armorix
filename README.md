# Armorix

Offline code auditor for developers. AST taint analysis, secrets, vulnerable packages, CI / Docker / cloud misconfigurations —
and a local AI that fixes what it finds, with every patch re-scanned before you see it. No account, no cloud, no telemetry:
the scan runs entirely on your machine.

**Languages:** JavaScript · TypeScript · Python · PHP · Go · Java · C · C++ &nbsp;·&nbsp;
**Also:** GitHub Actions · Dockerfile · docker-compose · Kubernetes · Terraform · `.env` · npm / PyPI lockfiles

## Install

| | |
|---|---|
| **Desktop app** (Linux, Windows, macOS) | [Releases](https://github.com/Abubakr-code/armorix/releases/latest) — AppImage / .deb / .exe / .dmg. The .deb also puts `armorix` on your PATH. |
| **CLI — Linux / macOS / Kali** | `curl -fsSL https://abubakr-code.github.io/install.sh \| sh` |
| **CLI — Windows (PowerShell)** | `irm https://abubakr-code.github.io/install.ps1 \| iex` |
| **Docker** | `docker run --rm -v "$PWD:/src" ghcr.io/abubakr-code/armorix scan /src` |
| **GitHub Actions** | `uses: Abubakr-code/armorix@v0.3.0` (see below) |
| **VS Code** | `code --install-extension Armorix-vscode.vsix` (attached to every release) |

The CLI is a self-contained binary — no Python, no pip. The installers verify the download against `SHA256SUMS`;
`armorix update` upgrades a standalone install the same way. Behind a firewall set `ARMORIX_DOWNLOAD_BASE` to a mirror.

## Use

```bash
armorix scan .                                   # terminal report (uz / ru / en: --lang uz)
armorix scan . --format html                     # → armorix-report.html (offline, single file)
armorix scan . --format sarif -o armorix.sarif   # GitHub code scanning / any SARIF viewer
armorix scan . --format github                   # inline annotations in GitHub Actions
armorix scan . --format markdown                 # PR comment / job summary
armorix scan . --fail-on critical                # CI: exit 1 on critical findings

armorix scan . --write-baseline armorix-baseline.json   # accept today's findings …
armorix scan . --baseline armorix-baseline.json         # … and fail only on new ones

armorix db update                                # one-time OSV download (npm + PyPI, ~250k advisories)
armorix db update --from /media/usb/osv          # air-gapped: import the OSV all.zip files from a folder

armorix ai setup                                 # local AI (llama.cpp + Qwen2.5-Coder 1.5B, 1.1 GB, once)
armorix fix .                                    # AI patches, each one re-scanned (dry run)
armorix fix . --apply --limit 5                  # review the diffs, then write them (*.armorix.bak backups; -y skips the prompt)

armorix scan . --deep                            # + git history secrets, auth / IDOR checks, AI handler review
armorix hook install                             # git pre-commit: block commits with critical findings
armorix init --ci                                # armorix.toml + .github/workflows/armorix.yml
armorix rules                                    # every rule with its CWE
armorix update                                   # upgrade the standalone CLI
```

An existing [Ollama](https://ollama.com) with `qwen2.5-coder:1.5b` is used automatically. Armorix only talks to a loopback
endpoint; a remote model URL is refused unless `ARMORIX_ALLOW_REMOTE_AI=1`.

### Project settings

`armorix.toml` (or `.armorix.toml`) next to your code:

```toml
[scan]
exclude = ["legacy/", "public/vendor/*.js"]   # gitignore-style; .armorixignore works too
disable = ["ARX-WEAKHASH"]
min_severity = "medium"
include_tests = false                         # test/, __tests__/, *.test.js, test_*.py are skipped by default
baseline = "armorix-baseline.json"
```

Silence one finding in code: `// armorix-ignore: ARX-SQLI` (or `# armorix-ignore`) on the line or the line above;
`armorix-ignore-file` in the first lines skips a whole file.

### GitHub Actions

```yaml
jobs:
  armorix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Abubakr-code/armorix@v0.3.0
        with:
          fail-on: high                  # low | medium | high | critical | none
          # baseline: armorix-baseline.json
          # sarif: "true"                # then upload armorix.sarif with github/codeql-action/upload-sarif
```

Findings appear as annotations on the pull request diff and as a table in the job summary.

## How it works

1. **Parse** — every file is turned into an AST with tree-sitter (parallel workers; unchanged files come from a cache,
   so a re-scan of a large repo takes a moment).
2. **Track taint** — values from entry points (`req.query`, `request.args`, `$_GET`, `r.FormValue`, `@RequestParam`,
   Flask / FastAPI / Laravel route parameters, NestJS `@Body`, gin `ShouldBindJSON` …) are followed through assignments,
   helper-function parameters and return values to dangerous sinks, with lexical scopes. Numeric casts and escaping
   helpers (`intval`, `parseInt`, `strconv.Atoi`, `esc_html`, `$wpdb->prepare` …) stop the flow.
3. **Match rules** — deterministic, CWE-mapped rules decide what is a vulnerability. A proven source → sink path is
   `critical`; risky patterns without one get a lower severity.
4. **Dependencies** — lockfiles (`package-lock.json`, `yarn.lock`, `requirements*.txt`, `poetry.lock`, `uv.lock`,
   `Pipfile.lock`) are matched against a local OSV snapshot: known CVEs and known-malicious packages.
5. **Fix** — the local model rewrites the enclosing function. A patch counts only if it parses, the finding is gone on
   re-scan, no issue count grows, it uses no invented names or variables, and it avoids known self-defeating fixes.
   Rejected patches are retried once with the verifier's reason.
6. **Report** — terminal (uz / ru / en), HTML, PDF (desktop), SARIF, JSON, Markdown, GitHub annotations; exit codes for CI.

## Rules

| ID | CWE | Detects |
|---|---|---|
| ARX-SQLI | CWE-89 | SQL built from strings — JS/TS, Python, PHP (mysqli, PDO, Laravel DB, `$wpdb`), Go (`database/sql`, sqlx, gorm), Java (JDBC, JdbcTemplate, JPA) |
| ARX-NOSQL | CWE-943 | request objects as MongoDB queries, `$where` with dynamic code |
| ARX-CMDI | CWE-78 | shell commands from input — `exec`, `os.system`, `shell_exec`, backticks, `exec.Command("sh","-c",…)`, `Runtime.exec`, `ProcessBuilder` |
| ARX-EVAL | CWE-95 | `eval`, `new Function`, `vm.run*`, PHP `eval` / `assert`, Java `ScriptEngine` / SpEL |
| ARX-SSTI | CWE-1336 | templates compiled from input (Jinja2, Handlebars, EJS, Pug, Twig, Blade, Go `text/template`) |
| ARX-XSS | CWE-79 | unescaped input in HTML — `res.send`, `innerHTML`, `dangerouslySetInnerHTML`, PHP `echo`, Go `template.HTML` / `w.Write`, servlet writers |
| ARX-AUTOESCAPE | CWE-79 | template auto-escaping switched off, `mark_safe` / `Markup` on input |
| ARX-PATH | CWE-22 | file paths from input (`fs.*`, `open`, `file_get_contents`, `os.Open`, `new File`) |
| ARX-LFI | CWE-98 | PHP `include` / `require` of a user-chosen file |
| ARX-SSRF | CWE-918 | server requests to user-controlled URLs (`fetch`, `axios`, `requests`, curl, `http.Get`, `RestTemplate`) |
| ARX-REDIRECT | CWE-601 | redirects to request-supplied URLs |
| ARX-DESER | CWE-502 | `pickle`, `yaml.load`, `node-serialize`, PHP `unserialize`, Java `ObjectInputStream` / `XMLDecoder` |
| ARX-XXE | CWE-611 | XML parsers that resolve external entities (libxmljs `noent`, lxml, `DocumentBuilderFactory`, `LIBXML_NOENT`) |
| ARX-MASS | CWE-915 | the whole request body saved into a model |
| ARX-PROTO | CWE-1321 | deep merges / nested keys from input (prototype pollution) |
| ARX-REGEX | CWE-1333 | regular expressions built from input (ReDoS) |
| ARX-SECRET | CWE-798 | AWS / GitHub / GitLab / Stripe / OpenAI / Anthropic / Telegram / Slack / Google / npm / PyPI keys, DB URLs with passwords, private keys, committed `.env` |
| ARX-SIGNKEY | CWE-321 | JWT / session / Flask secret keys written in code |
| ARX-JWT | CWE-347 | `alg: none`, signature verification disabled |
| ARX-COOKIE | CWE-1004 | session / token cookies without HttpOnly / Secure |
| ARX-RANDOM | CWE-338 | tokens, OTPs, passwords from `Math.random`, `random`, `rand`, `java.util.Random`, `math/rand` |
| ARX-CORS | CWE-942 | wildcard / reflected origin combined with credentials |
| ARX-TLS | CWE-295 | certificate checks disabled (`rejectUnauthorized`, `verify=False`, `InsecureSkipVerify`, curl verify off, trust-all TrustManager) |
| ARX-CSRF | CWE-352 | `@csrf_exempt` views |
| ARX-DEBUG | CWE-489 | Flask `debug=True`, Django `DEBUG = True` |
| ARX-WEAKHASH | CWE-328 | MD5 / SHA-1 (password hashing with them reported higher) |
| ARX-PERMS / ARX-TMPFILE | CWE-732 / 377 | world-writable modes, `tempfile.mktemp` |
| ARX-C-BOF / GETS / UAF / DFREE / FMT / INTOVF / CMDI | CWE-120 / 242 / 416 / 415 / 134 / 190 / 78 | C / C++ memory safety |
| ARX-GHA-INJECT | CWE-78 | issue titles, branch names, commit messages expanded inside GitHub Actions `run:` |
| ARX-GHA-PWN | CWE-829 | `pull_request_target` / `workflow_run` jobs that check out the PR head |
| ARX-DOCKER | CWE-250 | root containers, secrets in `ENV` / `ARG`, `curl \| sh`, unpinned base images |
| ARX-CONTAINER | CWE-250 | `privileged`, Docker socket mounts, host namespaces, SYS_ADMIN (compose / Kubernetes) |
| ARX-TF | CWE-284 | public buckets, public databases, admin ports open to 0.0.0.0/0, encryption off (Terraform) |
| ARX-DEP | CWE-1395 | dependency versions with known CVEs (OSV / GHSA), known-malicious packages |

## Desktop app

`desktop/` — Electron around the engine: a dashboard with a security score and history, a findings browser with the code
and the taint path highlighted, side-by-side AI patches, watch mode (re-scan on save), rules on/off, PDF / HTML / SARIF
export, drag & drop, and a task chat (“~/projects/shop ni chuqur tekshir”). Updates are opt-in: the AppImage and the
Windows build update themselves.

```bash
python packaging/prepare.py          # freeze the engine (PyInstaller) + fetch llama.cpp into desktop/vendor/
cd desktop && npm install
npm start                            # run from source
npm run dist:linux                   # → release/Armorix-linux-x86_64.AppImage and .deb
```

## VS Code extension

`vscode/` — diagnostics on save (with the taint trace and CWE links) and a **Fix with local AI** quick fix that previews the
verified patch before applying it. Uses the desktop app's engine, a standalone install, or `armorix.path`.

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q
```

Releases (desktop apps, CLI archives, VS Code extension, Docker image, `SHA256SUMS`) are built by
`.github/workflows/release.yml` when a `v*` tag is pushed.
