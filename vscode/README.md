# Armorix for VS Code

Offline AI code auditor. Findings appear as you save, with a one-click **Fix with local AI** —
every patch is re-scanned before you can apply it. Your code never leaves your machine.

- SQL injection, XSS, command injection, SSRF, path traversal, NoSQL injection, secrets, JWT/CORS/TLS misconfig
- C/C++: buffer overflow (CWE-120/787), use-after-free (CWE-416), double free, format strings, `gets`
- Vulnerable and malicious dependencies (offline OSV database)
- Messages in O'zbek / Русский / English (`armorix.language`)

**Requires** the Armorix engine: install the desktop app from https://abubakr-code.github.io
(the extension finds it automatically) or `pip install git+https://github.com/Abubakr-code/armorix`.

Commands: *Armorix: Scan current file*, *Armorix: Scan workspace* (also the status-bar shield), *Armorix: Clear findings*.
