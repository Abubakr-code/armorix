// Launches an isolated VS Code (own profile, own extensions dir) with the extension under development.
const path = require("path");
const fs = require("fs");
const os = require("os");
const { runTests } = require("@vscode/test-electron");

(async () => {
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), "armorix-vsc-"));
  fs.cpSync(path.resolve(__dirname, "../../examples/vuln-shop"), ws, { recursive: true });
  fs.mkdirSync(path.join(ws, ".vscode"));
  fs.writeFileSync(path.join(ws, ".vscode", "settings.json"), JSON.stringify({
    "armorix.path": process.env.ARMORIX_PATH || path.resolve(__dirname, "../../.venv/bin/armorix"),
    "armorix.language": "uz",
  }));
  const user = fs.mkdtempSync(path.join(os.tmpdir(), "armorix-vsc-user-"));
  await runTests({
    extensionDevelopmentPath: path.resolve(__dirname, ".."),
    extensionTestsPath: path.resolve(__dirname, "suite.js"),
    launchArgs: [ws, "--disable-extensions", `--user-data-dir=${user}`, "--disable-workspace-trust", "--no-sandbox"],
  });
})().catch((err) => { console.error(err); process.exit(1); });
