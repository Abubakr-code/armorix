// Launches an isolated VS Code (own profile, own extensions dir) with the extension under development.
// The workspace is hostile on purpose: its .vscode/settings.json points armorix.path at a trap program —
// the extension must ignore it (only the user's own setting may choose what runs).
const path = require("path");
const fs = require("fs");
const os = require("os");
const { runTests } = require("@vscode/test-electron");

(async () => {
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), "armorix-vsc-"));
  fs.cpSync(path.resolve(__dirname, "../../examples/vuln-shop"), ws, { recursive: true });
  const marker = path.join(os.tmpdir(), `armorix-trap-${process.pid}`);
  const trap = path.join(ws, "trap.sh");
  fs.writeFileSync(trap, `#!/bin/sh\ntouch "${marker}"\n`, { mode: 0o755 });
  fs.mkdirSync(path.join(ws, ".vscode"));
  fs.writeFileSync(path.join(ws, ".vscode", "settings.json"), JSON.stringify({ "armorix.path": trap, "armorix.language": "uz" }));

  const user = fs.mkdtempSync(path.join(os.tmpdir(), "armorix-vsc-user-"));
  fs.mkdirSync(path.join(user, "User"), { recursive: true });
  fs.writeFileSync(path.join(user, "User", "settings.json"), JSON.stringify({
    "armorix.path": process.env.ARMORIX_PATH || path.resolve(__dirname, "../../.venv/bin/armorix"),
  }));
  await runTests({
    extensionDevelopmentPath: path.resolve(__dirname, ".."),
    extensionTestsPath: path.resolve(__dirname, "suite.js"),
    launchArgs: [ws, "--disable-extensions", `--user-data-dir=${user}`, "--disable-workspace-trust", "--no-sandbox"],
  });
  if (fs.existsSync(marker)) {
    fs.rmSync(marker);
    throw new Error("SECURITY: the workspace's armorix.path was executed");
  }
  console.log("workspace armorix.path ignored ✓");
})().catch((err) => { console.error(err); process.exit(1); });
