const assert = require("assert");
const path = require("path");
const vscode = require("vscode");

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 60000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { const v = await fn(); if (v) return v; await wait(300); }
  throw new Error("timed out");
}

exports.run = async () => {
  try { await body(); } catch (e) { console.log("TEST FAILURE:", e && e.stack || e); throw e; }
};

async function body() {
  const root = vscode.workspace.workspaceFolders[0].uri.fsPath;
  const ext = vscode.extensions.all.find((e) => e.packageJSON.name === "armorix");
  const api = await ext.activate();

  // 1) opening a file scans it and publishes diagnostics with trace + CWE link
  const uri = vscode.Uri.file(path.join(root, "server.js"));
  const doc = await vscode.workspace.openTextDocument(uri);
  await vscode.window.showTextDocument(doc);
  const diags = await until(() => { const d = vscode.languages.getDiagnostics(uri).filter((x) => x.source === "Armorix"); return d.length ? d : null; });
  const sqli = diags.find((d) => String(d.code.value).startsWith("ARX-SQLI"));
  assert.ok(sqli, "SQL injection reported");
  assert.match(sqli.message, /SQL in'ektsiya/);
  assert.strictEqual(sqli.severity, vscode.DiagnosticSeverity.Error);
  assert.ok(sqli.relatedInformation.length >= 1, "taint trace attached");
  assert.match(String(sqli.code.target), /cwe\.mitre\.org\/data\/definitions\/89/);
  console.log(`server.js: ${diags.length} diagnostics, e.g. line ${sqli.range.start.line + 1}: ${sqli.message.split("\n")[0].slice(0, 80)}`);

  // 2) the quick fix is offered on the finding
  await wait(1500); // let the editor settle (a rescan may still be in flight)
  const actions = await vscode.commands.executeCommand("vscode.executeCodeActionProvider", uri, sqli.range, vscode.CodeActionKind.QuickFix.value);
  const fix = actions.find((a) => /AI bilan tuzatish/.test(a.title));
  assert.ok(fix && fix.command.command === "armorix.fixFinding", "quick fix offered");
  console.log("quick fix:", fix.title);

  // 3) C++ file: use-after-free
  const cpp = vscode.Uri.file(path.join(root, "native", "session.cpp"));
  await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(cpp));
  const uaf = await until(() => vscode.languages.getDiagnostics(cpp).find((d) => String(d.code.value).startsWith("ARX-C-UAF")));
  console.log("session.cpp:", uaf.message.split("\n")[0].slice(0, 90));

  // 4) workspace scan fills other files, including dependency findings
  await vscode.commands.executeCommand("armorix.scanWorkspace");
  const all = await until(() => { let n = 0; api.diagnostics.forEach((_, l) => (n += l.length)); return n > 20 ? n : null; }, 120000);
  console.log("workspace diagnostics:", all);
}
