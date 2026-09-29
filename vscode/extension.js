// Armorix for VS Code — runs the local `armorix` engine, shows findings as diagnostics,
// and offers "Fix with local AI" code actions. Nothing is sent over the network.
const vscode = require("vscode");
const { execFile } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const LANGS = new Set(["javascript", "javascriptreact", "typescript", "typescriptreact", "python", "c", "cpp"]);
const RANK = { low: 1, medium: 2, high: 3, critical: 4 };
const UI = {
  uz: { fix: "Armorix: AI bilan tuzatish", fixing: "Armorix: lokal AI patch yozmoqda…", scanning: "Armorix tekshirmoqda…", verified: "✓ Patch qayta tekshirildi. Qo'llaysizmi?", apply: "Qo'llash", cancel: "Bekor qilish", rejected: "Patch rad etildi", notFound: "Armorix topilmadi. Desktop ilovani o'rnating yoki sozlamalarda armorix.path ni ko'rsating.", issues: "muammo", clean: "muammo yo'q", manba: "manba", diffTitle: "Armorix patch (✓ tekshirildi)" },
  ru: { fix: "Armorix: исправить с ИИ", fixing: "Armorix: локальный ИИ пишет патч…", scanning: "Armorix проверяет…", verified: "✓ Патч проверен повторным сканированием. Применить?", apply: "Применить", cancel: "Отмена", rejected: "Патч отклонён", notFound: "Armorix не найден. Установите приложение или укажите armorix.path в настройках.", issues: "проблем", clean: "проблем нет", manba: "источник", diffTitle: "Патч Armorix (✓ проверен)" },
  en: { fix: "Armorix: fix with local AI", fixing: "Armorix: local AI is writing a patch…", scanning: "Armorix is scanning…", verified: "✓ Patch verified by re-scan. Apply it?", apply: "Apply", cancel: "Cancel", rejected: "Patch rejected", notFound: "Armorix not found. Install the desktop app or set armorix.path in settings.", issues: "issues", clean: "no issues", manba: "source", diffTitle: "Armorix patch (✓ verified)" },
};

let diagnostics, status, output;
const cwe = (id) => vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${String(id).replace("CWE-", "")}.html`);
const cfg = () => vscode.workspace.getConfiguration("armorix");
const t = () => UI[cfg().get("language")] || UI.en;

// The CLI: explicit setting → PATH → the desktop app's bundled engine.
function candidates() {
  const own = cfg().get("path");
  const exe = process.platform === "win32" ? "armorix.exe" : "armorix";
  const list = own ? [own] : [];
  list.push("armorix");
  if (process.platform === "linux") list.push("/opt/Armorix/resources/engine/armorix");
  if (process.platform === "darwin") list.push("/Applications/Armorix.app/Contents/Resources/engine/armorix");
  if (process.platform === "win32") list.push(path.join(process.env.LOCALAPPDATA || "", "Programs", "Armorix", "resources", "engine", exe));
  return list;
}

let resolved = null;
function run(args, cwd) {
  const tryOne = (list) =>
    new Promise((resolve, reject) => {
      const [bin, ...rest] = list;
      if (!bin) return reject(new Error("not-found"));
      execFile(bin, args, { cwd, maxBuffer: 64 * 1024 * 1024, timeout: 15 * 60 * 1000, env: { ...process.env, PYTHONIOENCODING: "utf-8" } }, (err, stdout, stderr) => {
        if (err && (err.code === "ENOENT" || err.code === "EACCES")) return tryOne(rest).then(resolve, reject);
        resolved = bin;
        if (stderr) output.appendLine(stderr.trim());
        resolve(stdout);
      });
    });
  return tryOne(resolved ? [resolved] : candidates());
}

function toDiagnostics(findings) {
  const min = RANK[cfg().get("minSeverity")] || 1;
  const byFile = new Map();
  for (const f of findings) {
    if ((RANK[f.severity] || 1) < min) continue;
    const line = Math.max(0, f.line - 1);
    const range = new vscode.Range(line, Math.max(0, f.column - 1), line, 1000);
    const sev = f.severity === "critical" || f.severity === "high" ? vscode.DiagnosticSeverity.Error : f.severity === "medium" ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Information;
    const d = new vscode.Diagnostic(range, `${f.severity_label || f.severity.toUpperCase()} · ${f.title}: ${f.message}\n→ ${f.fix}`, sev);
    d.source = "Armorix";
    d.code = { value: `${f.rule_id} · ${f.cwe}`, target: cwe(f.cwe) };
    d.armorix = { rule: f.rule_id, line: f.line };
    const list = byFile.get(f.file) || [];
    list.push(d);
    byFile.set(f.file, list);
    d._trace = f.trace || [];
  }
  return byFile;
}

function attachTrace(uri, list) {
  for (const d of list) {
    d.relatedInformation = (d._trace || [])
      .filter((s) => s.label !== "sink")
      .map((s) => new vscode.DiagnosticRelatedInformation(new vscode.Location(uri, new vscode.Position(s.line - 1, 0)), `${s.label_text || s.label}: ${s.code}`));
  }
  return list;
}

function updateStatus() {
  let n = 0;
  diagnostics.forEach((_, list) => (n += list.length));
  status.text = n ? `$(shield) Armorix: ${n} ${t().issues}` : `$(shield) Armorix: ${t().clean}`;
  status.backgroundColor = n ? new vscode.ThemeColor("statusBarItem.warningBackground") : undefined;
}

async function scanDocument(doc) {
  if (!doc || doc.uri.scheme !== "file" || !LANGS.has(doc.languageId)) return;
  try {
    const out = await run(["scan", doc.fileName, "--format", "json", "--fail-on", "none", "--lang", cfg().get("language")], path.dirname(doc.fileName));
    const data = JSON.parse(out);
    const list = [...toDiagnostics(data.findings).values()].flat();
    diagnostics.set(doc.uri, attachTrace(doc.uri, list));
    updateStatus();
  } catch (err) {
    report(err);
  }
}

async function scanWorkspace() {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) return;
  await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: t().scanning }, async () => {
    try {
      const out = await run(["scan", folder.uri.fsPath, "--format", "json", "--fail-on", "none", "--lang", cfg().get("language")], folder.uri.fsPath);
      const data = JSON.parse(out);
      diagnostics.clear();
      for (const [file, list] of toDiagnostics(data.findings)) {
        const uri = vscode.Uri.file(path.join(folder.uri.fsPath, file));
        diagnostics.set(uri, attachTrace(uri, list));
      }
      updateStatus();
    } catch (err) {
      report(err);
    }
  });
}

async function fixFinding(uri, rule, line) {
  const doc = await vscode.workspace.openTextDocument(uri);
  if (doc.isDirty) await doc.save();
  const result = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: t().fixing }, async () => {
    try {
      return JSON.parse(await run(["patch", uri.fsPath, "--line", String(line), "--rule", rule], path.dirname(uri.fsPath)));
    } catch (err) {
      report(err);
      return null;
    }
  });
  if (!result) return;
  if (!result.ok || !result.verified) {
    vscode.window.showWarningMessage(`${t().rejected}: ${result.error || result.reason}`);
    return;
  }
  // Preview: original ↔ patched, then ask.
  const tmp = path.join(os.tmpdir(), `armorix-${Date.now()}-${path.basename(uri.fsPath)}`);
  fs.writeFileSync(tmp, result.new_text, "utf8");
  await vscode.commands.executeCommand("vscode.diff", uri, vscode.Uri.file(tmp), `${path.basename(uri.fsPath)} — ${t().diffTitle}`, { preview: true });
  const choice = await vscode.window.showInformationMessage(t().verified, { modal: true }, t().apply);
  if (choice === t().apply) {
    const edit = new vscode.WorkspaceEdit();
    edit.replace(uri, new vscode.Range(0, 0, doc.lineCount, 0), result.new_text);
    await vscode.workspace.applyEdit(edit);
    await doc.save();
    await vscode.commands.executeCommand("workbench.action.closeActiveEditor");
    await scanDocument(doc);
  }
  fs.rmSync(tmp, { force: true });
}

function report(err) {
  output.appendLine(String(err && err.stack ? err.stack : err));
  if (String(err.message || err).includes("not-found")) vscode.window.showErrorMessage(t().notFound);
}

class FixProvider {
  provideCodeActions(document, range, context) {
    return context.diagnostics
      .filter((d) => d.source === "Armorix" && d.armorix && !/ARX-DEP|ARX-SECRET-HISTORY|ARX-NOAUTH/.test(d.armorix.rule))
      .map((d) => {
        const action = new vscode.CodeAction(t().fix, vscode.CodeActionKind.QuickFix);
        action.command = { command: "armorix.fixFinding", title: t().fix, arguments: [document.uri, d.armorix.rule, d.armorix.line] };
        action.diagnostics = [d];
        action.isPreferred = true;
        return action;
      });
  }
}

function activate(context) {
  diagnostics = vscode.languages.createDiagnosticCollection("armorix");
  output = vscode.window.createOutputChannel("Armorix");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.command = "armorix.scanWorkspace";
  status.text = "$(shield) Armorix";
  status.tooltip = "Armorix — offline AI code auditor";
  status.show();

  context.subscriptions.push(
    diagnostics, output, status,
    vscode.commands.registerCommand("armorix.scanFile", () => scanDocument(vscode.window.activeTextEditor?.document)),
    vscode.commands.registerCommand("armorix.scanWorkspace", scanWorkspace),
    vscode.commands.registerCommand("armorix.fixFinding", fixFinding),
    vscode.commands.registerCommand("armorix.clear", () => { diagnostics.clear(); updateStatus(); }),
    vscode.languages.registerCodeActionsProvider([...LANGS].map((language) => ({ language, scheme: "file" })), new FixProvider(), { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
    vscode.workspace.onDidSaveTextDocument((doc) => cfg().get("scanOnSave") && scanDocument(doc)),
    vscode.workspace.onDidOpenTextDocument((doc) => cfg().get("scanOnOpen") && scanDocument(doc)),
    vscode.workspace.onDidCloseTextDocument((doc) => diagnostics.delete(doc.uri))
  );
  if (cfg().get("scanOnOpen")) vscode.workspace.textDocuments.forEach(scanDocument);
  return { diagnostics }; // exposed for tests
}

function deactivate() {}

module.exports = { activate, deactivate };
