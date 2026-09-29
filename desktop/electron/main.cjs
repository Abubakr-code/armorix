// Armorix desktop shell: starts the local engine (`armorix serve`), then shows the UI.
const { app, BrowserWindow, dialog, ipcMain, shell } = require("electron");
const { spawn } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");
const readline = require("node:readline");

let engine = null;
let engineInfo = null;
let win = null;

function engineCommand() {
  if (app.isPackaged) {
    const dir = path.join(process.resourcesPath, "engine");
    const exe = process.platform === "win32" ? "armorix.exe" : "armorix";
    return { cmd: path.join(dir, exe), args: ["serve"], llama: path.join(process.resourcesPath, "llama") };
  }
  // Development: the engine's virtualenv next to this folder.
  const root = path.resolve(__dirname, "..", "..");
  const py = process.platform === "win32" ? path.join(root, ".venv", "Scripts", "python.exe") : path.join(root, ".venv", "bin", "python");
  const llama = process.env.ARMORIX_LLAMA_DIR || path.join(__dirname, "..", "vendor", "llama");
  return { cmd: fs.existsSync(py) ? py : "python3", args: ["-m", "armorix", "serve"], llama, cwd: root };
}

function startEngine() {
  return new Promise((resolve, reject) => {
    const { cmd, args, llama, cwd } = engineCommand();
    engine = spawn(cmd, args, {
      cwd: cwd || app.getPath("home"),
      env: { ...process.env, ARMORIX_LLAMA_DIR: llama, PYTHONUNBUFFERED: "1" },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    const timer = setTimeout(() => reject(new Error("engine did not start in 30 s")), 30000);
    readline.createInterface({ input: engine.stdout }).on("line", (line) => {
      if (line.startsWith("ARMORIX_READY ")) {
        clearTimeout(timer);
        engineInfo = JSON.parse(line.slice("ARMORIX_READY ".length));
        resolve(engineInfo);
      }
    });
    engine.stderr.on("data", (d) => process.stderr.write(`[engine] ${d}`));
    engine.on("error", (err) => { clearTimeout(timer); reject(err); });
    engine.on("exit", (code) => { if (!engineInfo) { clearTimeout(timer); reject(new Error(`engine exited (${code})`)); } });
  });
}

function stopEngine() {
  if (engine && engine.exitCode === null) engine.kill("SIGTERM");
}

function createWindow() {
  win = new BrowserWindow({
    width: 1320,
    height: 860,
    minWidth: 980,
    minHeight: 640,
    backgroundColor: "#0b0c0f",
    title: "Armorix",
    icon: path.join(__dirname, "..", "build", "icon.png"),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  // Links from reports open in the system browser, never inside the app.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/.test(url)) shell.openExternal(url);
    return { action: "deny" };
  });
  win.webContents.on("will-navigate", (e) => e.preventDefault());
  if (process.env.VITE_DEV_SERVER_URL) win.loadURL(process.env.VITE_DEV_SERVER_URL);
  else win.loadFile(path.join(__dirname, "..", "dist", "index.html"));
  if (process.env.ARMORIX_SMOKE) win.webContents.once("did-finish-load", () => smoke(win));
}

// CI / release check: pick a folder, click a quick action, screenshot, quit.
async function smoke(w) {
  const shot = async (name) => fs.writeFileSync(path.join(process.env.ARMORIX_SMOKE, name), (await w.webContents.capturePage()).toPNG());
  const click = (sel) => w.webContents.executeJavaScript(`document.querySelector(${JSON.stringify(sel)})?.click(); true`);
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  w.webContents.on("console-message", (e) => console.log("[renderer]", e.level, e.message));
  await wait(1500);
  await shot("1-start.png");
  await click(".folder");
  await wait(500);
  await click(`.quick button:nth-child(${process.env.ARMORIX_SMOKE_ACTION || 1})`);
  await wait(Number(process.env.ARMORIX_SMOKE_WAIT || 6000));
  await w.webContents.executeJavaScript(`document.querySelector(".thread").scrollTop = 0; true`);
  await shot("2-result.png");
  await w.webContents.executeJavaScript(`const t=document.querySelector(".thread"); t.scrollTop = t.scrollHeight; true`);
  await wait(300);
  await shot("3-bottom.png");
  app.quit();
}

ipcMain.handle("engine:info", async () => engineInfo);
ipcMain.handle("dialog:folder", async () => {
  if (process.env.ARMORIX_SMOKE_FOLDER) return process.env.ARMORIX_SMOKE_FOLDER;
  const res = await dialog.showOpenDialog(win, { properties: ["openDirectory"] });
  return res.canceled ? null : res.filePaths[0];
});
ipcMain.handle("dialog:model", async () => {
  const res = await dialog.showOpenDialog(win, { properties: ["openFile"], filters: [{ name: "GGUF model", extensions: ["gguf"] }] });
  return res.canceled ? null : res.filePaths[0];
});
ipcMain.handle("shell:open", async (_e, target) => {
  if (typeof target === "string" && /^https?:\/\/127\.0\.0\.1:\d+\/report\//.test(target)) return shell.openExternal(target);
  if (typeof target === "string" && fs.existsSync(target)) return shell.openPath(target);
  return null;
});

const single = app.requestSingleInstanceLock();
if (!single) app.quit();
else {
  app.on("second-instance", () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
  app.whenReady().then(async () => {
    try {
      await startEngine();
    } catch (err) {
      dialog.showErrorBox("Armorix", `The analysis engine could not start:\n${err.message}`);
      app.quit();
      return;
    }
    createWindow();
  });
}
app.on("window-all-closed", () => app.quit());
app.on("before-quit", stopEngine);
