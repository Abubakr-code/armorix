// Armorix desktop shell: shows the window at once, starts the local engine (`armorix serve`) in the
// background, and gives the UI a few native powers — folder dialogs, file watching, opening files in
// an editor, saving reports (incl. PDF), notifications and self-update from GitHub Releases.
const { app, BrowserWindow, Menu, dialog, ipcMain, nativeTheme, net, shell } = require("electron");
const { spawn, execFile } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const readline = require("node:readline");

// Ubuntu 24.04+ blocks the unprivileged user namespaces Chromium's sandbox needs; the .deb installs an AppArmor
// profile for that, an AppImage cannot — so an AppImage on such a system runs without the OS-level sandbox
// (the UI is a local page under a strict CSP either way).
if (process.platform === "linux" && process.env.APPIMAGE) {
  try {
    if (fs.readFileSync("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "utf8").trim() === "1") app.commandLine.appendSwitch("no-sandbox");
  } catch {
    /* no such setting: the sandbox works */
  }
}

// GPU fallback: on some machines (VMs without 3D acceleration, new Mesa under Xvfb, broken drivers) Chromium never
// paints a frame and the window would stay invisible. If the first paint does not come — or the GPU process dies —
// Armorix remembers it and restarts once with hardware acceleration off.
const gpuOffFlag = path.join(app.getPath("userData"), "gpu-disabled");
const gpuOff = Boolean(process.env.ARMORIX_DISABLE_GPU) || fs.existsSync(gpuOffFlag);
if (gpuOff) app.disableHardwareAcceleration();

function restartWithoutGpu(reason) {
  if (gpuOff) return false;
  console.error(`[armorix] ${reason} — restarting without GPU acceleration`);
  try {
    fs.mkdirSync(path.dirname(gpuOffFlag), { recursive: true });
    fs.writeFileSync(gpuOffFlag, `${new Date().toISOString()} ${reason}\n`);
  } catch {
    /* read-only profile: the env var below still carries the choice */
  }
  app.relaunch({ args: process.argv.slice(1), execPath: process.env.APPIMAGE || process.execPath });
  quitting = true;
  stopEngine();
  app.exit(0);
  return true;
}

app.on("child-process-gone", (_event, details) => {
  if (details.type === "GPU" && details.reason !== "clean-exit") restartWithoutGpu(`GPU process ${details.reason}`);
});

const REPO = "Abubakr-code/armorix";
const SITE = "https://abubakr-code.github.io";
const isMac = process.platform === "darwin";

let engine = null;
let engineInfo = null; // { port, token, version } once ready
let engineError = null;
let win = null;
let watcher = null;
let quitting = false;
let pendingPath = null; // folder passed on the command line / by a second instance

// ── engine ──────────────────────────────────────────────────────
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
  engineInfo = null;
  engineError = null;
  return new Promise((resolve, reject) => {
    const { cmd, args, llama, cwd } = engineCommand();
    engine = spawn(cmd, args, {
      cwd: cwd || app.getPath("home"),
      env: { ...process.env, ARMORIX_LLAMA_DIR: llama, PYTHONUNBUFFERED: "1" },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    const fail = (err) => {
      clearTimeout(timer);
      engineError = err.message;
      send("engine", { error: engineError });
      reject(err);
    };
    const timer = setTimeout(() => fail(new Error("engine did not start in 45 s")), 45000);
    readline.createInterface({ input: engine.stdout }).on("line", (line) => {
      if (line.startsWith("ARMORIX_READY ")) {
        clearTimeout(timer);
        engineInfo = JSON.parse(line.slice("ARMORIX_READY ".length));
        send("engine", engineInfo);
        resolve(engineInfo);
      }
    });
    engine.stderr.on("data", (d) => process.stderr.write(`[engine] ${d}`));
    engine.on("error", fail);
    engine.on("exit", (code) => {
      if (!engineInfo) return fail(new Error(`engine exited (${code})`));
      if (!quitting) {
        engineInfo = null;
        engineError = `engine stopped (${code})`;
        send("engine", { error: engineError });
      }
    });
  });
}

function stopEngine() {
  if (engine && engine.exitCode === null) engine.kill("SIGTERM");
}

function send(channel, payload) {
  if (win && !win.isDestroyed()) win.webContents.send(channel, payload);
}

// ── window ──────────────────────────────────────────────────────
const stateFile = () => path.join(app.getPath("userData"), "window.json");

function loadState() {
  try {
    return JSON.parse(fs.readFileSync(stateFile(), "utf8"));
  } catch {
    return { width: 1360, height: 880 };
  }
}

function saveState() {
  if (!win || win.isDestroyed()) return;
  const bounds = win.getNormalBounds();
  try {
    fs.writeFileSync(stateFile(), JSON.stringify({ ...bounds, maximized: win.isMaximized() }));
  } catch {
    /* read-only profile */
  }
}

function createWindow() {
  const state = loadState();
  win = new BrowserWindow({
    x: state.x,
    y: state.y,
    width: state.width || 1360,
    height: state.height || 880,
    minWidth: 1024,
    minHeight: 660,
    show: false,
    backgroundColor: nativeTheme.shouldUseDarkColors ? "#0b0c10" : "#f4f4f1",
    title: "Armorix",
    icon: path.join(__dirname, "..", "build", "icon.png"),
    autoHideMenuBar: !isMac,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
    },
  });
  if (state.maximized) win.maximize();
  let painted = false;
  win.once("ready-to-show", () => {
    painted = true;
    win.show();
    if (process.env.ARMORIX_SMOKE) smoke(win);
  });
  setTimeout(() => {
    if (painted || restartWithoutGpu("no frame painted in 12 s")) return;
    win.show(); // even without a confirmed paint, never leave the user with no window
  }, 12000);
  win.on("close", saveState);
  // Links open in the system browser, never inside the app.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/.test(url)) shell.openExternal(url);
    return { action: "deny" };
  });
  win.webContents.on("will-navigate", (e) => e.preventDefault());
  if (process.env.VITE_DEV_SERVER_URL) win.loadURL(process.env.VITE_DEV_SERVER_URL);
  else win.loadFile(path.join(__dirname, "..", "dist", "index.html"));
  win.webContents.on("did-finish-load", () => {
    if (pendingPath) send("open-path", pendingPath);
    pendingPath = null;
  });
}

function folderFromArgs(argv) {
  const candidates = argv.slice(app.isPackaged ? 1 : 2).filter((a) => !a.startsWith("-"));
  for (const c of candidates.reverse()) {
    try {
      const full = path.resolve(c);
      if (fs.statSync(full).isDirectory() && full !== path.resolve(__dirname, "..")) return full;
    } catch {
      /* not a path */
    }
  }
  return null;
}

// ── menu ────────────────────────────────────────────────────────
function buildMenu() {
  const act = (action) => () => send("menu", action);
  const template = [
    ...(isMac ? [{ role: "appMenu" }] : []),
    {
      label: "&File",
      submenu: [
        { label: "Open Folder…", accelerator: "CmdOrCtrl+O", click: act("open") },
        { label: "Scan Again", accelerator: "CmdOrCtrl+R", click: act("rescan") },
        { label: "Deep Scan", accelerator: "CmdOrCtrl+Shift+R", click: act("deep") },
        { type: "separator" },
        { label: "Export Report…", accelerator: "CmdOrCtrl+E", click: act("export") },
        { type: "separator" },
        { label: "Settings", accelerator: "CmdOrCtrl+,", click: act("settings") },
        { type: "separator" },
        isMac ? { role: "close" } : { role: "quit" },
      ],
    },
    { label: "&Edit", submenu: [{ role: "undo" }, { role: "redo" }, { type: "separator" }, { role: "cut" }, { role: "copy" }, { role: "paste" }, { role: "selectAll" }] },
    {
      label: "&View",
      submenu: [
        { label: "Overview", accelerator: "CmdOrCtrl+1", click: act("overview") },
        { label: "Findings", accelerator: "CmdOrCtrl+2", click: act("findings") },
        { label: "Assistant", accelerator: "CmdOrCtrl+3", click: act("assistant") },
        { label: "Search Findings", accelerator: "CmdOrCtrl+F", click: act("search") },
        { type: "separator" },
        { label: "Toggle Theme", accelerator: "CmdOrCtrl+Shift+L", click: act("theme") },
        { role: "resetZoom" }, { role: "zoomIn" }, { role: "zoomOut" },
        { type: "separator" },
        { role: "togglefullscreen" },
        ...(app.isPackaged ? [] : [{ role: "toggleDevTools" }, { role: "reload" }]),
      ],
    },
    {
      label: "&Help",
      submenu: [
        { label: "Website", click: () => shell.openExternal(SITE) },
        { label: "GitHub", click: () => shell.openExternal(`https://github.com/${REPO}`) },
        { label: "Check for Updates…", click: act("update") },
        { type: "separator" },
        { label: `About Armorix ${app.getVersion()}`, click: act("about") },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// ── file watching (re-scan on save) ─────────────────────────────
const IGNORED = /(^|[/\\])(\.git|node_modules|\.venv|venv|__pycache__|dist|build|\.next|\.cache|coverage)([/\\]|$)|\.armorix\.bak$/;

function watch(root) {
  unwatch();
  let timer = null;
  const changed = new Set();
  try {
    watcher = fs.watch(root, { recursive: true }, (_event, file) => {
      if (!file || IGNORED.test(file)) return;
      changed.add(file);
      clearTimeout(timer);
      timer = setTimeout(() => {
        send("fs-changed", { root, files: [...changed].slice(0, 20) });
        changed.clear();
      }, 1500);
    });
    watcher.on("error", () => unwatch());
    return true;
  } catch {
    return false;
  }
}

function unwatch() {
  if (watcher) watcher.close();
  watcher = null;
}

// ── editor ──────────────────────────────────────────────────────
// On Windows `code` is a .cmd script that only runs through cmd.exe, which would interpret & | < > ^ " % in a
// file name from the scanned (untrusted) repo — such names skip the editor and just get revealed in Explorer.
const CMD_META = /["&|<>^%!\r\n]/;

function openInEditor(file, line) {
  const target = `${file}:${Number(line) || 1}`;
  const win32 = process.platform === "win32";
  const tryCode = (bin) =>
    new Promise((ok) => {
      if (win32 && CMD_META.test(target)) return ok(false);
      const args = win32 ? ["-g", `"${target}"`] : ["-g", target];
      execFile(bin, args, { windowsHide: true, shell: win32, windowsVerbatimArguments: win32 }, (err) => ok(!err));
    });
  return (async () => {
    for (const bin of ["code", "codium", "cursor"]) {
      if (await tryCode(bin)) return "editor";
    }
    shell.showItemInFolder(file); // never "open" the file itself: that could execute it
    return "folder";
  })();
}

// ── reports ─────────────────────────────────────────────────────
const LOCAL_REPORT = /^http:\/\/127\.0\.0\.1:\d+\/report\/\w+\.(html|sarif|json)\?/;

async function saveReport({ url, format, name }) {
  if (typeof url !== "string" || !LOCAL_REPORT.test(url)) return null;
  const ext = { pdf: "pdf", html: "html", sarif: "sarif", json: "json" }[format] || "html";
  const res = await dialog.showSaveDialog(win, {
    defaultPath: path.join(app.getPath("documents"), `${name || "armorix-report"}.${ext}`),
    filters: [{ name: ext.toUpperCase(), extensions: [ext] }],
  });
  if (res.canceled || !res.filePath) return null;
  if (format === "pdf") {
    const hidden = new BrowserWindow({ show: false, webPreferences: { sandbox: true } });
    await hidden.loadURL(url);
    await new Promise((r) => setTimeout(r, 400));
    const data = await hidden.webContents.printToPDF({ printBackground: true, pageSize: "A4" });
    hidden.destroy();
    fs.writeFileSync(res.filePath, data);
  } else {
    const body = await (await net.fetch(url)).text();
    fs.writeFileSync(res.filePath, body, "utf8");
  }
  shell.showItemInFolder(res.filePath);
  return res.filePath;
}

// ── updates (opt-in; asks GitHub only for the latest version number) ──
function newer(a, b) {
  const pa = a.replace(/^v/, "").split(".").map(Number);
  const pb = b.replace(/^v/, "").split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) > (pb[i] || 0);
  return false;
}

function assetName() {
  if (process.platform === "win32") return "Armorix-win-x64.exe";
  if (isMac) return `Armorix-mac-${process.arch}.dmg`;
  return process.env.APPIMAGE ? "Armorix-linux-x86_64.AppImage" : "Armorix-linux-amd64.deb";
}

async function checkUpdate() {
  const res = await net.fetch(`https://api.github.com/repos/${REPO}/releases/latest`, { headers: { Accept: "application/vnd.github+json" } });
  if (!res.ok) throw new Error(`GitHub ${res.status}`);
  const rel = await res.json();
  const latest = String(rel.tag_name || "").replace(/^v/, "");
  const asset = (rel.assets || []).find((a) => a.name === assetName());
  const sums = (rel.assets || []).find((a) => a.name === "SHA256SUMS");
  return {
    sums: sums ? sums.browser_download_url : null,
    current: app.getVersion(),
    latest,
    available: Boolean(latest) && newer(latest, app.getVersion()),
    notes: String(rel.body || "").slice(0, 4000),
    url: asset ? asset.browser_download_url : rel.html_url,
    page: rel.html_url,
    selfUpdate: Boolean(process.env.APPIMAGE || process.platform === "win32") && Boolean(asset),
  };
}

async function download(url, dest, onProgress) {
  const res = await net.fetch(url);
  if (!res.ok) throw new Error(`download failed (${res.status})`);
  const total = Number(res.headers.get("content-length")) || 0;
  const out = fs.createWriteStream(dest);
  let done = 0;
  const reader = res.body.getReader();
  for (;;) {
    const { done: end, value } = await reader.read();
    if (end) break;
    done += value.length;
    out.write(Buffer.from(value));
    onProgress(done, total);
  }
  await new Promise((r) => out.end(r));
}

/** The installer must match the release's SHA256SUMS — a corrupted or swapped download is deleted, never run. */
async function verifyDownload(file, sumsUrl) {
  if (!sumsUrl) throw new Error("the release has no SHA256SUMS — not installing an unverified file");
  const res = await net.fetch(sumsUrl);
  if (!res.ok) throw new Error(`checksums unavailable (${res.status})`);
  const line = (await res.text()).split("\n").find((l) => l.trim().endsWith(` ${assetName()}`));
  const expected = line ? line.trim().split(/\s+/)[0].toLowerCase() : "";
  const actual = await new Promise((resolve, reject) => {
    const hash = require("node:crypto").createHash("sha256");
    fs.createReadStream(file).on("data", (d) => hash.update(d)).on("end", () => resolve(hash.digest("hex"))).on("error", reject);
  });
  if (!expected || expected !== actual) {
    fs.rmSync(file, { force: true });
    throw new Error("checksum mismatch — the download was discarded");
  }
}

async function installUpdate() {
  const info = await checkUpdate();
  if (!info.available) return { ok: false, reason: "up-to-date" };
  if (!info.selfUpdate) {
    shell.openExternal(info.url);
    return { ok: true, opened: true };
  }
  const progress = (done, total) => send("update-progress", { done, total });
  if (process.env.APPIMAGE) {
    const target = process.env.APPIMAGE;
    const tmp = `${target}.download`;
    await download(info.url, tmp, progress);
    await verifyDownload(tmp, info.sums);
    fs.chmodSync(tmp, 0o755);
    fs.renameSync(tmp, target);
    app.relaunch({ execPath: target });
    quitting = true;
    app.exit(0);
    return { ok: true };
  }
  const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "armorix-update-")), assetName());
  await download(info.url, tmp, progress);
  await verifyDownload(tmp, info.sums);
  spawn(tmp, [], { detached: true, stdio: "ignore" }).unref();
  quitting = true;
  app.quit();
  return { ok: true };
}

// ── CI / release check: screenshots of the main screens, then quit ──
async function smoke(w) {
  const shot = async (name) => fs.writeFileSync(path.join(process.env.ARMORIX_SMOKE, name), (await w.webContents.capturePage()).toPNG());
  const run = (js) => w.webContents.executeJavaScript(js);
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  w.webContents.on("console-message", (e) => console.log("[renderer]", e.level, e.message));
  await wait(Number(process.env.ARMORIX_SMOKE_START || 2500));
  await shot("0-onboarding.png");
  await run(`localStorage.setItem("armorix_settings", JSON.stringify({ ...JSON.parse(localStorage.getItem("armorix_settings") || "{}"), onboarded: true, lang: ${JSON.stringify(process.env.ARMORIX_SMOKE_LANG || "uz")}, theme: ${JSON.stringify(process.env.ARMORIX_SMOKE_THEME || "dark")} })); true`);
  w.webContents.reload();
  await wait(2500);
  await shot("1-home.png");
  if (process.env.ARMORIX_SMOKE_FOLDER) {
    send("open-path", process.env.ARMORIX_SMOKE_FOLDER);
    await wait(Number(process.env.ARMORIX_SMOKE_WAIT || 6000));
    await shot("2-overview.png");
    await run(`document.querySelector('[data-tab="findings"]')?.click(); true`);
    await wait(1500);
    await shot("3-findings.png");
    await run(`document.querySelector('[data-tab="history"]')?.click(); true`);
    await wait(800);
    await shot("4-history.png");
    if (process.env.ARMORIX_SMOKE_FIX) {
      await run(`document.querySelector('[data-tab="findings"]')?.click(); true`);
      await wait(800);
      await run(`document.querySelector('.detail .primary')?.click(); true`);
      await wait(Number(process.env.ARMORIX_SMOKE_FIX));
      await shot("6-fix.png");
      await run(`document.querySelector('.modal-foot .ghost')?.click(); true`);
    }
  }
  for (const view of (process.env.ARMORIX_SMOKE_VIEWS || "").split(",").filter(Boolean)) {
    send("menu", view);
    await wait(1200);
    await shot(`5-${view}.png`);
  }
  quitting = true;
  app.quit();
}

// ── IPC ─────────────────────────────────────────────────────────
ipcMain.handle("engine:info", async () => engineInfo || (engineError ? { error: engineError } : { pending: true }));
ipcMain.handle("engine:restart", async () => {
  stopEngine();
  try {
    return await startEngine();
  } catch (err) {
    return { error: err.message };
  }
});
ipcMain.handle("app:info", async () => ({
  version: app.getVersion(), platform: process.platform, arch: process.arch, appImage: Boolean(process.env.APPIMAGE),
  dark: nativeTheme.shouldUseDarkColors,
}));
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
  if (typeof target === "string" && /^https:\/\//.test(target)) return shell.openExternal(target);
  if (typeof target === "string" && /^http:\/\/127\.0\.0\.1:\d+\/report\//.test(target)) return shell.openExternal(target);
  // Local paths: folders only — opening a file could run it (a scanned repo is untrusted content).
  if (typeof target === "string" && fs.existsSync(target) && fs.statSync(target).isDirectory()) return shell.openPath(target);
  return null;
});
ipcMain.handle("shell:reveal", async (_e, target) => {
  if (typeof target === "string" && fs.existsSync(target)) shell.showItemInFolder(target);
});
ipcMain.handle("editor:open", async (_e, file, line) => (typeof file === "string" && fs.existsSync(file) ? openInEditor(file, line) : null));
ipcMain.handle("report:save", async (_e, opts) => saveReport(opts || {}));
ipcMain.handle("watch:start", async (_e, root) => (typeof root === "string" && fs.existsSync(root) ? watch(root) : false));
ipcMain.handle("watch:stop", async () => unwatch());
ipcMain.handle("update:check", async () => {
  try {
    return await checkUpdate();
  } catch (err) {
    return { error: err.message };
  }
});
ipcMain.handle("update:install", async () => {
  try {
    return await installUpdate();
  } catch (err) {
    return { error: err.message };
  }
});
ipcMain.handle("window:attention", async () => {
  if (win && !win.isFocused()) win.flashFrame(true);
});

// ── lifecycle ───────────────────────────────────────────────────
const single = app.requestSingleInstanceLock();
if (!single) app.quit();
else {
  pendingPath = folderFromArgs(process.argv) || process.env.ARMORIX_OPEN || null;
  app.on("second-instance", (_e, argv) => {
    const folder = folderFromArgs(argv);
    if (win) {
      if (win.isMinimized()) win.restore();
      win.focus();
      if (folder) send("open-path", folder);
    }
  });
  app.whenReady().then(() => {
    buildMenu();
    createWindow();
    startEngine().catch((err) => console.error("[engine]", err.message));
  });
}
app.on("window-all-closed", () => {
  quitting = true;
  app.quit();
});
app.on("before-quit", () => {
  quitting = true;
  unwatch();
  stopEngine();
});
