// The only bridge between the UI and the OS: engine address, dialogs, files, watching, reports, updates.
const { contextBridge, ipcRenderer, webUtils } = require("electron");

const on = (channel) => (callback) => {
  const listener = (_event, payload) => callback(payload);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
};

contextBridge.exposeInMainWorld("armorix", {
  engine: () => ipcRenderer.invoke("engine:info"),
  restartEngine: () => ipcRenderer.invoke("engine:restart"),
  appInfo: () => ipcRenderer.invoke("app:info"),
  chooseFolder: () => ipcRenderer.invoke("dialog:folder"),
  chooseModel: () => ipcRenderer.invoke("dialog:model"),
  open: (target) => ipcRenderer.invoke("shell:open", target),
  reveal: (target) => ipcRenderer.invoke("shell:reveal", target),
  openInEditor: (file, line) => ipcRenderer.invoke("editor:open", file, line),
  saveReport: (opts) => ipcRenderer.invoke("report:save", opts),
  watch: (root) => ipcRenderer.invoke("watch:start", root),
  unwatch: () => ipcRenderer.invoke("watch:stop"),
  checkUpdate: () => ipcRenderer.invoke("update:check"),
  installUpdate: () => ipcRenderer.invoke("update:install"),
  attention: () => ipcRenderer.invoke("window:attention"),
  pathForFile: (file) => {
    try {
      return webUtils.getPathForFile(file);
    } catch {
      return null;
    }
  },
  onEngine: on("engine"),
  onMenu: on("menu"),
  onOpenPath: on("open-path"),
  onFsChanged: on("fs-changed"),
  onUpdateProgress: on("update-progress"),
  platform: process.platform,
});
