// The only bridge between the UI and the OS: engine address, folder pickers, opening files.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("armorix", {
  engine: () => ipcRenderer.invoke("engine:info"),
  chooseFolder: () => ipcRenderer.invoke("dialog:folder"),
  chooseModel: () => ipcRenderer.invoke("dialog:model"),
  open: (target) => ipcRenderer.invoke("shell:open", target),
  platform: process.platform,
});
