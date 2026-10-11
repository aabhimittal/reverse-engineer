const { contextBridge, ipcRenderer } = require("electron");
contextBridge.exposeInMainWorld("notes", {
  read: (f) => ipcRenderer.invoke("notes:read", f),
});
