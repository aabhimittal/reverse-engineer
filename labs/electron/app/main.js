// Deliberately insecure demo app for the rex Electron lab. It is never run.
const { app, BrowserWindow, ipcMain, shell } = require("electron");
const fs = require("fs");
const path = require("path");
const config = require("./config");

function createWindow() {
  const win = new BrowserWindow({
    width: 900,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      preload: path.join(__dirname, "preload.js"),
    },
  });
  win.loadURL("http://notes.example.test/app");
}

// Renderer-callable RPC: reads any path the renderer names.
ipcMain.handle("notes:read", (_e, file) => fs.readFileSync(file, "utf8"));
ipcMain.handle("notes:write", (_e, file, text) => fs.writeFileSync(file, text));
ipcMain.on("open-link", (_e, url) => shell.openExternal(url));

app.whenReady().then(createWindow);
