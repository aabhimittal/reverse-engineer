# Electron apps (app.asar)

## The mental model

An Electron app is **a web browser with a Node.js engine bolted to its side**. The browser half (the
*renderer*) draws windows from HTML and JavaScript. The Node half (the *main process*) can touch the
file system, spawn processes and open sockets. The two halves talk over **IPC**, a private
phone line.

Security in Electron is entirely a question of *how much of the Node half a web page is allowed to
reach*. Think of the main process as a bank vault and the renderer as the lobby. Good apps keep the
vault door shut and expose a few narrow teller windows (IPC channels). Bad apps knock the wall
down (`nodeIntegration: true`) so anyone who can run script in the lobby, via an XSS bug or a remote
page, walks straight into the vault.

All of this lives in one file you can read: `resources/app.asar`.

## What an ASAR is

Not an encrypted container, not compiled code. It is **a header of file offsets followed by the files**,
concatenated, uncompressed:

```text
 0      4      8            12           16 ...            8+N
 ├──────┼──────┼────────────┼────────────┼────────────────┼──────────────┐
 │  4   │  N   │ N-4        │ JSON len L │ JSON (padded)  │ file bytes…  │
 └──────┴──────┴────────────┴────────────┴────────────────┴──────────────┘
   Chromium "Pickle" framing                 {"files":{"main.js":{"size":845,"offset":"0"}, …}}
```

Electron patches `fs` so `require("./main.js")` reads straight out of the archive. Nothing is
hidden: the JavaScript inside is usually minified at worst. Native addons (`.node`) cannot be loaded
from inside an archive, so they sit next to it in `app.asar.unpacked/`.

## Triage in one command

```console
$ rex analyze labs/electron/app.asar
── IPC channels exposed by the main process (each is an RPC a renderer can call)
  channel      kind    defined in
  notes:read   handle  main.js
  notes:write  handle  main.js
  open-link    on      main.js
── Findings
  HIGH     contextIsolation disabled                 ELECTRON-NO-CONTEXT-ISOLATION
  HIGH     nodeIntegration enabled in a renderer     ELECTRON-NODE-INTEGRATION
  HIGH     Credentials embedded in the app           ELECTRON-SECRETS
           • config.js: AWS access key id AKIAI…MPLE (20 chars)
  MEDIUM   Window loads a page over plain HTTP       ELECTRON-LOADS-HTTP
  MEDIUM   shell.openExternal called with a non-literal URL   ELECTRON-OPEN-EXTERNAL
  LOW      Archive has no integrity hashes           ELECTRON-NO-INTEGRITY
```

Then read the code: `rex web asar labs/electron/app.asar -d out/` writes the files (any entry whose
path would escape `out/` is skipped).

## How to read the findings

| Finding | Why it matters | What an attacker needs first |
|---|---|---|
| `nodeIntegration: true` | Page script gets `require("child_process")` | Any script execution in that window: XSS, a third-party tag, a remote page |
| `contextIsolation: false` | Page and preload share one JS world, so the page can poison the preload's objects | Script execution in the page |
| `webSecurity: false` | Same-origin policy off for the window | Any hostile content loaded in it |
| `sandbox: false` | No Chromium sandbox behind the renderer | A renderer exploit |
| `shell.openExternal(variable)` | The OS decides how to open the string; `file:` and custom schemes can run things | Influence over the URL |
| Plain-HTTP `loadURL` | Content is replaceable on the wire | A network position |

**The IPC table is the real attack surface.** Each row is a function a renderer can call in the
privileged process. In the lab, `notes:read` reads *any path the renderer names*: a path traversal
primitive sitting behind a friendly name. The exercise is to trace each handler and ask what the worst
argument is.

## Integrity

An ASAR is not signed by itself. If an attacker can write to the install directory they can swap
`main.js` and it runs with the app's identity. Electron can verify archive hashes only when the
`EnableEmbeddedAsarIntegrityValidation` fuse is on and a matching hash is embedded in the executable;
check the fuses with `npx @electron/fuses read --app <path to app binary>`. rex reports whether the
*archive* carries hashes (`ELECTRON-NO-INTEGRITY`); it cannot see the fuse state of the executable.

## Limits (be skeptical of the output)

- Settings are found by pattern. A value computed at runtime (`nodeIntegration: isDev`) is invisible.
  Minified code that spreads options through variables can hide a setting.
- IPC channel names are found when passed as string literals to `ipcMain.handle/on/once`.
- Dependencies are listed with versions, not matched against advisories. Feed them to `npm audit` or
  OSV.
- rex does not unpack other Electron packaging (e.g. an unpacked `app/` folder). Point `rex code map`
  at that directory instead.

## Exercises

1. In the lab, name every IPC channel and write the one-line exploit for `notes:read`.
2. Fix `main.js` (enable isolation, remove Node integration, expose only a narrow `read(name)`
   that resolves inside one directory), re-pack with `labs/electron/make_asar.py`, and rerun `rex analyze`.
3. Write down which findings *cannot* disappear by editing JavaScript alone (hint: integrity).
