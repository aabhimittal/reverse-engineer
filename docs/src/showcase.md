# Showcase

Every transcript below is real output from files in this repository's `labs/` directory. Run them yourself;
nothing here is mocked.

## 1. "What does this Windows program do?" (a PE with capability imports)

```console
$ rex analyze crates/rex-binary/tests/fixtures/sample.exe --fail-on high
```

Imports like `CreateRemoteThread`, `VirtualAllocEx` and `WriteProcessMemory` show up as **process injection
(T1055)**, with the import names as evidence, in under 100 ms.

## 2. "Why does this binary crash on long input?" (no mitigations)

```console
$ rex analyze labs/build/vuln --fail-on high
  HIGH     NX: disabled                                      BIN-MITIGATION-NX
  HIGH     Calls memory-unsafe C library functions           BIN-UNSAFE-API
           • gets ← main
           • strcpy ← greet
rex: findings at or above 'high' (exit 3)
```

The `← main` shows the *caller*, resolved through the PLT, so you know which function to open.

## 3. "Document this API" (browser traffic to spec)

```console
$ rex web har2openapi labs/web/sample.har -o api.yaml     # 13 endpoints, schemas, bearer auth
$ rex analyze labs/web/sample.har
  HIGH     Credentials or form data sent over plain HTTP     WEB-CLEARTEXT
  MEDIUM   Capture contains live credentials                 WEB-CAPTURE-CREDENTIALS
           • /auth/login body field 'password': correc…aple (28 chars)
```

Values are masked in the report: rex tells you a password is in the capture without leaking it into your
terminal history or your CI logs.

## 4. "Is this desktop app safe to ship?" (Electron)

```console
$ rex analyze labs/electron/app.asar --fail-on high
  HIGH     nodeIntegration enabled in a renderer          ELECTRON-NODE-INTEGRATION
  HIGH     contextIsolation disabled                      ELECTRON-NO-CONTEXT-ISOLATION
  HIGH     Credentials embedded in the app                ELECTRON-SECRETS
           • config.js: AWS access key id AKIAI…MPLE (20 chars)
  MEDIUM   shell.openExternal called with a non-literal URL   ELECTRON-OPEN-EXTERNAL
rex: findings at or above 'high' (exit 3)
```

Plus a table of every IPC channel the main process exposes. See [Electron apps](web/electron.md).

## 5. "What can this .wasm do?" (WebAssembly)

```console
$ rex analyze labs/wasm/sample.wasm
  MEDIUM   Module reaches outside the sandbox through WASI   WASM-WASI-REACH
           • path_open: open files and directories
           • sock_connect: open outbound connections
```

## 6. "Where do I start in this repo?" (codebase)

```console
$ rex code map ~/src/unfamiliar-repo -o atlas.md
```

Entry points, HTTP routes, a PageRank-ranked "read this first" list, churn × complexity hotspots, and bus factor.

## 7. In CI, as a gate and in code scanning

```yaml
- run: rex analyze build/app --fail-on high -f sarif -o rex.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: rex.sarif }
```
