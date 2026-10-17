<div align="center">

# rex

**Point it at anything you need to understand: a binary, firmware, an APK, an Electron app, a `.wasm`, a HAR capture, a codebase.**
In seconds it tells you what it is, what it can do, what's risky and where to look next. One static binary. Never executes its input. Drivable by your AI coding agent.

[![CI](https://github.com/aabhimittal/reverse-engineer/actions/workflows/ci.yml/badge.svg)](https://github.com/aabhimittal/reverse-engineer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

</div>

```console
$ rex setup                               # wire rex into Claude Code / Cursor / Codex / Gemini / Claude Desktop (optional)
$ rex analyze ./app --fail-on high        # auto-detects what it is, exits 3 in CI on high findings
$ rex disasm ./a.out -F main              # annotated disassembly: imports resolved, strings inlined
$ rex diff old.bin new.bin                # which functions did the patch change?
$ rex analyze resources/app.asar          # Electron app: window security, IPC surface, secrets, deps
$ rex web har2openapi traffic.har         # undocumented API -> OpenAPI 3.1
$ rex code map ~/src/unfamiliar-repo      # where do I start reading?
```

Most reverse-engineering tools are excellent at one thing and a context switch away from the next.
`rex` is the **triage layer** across all of them. In seconds it tells you *what a thing is, what it can do,
what's risky about it, and where to look next*, then hands you off to Ghidra, a debugger or your editor.

## What it does

| Domain | Capabilities |
|---|---|
| **Native binaries** (ELF, PE, Mach-O, incl. fat) | Unified model of sections/imports/exports/symbols; **checksec** (NX, PIE/ASLR, RELRO, canary, FORTIFY, CFG, CET/BTI, signing, hardened runtime); classified strings (URLs, IPs, registry keys, secrets, commands); **50+ capability rules mapped to MITRE ATT&CK**; packer heuristics; imphash + TLSH; optional YARA-X. **Go**: version, modules, dependencies and build settings, plus every function name from the pclntab even in stripped builds (all Go targets). **.NET**: CLI metadata (assembly, references, types, P/Invoke imports fed to the capability rules). **PE** version info and manifest elevation/uiAccess. **ELF relocations** from every table (RELA, REL, PLT, RELR) and a GOT view (`rex relocs --got`: what lands in each slot, the PLT stub using it, RELRO), with a text-relocation finding |
| **Code recovery** (x86/x64 built in; **AArch64 and 32-bit ARM** via `--features multiarch`, linear disassembly for MIPS, PowerPC, RISC-V) | Recursive-descent function discovery seeded from symbols, `.eh_frame`, `.pdata`, `LC_FUNCTION_STARTS`; PLT/IAT/stub resolution; `main` inference in stripped binaries; basic blocks, CFGs (Mermaid/DOT), call graph, cross-references, cyclomatic complexity |
| **Firmware & blobs** | binwalk-style carving with per-format validators and exact sizing, entropy profile, extraction (gzip/uImage unwrapping), embedded credential and key checks |
| **Patch analysis** | Function-level binary diff: matches by name, instruction hash, then trigram similarity; flags small surgical changes. `rex compare old.json new.json` diffs two saved reports (findings, imports, capabilities, mitigations…) and `--fail-on` turns regressions into a failing CI step |
| **Android** | APK triage: binary manifest decoder, exported components (incl. implicit exports), deep links, permissions, DEX parser with checksum/signature validation, risky-API rules, TLS trust classes, native-lib hardening, signing |
| **Desktop & portable code** | **Electron `app.asar`**: BrowserWindow security settings (`nodeIntegration`, `contextIsolation`, `sandbox`…), the full IPC channel table, embedded secrets, source maps, native addons, bundled dependencies, safe extraction. **WebAssembly**: sections, imports/exports, WASI reach with call sites, memory limits, debug info, largest functions, instruction-level disassembly (`rex disasm x.wasm -F fn`) |
| **Web & APIs** | **HAR to OpenAPI 3.1** with path templating, JSON-schema inference, auth schemes; passive traffic audit (JWT decoding, cookies, CORS, cleartext); JS bundle analysis (endpoints with methods, secrets, sinks); source-map unpacking with path-traversal protection |
| **Codebases** | tree-sitter symbol extraction (Rust, Python, JS/TS, Go, Java), cross-language import graph, PageRank "read this first" ranking, routes for 11 web frameworks, entry points, stack detection, churn x complexity hotspots, bus factor, security smells |
| **AI (optional)** | `--ai` briefings, `rex ai explain`, `rex ai name` via Claude or a local Ollama model; **secrets redacted before sending**; off unless you ask. **MCP server** (`rex mcp`) so agents can drive every analysis |

## Install

```sh
# build from source (works today)
cargo install --git https://github.com/aabhimittal/reverse-engineer rex-cli

# prebuilt binary for Linux/macOS from the latest release, SHA-256 verified
curl -fsSL https://raw.githubusercontent.com/aabhimittal/reverse-engineer/main/install.sh | sh

# extras: ARM/MIPS/... disassembly and YARA-X rules (only load YARA rules you trust; see SECURITY.md)
cargo install --git https://github.com/aabhimittal/reverse-engineer rex-cli --features multiarch,yara

# or Docker
docker build -t rex . && docker run --rm -v "$PWD:/work" rex analyze /work/sample
```

Windows: download the `.zip` from the releases page. `cargo binstall --git …` also works against release archives.
Check your install with `rex doctor`.

## Use it from your AI coding agent

```sh
rex setup            # detects Claude Code, Claude Desktop, Cursor, Gemini CLI, Codex CLI and configures each
rex setup --dry-run  # preview; --uninstall removes only rex's entry
```

That registers `rex mcp` (11 tools plus workflow prompts such as `triage_binary`, `patch_diff`, `audit_electron`)
and, for Claude Code, a skill that teaches the agent the triage-then-drill-down loop. Then just ask:
*"triage ./sample.bin"*, *"what did this patch change?"*, *"audit this app.asar"*. See [the agent guide](docs/src/ai/agents.md).

## Is it safe to point at my files?

rex never executes input, makes no network calls on its own, masks secrets in every report, and the AI features
are off unless you ask. Details and the trade-offs of the installer script are in the [FAQ](docs/src/faq.md).

## 60-second tour

```console
$ rex analyze labs/web/sample.har
── Findings
  HIGH     Credentials or form data sent over plain HTTP     WEB-CLEARTEXT
  MEDIUM   Capture contains live credentials                 WEB-CAPTURE-CREDENTIALS
           • /auth/login body field 'password': correc…aple (28 chars)     <- values are masked
  MEDIUM   Server errors leak stack traces or SQL errors     WEB-VERBOSE-ERRORS
  LOW      JWT lifetime is 90 days                           WEB-JWT-LONG-LIVED
$ rex web har2openapi labs/web/sample.har -o api.yaml     # 13 endpoints, schemas, bearer auth
```

```console
$ rex analyze labs/electron/app.asar --fail-on high
  HIGH     nodeIntegration enabled in a renderer             ELECTRON-NODE-INTEGRATION
  HIGH     contextIsolation disabled                         ELECTRON-NO-CONTEXT-ISOLATION
  HIGH     Credentials embedded in the app                   ELECTRON-SECRETS
           • config.js: AWS access key id AKIAI…MPLE (20 chars)
  MEDIUM   shell.openExternal called with a non-literal URL  ELECTRON-OPEN-EXTERNAL
rex: findings at or above 'high' (exit 3)
```

```console
$ rex analyze labs/build/vuln --fail-on high
  HIGH     NX: disabled                                      BIN-MITIGATION-NX
  HIGH     Calls memory-unsafe C library functions           BIN-UNSAFE-API
           • gets ← main
           • strcpy ← greet
  MEDIUM   PIE: disabled / RELRO: disabled / Stack canary: disabled
rex: findings at or above 'high' (exit 3)
```

Every report renders as terminal text, **JSON** (stable schema), **Markdown** (with Mermaid diagrams), **SARIF 2.1**
(GitHub code scanning) or a **self-contained HTML** file with dark mode and live filtering.

## The handbook and labs

This repo is also a course. [`docs/`](docs) is an mdBook handbook, with an analogy-driven explanation, mechanics
down to the bytes, hands-on `rex` commands and the equivalent classic-tool commands in each chapter:

foundations and ethics, executable formats, x86-64 for reversers, static and dynamic analysis, mitigations, packers,
malware triage and YARA, patch diffing, traffic to API spec, JS bundles, codebase archaeology, AI-assisted RE.

[`labs/`](labs) contains benign, reproducible practice material: a crackme, an intentionally vulnerable binary, a
Windows PE, a Mach-O, a firmware image, a HAR capture, a JS bundle with a source map, an Android APK, a WebAssembly
module and a deliberately insecure Electron app. See the [showcase](docs/src/showcase.md) for real transcripts. All are built
from sources or generator scripts in the repo.

```sh
make -C labs && mdbook serve docs
```

## How it compares

| | rex | Ghidra / IDA / Binary Ninja | radare2 | binwalk / unblob | mitmproxy2swagger |
|---|---|---|---|---|---|
| Decompiler | no | **yes** | partial | no | n/a |
| Interactive debugging | no | partial | **yes** | no | n/a |
| Binaries + firmware + APK + Electron + WASM + HAR + JS + source trees in one tool | **yes** | no | no | no | no |
| Machine-readable findings, SARIF, CI gating | **yes** | no | no | no | no |
| Single static binary, instant start | **yes** | no | yes | no | no |
| MCP server for agents | **yes** | via plugins | via plugins | no | no |

`rex` is **not** a decompiler or debugger and doesn't try to be. Use it to decide where to point those.

## Honest limitations

- Control-flow recovery and function diffing cover **x86/x64, AArch64 and 32-bit ARM (ARM and Thumb-2, including mixed binaries)**. MIPS, PowerPC and RISC-V get linear disassembly (Capstone) only. On AArch64 and ARM32, PLT stubs, string references (including ARM's PC-relative literal pools) and `main` in stripped glibc-style binaries are resolved. Indirect branches (`br`, `blr`, `bx rN`, jump tables) are not followed.
- Heuristics (capabilities, packer score, secret patterns) produce **leads, not verdicts**. Findings say why they fired.
- Obfuscated or virtualised code defeats static analysis; unpack or trace dynamically first.
- WebAssembly is disassembled (with branch targets and import call sites) but not decompiled, and `call_indirect` targets are not resolved; pair it with WABT or Ghidra.
- Electron checks are pattern-based: a setting computed at runtime or hidden behind minified indirection is invisible,
  and executable-level protections (fuses) are out of view.
- HAR-derived specs describe **observed** traffic only. Review before publishing.
- Treat all inputs as hostile and analyse malware in an isolated environment. rex never executes input, but your
  other tools might.

## Safety and legality

rex is a defensive and educational tool for software you own or are authorised to analyse. It never executes its
input, never contacts a target (HAR analysis is offline), masks credentials in reports and redacts them before any
AI call. See the [legal chapter](docs/src/foundations/legal.md) and [SECURITY.md](SECURITY.md).

## Architecture

A Cargo workspace; every crate is `#![forbid(unsafe_code)]`.

```text
rex-core ─► Artifact · detection · Analyzer registry (parallel, panic-isolated) · Finding · Report
rex-binary  rex-web  rex-code          domain analyzers
rex-report ─► text | json | md | sarif | html
rex-engine ─► the verbs, shared by rex-cli and rex-mcp          rex-ai ─► optional LLM
```

Writing a new analyzer is one trait impl. See [ARCHITECTURE](docs/src/reference/architecture.md).

## Quality

130 tests including real ELF/PE/Mach-O fixtures built from this repo's sources, seeded mutation tests that feed
corrupted inputs to every parser, libFuzzer targets under [`fuzz/`](fuzz), clippy `-D warnings`, `cargo deny`, CI on
Linux/macOS/Windows, and the repository scans itself with `rex` in CI.

## Contributing

Issues and pull requests are welcome, especially new analyzers, capability rules, framework route patterns and lab
exercises. Start with [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
