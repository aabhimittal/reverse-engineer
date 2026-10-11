<div align="center">

# rex

**Reverse engineer anything: binaries, firmware, Android apps, web APIs and codebases.**
One static-analysis toolkit, one command, five output formats. Written in Rust, never executes its input.

[![CI](https://github.com/aabhimittal/reverse-engineer/actions/workflows/ci.yml/badge.svg)](https://github.com/aabhimittal/reverse-engineer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

</div>

```console
$ rex analyze ./app --fail-on high        # auto-detects what it is, exits 3 in CI on high findings
$ rex disasm ./a.out -F main              # annotated disassembly: imports resolved, strings inlined
$ rex diff old.bin new.bin                # which functions did the patch change?
$ rex web har2openapi traffic.har         # undocumented API -> OpenAPI 3.1
$ rex code map ~/src/unfamiliar-repo      # where do I start reading?
```

Most reverse-engineering tools are excellent at one thing and a context switch away from the next.
`rex` is the **triage layer** across all of them. In seconds it tells you *what a thing is, what it can do,
what's risky about it, and where to look next*, then hands you off to Ghidra, a debugger or your editor.

## What it does

| Domain | Capabilities |
|---|---|
| **Native binaries** (ELF, PE, Mach-O, incl. fat) | Unified model of sections/imports/exports/symbols; **checksec** (NX, PIE/ASLR, RELRO, canary, FORTIFY, CFG, CET/BTI, signing, hardened runtime); classified strings (URLs, IPs, registry keys, secrets, commands); **50+ capability rules mapped to MITRE ATT&CK**; packer heuristics; imphash + TLSH; optional YARA-X |
| **Code recovery** (x86/x64 built in; ARM, AArch64, MIPS, PowerPC, RISC-V via `--features multiarch`) | Recursive-descent function discovery seeded from symbols, `.eh_frame`, `.pdata`, `LC_FUNCTION_STARTS`; PLT/IAT/stub resolution; `main` inference in stripped binaries; basic blocks, CFGs (Mermaid/DOT), call graph, cross-references, cyclomatic complexity |
| **Firmware & blobs** | binwalk-style carving with per-format validators and exact sizing, entropy profile, extraction (gzip/uImage unwrapping), embedded credential and key checks |
| **Patch analysis** | Function-level binary diff: matches by name, instruction hash, then trigram similarity; flags small surgical changes |
| **Android** | APK triage: binary manifest decoder, exported components (incl. implicit exports), deep links, permissions, DEX parser with checksum/signature validation, risky-API rules, TLS trust classes, native-lib hardening, signing |
| **Web & APIs** | **HAR to OpenAPI 3.1** with path templating, JSON-schema inference, auth schemes; passive traffic audit (JWT decoding, cookies, CORS, cleartext); JS bundle analysis (endpoints with methods, secrets, sinks); source-map unpacking with path-traversal protection |
| **Codebases** | tree-sitter symbol extraction (Rust, Python, JS/TS, Go, Java), cross-language import graph, PageRank "read this first" ranking, routes for 11 web frameworks, entry points, stack detection, churn x complexity hotspots, bus factor, security smells |
| **AI (optional)** | `--ai` briefings, `rex ai explain`, `rex ai name` via Claude or a local Ollama model; **secrets redacted before sending**; off unless you ask. **MCP server** (`rex mcp`) so agents can drive every analysis |

## Install

```sh
cargo install --git https://github.com/aabhimittal/reverse-engineer rex-cli
# extras: ARM/MIPS/... disassembly and YARA-X rules
cargo install --git https://github.com/aabhimittal/reverse-engineer rex-cli --features multiarch,yara
# or
docker build -t rex . && docker run --rm -v "$PWD:/work" rex analyze /work/sample
```

Release binaries for Linux (musl), macOS and Windows are attached to tagged releases.

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
Windows PE, a Mach-O, a firmware image, a HAR capture, a JS bundle with a source map and an Android APK. All are built
from sources or generator scripts in the repo.

```sh
make -C labs && mdbook serve docs
```

## How it compares

| | rex | Ghidra / IDA / Binary Ninja | radare2 | binwalk / unblob | mitmproxy2swagger |
|---|---|---|---|---|---|
| Decompiler | no | **yes** | partial | no | n/a |
| Interactive debugging | no | partial | **yes** | no | n/a |
| Binaries + firmware + APK + HAR + JS + source trees in one tool | **yes** | no | no | no | no |
| Machine-readable findings, SARIF, CI gating | **yes** | no | no | no | no |
| Single static binary, instant start | **yes** | no | yes | no | no |
| MCP server for agents | **yes** | via plugins | via plugins | no | no |

`rex` is **not** a decompiler or debugger and doesn't try to be. Use it to decide where to point those.

## Honest limitations

- Control-flow recovery and function diffing are **x86/x64 only**. Other architectures get linear disassembly (Capstone).
- Heuristics (capabilities, packer score, secret patterns) produce **leads, not verdicts**. Findings say why they fired.
- Obfuscated or virtualised code defeats static analysis; unpack or trace dynamically first.
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

100+ tests including real ELF/PE/Mach-O fixtures built from this repo's sources, seeded mutation tests that feed
corrupted inputs to every parser, libFuzzer targets under [`fuzz/`](fuzz), clippy `-D warnings`, `cargo deny`, CI on
Linux/macOS/Windows, and the repository scans itself with `rex` in CI.

## Contributing

Issues and pull requests are welcome, especially new analyzers, capability rules, framework route patterns and lab
exercises. Start with [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
