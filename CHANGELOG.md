# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Initial release: `rex-core`, `rex-report`, `rex-binary`, `rex-web`, `rex-code`, `rex-engine`, `rex-cli`,
  `rex-mcp`, `rex-ai`.
- Native binary analysis (ELF/PE/Mach-O), checksec, capabilities (ATT&CK), packer heuristics, function recovery,
  CFGs, carving, binary diffing, optional YARA-X and Capstone.
- HAR to OpenAPI 3.1, traffic audit, JS bundle analysis, source-map unpacking, APK/DEX/AXML analysis.
- Codebase atlas with tree-sitter symbols, import graphs, routes, hotspots and security smells.
- Optional AI assistance (Claude or Ollama) and an MCP server.
- Handbook (`docs/`) and reproducible labs (`labs/`).
- `rex setup` / `rex doctor`: one-command MCP + skill configuration for Claude Code, Claude Desktop, Cursor,
  Gemini CLI and Codex CLI (idempotent, `--dry-run`, `--uninstall`, never overwrites unparseable config).
- MCP workflow prompts (`triage_binary`, `patch_diff`, `reverse_api`, `map_codebase`, `audit_apk`, `audit_electron`).
- WebAssembly analyzer (imports, exports, WASI reach, memory limits, debug info, largest functions).
- Electron `app.asar` analyzer and `rex web asar` extractor (window security settings, IPC table, secrets,
  source maps, native addons, dependencies).
- `install.sh` (SHA-256 verified), cargo-binstall metadata, Homebrew formula generator, build-provenance
  attestations on releases, GitHub Pages workflow for the handbook.
- Handbook: showcase, FAQ and trust, WebAssembly, Electron, and AI-agent chapters.
- `scripts/build-demo.py` and `docs/demo/template.html`: a demo page generated from real `rex` runs on the labs (findings, tables, disassembly, CFGs, agent setup).
- AArch64 and 32-bit ARM (ARM mode) function discovery, CFGs, call graph, PLT import resolution, string references and `main` inference (feature `multiarch`); functions no longer run on into the next function or the PLT after a call to an unknown no-return function.
- WebAssembly instruction disassembly (`rex disasm`/`rex xrefs` on `.wasm`), resolved branch targets and per-import call sites.
- Release workflow can be rehearsed (`workflow_dispatch`) and smoke-tests `install.sh` against the built assets.
- Hardening: `rex` refuses FIFOs and devices instead of blocking or reading forever, caps reads of files that report size 0, and stops directory walks at `/` or `$HOME` after a bounded number of entries.
- ELF core-dump triage (`rex core`, analyzer `binary.core`, MCP tool `rex_core`): signal and `si_code`, fault address, threads with x86-64/AArch64 registers, `NT_FILE` mappings, auxv and command line, the crashing pc as `module+offset`, a stack scan for code pointers, and `BIN-CORE-CRASH` / `BIN-CORE-NULL-DEREF` findings. Checksec, function recovery, capabilities and packer detection no longer run on cores. Lab: `labs/crash/make_core.py`.
- Fuzzing in CI (`.github/workflows/fuzz.yml`) plus a whole-pipeline `analyze_all` target; fixes for what it found: an ELF size overflow that discarded valid files, and a Mach-O export trie that made goblin allocate 3 GB from an 18 KB file (rex now reads the trie itself, once per node).
- Large binaries: each artifact is parsed once and shared by every analyzer (`rex analyze` on a 200 MB binary 14 s → 9 s); `rex functions` no longer serializes every instruction (2.7 s → 1.1 s on a Go binary); new `--max-functions` and a finding when the limit cuts recovery short.
- `scripts/corpus-smoke.sh`: run rex over every file under a directory tree and report crashes, hangs and slow inputs.
- AArch64 `main` inference follows GOT slots filled by RELATIVE relocations (glibc PIE `_start`); release rehearsal installs the Homebrew formula from the built archives.
- Go: build info (version, modules, dependencies, build settings) and function names from the pclntab in stripped binaries on every Go target; libc hardening findings marked not applicable; discovery spends the `--max-functions` budget on `main` and its callees first.
- .NET: CLI metadata reader (assembly, referenced assemblies, types, methods, string literals, P/Invoke imports, which also feed the capability rules).
- PE: version-info strings, and manifest `requestedExecutionLevel` / `uiAccess` findings.
- Thumb-2 code recovery on 32-bit ARM, including mixed ARM/Thumb binaries (mode from mapping symbols, symbol and pointer bit 0, and `blx`); `it` blocks; ARM32 PLT entries are named and literal-pool string references resolved in both modes; `main` inference for 32-bit glibc `_start`, including the PIE form that loads it from its GOT slot.
- `rex relocs [--got]`: ELF dynamic relocations from RELA, REL, PLT and RELR tables (type, symbol, addend, section, RELRO), and a GOT view naming the PLT stub and target of each slot; `BIN-ELF-TEXTREL` for relocations in read-only sections; MCP tool `rex_relocs`.
- `rex decompile FILE FUNC|--all`: optional Ghidra bridge that runs `analyzeHeadless` with a bundled post-script and returns pseudo-C named the way rex names functions; found via `GHIDRA_INSTALL_DIR`, `REX_GHIDRA` or `PATH` (shown by `rex doctor`); whole-run `--timeout`; MCP tool `rex_decompile`. A CI job tests it against a pinned Ghidra release.
- `rex compare old.json new.json`: what changed between two saved reports; new or escalated findings honour `--fail-on`.
