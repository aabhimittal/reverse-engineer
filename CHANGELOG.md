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
- AArch64 and 32-bit ARM (ARM mode) function discovery, CFGs, call graph, PLT import resolution, string references and `main` inference (feature `multiarch`); functions no longer run on into the next function or the PLT after a call to an unknown no-return function.
- WebAssembly instruction disassembly (`rex disasm`/`rex xrefs` on `.wasm`), resolved branch targets and per-import call sites.
- Release workflow can be rehearsed (`workflow_dispatch`) and smoke-tests `install.sh` against the built assets.
- Hardening: `rex` refuses FIFOs and devices instead of blocking or reading forever, caps reads of files that report size 0, and stops directory walks at `/` or `$HOME` after a bounded number of entries.
- Fuzzing in CI (`.github/workflows/fuzz.yml`) plus a whole-pipeline `analyze_all` target; fixes for what it found: an ELF size overflow that discarded valid files, and a Mach-O export trie that made goblin allocate 3 GB from an 18 KB file (rex now reads the trie itself, once per node).
- Large binaries: each artifact is parsed once and shared by every analyzer (`rex analyze` on a 200 MB binary 14 s → 9 s); `rex functions` no longer serializes every instruction (2.7 s → 1.1 s on a Go binary); new `--max-functions` and a finding when the limit cuts recovery short.
- `scripts/corpus-smoke.sh`: run rex over every file under a directory tree and report crashes, hangs and slow inputs.

- AArch64 `main` inference follows GOT slots filled by RELATIVE relocations (glibc PIE `_start`); release rehearsal installs the Homebrew formula from the built archives.
