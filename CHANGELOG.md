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
