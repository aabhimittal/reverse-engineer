# CLI reference

Generated from `rex --help` by `scripts/gen-cli-docs.sh`. Do not edit by hand.

```text
rex: reverse engineer anything.

Static analysis for ELF/PE/Mach-O binaries, firmware images, Android apps, HTTP traffic (HAR),
JavaScript bundles and source trees. Inputs are never executed.

Usage: rex [OPTIONS] <COMMAND>

Commands:
  analyze      Auto-detect and analyse files or directories (binaries, firmware, APK, HAR, JS,
               source trees) [alias: a]
  info         Headers, sections, imports and exports of a binary
  checksec     Exploit-mitigation table for one or more binaries
  core         Crash triage of a Linux core dump: signal, fault address, threads, mappings
  strings      Extract and classify strings
  functions    List recovered functions
  disasm       Disassemble a function or address range
  cfg          Control-flow graph of a function (Mermaid, or Graphviz with --dot)
  callgraph    Call graph (Mermaid) from main/entry or a given function
  xrefs        Cross-references for a function, import or string
  carve        Find (and optionally extract) embedded files and filesystems
  diff         Function-level diff of two binaries (patch analysis)
  compare      Compare two saved `rex analyze -f json` reports (what changed between builds or
               runs). With --fail-on, new or escalated findings fail the run
  web          Web & API reverse engineering
  apk          Analyse an Android APK (shortcut for `analyze`)
  code         Codebase archaeology
  ai           LLM-assisted analysis
  mcp          Run the Model Context Protocol server on stdio
  setup        Register rex's MCP server (and a skill) with your AI agents. Backs up configs;
               reversible
  doctor       Check this build, AI credentials and which companion tools (Ghidra, jadx, ...) are
               installed
  analyzers    List analyzers
  completions  Print shell completions
  help         Print this message or the help of the given subcommand(s)

Options:
  -f, --format <FORMAT>                Output format (default: text, or inferred from --output
                                       extension) [possible values: text, json, md, sarif, html]
  -o, --output <FILE>                  Write output to a file instead of stdout
      --color <COLOR>                  Colourise terminal output [default: auto] [possible values:
                                       auto, always, never]
      --max-rows <MAX_ROWS>            Maximum rows per table (0 = unlimited) [default: 50]
      --max-functions <MAX_FUNCTIONS>  Stop function discovery after this many functions (large
                                       binaries are reported as partial) [default: 5000]
      --max-size <MAX_SIZE>            Refuse inputs larger than this many MiB [default: 1024]
      --fail-on <SEVERITY>             Exit with status 3 if any finding is at or above this
                                       severity (CI gating)
      --as <KIND>                      Override input type detection [possible values: elf, pe,
                                       macho, apk, dex, axml, har, js, sourcemap, wasm, asar, blob]
  -v, --verbose...                     Verbose logging (-v, -vv)
  -h, --help                           Print help
  -V, --version                        Print version

Examples:
  rex analyze ./suspicious.exe                  Auto-detect and analyse anything
  rex analyze ./app.apk -f html -o report.html  Shareable single-file HTML report
  rex analyze . -f sarif -o rex.sarif           Code scanning for a repo (GitHub SARIF)
  rex disasm ./a.out --function main            Annotated disassembly of a function
  rex xrefs ./a.out "password"                  Which functions use a string?
  rex diff v1.bin v2.bin                        What changed between two builds?
  rex carve firmware.bin --extract out/         Pull filesystems out of a firmware image
  rex web har2openapi traffic.har -o api.yaml   Undocumented API → OpenAPI 3.1
  rex code map ~/src/project -o ATLAS.md        Map an unfamiliar codebase
  rex analyze ./malware.bin --ai                Add an LLM briefing (needs ANTHROPIC_API_KEY)
  rex mcp                                       Serve rex as tools to AI agents (MCP)
```

## rex analyze

```text
Auto-detect and analyse files or directories (binaries, firmware, APK, HAR, JS, source trees)

Usage: rex analyze [OPTIONS] <PATHS>...

Arguments:
  <PATHS>...  Inputs

Options:
  -f, --format <FORMAT>                Output format (default: text, or inferred from --output
                                       extension) [possible values: text, json, md, sarif, html]
      --only <ONLY>                    Only run analyzers whose name starts with one of these
                                       (comma-separated), e.g. binary.checksec,binary.strings
      --deep                           Enable expensive passes (full listings)
  -o, --output <FILE>                  Write output to a file instead of stdout
      --ai                             Add an LLM-written briefing to the report (sends a redacted
                                       report to the provider)
      --color <COLOR>                  Colourise terminal output [default: auto] [possible values:
                                       auto, always, never]
      --ai-provider <PROVIDER>         AI provider: anthropic (default) or ollama (local)
      --max-rows <MAX_ROWS>            Maximum rows per table (0 = unlimited) [default: 50]
      --ai-model <MODEL>               Model override (default: claude-opus-5-5 / llama3.1)
      --max-functions <MAX_FUNCTIONS>  Stop function discovery after this many functions (large
                                       binaries are reported as partial) [default: 5000]
      --max-size <MAX_SIZE>            Refuse inputs larger than this many MiB [default: 1024]
      --fail-on <SEVERITY>             Exit with status 3 if any finding is at or above this
                                       severity (CI gating)
      --as <KIND>                      Override input type detection [possible values: elf, pe,
                                       macho, apk, dex, axml, har, js, sourcemap, wasm, asar, blob]
  -v, --verbose...                     Verbose logging (-v, -vv)
  -h, --help                           Print help
  -V, --version                        Print version
```

## rex disasm

```text
Disassemble a function or address range

Usage: rex disasm [OPTIONS] <PATH>

Arguments:
  <PATH>  

Options:
  -f, --format <FORMAT>                Output format (default: text, or inferred from --output
                                       extension) [possible values: text, json, md, sarif, html]
  -F, --function <FUNCTION>            Function name or address
  -a, --addr <ADDR>                    Start address (hex)
  -o, --output <FILE>                  Write output to a file instead of stdout
      --color <COLOR>                  Colourise terminal output [default: auto] [possible values:
                                       auto, always, never]
  -n, --count <COUNT>                  Instructions to decode (address mode) [default: 64]
      --max-rows <MAX_ROWS>            Maximum rows per table (0 = unlimited) [default: 50]
      --max-functions <MAX_FUNCTIONS>  Stop function discovery after this many functions (large
                                       binaries are reported as partial) [default: 5000]
      --max-size <MAX_SIZE>            Refuse inputs larger than this many MiB [default: 1024]
      --fail-on <SEVERITY>             Exit with status 3 if any finding is at or above this
                                       severity (CI gating)
      --as <KIND>                      Override input type detection [possible values: elf, pe,
                                       macho, apk, dex, axml, har, js, sourcemap, wasm, asar, blob]
  -v, --verbose...                     Verbose logging (-v, -vv)
  -h, --help                           Print help
  -V, --version                        Print version
```

## rex xrefs

```text
Cross-references for a function, import or string

Usage: rex xrefs [OPTIONS] <PATH> <TARGET>

Arguments:
  <PATH>    
  <TARGET>  

Options:
  -f, --format <FORMAT>                Output format (default: text, or inferred from --output
                                       extension) [possible values: text, json, md, sarif, html]
  -o, --output <FILE>                  Write output to a file instead of stdout
      --color <COLOR>                  Colourise terminal output [default: auto] [possible values:
                                       auto, always, never]
      --max-rows <MAX_ROWS>            Maximum rows per table (0 = unlimited) [default: 50]
      --max-functions <MAX_FUNCTIONS>  Stop function discovery after this many functions (large
                                       binaries are reported as partial) [default: 5000]
      --max-size <MAX_SIZE>            Refuse inputs larger than this many MiB [default: 1024]
      --fail-on <SEVERITY>             Exit with status 3 if any finding is at or above this
                                       severity (CI gating)
      --as <KIND>                      Override input type detection [possible values: elf, pe,
                                       macho, apk, dex, axml, har, js, sourcemap, wasm, asar, blob]
  -v, --verbose...                     Verbose logging (-v, -vv)
  -h, --help                           Print help
  -V, --version                        Print version
```

## rex carve

```text
Find (and optionally extract) embedded files and filesystems

Usage: rex carve [OPTIONS] <PATH>

Arguments:
  <PATH>  

Options:
  -f, --format <FORMAT>                Output format (default: text, or inferred from --output
                                       extension) [possible values: text, json, md, sarif, html]
  -x, --extract <DIR>                  Extract into this directory
  -o, --output <FILE>                  Write output to a file instead of stdout
      --color <COLOR>                  Colourise terminal output [default: auto] [possible values:
                                       auto, always, never]
      --max-rows <MAX_ROWS>            Maximum rows per table (0 = unlimited) [default: 50]
      --max-functions <MAX_FUNCTIONS>  Stop function discovery after this many functions (large
                                       binaries are reported as partial) [default: 5000]
      --max-size <MAX_SIZE>            Refuse inputs larger than this many MiB [default: 1024]
      --fail-on <SEVERITY>             Exit with status 3 if any finding is at or above this
                                       severity (CI gating)
      --as <KIND>                      Override input type detection [possible values: elf, pe,
                                       macho, apk, dex, axml, har, js, sourcemap, wasm, asar, blob]
  -v, --verbose...                     Verbose logging (-v, -vv)
  -h, --help                           Print help
  -V, --version                        Print version
```

## rex core

```text
Crash triage of a Linux core dump: signal, fault address, threads, mappings

Usage: rex core [OPTIONS] <PATH>

Arguments:
  <PATH>  

Options:
  -f, --format <FORMAT>                Output format (default: text, or inferred from --output
                                       extension) [possible values: text, json, md, sarif, html]
  -o, --output <FILE>                  Write output to a file instead of stdout
      --color <COLOR>                  Colourise terminal output [default: auto] [possible values:
                                       auto, always, never]
      --max-rows <MAX_ROWS>            Maximum rows per table (0 = unlimited) [default: 50]
      --max-functions <MAX_FUNCTIONS>  Stop function discovery after this many functions (large
                                       binaries are reported as partial) [default: 5000]
      --max-size <MAX_SIZE>            Refuse inputs larger than this many MiB [default: 1024]
      --fail-on <SEVERITY>             Exit with status 3 if any finding is at or above this
                                       severity (CI gating)
      --as <KIND>                      Override input type detection [possible values: elf, pe,
                                       macho, apk, dex, axml, har, js, sourcemap, wasm, asar, blob]
  -v, --verbose...                     Verbose logging (-v, -vv)
  -h, --help                           Print help
  -V, --version                        Print version
```

## rex diff

```text
Function-level diff of two binaries (patch analysis)

Usage: rex diff [OPTIONS] <OLD> <NEW>

Arguments:
  <OLD>  
  <NEW>  

Options:
  -f, --format <FORMAT>                Output format (default: text, or inferred from --output
                                       extension) [possible values: text, json, md, sarif, html]
  -o, --output <FILE>                  Write output to a file instead of stdout
      --color <COLOR>                  Colourise terminal output [default: auto] [possible values:
                                       auto, always, never]
      --max-rows <MAX_ROWS>            Maximum rows per table (0 = unlimited) [default: 50]
      --max-functions <MAX_FUNCTIONS>  Stop function discovery after this many functions (large
                                       binaries are reported as partial) [default: 5000]
      --max-size <MAX_SIZE>            Refuse inputs larger than this many MiB [default: 1024]
      --fail-on <SEVERITY>             Exit with status 3 if any finding is at or above this
                                       severity (CI gating)
      --as <KIND>                      Override input type detection [possible values: elf, pe,
                                       macho, apk, dex, axml, har, js, sourcemap, wasm, asar, blob]
  -v, --verbose...                     Verbose logging (-v, -vv)
  -h, --help                           Print help
  -V, --version                        Print version
```

## rex setup

```text
Register rex's MCP server (and a skill) with your AI agents. Backs up configs; reversible

Usage: rex setup [OPTIONS]

Options:
  -a, --agent <AGENT>
          Agents to configure (default: every detected agent)

          Possible values:
          - claude-code:    Claude Code (via the `claude` CLI)
          - claude-desktop: Claude Desktop (`claude_desktop_config.json`)
          - cursor:         Cursor (`~/.cursor/mcp.json`)
          - gemini:         Gemini CLI (`~/.gemini/settings.json`)
          - codex:          OpenAI Codex CLI (`~/.codex/config.toml`)

  -f, --format <FORMAT>
          Output format (default: text, or inferred from --output extension)
          
          [possible values: text, json, md, sarif, html]

      --dry-run
          Show what would change without changing anything

  -o, --output <FILE>
          Write output to a file instead of stdout

      --color <COLOR>
          Colourise terminal output
          
          [default: auto]
          [possible values: auto, always, never]

      --uninstall
          Remove rex from the agents instead

      --max-rows <MAX_ROWS>
          Maximum rows per table (0 = unlimited)
          
          [default: 50]

      --no-skill
          Don't install the skill file

      --command <PATH>
          Path the agent should launch (default: this executable)

      --max-functions <MAX_FUNCTIONS>
          Stop function discovery after this many functions (large binaries are reported as partial)
          
          [default: 5000]

      --max-size <MAX_SIZE>
          Refuse inputs larger than this many MiB
          
          [default: 1024]

      --fail-on <SEVERITY>
          Exit with status 3 if any finding is at or above this severity (CI gating)

      --as <KIND>
          Override input type detection
          
          [possible values: elf, pe, macho, apk, dex, axml, har, js, sourcemap, wasm, asar, blob]

  -v, --verbose...
          Verbose logging (-v, -vv)

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## rex doctor

```text
Check this build, AI credentials and which companion tools (Ghidra, jadx, ...) are installed

Usage: rex doctor [OPTIONS]

Options:
  -f, --format <FORMAT>                Output format (default: text, or inferred from --output
                                       extension) [possible values: text, json, md, sarif, html]
  -o, --output <FILE>                  Write output to a file instead of stdout
      --color <COLOR>                  Colourise terminal output [default: auto] [possible values:
                                       auto, always, never]
      --max-rows <MAX_ROWS>            Maximum rows per table (0 = unlimited) [default: 50]
      --max-functions <MAX_FUNCTIONS>  Stop function discovery after this many functions (large
                                       binaries are reported as partial) [default: 5000]
      --max-size <MAX_SIZE>            Refuse inputs larger than this many MiB [default: 1024]
      --fail-on <SEVERITY>             Exit with status 3 if any finding is at or above this
                                       severity (CI gating)
      --as <KIND>                      Override input type detection [possible values: elf, pe,
                                       macho, apk, dex, axml, har, js, sourcemap, wasm, asar, blob]
  -v, --verbose...                     Verbose logging (-v, -vv)
  -h, --help                           Print help
  -V, --version                        Print version
```

## rex web har2openapi

```text
Infer an OpenAPI 3.1 spec from a HAR capture (YAML; JSON with --json)

Usage: rex web har2openapi [OPTIONS] <HAR>

Arguments:
  <HAR>  

Options:
  -f, --format <FORMAT>                Output format (default: text, or inferred from --output
                                       extension) [possible values: text, json, md, sarif, html]
      --json                           Emit JSON instead of YAML
      --include-static                 Keep static assets (JS, CSS, images)
  -o, --output <FILE>                  Write output to a file instead of stdout
      --color <COLOR>                  Colourise terminal output [default: auto] [possible values:
                                       auto, always, never]
      --host <HOST>                    Only hosts containing this text (repeatable)
      --max-rows <MAX_ROWS>            Maximum rows per table (0 = unlimited) [default: 50]
      --title <TITLE>                  API title
      --max-functions <MAX_FUNCTIONS>  Stop function discovery after this many functions (large
                                       binaries are reported as partial) [default: 5000]
      --max-size <MAX_SIZE>            Refuse inputs larger than this many MiB [default: 1024]
      --fail-on <SEVERITY>             Exit with status 3 if any finding is at or above this
                                       severity (CI gating)
      --as <KIND>                      Override input type detection [possible values: elf, pe,
                                       macho, apk, dex, axml, har, js, sourcemap, wasm, asar, blob]
  -v, --verbose...                     Verbose logging (-v, -vv)
  -h, --help                           Print help
  -V, --version                        Print version
```

## rex web sourcemap

```text
Recover original sources from a source map (or a bundle with an inline/adjacent map)

Usage: rex web sourcemap [OPTIONS] <PATH>

Arguments:
  <PATH>  

Options:
  -d, --dir <DIR>                      Output directory [default: rex-out/sources]
  -f, --format <FORMAT>                Output format (default: text, or inferred from --output
                                       extension) [possible values: text, json, md, sarif, html]
  -o, --output <FILE>                  Write output to a file instead of stdout
      --color <COLOR>                  Colourise terminal output [default: auto] [possible values:
                                       auto, always, never]
      --max-rows <MAX_ROWS>            Maximum rows per table (0 = unlimited) [default: 50]
      --max-functions <MAX_FUNCTIONS>  Stop function discovery after this many functions (large
                                       binaries are reported as partial) [default: 5000]
      --max-size <MAX_SIZE>            Refuse inputs larger than this many MiB [default: 1024]
      --fail-on <SEVERITY>             Exit with status 3 if any finding is at or above this
                                       severity (CI gating)
      --as <KIND>                      Override input type detection [possible values: elf, pe,
                                       macho, apk, dex, axml, har, js, sourcemap, wasm, asar, blob]
  -v, --verbose...                     Verbose logging (-v, -vv)
  -h, --help                           Print help
  -V, --version                        Print version
```

## rex web asar

```text
Extract an Electron app.asar (analyse it first with `rex analyze app.asar`)

Usage: rex web asar [OPTIONS] <PATH>

Arguments:
  <PATH>  

Options:
  -d, --dir <DIR>                      Output directory [default: rex-out/asar]
  -f, --format <FORMAT>                Output format (default: text, or inferred from --output
                                       extension) [possible values: text, json, md, sarif, html]
  -o, --output <FILE>                  Write output to a file instead of stdout
      --color <COLOR>                  Colourise terminal output [default: auto] [possible values:
                                       auto, always, never]
      --max-rows <MAX_ROWS>            Maximum rows per table (0 = unlimited) [default: 50]
      --max-functions <MAX_FUNCTIONS>  Stop function discovery after this many functions (large
                                       binaries are reported as partial) [default: 5000]
      --max-size <MAX_SIZE>            Refuse inputs larger than this many MiB [default: 1024]
      --fail-on <SEVERITY>             Exit with status 3 if any finding is at or above this
                                       severity (CI gating)
      --as <KIND>                      Override input type detection [possible values: elf, pe,
                                       macho, apk, dex, axml, har, js, sourcemap, wasm, asar, blob]
  -v, --verbose...                     Verbose logging (-v, -vv)
  -h, --help                           Print help
  -V, --version                        Print version
```

## rex code map

```text
Build a codebase atlas (Markdown by default with -o *.md)

Usage: rex code map [OPTIONS] <PATH>

Arguments:
  <PATH>  

Options:
  -f, --format <FORMAT>                Output format (default: text, or inferred from --output
                                       extension) [possible values: text, json, md, sarif, html]
  -o, --output <FILE>                  Write output to a file instead of stdout
      --color <COLOR>                  Colourise terminal output [default: auto] [possible values:
                                       auto, always, never]
      --max-rows <MAX_ROWS>            Maximum rows per table (0 = unlimited) [default: 50]
      --max-functions <MAX_FUNCTIONS>  Stop function discovery after this many functions (large
                                       binaries are reported as partial) [default: 5000]
      --max-size <MAX_SIZE>            Refuse inputs larger than this many MiB [default: 1024]
      --fail-on <SEVERITY>             Exit with status 3 if any finding is at or above this
                                       severity (CI gating)
      --as <KIND>                      Override input type detection [possible values: elf, pe,
                                       macho, apk, dex, axml, har, js, sourcemap, wasm, asar, blob]
  -v, --verbose...                     Verbose logging (-v, -vv)
  -h, --help                           Print help
  -V, --version                        Print version
```

## rex ai name

```text
Suggest names for unnamed (sub_*) functions

Usage: rex ai name [OPTIONS] <PATH>

Arguments:
  <PATH>  

Options:
  -f, --format <FORMAT>                Output format (default: text, or inferred from --output
                                       extension) [possible values: text, json, md, sarif, html]
      --limit <LIMIT>                  Maximum functions to send [default: 25]
      --ai                             Add an LLM-written briefing to the report (sends a redacted
                                       report to the provider)
  -o, --output <FILE>                  Write output to a file instead of stdout
      --ai-provider <PROVIDER>         AI provider: anthropic (default) or ollama (local)
      --color <COLOR>                  Colourise terminal output [default: auto] [possible values:
                                       auto, always, never]
      --ai-model <MODEL>               Model override (default: claude-opus-5-5 / llama3.1)
      --max-rows <MAX_ROWS>            Maximum rows per table (0 = unlimited) [default: 50]
      --max-functions <MAX_FUNCTIONS>  Stop function discovery after this many functions (large
                                       binaries are reported as partial) [default: 5000]
      --max-size <MAX_SIZE>            Refuse inputs larger than this many MiB [default: 1024]
      --fail-on <SEVERITY>             Exit with status 3 if any finding is at or above this
                                       severity (CI gating)
      --as <KIND>                      Override input type detection [possible values: elf, pe,
                                       macho, apk, dex, axml, har, js, sourcemap, wasm, asar, blob]
  -v, --verbose...                     Verbose logging (-v, -vv)
  -h, --help                           Print help
  -V, --version                        Print version
```
