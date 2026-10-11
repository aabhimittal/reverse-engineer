# Getting started

## Install

```sh
# From source (Rust 1.85+)
cargo install --git https://github.com/aabhimittal/reverse-engineer rex-cli

# With ARM/MIPS/PowerPC/RISC-V disassembly and YARA-X rules
cargo install --git https://github.com/aabhimittal/reverse-engineer rex-cli --features multiarch,yara

# Docker
docker run --rm -v "$PWD:/work" ghcr.io/aabhimittal/rex analyze /work/sample.bin
```

Pre-built binaries for Linux, macOS and Windows are attached to every
[GitHub release](https://github.com/aabhimittal/reverse-engineer/releases).

## Build the labs

```sh
git clone https://github.com/aabhimittal/reverse-engineer && cd reverse-engineer
make -C labs          # crackme, vulnerable binary, firmware image
```

## Your first analysis

```sh
rex analyze labs/build/crackme
```

You'll see sections (overview, sections, imports, mitigations, capabilities,
strings, recovered functions, a call graph and the disassembly of `main`) followed
by **findings** sorted by severity. Every finding has a stable rule id
(`BIN-MITIGATION-NX`, `APK-DEBUGGABLE`, …) so you can grep, gate CI, or suppress it.

## Output formats

| Flag | Use it for |
|---|---|
| *(default)* `-f text` | Reading in a terminal |
| `-f json` | Scripts and pipelines (`jq`) |
| `-f md` | Pull requests, wikis, notes |
| `-f html -o report.html` | A single self-contained file to share |
| `-f sarif -o rex.sarif` | GitHub code scanning / any SARIF viewer |

The format is inferred from `-o`'s extension, so `-o report.html` is enough.

## Gating CI

```sh
rex analyze ./build/firmware.bin --fail-on high   # exit code 3 on any high/critical finding
```

## Mental model of the tool

```text
input ──► detect kind ──► analyzers (parallel, sandboxed from each other) ──► report ──► renderer
```

Analyzers are independent plugins. A crashing parser can't take the run down;
its error is recorded under *Analyzer warnings* and the rest of the report survives.
