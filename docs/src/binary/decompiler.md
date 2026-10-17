# Decompiling with Ghidra (optional bridge)

rex has no decompiler of its own, and its default promise stands: one static binary, nothing else installed.
When you do have [Ghidra](https://ghidra-sre.org/) installed, `rex decompile` drives it for you, so you can go
from a rex finding to pseudo-C without leaving the terminal or your agent session.

## Analogy: a translator on call

rex reads the binary itself: headers, imports, functions, control flow. For a line-by-line reading in C it calls a
specialist: Ghidra's decompiler. rex prepares the work (finds the function, its address and rex's name for it),
hands it over, and puts the answer in the same report as everything else.

## Setup

1. Install Ghidra (it needs a Java 21 JDK).
2. Tell rex where it is, in any of these ways:
   - `GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.4_PUBLIC` (the directory that contains `support/analyzeHeadless`),
   - `REX_GHIDRA=/path/to/analyzeHeadless` (or the install directory),
   - or put `analyzeHeadless` on `PATH`.
3. `rex doctor` shows the `analyzeHeadless` it found in the companion-tools table.

## Hands-on

```sh
rex functions crates/rex-binary/tests/fixtures/crackme.elf          # pick a function
rex decompile crates/rex-binary/tests/fixtures/crackme.elf check_password
rex decompile crackme.elf 0x1189                                    # by address
rex decompile crackme.elf --all -f json -o decompiled.json          # every function (up to 500)
```

Functions are named the way rex names them, so `main` inferred in a stripped binary or `strlen@plt` read the same
in `rex disasm` and `rex decompile`. Agents get the same through the MCP tool `rex_decompile`.

## What happens under the hood

`rex decompile` creates a temporary Ghidra project, imports the file, lets Ghidra's auto-analysis run, and runs a
small bundled post-script (`RexDecompile.java`) that decompiles the requested entry points and writes JSON. The
project is deleted afterwards. rex addresses functions by the file's own virtual addresses; Ghidra loads PIE ELF
files at `0x100000`, so the script shifts addresses by the difference between the two image bases.

It is slow compared with the rest of rex: the JVM starts, and Ghidra analyses the whole file before decompiling
anything (tens of seconds for a small binary, minutes for a large one). The whole run is limited by `--timeout`
(600 seconds by default), and a hung Ghidra is killed.

## Limits

- Pseudo-C is Ghidra's reading of the machine code, not the original source: names, types and structure are
  guesses, and wrong ones are common around optimised code, indirect calls and hand-written assembly.
- Without Ghidra, `rex decompile` fails with a message saying how to install it. Nothing else in rex depends on it.
