# FAQ and trust

**Does rex upload my files?**
No. Analysis is entirely local and rex makes no network calls on its own. The only code that can touch the
network is the optional AI feature, which is off unless you pass `--ai` or run `rex ai …`; it sends text
extracted from your input after redacting detected secrets, to the provider you choose. `--ai-provider ollama`
keeps it on your machine. You can build without it: `cargo install … --no-default-features`.

**Does rex execute the sample?**
Never. Every crate forbids `unsafe` and there is no code path that loads or runs input. Do keep malware in
an isolated environment anyway: your editor, preview pane and other tools may not be as careful.

**Is the installer safe to pipe into `sh`?**
`install.sh` is short, verifies the archive's SHA-256 against the release's `SHA256SUMS`, and installs one
file to `~/.local/bin` (override with `REX_INSTALL_DIR`). That check catches corrupt downloads, not a compromised
release; for that, releases carry build-provenance attestations (`gh attestation verify <archive> --repo
aabhimittal/reverse-engineer`). Read the script first if you prefer: it is one page. `cargo install --git …`
builds from source instead.

**How is this different from Ghidra, IDA, radare2 or binwalk?**
Those are deeper. rex is the triage layer in front of them. It answers *what is this, what can it do, what is
risky, where do I look* across binaries, firmware, APKs, WebAssembly, Electron apps, HAR captures and source trees,
in seconds, with output a machine can consume. When it points you at a function, you open Ghidra on that
function, or let `rex decompile` do it for you when Ghidra is installed. rex itself is not a decompiler and not a
debugger.

**Which architectures get full analysis?**
Function discovery, control-flow graphs, call graphs and function-level diffing work for x86, x86-64, AArch64 and
32-bit ARM in ARM mode (the last two need `--features multiarch`, which release binaries include). Thumb code,
MIPS, PowerPC and RISC-V get linear disassembly only. Everything format-level (headers, imports, checksec, strings,
capabilities) works on all supported formats.

Go binaries are named on every architecture Go targets, because rex reads Go's own function table (pclntab), which
stripping does not remove: a stripped arm64 or RISC-V Go binary lists `main.main`, `net/http.(*Client).Do` and the
rest by name, even where no CFG is built.

**How is rex different from tools that drive Ghidra or IDA?**
rex does its own parsing, disassembly and control-flow recovery in one static binary, so it runs in CI, in a container
or behind an MCP server with nothing else installed. It does not decompile to C by itself; when you need pseudocode
and have Ghidra installed, `rex decompile FILE FUNC` runs Ghidra headless on that function (see
[Decompiling with Ghidra](binary/decompiler.md)).

**Can I trust the findings?**
Treat them as leads. Rules fire on evidence they print (imports, strings, flag values), and every heuristic can be
wrong in both directions: a benign tool can import `CreateRemoteThread`, and a malicious sample can hide its
imports. If a finding matters, check the evidence yourself.

**Why Rust?**
Inputs are hostile by definition. Memory safety in the parsers, no runtime to install, one static binary,
and fast enough to scan thousands of files.

**How do I add a rule or an analyzer?**
Capability rules are table entries; analyzers are one trait impl. See [Architecture](reference/architecture.md)
and CONTRIBUTING.md.

**Is it legal to use?**
Analysing software you own or are authorised to analyse is the intended use. Laws vary by country and contract.
Read the [legal chapter](foundations/legal.md); it is not legal advice.
