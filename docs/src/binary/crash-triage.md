# Crash triage: core dumps

## The mental model

A core dump is **a photograph of the crime scene**, taken by the kernel at the moment a process died.
Nothing in it moves any more: there is no program to run and no code to recover, only memory and a
police report pinned to the front. The report (the ELF notes) says which signal killed the process, the
address it choked on, where every thread was standing, and which files were mapped where. The memory says
what was on the stack.

So crash triage reads the report first, then uses the mappings to translate raw addresses into
`module+offset`, which is something you can open in a disassembler.

## Anatomy

A Linux core is an ELF file with `e_type = ET_CORE`, no sections, and two kinds of program header:

```text
PT_NOTE   the crash context, one note per record (owner "CORE")
  NT_PRSTATUS  one per thread, crashing thread first: pid, pr_cursig, general registers
  NT_SIGINFO   siginfo_t: si_signo, si_code, si_addr (the faulting address)
  NT_PRPSINFO  command name (pr_fname) and the first 80 bytes of the command line
  NT_AUXV      what the kernel told the program at exec: AT_ENTRY, AT_PHDR, AT_EXECFN, AT_HWCAP …
  NT_FILE      every file-backed mapping: start, end, page offset, path
PT_LOAD   one per mapping, flags = the mapping's r/w/x; p_filesz is 0 for pages the
          kernel did not dump (typically read-only file pages, which you have on disk)
```

`si_code` says *why* the signal came: for `SIGSEGV`, `SEGV_MAPERR` means nothing is mapped at the
address, `SEGV_ACCERR` means something is mapped there but not with the needed permission (a write to
read-only data, a jump into a non-executable page).

## Triage

```console
$ rex core labs/crash/core.x64
── Crash summary
  Signal            SIGSEGV (11) — invalid memory reference
  si_code           1 (SEGV_MAPERR: address not mapped)
  Fault address     0x10
  Crashing thread   4242
  PC                0x555555555139 (crashme+0x1139)
  SP                0x7fffffffe800
  Executable        /usr/bin/crashme
  Command line      /usr/bin/crashme --input /tmp/poc.bin
── Threads (2)
  tid   signal   pc              location           sp
  4242  SIGSEGV  0x555555555139  crashme+0x1139     0x7fffffffe800
  4243  -        0x7ffff7e732a1  libc.so.6+0xa32a1  0x7fffffffc800
── Code pointers on the stack (a scan of 64 words at SP, not an unwind)
  slot     value           location
  sp+0x8   0x5555555551a4  crashme+0x11a4
  sp+0x38  0x7ffff7e21d90  libc.so.6+0x51d90
── Findings
  MEDIUM   /usr/bin/crashme crashed with SIGSEGV  BIN-CORE-CRASH
  LOW      NULL pointer dereference  BIN-CORE-NULL-DEREF
```

`rex analyze` on a core runs the same analyzer (`binary.core`) plus strings, hashes and carving. Checksec,
function recovery, capabilities and packer detection skip cores: they judge a program, and a core is memory.
`rex checksec` and `rex functions` say so instead of printing nonsense. Over MCP the tool is `rex_core`.

**Offsets are file offsets.** `crashme+0x1139` is `pc - mapping start + mapping file offset`. For PIE
executables and shared libraries built by the usual toolchains, file offset and link-time address coincide
in the text segment, so `rex disasm /usr/bin/crashme --addr 0x1139` lands on the faulting instruction.

**Reading the severity.** `BIN-CORE-CRASH` is Medium by default and Low for `SIGABRT`/`SIGTRAP` (an
assertion or a debugger trap: the program stopped itself). It is **High** when the pc is outside every
executable mapping, or when a `SIGSEGV`'s fault address equals the pc: the CPU tried to fetch instructions
from somewhere it should never have jumped, which is what a smashed return address or a corrupted function
pointer looks like. `BIN-CORE-NULL-DEREF` fires when the fault address is in the first page.

**The stack scan is not a backtrace.** rex reads 64 pointer-sized words at the crashing thread's SP and
lists those that point into executable memory. Real return addresses show up, but so do stale ones from
frames that already returned and function pointers held in locals. Use it to pick where to look, then
confirm in the disassembly (the instruction before a return address should be a `call`/`bl`).

## Limits

Registers and the stack scan are decoded for x86-64 and AArch64. Other 64-bit machines and all 32-bit cores
keep the signal, `si_code`, fault address and pid. There is no DWARF/CFI unwinding and no symbolization beyond
`module+offset`: for function names, run `rex functions` on the module from disk (or `eu-stack`/`gdb` with
debug info). Cores written by `gcore` usually record no signal, so they get the tables but no crash finding. Kernel cores
cap `pr_psargs` at 80 bytes, so long command lines are truncated.

## Classic tools

`gdb ./crashme core` then `bt`, `info registers`, `x/64gx $sp`; `eu-readelf -n core` for the notes;
`eu-stack --core core` for an unwind with debug info; `coredumpctl info` on systemd hosts.

## Exercises

1. Edit `labs/crash/make_core.py` so the crashing pc is a stack address and rerun. Which finding changes
   severity, and why?
2. Change `si_code` to `SEGV_ACCERR` and the fault address to an address in crashme's text. What kind of
   bug does that describe?
3. Thread 4243 is in `libc.so.6+0xa32a1`. Without the libc file, what can you still say about it?
