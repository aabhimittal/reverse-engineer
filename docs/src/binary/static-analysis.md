# Static analysis: functions, CFGs, xrefs

## Linear sweep vs. recursive descent

A **linear sweep** decodes bytes front to back. It's simple and wrong whenever data sits
between code (jump tables, literal pools, padding): it will happily "disassemble" a string.

**Recursive descent** starts from *known* code and follows control flow:

```text
seeds = {entry, symbols, exports, .eh_frame/.pdata/LC_FUNCTION_STARTS}
while seeds:
    f = seeds.pop()
    decode from f, following jumps and both sides of conditional branches
    every call target becomes a new seed
    stop a path at ret / jmp to another function / call to a noreturn function (exit, abort…)
```

Analogy: exploring a cave with a ball of string. You only enter passages you can reach from
where you've been, so you never mistake a painting on the wall (data) for a tunnel (code).

The subtle part is **noreturn** calls: after `call exit`, the next bytes belong to *another*
function. Treating them as fall-through merges unrelated code into one giant function. rex
knows the common noreturn functions (`exit`, `abort`, `__stack_chk_fail`, `ExitProcess`,
Rust/Go panics, …).

## Basic blocks and CFGs

A **basic block** is straight-line code with one entry and one exit. A **control-flow graph**
connects blocks by edges: *true*/*false* for conditional branches, *jump*, *fall-through*.
Shapes in the CFG are readable at a glance:

| Shape | Meaning |
|---|---|
| diamond | if/else |
| back edge (to an earlier block) | loop |
| fan-out from one block | switch / jump table |
| long chain with early exits | input validation |

**Cyclomatic complexity** = edges − nodes + 2 = the number of independent paths. It's a
quick "where's the logic?" heuristic: parsers and protocol state machines score high.

```sh
rex cfg labs/build/crackme check_password            # Mermaid (paste into GitHub/markdown)
rex cfg labs/build/crackme check_password --dot | dot -Tsvg > cfg.svg
```

## Cross-references (xrefs)

Xrefs answer "who uses this?":

```sh
rex xrefs labs/build/crackme check_password     # callers, callees, strings
rex xrefs labs/build/crackme "Access granted"   # which function prints this?
rex xrefs labs/build/vuln gets                  # who calls the dangerous import?
```

rex records data references from RIP-relative operands, absolute memory operands and
address-like immediates, and follows **one pointer hop** (`mov rcx, [config]` where `config`
points to a string), a pattern compilers emit for global string tables.

## Finding `main` in a stripped binary

On Linux, `_start` passes `main` to `__libc_start_main` in `rdi` (x86-64) or on the stack
(x86). rex recognises that pattern and names the function `main` even with no symbols:

```sh
rex functions labs/build/crackme.stripped | head
```

## Classic tools

Ghidra (auto-analysis + decompiler), IDA, Binary Ninja, radare2/rizin (`aaa; afl; agf`),
Cutter. They go further than rex (decompilation, type recovery, data-flow), so use rex to
find *where* to look, then open those addresses there, or run `rex decompile` to get Ghidra's pseudo-C for one
function without opening its UI ([Decompiling with Ghidra](decompiler.md)).

## Exercises

1. Run `rex functions` on `/bin/ls`. How many functions come from `.eh_frame` vs. calls?
   (Compare with `REX_LOG=debug`.)
2. Find a function in `/bin/ls` with cyclomatic complexity > 50. What does it do?

## Beyond x86: AArch64 and ARM

With `--features multiarch` (included in release binaries) the same recursive-descent pipeline runs on AArch64 and
32-bit ARM in ARM mode. The differences you will notice reading the output:

- **Addresses are built in two steps.** AArch64 cannot load a 64-bit address in one instruction, so `adrp x0, #page`
  gives the 4 KiB page and `add x0, x0, #off` finishes the job. rex pairs them, which is how
  `adrp+add` turns into the `"open-sesame"` annotation beside a string reference. After linker relaxation the pair may
  collapse into a single `adr`.
- **PLT stubs look different.** `adrp x16, page; ldr x17, [x16, #off]; br x17` means "jump to whatever the GOT slot
  holds". Resolving the slot names the import, so calls show up as `stub_log@plt`.
- **Fixed-width instructions** make disassembly sync trivially, but there is no `call`/`ret` pair: calls are `bl`/`blr`
  and return is `ret` (a branch to `x30`).

Known gaps: Thumb code (most 32-bit ARM Linux binaries are Thumb-2) is not followed, ARM32 PLT stubs and PC-relative
literal pools are not resolved, and indirect branches are shown but not followed.
