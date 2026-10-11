# Executable formats: ELF, PE, Mach-O

## Analogy: a shipping manifest

An executable is a container ship. The **header** is the manifest stapled to the hull:
which CPU it's for, where to start (entry point), and a table of containers. Two
*different* tables describe the same cargo:

- **Sections** are the *packing list*: named, fine-grained (`.text`, `.rodata`, `.data`),
  meant for linkers and debuggers.
- **Segments** (ELF program headers / Mach-O load commands / PE sections-as-mapped) are the
  *dock instructions*: what the loader maps into memory, at which address, with which
  permissions.

Stripped binaries can drop the packing list (section headers) but never the dock
instructions, which is why rex falls back to `PT_LOAD` segments when sections are missing.

## The three families side by side

| Concept | ELF (Linux, Android, firmware) | PE (Windows) | Mach-O (Apple) |
|---|---|---|---|
| Magic | `7f 45 4c 46` | `MZ` … `PE\0\0` | `cf fa ed fe` (64-bit LE), `ca fe ba be` (fat) |
| Code | `.text` | `.text` | `__TEXT,__text` |
| Read-only data | `.rodata` | `.rdata` | `__TEXT,__cstring`, `__DATA_CONST` |
| Imports | `.dynsym` + PLT/GOT relocations | Import Directory → IAT | `LC_DYLD_INFO` / chained fixups → `__got`/`__la_symbol_ptr` |
| Calls to imports go via | PLT stub `jmp [GOT]` | `call [IAT]` | `__stubs` `jmp [ptr]` |
| Function list (even stripped) | `.eh_frame` FDEs | `.pdata` (x64) | `LC_FUNCTION_STARTS` |
| Debug info | DWARF (`.debug_*`), build-id note | PDB path in CodeView record | dSYM bundle, `LC_UUID` |

The *function list* row is the secret weapon for stripped binaries: unwind tables
must survive stripping because exceptions and stack traces need them. rex seeds its
function discovery from all three.

## How a call to `printf` is resolved

```text
ELF:     call printf@plt ──► .plt.sec: jmp [rip+GOT_printf] ──► GOT slot ──► libc!printf
PE:      call [rip+__imp_printf]  ──► IAT slot (filled by the loader)    ──► msvcrt!printf
Mach-O:  call printf@stub ──► __stubs: jmp [rip+ptr]  ──► __got / lazy pointer ──► libSystem
```

rex reverses this: it decodes every stub, reads the slot each one jumps through, and maps
the slot back to the import name from the relocation / import tables. That's how a stripped
binary's disassembly still says `call strlen@plt`.

## Hands-on

```sh
rex info labs/build/crackme                 # overview, sections, imports
rex info crates/rex-binary/tests/fixtures/sample.exe
rex info crates/rex-binary/tests/fixtures/hello.macho
rex analyze firmware.bin --as elf           # force a kind if detection is wrong
```

Things to notice:

- Section **entropy** (the little bar): code ≈ 5–6.5, text ≈ 4–5, compressed ≈ 7.5–8.
- **Overlay**: bytes after the last section. Installers and droppers hide payloads there.
- PE **timestamp** and **PDB path** often leak build environments (`C:\Users\dev\...`).
- ELF **`.comment`** reveals the compiler; **Build ID** links to debug symbols on distro servers.

## Classic tools

| Task | Tool |
|---|---|
| ELF headers / sections / dynamic table | `readelf -h -S -d -n`, `objdump -x` |
| PE | `dumpbin /headers /imports`, `pefile` (Python), PE-bear |
| Mach-O | `otool -l -L`, `jtool2`, `nm -m` |
| Any | `rabin2 -I -S -i` (radare2), LIEF (Python) |

## Exercises

1. Compare `rex info` on `crackme` and `crackme.stripped`: which sections disappear, and why do
   functions still get recovered?
2. In `sample.exe`, find the IAT slot address of `IsDebuggerPresent` and confirm with
   `rex disasm … -F entry` that the call goes through it.
