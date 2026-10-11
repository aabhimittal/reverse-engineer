# Cheat sheets

## x86-64 calling conventions

| | System V (Linux/macOS) | Microsoft x64 |
|---|---|---|
| Integer args | `rdi rsi rdx rcx r8 r9` | `rcx rdx r8 r9` |
| Float args | `xmm0-7` | `xmm0-3` |
| Return | `rax` (`rdx:rax` for 128-bit) | `rax` |
| Shadow space | none (red zone 128 B below `rsp`) | 32 bytes above return address |
| Callee-saved | `rbx rbp r12-r15` | `rbx rbp rdi rsi r12-r15` |
| Stack alignment at call | 16 bytes | 16 bytes |

## Format quick facts

| | ELF | PE | Mach-O |
|---|---|---|---|
| Magic | `7f 45 4c 46` | `4d 5a` ... `50 45 00 00` | `cf fa ed fe` |
| Entry | `e_entry` | `AddressOfEntryPoint` (RVA) | `LC_MAIN` offset |
| Imports | `.dynsym`, `.rela.plt` | Import Directory / IAT | dyld bind info |
| Unwind tables | `.eh_frame` | `.pdata` | `__unwind_info`, `LC_FUNCTION_STARTS` |
| Debug | DWARF | PDB (CodeView) | DWARF in dSYM |

## Everyday command equivalents

| Task | rex | Classic |
|---|---|---|
| Headers and sections | `rex info f` | `readelf -h -S`, `objdump -x`, `otool -l` |
| Mitigations | `rex checksec f` | `checksec.sh`, `winchecksec` |
| Strings | `rex strings f -c url,path` | `strings -a`, FLOSS |
| Disassemble a function | `rex disasm f -F name` | `objdump -d`, `r2 pdf`, Ghidra |
| Who calls this? | `rex xrefs f name` | Ghidra "References to" |
| CFG | `rex cfg f name` | `r2 agf`, Cutter |
| Embedded files | `rex carve f -x out/` | `binwalk -e`, unblob |
| What changed? | `rex diff a b` | BinDiff, Diaphora |
| HAR to API spec | `rex web har2openapi f.har` | mitmproxy2swagger |
| Map a codebase | `rex code map dir` | `tokei`, `cloc`, manual reading |

## gdb essentials

```text
break *0x401136   run   si/ni   x/8gx $rsp   x/s 0x402010   info registers
disassemble /r main   set disassembly-flavor intel   bt   watch *0x404040
```

## radare2 essentials

```text
aaa  afl  s main  pdf  VV  iz  ii  axt sym.check_password  px 64 @ rsp
```
