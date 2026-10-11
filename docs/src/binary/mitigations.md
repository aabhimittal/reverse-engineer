# Exploit mitigations (checksec)

## Analogy: securing a house

| Mitigation | The house version | What it stops |
|---|---|---|
| **NX / DEP** | Windows don't open from outside | Executing injected shellcode on the stack/heap |
| **ASLR / PIE** | The furniture moves every night | Hard-coded addresses in ROP chains |
| **Stack canary / GS** | A tripwire in the hallway | Linear stack overflows reaching the return address |
| **RELRO (full)** | The address book is bolted shut | Overwriting GOT entries to hijack library calls |
| **FORTIFY_SOURCE** | Measuring every box before it goes through the door | Overflows in `memcpy`/`sprintf` with known sizes |
| **CFG / CET IBT / BTI** | Guards check you only walk through real doors | Jumping into the middle of functions (ROP/JOP) |
| **Shadow stack (CET SHSTK)** | A second, guarded copy of the hallway map | Return-address overwrites, even without a canary leak |
| **Code signing / hardened runtime** | ID checks at the front door | Tampering, unsigned code injection (macOS/Windows) |

## How rex determines each one

| Check | ELF evidence | PE evidence | Mach-O evidence |
|---|---|---|---|
| NX | `PT_GNU_STACK` without `PF_X` | `DllCharacteristics & NX_COMPAT` | no `MH_ALLOW_STACK_EXECUTION` |
| PIE/ASLR | `ET_DYN` + interpreter or `DF_1_PIE` | `DYNAMIC_BASE` (+ relocs present) | `MH_PIE` |
| RELRO | `PT_GNU_RELRO` + `BIND_NOW` = full | n/a | n/a |
| Canary | references `__stack_chk_fail` | load-config `SecurityCookie` | imports `___stack_chk_fail` |
| CFI | GNU property note: IBT/SHSTK, BTI/PAC | `GUARD_CF`, `CET_COMPAT` | n/a |
| Signing | n/a | certificate data directory | `LC_CODE_SIGNATURE`, CodeDirectory `CS_RUNTIME` |

Static checks have honest limits. A "missing canary" can simply mean no function had a
stack buffer worth protecting (`-fstack-protector-strong` is selective), so rex's finding says so.

```sh
rex checksec labs/build/crackme labs/build/vuln crates/rex-binary/tests/fixtures/*
rex analyze firmware-rootfs/bin/* --only binary.checksec --fail-on high   # audit a whole rootfs
```

## Compiler flags to fix findings

```sh
# GCC/Clang, Linux
-fstack-protector-strong -D_FORTIFY_SOURCE=3 -O2 -fPIE -pie -Wl,-z,relro,-z,now -fcf-protection=full
# MSVC
/GS /guard:cf /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /CETCOMPAT
```

## Exercises

1. Compile `labs/binary/02-vuln/vuln.c` with and without each flag above and watch the checksec table change.
2. Why is RELRO irrelevant for statically linked binaries without a dynamic section?
