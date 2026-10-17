#!/usr/bin/env python3
"""Build small synthetic Linux core dumps for the crash-triage lab.

Each core describes the same crash: `crashme` (pid 4242, two threads) dereferences a NULL struct
pointer, so the kernel delivers SIGSEGV / SEGV_MAPERR for address 0x10 while the crashing
thread's pc is in crashme's text. The second thread sits in libc. The stack holds return
addresses into crashme and libc for the stack scan to find.

Layout: ELF header, program headers, one PT_NOTE (NT_PRSTATUS x2, NT_PRPSINFO, NT_SIGINFO,
NT_AUXV, NT_FILE), then the dumped bytes of crashme's text and of the stack. libc's and
crashme's other mappings are PT_LOADs with no file bytes, like pages the kernel skips.

Usage:  python3 make_core.py OUTDIR      # writes OUTDIR/core.x64 and OUTDIR/core.a64
Then:   rex core OUTDIR/core.x64
"""
import os, struct, sys

EXE, LIBC = "/usr/bin/crashme", "/usr/lib/libc.so.6"
EXE_BASE, LIBC_BASE = 0x555555554000, 0x7ffff7dd0000
TEXT = EXE_BASE + 0x1000            # crashme r-x
LIBC_TEXT = LIBC_BASE + 0x28000     # libc r-x
STACK = 0x7fffffffe000              # one dumped stack page
SP = STACK + 0x800
PC = TEXT + 0x139                   # faulting instruction in crashme
LIBC_PC = LIBC_TEXT + 0x7b2a1       # thread 2, blocked in a futex
FAULT = 0x10
SIGSEGV, SEGV_MAPERR = 11, 1
PF_X, PF_W, PF_R = 1, 2, 4

def note(name: bytes, ntype: int, desc: bytes) -> bytes:
    name += b"\0"
    pad = lambda b: b + b"\0" * (-len(b) % 4)
    return struct.pack("<III", len(name), len(desc), ntype) + pad(name) + pad(desc)

def prstatus(tid: int, cursig: int, regs: list) -> bytes:
    # struct elf_prstatus (64-bit): pr_info, pr_cursig, sigpend/sighold, pids, 4 timevals, pr_reg.
    hdr = struct.pack("<iiihxxQQIIII", cursig, 0, 0, cursig, 0, 0, tid, 1, 4242, 1)
    hdr += b"\0" * 64
    return hdr + struct.pack(f"<{len(regs)}Q", *regs) + struct.pack("<i4x", 1)

def prpsinfo() -> bytes:
    return struct.pack("<bcbbxxxxQIIIIII16s80s", 0, b"R", 0, 0, 0x400600, 1000, 1000, 4242, 1, 4242, 1,
                       b"crashme", b"/usr/bin/crashme --input /tmp/poc.bin")

def siginfo() -> bytes:
    return struct.pack("<iii4xQ", SIGSEGV, 0, SEGV_MAPERR, FAULT).ljust(128, b"\0")

def auxv(execfn_addr: int) -> bytes:
    ents = [(3, EXE_BASE + 0x40), (6, 0x1000), (9, TEXT + 0x40), (16, 0x178bfbff), (31, execfn_addr), (0, 0)]
    return b"".join(struct.pack("<QQ", t, v) for t, v in ents)

def nt_file() -> bytes:
    maps = [(EXE_BASE, TEXT, 0, EXE), (TEXT, TEXT + 0x1000, 1, EXE),
            (LIBC_BASE, LIBC_TEXT, 0, LIBC), (LIBC_TEXT, LIBC_TEXT + 0x195000, 0x28, LIBC)]
    out = struct.pack("<QQ", len(maps), 0x1000)
    out += b"".join(struct.pack("<QQQ", s, e, o) for s, e, o, _ in maps)
    return out + b"".join(p.encode() + b"\0" for *_, p in maps)

def regs_x64(pc: int, sp: int, rax: int) -> list:
    # user_regs_struct: r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax
    #                   rip cs eflags rsp ss fs_base gs_base ds es fs gs
    r = [0] * 27
    r[4], r[10], r[15], r[16], r[17], r[18], r[19], r[20] = sp + 0x40, rax, 2**64 - 1, pc, 0x33, 0x10246, sp, 0x2b
    r[21] = 0x7ffff7d8a740
    return r

def regs_a64(pc: int, sp: int, x0: int) -> list:
    # x0-x30, sp, pc, pstate
    r = [0] * 34
    r[0], r[29], r[30], r[31], r[32], r[33] = x0, sp + 0x40, TEXT + 0x1a4, sp, pc, 0x60000000
    return r

def stack_page(execfn_at: int) -> bytes:
    page = bytearray(0x1000)
    words = {0x00: 0x4141414141414141, 0x08: TEXT + 0x1a4, 0x10: SP + 0x40, 0x18: 0x2a,
             0x28: TEXT + 0x2d0, 0x38: LIBC_TEXT + 0x29d90, 0x48: LIBC_TEXT + 0x29e40,
             0x58: TEXT + 0x60, 0x60: STACK + 0x10, 0x70: 0xdeadbeef}
    for off, v in words.items():
        struct.pack_into("<Q", page, 0x800 + off, v)
    page[execfn_at:execfn_at + len(EXE) + 1] = EXE.encode() + b"\0"
    return bytes(page)

def core(machine: int, regs) -> bytes:
    execfn_at = 0xfe0
    notes = b"".join([
        note(b"CORE", 1, prstatus(4242, SIGSEGV, regs(PC, SP, 0))),
        note(b"CORE", 3, prpsinfo()),
        note(b"CORE", 0x53494749, siginfo()),
        note(b"CORE", 6, auxv(STACK + execfn_at)),
        note(b"CORE", 0x46494C45, nt_file()),
        note(b"CORE", 1, prstatus(4243, 0, regs(LIBC_PC, SP - 0x2000, 0xfffffffffffffe00))),
    ])
    # x86-64: mov eax, [rax+0x10]; AArch64: ldr w0, [x0, #0x10]. Pad with nops / brk.
    code = (bytes.fromhex("8b4010") + b"\x90" * 61) if machine == 62 else (bytes.fromhex("000840b9") + bytes.fromhex("1f2003d5") * 15)
    stack = stack_page(execfn_at)
    loads = [  # (vaddr, memsz, flags, data)
        (EXE_BASE, 0x1000, PF_R, b""),
        (TEXT, 0x1000, PF_R | PF_X, code),
        (LIBC_BASE, 0x28000, PF_R, b""),
        (LIBC_TEXT, 0x195000, PF_R | PF_X, b""),
        (STACK, 0x1000, PF_R | PF_W, stack),
    ]
    phnum = 1 + len(loads)
    off = 64 + 56 * phnum
    phdrs = struct.pack("<IIQQQQQQ", 4, 0, off, 0, 0, len(notes), 0, 4)
    body = notes
    for vaddr, memsz, flags, data in loads:
        at = off + len(body)
        phdrs += struct.pack("<IIQQQQQQ", 1, flags, at, vaddr, 0, len(data), memsz, 0x1000)
        body += data
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    ehdr = ident + struct.pack("<HHIQQQIHHHHHH", 4, machine, 1, 0, 64, 0, 0, 64, 56, phnum, 0, 0, 0)
    return ehdr + phdrs + body

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    os.makedirs(out, exist_ok=True)
    for name, machine, regs in (("core.x64", 62, regs_x64), ("core.a64", 183, regs_a64)):
        with open(os.path.join(out, name), "wb") as f:
            f.write(core(machine, regs))
