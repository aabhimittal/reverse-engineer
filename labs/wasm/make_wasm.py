#!/usr/bin/env python3
"""Assemble a small, benign WebAssembly module for the rex WASM lab.

It imports two WASI functions that reach outside the sandbox (path_open, sock_connect) and one
host function, has a memory with no maximum, a start function, two bodies and a `name` section.
Usage: make_wasm.py [out.wasm]
"""
import sys


def leb(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v == 0:
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def name(s):
    b = s.encode()
    return leb(len(b)) + b


def section(sid, payload):
    return bytes([sid]) + leb(len(payload)) + payload


w = bytearray(b"\0asm\x01\0\0\0")
w += section(1, bytes([1, 0x60, 0, 0]))
imp = leb(3)
for m, f in [("wasi_snapshot_preview1", "path_open"), ("wasi_snapshot_preview1", "sock_connect"), ("env", "log")]:
    imp += name(m) + name(f) + bytes([0, 0])
w += section(2, imp)
w += section(3, bytes([2, 0, 0]))
w += section(5, bytes([1, 0, 1]))
w += section(7, leb(2) + name("memory") + bytes([2, 0]) + name("run") + bytes([0, 3]))
w += section(8, bytes([3]))
w += section(10, bytes([2, 2, 0, 0x0B, 4, 0, 0x01, 0x01, 0x0B]))
w += section(11, bytes([1, 0, 0x41, 0, 0x0B]) + leb(5) + b"hello")
sub = leb(1) + leb(4) + name("decrypt_config")
w += section(0, name("name") + bytes([1]) + leb(len(sub)) + sub)
w += section(0, name("producers") + leb(1) + name("processed-by") + leb(1) + name("rustc") + name("1.80.0"))

out = sys.argv[1] if len(sys.argv) > 1 else "sample.wasm"
open(out, "wb").write(w)
print(f"wrote {out} ({len(w)} bytes)")
