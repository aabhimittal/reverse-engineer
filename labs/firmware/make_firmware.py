#!/usr/bin/env python3
"""Build a synthetic router-style firmware image for the carving lab.

Layout (offsets vary; that's the point of the exercise):
  [bootloader-ish padding] [uImage header + gzip "kernel"] [0xFF erase padding]
  [cpio newc root filesystem] [PNG logo] [PEM private key (fake)] [random "encrypted" blob]

Usage:  python3 make_firmware.py firmware.bin
Then:   rex carve firmware.bin --extract out/
"""
import gzip, io, os, random, struct, sys, zlib

random.seed(1337)

def uimage(payload: bytes, name: bytes) -> bytes:
    hdr = struct.pack(">IIIIIIIBBBB32s", 0x27051956, 0, 1700000000, len(payload), 0x80008000, 0x80008000,
                      zlib.crc32(payload) & 0xffffffff, 5, 2, 2, 1, name.ljust(32, b"\0"))
    hcrc = zlib.crc32(hdr) & 0xffffffff
    return hdr[:4] + struct.pack(">I", hcrc) + hdr[8:] + payload

def cpio(files: dict) -> bytes:
    out = io.BytesIO()
    def entry(name: bytes, data: bytes, mode: int):
        hdr = b"070701" + b"".join(b"%08X" % v for v in (0, mode, 0, 0, 1, 1700000000, len(data), 0, 0, 0, 0, len(name) + 1, 0))
        out.write(hdr + name + b"\0")
        while out.tell() % 4: out.write(b"\0")
        out.write(data)
        while out.tell() % 4: out.write(b"\0")
    for name, data in files.items():
        entry(name.encode(), data, 0o100644)
    entry(b"TRAILER!!!", b"", 0)
    return out.getvalue()

def png(w=8, h=8) -> bytes:
    def chunk(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    raw = b"".join(b"\0" + bytes([200, 30, 30] * w) for _ in range(h))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")

kernel = gzip.compress(b"Linux version 5.10.0-rexlab (builder@example) #1 SMP\n" + bytes(random.getrandbits(8) for _ in range(6000)), mtime=0)
rootfs = cpio({
    "etc/passwd": b"root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000::/home/admin:/bin/sh\n",
    "etc/shadow": b"root:$1$rexlab$Q0nqYQpU6R2LHq4rI3H3c/:19000:0:99999:7:::\n",
    "etc/init.d/rcS": b"#!/bin/sh\ntelnetd -l /bin/sh &\nhttpd -h /www &\n",
    "www/cgi-bin/ping.cgi": b"#!/bin/sh\nping -c 1 $QUERY_STRING\n",
    "etc/config/cloud.conf": b"endpoint=http://iot-cloud.example.net/api/v1/telemetry\napi_password=Rexlab2024!\n",
})
pem_label = "RSA " + "PRIVATE KEY"  # assembled at runtime; this is a fake lab key
key = ("-----BEGIN %s-----\n" % pem_label + "\n".join(
    "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(64)) for _ in range(6)
) + "\n-----END %s-----\n" % pem_label).encode()

blob = bytearray(b"\0" * 0x400)
blob += b"RexBoot v1.2 (c) example\0" + b"\0" * 64
blob += uimage(kernel, b"rex-lab kernel")
blob += b"\xff" * 0x800
blob += rootfs
blob += b"\0" * 37
blob += png()
blob += b"\0" * 19
blob += key
blob += bytes(random.getrandbits(8) for _ in range(8192))
out = sys.argv[1] if len(sys.argv) > 1 else "firmware.bin"
os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
open(out, "wb").write(blob)
print(f"wrote {out} ({len(blob)} bytes)")
