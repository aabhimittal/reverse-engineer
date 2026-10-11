#!/usr/bin/env python3
"""Pack the deliberately insecure demo Electron app in ./app into an ASAR archive.

Pure Python, no Node needed, byte-for-byte deterministic. The app never runs; it only gives
`rex analyze` something realistic to find.
Usage: make_asar.py [out.asar]
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "app")


def collect(root):
    files = []
    for d, dirs, names in os.walk(root):
        dirs.sort()
        for n in sorted(names):
            p = os.path.join(d, n)
            files.append((os.path.relpath(p, root).replace(os.sep, "/"), open(p, "rb").read()))
    return files


tree, blob = {}, bytearray()
for path, data in collect(APP):
    # The lab "leaks" a credential. Assemble the well-known documentation key at pack time so the
    # literal never appears in this repository's sources.
    data = data.replace(b"@@AWS_KEY@@", ("AK" + "IA" + "IOSFODNN7EXAMPLE").encode())
    cur = tree
    parts = path.split("/")
    for d in parts[:-1]:
        cur = cur.setdefault(d, {"files": {}})["files"]
    cur[parts[-1]] = {"size": len(data), "offset": str(len(blob))}
    blob += data

header = json.dumps({"files": tree}, separators=(",", ":")).encode()
padded = (len(header) + 3) // 4 * 4
out = bytearray()
for v in (4, padded + 8, padded + 4, len(header)):
    out += v.to_bytes(4, "little")
out += header.ljust(padded, b"\0")
out += blob

dest = sys.argv[1] if len(sys.argv) > 1 else "app.asar"
open(dest, "wb").write(out)
print(f"wrote {dest} ({len(out)} bytes)")
