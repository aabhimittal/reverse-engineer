# Introduction

Reverse engineering is the craft of working out **how something works when nobody
gave you the blueprints**. The "something" might be:

- a compiled program (`.exe`, ELF, Mach-O) you suspect is malicious,
- a router's firmware image you want to audit,
- an Android app whose backend API is undocumented,
- a web application's minified JavaScript,
- or simply a 200 000-line repository you've just inherited.

These look like different jobs, but they share one loop:

```text
   observe  ──►  hypothesise  ──►  test  ──►  name things  ──► (repeat)
```

You observe structure (headers, strings, imports, traffic), form a hypothesis
("this function decrypts the config"), test it (cross-references, a debugger,
a replayed request), and *name* what you've learned so the next pass is easier.
Good tools shorten each step of the loop. They don't replace it.

## How this handbook is organised

Each chapter follows the same arc:

1. **Concept**: what problem are we solving?
2. **Analogy**: a mental model you can carry around.
3. **Mechanics**: how it actually works, down to the bytes where it matters.
4. **Hands-on with `rex`**: commands you can run against the labs in this repository.
5. **The same task with classic tools**: Ghidra, radare2, objdump, binwalk, mitmproxy, jadx, so
   nothing you learn here is tool-specific.
6. **Exercises**.

## Why `rex`?

`rex` is the companion tool. It is deliberately **static** (it never runs the input)
and **broad**: one command, `rex analyze <anything>`, triages binaries, firmware,
APKs, HAR captures, JavaScript bundles and source trees. Be clear about its limits:
it does not compete with Ghidra's decompiler or IDA's debugger. It gets you from
*"what is this?"* to *"where should I look?"* in seconds, then tells you which
heavier tool to open next.

> **Tip:** Every chapter's commands work on the files in `labs/`. Run
> `make -C labs` first to build the native lab binaries and the firmware image.
