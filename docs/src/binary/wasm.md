# WebAssembly modules

## The mental model

A WebAssembly module is **a sealed box with a labelled set of holes**. Inside the box the code can
only do arithmetic on its own private memory. It cannot read a file, open a socket or print a line
unless the host *hands it a function through an import*. The imports are the box's entire reach into
the world, so reading them first tells you what the module can possibly do, however obfuscated the code
inside.

That is why WASM triage starts at the imports, not the instructions.

## Anatomy

```text
\0asm 01000000                       magic + version
 section: id, size (LEB128), payload  repeated, in order
   1 type      function signatures
   2 import    (module, name, kind)   ← the box's holes
   3 function  type index per body
   5 memory    min/max pages (64 KiB each)
   7 export    what the host can call
   8 start     runs on instantiation
  10 code      the function bodies
  11 data      initial memory contents (strings, tables, keys)
   0 custom    "name" (debug names), "producers" (toolchain), ".debug_*" (DWARF)
```

Function indices count imports first, then defined functions. That off-by-N is the classic way to
mislabel a function; rex does the arithmetic for you.

## Triage

```console
$ rex analyze labs/wasm/sample.wasm
── WebAssembly overview
  Functions                2 defined, 3 imported
  Start function           run
  Memory 0                 1 page(s) min, no max
  Producer (processed-by)  rustc 1.80.0
── Largest functions (start here)
  decrypt_config  4
  run             2
── Findings
  MEDIUM   Module reaches outside the sandbox through WASI  WASM-WASI-REACH
           • path_open: open files and directories
           • sock_connect: open outbound connections
  LOW      Linear memory has no declared maximum            WASM-MEMORY-UNBOUNDED
  INFO     Module calls host-provided functions             WASM-HOST-IMPORTS
           • env.log
```

How to read it:

- **WASI imports** (`wasi_snapshot_preview1.*`) are grants from a standard host interface. `path_open`
  means files, `sock_*` means network, `proc_exec` means processes. Whether those grants are honoured is
  the *runtime's* decision (a preopened directory list, a network policy), so the finding says "review
  before running", not "malicious".
- **Other imports** (`env.*`) are implemented by whoever embeds the module, usually JavaScript glue in a
  browser. The module is only as safe as that glue. Go read it.
- **Exports** are the module's API; **the start function** runs the moment it is instantiated.
- **Names** come from the optional `name` section. Stripped release builds lose them and you get
  `func_12`. **`.debug_*` or `sourceMappingURL`** means the build kept debug info, which makes your life easier
  and may leak build paths.
- **Data segments** are where embedded strings, tables and constants live; run `rex strings` too.

## Reading the code

```console
$ rex disasm labs/wasm/sample.wasm -F decrypt_config
;; func 4 $decrypt_config (i32) -> (i32)
;; locals: 1 x i32
0000009d  loop
0000009f    local.get 1
000000a1    i32.const 1
000000a3    i32.add
000000a4    local.tee 1
000000a6    local.get 0
000000a8    i32.lt_u
000000a9    br_if 0  ;; -> loop @0x9d (repeat)
000000ab  end
000000ac  local.get 1
000000ae  end
$ rex xrefs labs/wasm/sample.wasm path_open      # who calls this import?
```

WASM has no jump addresses, only nested `block`/`loop`/`if` labels and relative branch depths. The
listing indents by nesting and resolves every `br N` to the label it targets (`-> loop @0x9d (repeat)`
means "jump back to the top of the loop"; `-> end of block` means "skip forward"). Calls show the callee's
name (`module.name` for imports). `rex analyze` also lists, for each import, which functions call it, so
`path_open ← run` tells you where to start reading.

## Limits

rex disassembles instructions but does **not** decompile, recover types, or follow `call_indirect`
(the target is a runtime table lookup, shown as `call_indirect (type N)`). Unknown or very new opcodes stop
that one function's listing and say so. For structured pseudo-code use `wasm-decompile` (WABT) or Ghidra's
WASM loader on the functions rex ranked. Treat sizes as a hint: the largest function is often the
interesting one (crypto, parsing, interpreter loop), but not always.

## Exercises

1. Which single import in the lab would you remove first to cut off network access? What happens to the
   module if the host refuses it?
2. Change `labs/wasm/make_wasm.py` so memory declares a maximum, and rerun. Which finding disappears?
3. Take a real `.wasm` from a web app (DevTools, Network tab) and list what it asks the host for.
