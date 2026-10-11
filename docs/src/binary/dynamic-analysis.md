# Dynamic analysis

rex is purely static. This chapter covers when and how to go *dynamic*, safely.

## Analogy: reading the recipe vs. tasting the dish

Static analysis reads the recipe: complete, but you must imagine the result. Dynamic
analysis tastes the dish: concrete, but you only taste what was cooked this time
(one execution path). Packers, encrypted strings and runtime-resolved APIs often force you to
taste.

## The toolbox

| Goal | Linux | Windows | Android / iOS |
|---|---|---|---|
| Trace syscalls / API calls | `strace -f`, `ltrace` | Process Monitor, API Monitor | `frida-trace` |
| Debug | `gdb` + GEF/pwndbg | x64dbg, WinDbg | `lldb`, `jdb`, Frida |
| Instrument / hook | Frida, `LD_PRELOAD` | Frida, Detours | Frida, Objection |
| Watch network | Wireshark, `tcpdump` | Fiddler, Wireshark | mitmproxy, HTTP Toolkit |
| Sandboxed detonation | CAPE, Cuckoo-style VMs | CAPE, ANY.RUN | MobSF dynamic |

## Safety rules for malware

1. A **dedicated VM** with snapshots; no shared folders, no clipboard sharing.
2. **Host-only or simulated network** (INetSim, FakeNet-NG) unless you intend to watch live C2.
3. Never on a machine with credentials you care about.
4. Assume the sample detects VMs (rex's *Capabilities* section flags anti-VM / anti-debug).

## A workflow that combines both

1. `rex analyze sample` → capabilities, strings, packer verdict.
2. If packed: run in a debugger until the original entry point, dump memory, then
   `rex analyze dump.bin` statically.
3. Use `rex xrefs` to pick breakpoints (e.g. the function that references the C2 URL).
4. Confirm behaviour dynamically; feed new strings/IOCs back into YARA rules.

## Frida in one minute

```js
// trace every call to strcmp and its arguments
Interceptor.attach(Module.getExportByName(null, "strcmp"), {
  onEnter(args) { console.log(args[0].readCString(), "vs", args[1].readCString()); }
});
```

Run against the crackme: `frida -f ./labs/build/crackme -l trace.js -- guess`.
(Hint: the crackme compares byte-by-byte, not with `strcmp`, which is why tracing
alone doesn't solve it.)

## Exercises

1. Use `ltrace ./labs/build/crackme test` and explain what you see and don't see.
2. In gdb, break on the XOR loop found in the static chapter and print the expected bytes.
