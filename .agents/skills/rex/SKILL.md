---
name: rex
description: Static reverse engineering with the rex toolkit. Use when asked to analyse or understand a binary (ELF/PE/Mach-O), firmware image, Android APK, WebAssembly module, Electron app (app.asar), HAR capture, JavaScript bundle or an unfamiliar codebase, or to compare two builds. Triage first, then drill down.
---

# rex: static reverse engineering

`rex` analyses files without ever executing them. Prefer it for triage: it tells you what a thing is,
what it can do, what is risky, and where to look next, in seconds. It is not a decompiler or debugger.

## Workflow

1. **Triage**: `rex_analyze` on the path (or `rex analyze <path>`). Read the *Findings* first, then the sections.
2. **Drill down** by input type:
   - Native binary: `rex_functions` -> `rex_xrefs` (a string, import or function) -> `rex_disasm` (one function) -> `rex_cfg`.
   - Two builds: `rex_diff` (look at small "surgical" changes first).
   - Firmware blob: `rex_carve`, then analyse the extracted files.
   - WebAssembly: `rex_analyze` lists imports (WASI grants are its whole reach outside the sandbox), exports and the largest functions.
   - Electron `app.asar`: `rex_analyze` reports window security settings, IPC channels, secrets and dependencies; `rex web asar <file> -d dir` extracts the JS to read.
   - HAR capture: `rex_har_to_openapi` for the API spec; the report also lists traffic-audit findings.
   - Source tree: `rex_code_map` for entry points, routes, central modules and hotspots.
3. **Report** evidence, not guesses: cite addresses, strings, imports and finding ids (for example `BIN-MITIGATION-NX`).

## Rules

- Everything is static. Never run an untrusted sample on the user's machine.
- Findings are leads, not verdicts. State what evidence supports a conclusion and what is unknown.
- Secrets are masked in reports; do not try to reconstruct them. Do not paste live credentials into responses.
- Analyse only software the user owns or is authorised to analyse. Refuse requests to build malware or evade detection.
- Large outputs are truncated at 60 000 characters; narrow the request (a single function, `only` analyzer prefixes) rather than asking for everything.
