# The reverse engineer's mindset

## Read the map before walking the streets

Beginners open a disassembler and start reading at the entry point, instruction by
instruction. That's like exploring a city by walking every street in alphabetical order.
Experienced reversers **triage first**:

| Question | Cheap evidence | rex |
|---|---|---|
| What is it? | magic bytes, headers | `rex info` |
| What does it talk to? | imports, strings, URLs | `rex strings -c url,ip,path` |
| What can it do? | API combinations | *Capabilities* section |
| Is it hiding something? | entropy, section names | *Packing* section |
| Where's the interesting code? | xrefs from strings/imports | `rex xrefs <file> "password"` |

Only then do you read code, and you read **the 5% that matters**.

## Work outside-in, then inside-out

1. **Outside-in**: start from observable behaviour (a string, an error message, a network
   request) and follow cross-references *into* the code that produces it.
2. **Inside-out**: once you've found a core routine, name it, then follow its callers
   *outward* to discover the features built on it.

Analogy: tracing a river. You either start at the mouth (an observable effect) and walk
upstream, or start at a spring (a primitive like `recv` or `CreateFile`) and walk downstream.

## Name everything, immediately

`sub_401a20` tells you nothing; `decrypt_config` tells you everything. Naming is how you
*compress* what you've learned so you don't re-derive it. rex helps by naming import stubs
(`puts@plt`), IAT slots (`__imp_CreateFileW`), thunks (`j_ExitProcess`) and `main` in stripped
binaries; `rex ai name` suggests names for the rest.

## Keep a hypothesis log

Write down guesses with the evidence for and against. Two habits pay off:

- **Falsify, don't confirm.** "If this is RC4, I should see a 256-byte S-box initialisation loop."
- **Prefer cheap tests.** A cross-reference costs a second; a debugging session costs an hour.

## Exercises

1. Run `rex analyze labs/build/crackme` and, *without reading disassembly*, write down three
   hypotheses about how the password check works. Which sections gave you each idea?
2. Use `rex xrefs labs/build/crackme "Access granted"` to find the deciding function.
