# Packers and obfuscation

## Analogy: a vacuum-sealed suitcase

A packer compresses or encrypts the real program and prepends a small *stub* that
unpacks it in memory at runtime. From outside you see only the bag:

- **High entropy** (≈ 7.5–8.0 bits/byte) in an executable section
- **Few imports**, typically `LoadLibrary` + `GetProcAddress` (the stub resolves the rest)
- **Odd section names** (`UPX0`, `.vmp0`, `.themida`, `.aspack`)
- **Writable + executable** sections (the stub writes the code it then runs)
- Entry point in the **last** section, or in a section with no file bytes

```sh
rex analyze sample.exe --only binary.packer
```

rex prints a 0–100 score with every reason, plus a named packer when a signature matches.

## Entropy, intuitively

Entropy measures surprise per byte. English text reuses a few dozen symbols (≈ 4.5).
Machine code has structure (opcodes repeat) (≈ 6). Compressed or encrypted data looks
uniformly random (→ 8). A sudden plateau at ~8 in an entropy profile is a compressed or
encrypted region:

```sh
rex carve firmware.bin           # includes an entropy sparkline
```

## Unpacking strategies

| Packer | Approach |
|---|---|
| UPX (unmodified) | `upx -d sample.exe` |
| Modified UPX / simple stubs | Debugger: break at `VirtualProtect`/`mprotect` or the tail jump, dump at OEP (Scylla, `pe-sieve`) |
| Virtualisation (VMProtect, Themida) | Don't fully unpack; trace behaviour dynamically, devirtualise only the handler you need |
| Script obfuscation (JS/PowerShell) | Let the language evaluate the decoding layer in a sandbox; beautify; repeat |

## String obfuscation

Strings that are XOR'd, stack-built (`mov byte [rsp+0x10], 0x68` …) or decrypted at runtime
won't appear in `rex strings`. Clues: functions with many small immediate stores, or a loop
that XORs a buffer with a constant (see the crackme). Tools like FLOSS emulate these to recover strings.

## Exercises

1. Pack `labs/build/crackme` with `upx` and compare `rex analyze` before and after.
2. Why does UPX leave the string `UPX!` in the file, and why do malware authors patch it out?
