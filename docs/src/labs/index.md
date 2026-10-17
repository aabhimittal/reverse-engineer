# Lab index

All labs are **benign and synthetic**. Binaries are built from the C sources in `labs/binary/`,
and the core dumps, HAR, bundle, APK and firmware images come from generator scripts, so everything is
reproducible and reviewable.

| Lab | Build | Try |
|---|---|---|
| Crackme (hardened ELF) | `make -C labs` | `rex disasm labs/build/crackme -F check_password` |
| Vulnerable binary (no mitigations) | `make -C labs` | `rex analyze labs/build/vuln --fail-on high` |
| Windows PE with capability imports | `scripts/build-fixtures.sh` | `rex analyze crates/rex-binary/tests/fixtures/sample.exe` |
| Mach-O | `scripts/build-fixtures.sh` | `rex functions crates/rex-binary/tests/fixtures/hello.macho` |
| Firmware image | `make -C labs firmware` | `rex analyze labs/build/firmware.bin` |
| Crash core dumps (x86-64, AArch64) | `make -C labs crash` | `rex core labs/crash/core.x64` |
| HAR capture | `python3 labs/web/make_har.py > labs/web/sample.har` | `rex web har2openapi labs/web/sample.har` |
| JS bundle + source map | `python3 labs/web/make_bundle.py` | `rex web sourcemap labs/web/bundle/app.min.js` |
| Android APK | `cargo run -p rex-web --example make_lab_apk -- labs/android/rexlab.apk` | `rex apk labs/android/rexlab.apk` |
| WebAssembly module | `python3 labs/wasm/make_wasm.py labs/wasm/sample.wasm` | `rex analyze labs/wasm/sample.wasm` |
| Electron app (insecure by design) | `python3 labs/electron/make_asar.py labs/electron/app.asar` | `rex analyze labs/electron/app.asar` |
| AArch64 and ARM32 ELF with a PLT | `scripts/build-fixtures.sh` | `rex functions crates/rex-binary/tests/fixtures/sample_a64.elf` (needs `--features multiarch`) |
