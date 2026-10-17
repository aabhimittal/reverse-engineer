#!/usr/bin/env bash
# Build the binary test fixtures for all three executable formats from labs/ sources.
#
# Produces small, deterministic, *benign* executables used by the test-suite
# (committed under crates/rex-binary/tests/fixtures so CI needs no toolchains).
#
# Requirements: gcc (or cc), clang >= 15, lld (lld-link + ld64.lld), llvm-dlltool, strip.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/crates/rex-binary/tests/fixtures}"
LABS="$ROOT/labs/binary"
mkdir -p "$OUT"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export SOURCE_DATE_EPOCH=1700000000

echo "[*] ELF (x86-64, hardened)"
cc -O1 -g0 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now \
   -Wl,--build-id=none -o "$OUT/crackme.elf" "$LABS/01-crackme/crackme.c"
strip -o "$OUT/crackme.stripped.elf" "$OUT/crackme.elf"
# The same program with its RELATIVE relocations packed into a RELR table.
cc -O1 -g0 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now \
   -Wl,-z,pack-relative-relocs -Wl,--build-id=none -o "$OUT/crackme.relr.elf" "$LABS/01-crackme/crackme.c"

echo "[*] ELF (x86-64, no mitigations)"
cc -O0 -fno-stack-protector -no-pie -z execstack -Wl,-z,norelro -Wl,--build-id=none -w \
   -o "$OUT/vuln.elf" "$LABS/02-vuln/vuln.c"

echo "[*] PE (x86-64, no CRT)"
cat > "$TMP/kernel32.def" <<'DEF'
LIBRARY KERNEL32.dll
EXPORTS
IsDebuggerPresent
ExitProcess
VirtualAllocEx
WriteProcessMemory
CreateRemoteThread
DEF
cat > "$TMP/user32.def" <<'DEF'
LIBRARY USER32.dll
EXPORTS
MessageBoxA
DEF
llvm-dlltool -m i386:x86-64 -d "$TMP/kernel32.def" -l "$TMP/kernel32.lib"
llvm-dlltool -m i386:x86-64 -d "$TMP/user32.def" -l "$TMP/user32.lib"
clang --target=x86_64-pc-windows-msvc -O1 -fno-stack-protector -ffreestanding -fasynchronous-unwind-tables -c \
      "$LABS/03-windows/sample_win.c" -o "$TMP/sample_win.obj"
lld-link /nologo /entry:start /subsystem:windows /nodefaultlib /dynamicbase /nxcompat \
      /timestamp:1700000000 /out:"$OUT/sample.exe" "$TMP/sample_win.obj" "$TMP/kernel32.lib" "$TMP/user32.lib"

# Embedded manifest asking for elevation and UI access (lld-link writes the manifest itself).
printf '__declspec(dllimport) void __stdcall ExitProcess(unsigned);\nvoid start(void){ ExitProcess(0); }\n' > "$TMP/elevated.c"
clang --target=x86_64-pc-windows-msvc -O1 -ffreestanding -c "$TMP/elevated.c" -o "$TMP/elevated.obj"
lld-link /nologo /entry:start /subsystem:windows /nodefaultlib /dynamicbase /nxcompat /timestamp:1700000000 \
      /manifest:embed "/manifestuac:level='requireAdministrator' uiAccess='true'" \
      /out:"$OUT/elevated.exe" "$TMP/elevated.obj" "$TMP/kernel32.lib"

echo "[*] Mach-O (x86-64)"
mkdir -p "$TMP/sdk/usr/lib"
cat > "$TMP/sdk/usr/lib/libSystem.tbd" <<'TBD'
--- !tapi-tbd
tbd-version:     4
targets:         [ x86_64-macos ]
install-name:    '/usr/lib/libSystem.B.dylib'
current-version: 1311
exports:
  - targets:     [ x86_64-macos ]
    symbols:     [ _printf, _puts, _strcmp, dyld_stub_binder, ___stack_chk_fail, ___stack_chk_guard ]
...
TBD
clang --target=x86_64-apple-macos11 -O1 -fstack-protector-strong -c "$LABS/04-macos/hello_mac.c" -o "$TMP/hello_mac.o"
"$(command -v ld64.lld || command -v ld64.lld-18)" -arch x86_64 -platform_version macos 11.0 11.0 -syslibroot "$TMP/sdk" -lSystem -pie \
      -o "$OUT/hello.macho" "$TMP/hello_mac.o"

ls -l "$OUT"

echo "[*] ELF (AArch64 and 32-bit ARM, dynamic with a PLT)"
# A tiny stub library gives the lab a real PLT; lld links without needing a target libc.
for spec in "aarch64-linux-gnu:sample_a64.elf:/lib/ld-linux-aarch64.so.1:" \
            "armv7-linux-gnueabi:sample_arm32.elf:/lib/ld-linux.so.3:-marm" \
            "armv7-linux-gnueabihf:sample_thumb.elf:/lib/ld-linux-armhf.so.3:-mthumb -DLIBC_START"; do
  IFS=: read -r tgt out interp extra <<<"$spec"
  # shellcheck disable=SC2086
  clang --target="$tgt" $extra -O1 -fPIC -nostdlib -shared -fuse-ld=lld -Wl,-soname,libstub.so \
        -Wl,--build-id=none -o "$TMP/libstub.so" "$LABS/05-arm/stub.c"
  # shellcheck disable=SC2086
  clang --target="$tgt" $extra -O1 -fPIE -ffreestanding -fno-stack-protector -fasynchronous-unwind-tables \
        -c "$LABS/05-arm/sample_arm.c" -o "$TMP/sample_arm.o"
  ld.lld -pie -dynamic-linker "$interp" --build-id=none -o "$OUT/$out" "$TMP/sample_arm.o" "$TMP/libstub.so"
done
llvm-strip -o "$OUT/sample_a64.stripped.elf" "$OUT/sample_a64.elf"
llvm-strip -o "$OUT/sample_thumb.stripped.elf" "$OUT/sample_thumb.elf"
# A text relocation (R_ARM_RELATIVE in .text, linked with -z notext).
clang --target=armv7-linux-gnueabi -c "$LABS/05-arm/textrel.s" -o "$TMP/textrel.o"
ld.lld -pie -z notext --build-id=none -o "$OUT/textrel_arm.elf" "$TMP/textrel.o"
# glibc-style PIE _start: main comes from a GOT slot that holds 0 on disk and is filled by an
# R_AARCH64_RELATIVE relocation. --no-relax keeps the GOT load instead of turning it into adrp+add.
clang --target=aarch64-linux-gnu -DGOT_START -O1 -fPIE -ffreestanding -fno-stack-protector \
      -fasynchronous-unwind-tables -c "$LABS/05-arm/sample_arm.c" -o "$TMP/sample_arm_got.o"
clang --target=aarch64-linux-gnu -O1 -fPIC -nostdlib -shared -fuse-ld=lld -Wl,-soname,libstub.so \
      -Wl,--build-id=none -o "$TMP/libstub.so" "$LABS/05-arm/stub.c"
ld.lld -pie -z now --no-relax -dynamic-linker /lib/ld-linux-aarch64.so.1 --build-id=none \
       -o "$TMP/sample_a64_got.elf" "$TMP/sample_arm_got.o" "$TMP/libstub.so"
llvm-strip -o "$OUT/sample_a64_got.stripped.elf" "$TMP/sample_a64_got.elf"
