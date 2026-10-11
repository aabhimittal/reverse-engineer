#!/usr/bin/env bash
# Exercise install.sh against a local fake release: happy path, tampered archive, unlisted archive.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

case "$(uname -s)" in Linux) os=unknown-linux-musl ;; Darwin) os=apple-darwin ;; *) echo "skip: unsupported OS"; exit 0 ;; esac
case "$(uname -m)" in x86_64 | amd64) arch=x86_64 ;; arm64 | aarch64) arch=aarch64 ;; *) echo "skip: unsupported CPU"; exit 0 ;; esac
name="rex-v9.9.9-$arch-$os"

mkdir -p "$tmp/rel" "$tmp/$name"
printf '#!/bin/sh\necho "rex stub"\n' > "$tmp/$name/rex"
chmod +x "$tmp/$name/rex"
tar czf "$tmp/rel/$name.tar.gz" -C "$tmp" "$name"
sums() { (cd "$tmp/rel" && if command -v sha256sum >/dev/null; then sha256sum "$name.tar.gz"; else shasum -a 256 "$name.tar.gz"; fi > SHA256SUMS); }
install() { REX_VERSION="$1" REX_BASE_URL="file://$tmp/rel" REX_INSTALL_DIR="$tmp/bin" sh "$root/install.sh" 2>&1; }

sums
install v9.9.9 >/dev/null
[ "$("$tmp/bin/rex")" = "rex stub" ] || { echo "FAIL: binary not installed"; exit 1; }
install 9.9.9 >/dev/null || { echo "FAIL: version without 'v' prefix rejected"; exit 1; }

rm -f "$tmp/bin/rex"
echo tamper >> "$tmp/rel/$name.tar.gz"
if install v9.9.9 >"$tmp/out" 2>&1; then echo "FAIL: tampered archive accepted"; exit 1; fi
grep -q "checksum mismatch" "$tmp/out" || { echo "FAIL: no mismatch message"; cat "$tmp/out"; exit 1; }
[ ! -e "$tmp/bin/rex" ] || { echo "FAIL: installed despite mismatch"; exit 1; }

echo "abc  other.tar.gz" > "$tmp/rel/SHA256SUMS"
if install v9.9.9 >"$tmp/out" 2>&1; then echo "FAIL: unlisted archive accepted"; exit 1; fi
grep -q "not listed" "$tmp/out" || { echo "FAIL: no 'not listed' message"; exit 1; }
echo "install.sh: all checks passed"
