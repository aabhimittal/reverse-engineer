#!/bin/sh
# rex installer: downloads a prebuilt release, verifies its SHA-256, installs one binary.
#
#   curl -fsSL https://raw.githubusercontent.com/aabhimittal/reverse-engineer/main/install.sh | sh
#
# Environment:
#   REX_VERSION      tag to install, e.g. v0.1.0 (default: latest release)
#   REX_INSTALL_DIR  destination directory (default: $HOME/.local/bin)
#   REX_BASE_URL     where release assets live (default: the GitHub release for REX_VERSION);
#                    any URL curl understands, including file:///path, for mirrors and tests
#
# The checksum file is fetched from the same place as the archive, so verification catches
# corrupted or truncated downloads, not a compromised release. For that, verify the build
# provenance attestation: `gh attestation verify <archive> --repo aabhimittal/reverse-engineer`.
set -eu

REPO="aabhimittal/reverse-engineer"

say() { printf '%s\n' "$*" >&2; }
die() { say "rex-install: $*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed"; }

need curl
need tar
need uname

case "$(uname -s)" in
  Linux)  os=unknown-linux-musl ;;
  Darwin) os=apple-darwin ;;
  *) die "unsupported OS '$(uname -s)'. On Windows download the .zip from https://github.com/$REPO/releases" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64)  arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) die "unsupported CPU '$(uname -m)'" ;;
esac
target="$arch-$os"
case "$target" in
  x86_64-unknown-linux-musl | aarch64-unknown-linux-musl | aarch64-apple-darwin | x86_64-apple-darwin) ;;
  *) die "no prebuilt binary for $target" ;;
esac

version="${REX_VERSION:-}"
if [ -z "$version" ]; then
  # /releases/latest redirects to /releases/tag/<tag>; read the final URL, no API token needed.
  version="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed 's|.*/||')"
  [ -n "$version" ] || die "could not determine the latest release"
fi
case "$version" in v*) ;; *) version="v$version" ;; esac

base="${REX_BASE_URL:-https://github.com/$REPO/releases/download/$version}"
name="rex-$version-$target"
dest="${REX_INSTALL_DIR:-$HOME/.local/bin}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "rex-install: $version for $target"
curl -fsSL "$base/$name.tar.gz" -o "$tmp/$name.tar.gz" || die "download failed: $base/$name.tar.gz"
curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" || die "download failed: $base/SHA256SUMS"

want="$(awk -v f="$name.tar.gz" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")"
[ -n "$want" ] || die "$name.tar.gz is not listed in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
  got="$(sha256sum "$tmp/$name.tar.gz" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  got="$(shasum -a 256 "$tmp/$name.tar.gz" | awk '{print $1}')"
else
  die "need sha256sum or shasum to verify the download"
fi
[ "$got" = "$want" ] || die "checksum mismatch (expected $want, got $got); nothing was installed"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
[ -f "$tmp/$name/rex" ] || die "archive does not contain the rex binary"
mkdir -p "$dest"
cp "$tmp/$name/rex" "$dest/rex.new"
chmod 755 "$dest/rex.new"
mv "$dest/rex.new" "$dest/rex"

say "rex-install: installed $dest/rex"
case ":$PATH:" in
  *":$dest:"*) ;;
  *) say "rex-install: $dest is not on your PATH. Add:  export PATH=\"$dest:\$PATH\"" ;;
esac
say "rex-install: next:  rex setup    # wire rex into your AI coding agents (optional)"
say "rex-install:        rex doctor   # check what is available"
