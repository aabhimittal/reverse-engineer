#!/usr/bin/env bash
# Print a Homebrew formula for a release.
#   scripts/make-formula.sh v0.1.0 path/to/SHA256SUMS > rex.rb
# Commit the output to your tap (e.g. github.com/<you>/homebrew-tap/Formula/rex.rb).
set -euo pipefail
version="${1:?usage: make-formula.sh <vX.Y.Z> <SHA256SUMS>}"
sums="${2:?usage: make-formula.sh <vX.Y.Z> <SHA256SUMS>}"
repo="aabhimittal/reverse-engineer"
# Where the archives live. Defaults to the GitHub release; the release rehearsal points it at
# file:// so the formula can be installed for real before anything is published.
base="${REX_FORMULA_BASE_URL:-https://github.com/$repo/releases/download/$version}"

sha() {
  local want="rex-$version-$1.tar.gz" h
  h="$(awk -v f="$want" '$2 == f || $2 == "*" f { print $1 }' "$sums")"
  [ -n "$h" ] || { echo "no checksum for $want in $sums" >&2; exit 1; }
  printf '%s' "$h"
}
url() { printf '%s/rex-%s-%s.tar.gz' "$base" "$version" "$1"; }

cat <<RUBY
class Rex < Formula
  desc "Reverse engineer binaries, firmware, Android apps, Electron apps, web APIs and codebases"
  homepage "https://github.com/$repo"
  version "${version#v}"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "$(url aarch64-apple-darwin)"
      sha256 "$(sha aarch64-apple-darwin)"
    else
      url "$(url x86_64-apple-darwin)"
      sha256 "$(sha x86_64-apple-darwin)"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "$(url aarch64-unknown-linux-musl)"
      sha256 "$(sha aarch64-unknown-linux-musl)"
    else
      url "$(url x86_64-unknown-linux-musl)"
      sha256 "$(sha x86_64-unknown-linux-musl)"
    end
  end

  def install
    bin.install "rex"
  end

  test do
    assert_match "rex", shell_output("#{bin}/rex --version")
  end
end
RUBY
