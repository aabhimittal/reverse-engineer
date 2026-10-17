#!/usr/bin/env bash
# Regenerate docs/src/reference/cli.md from the real --help output.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p rex-cli
R=target/debug/rex
{
  echo "# CLI reference"; echo
  echo "Generated from \`rex --help\` by \`scripts/gen-cli-docs.sh\`. Do not edit by hand."; echo
  echo '```text'; $R --help; echo '```'
  for c in analyze disasm xrefs decompile carve diff; do echo; echo "## rex $c"; echo; echo '```text'; $R $c --help; echo '```'; done
  for c in setup doctor "web har2openapi" "web sourcemap" "web asar" "code map" "ai name"; do echo; echo "## rex $c"; echo; echo '```text'; $R $c --help; echo '```'; done
} > docs/src/reference/cli.md
