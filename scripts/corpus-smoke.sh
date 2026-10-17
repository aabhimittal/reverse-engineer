#!/usr/bin/env bash
# Run `rex analyze` over a corpus of real files and report crashes, hangs and slow inputs.
#   scripts/corpus-smoke.sh [rex-binary] [timeout-seconds] [paths...]
# With no paths it scans the usual system locations. Exits non-zero if any input made rex panic,
# crash or exceed the timeout. Exit 3 ("findings at or above --fail-on") counts as success, and so
# does a clean "unsupported file" error.
#   REX_MAX_FILES (default 4000)  REX_SLOW_SECS (default 5)  REX_JOBS (default: CPU count)
set -uo pipefail
REX="$(realpath "${1:-target/release/rex}")"; shift || true
LIMIT="${1:-20}"; shift || true
paths=("$@")
[ ${#paths[@]} -gt 0 ] || paths=(/usr/bin /usr/sbin /usr/lib /usr/libexec /usr/local/bin)
export REX LIMIT SLOW="${REX_SLOW_SECS:-5}"

one() {
  f="$1" err="$(mktemp)"
  start=$(date +%s%N)
  timeout -k 2 "$LIMIT" "$REX" analyze -f json "$f" > /dev/null 2> "$err"
  code=$? ms=$(( ($(date +%s%N) - start) / 1000000 ))
  if [ $code -eq 124 ] || [ $code -eq 137 ]; then
    echo "TIMEOUT ${LIMIT}s  $f"
  elif [ $code -gt 128 ] || grep -qE "panicked|stack overflow" "$err"; then
    echo "CRASH($code)  $f  $(grep -m1 -E 'panicked|overflow' "$err")"
  elif [ $ms -gt $((SLOW * 1000)) ]; then
    echo "SLOW ${ms}ms  $f"
  fi
  rm -f "$err"
}
export -f one

list="$(mktemp)"; trap 'rm -f "$list"' EXIT
find "${paths[@]}" -xdev -type f -size +0 2>/dev/null | head -n "${REX_MAX_FILES:-4000}" > "$list"
report="$(xargs -d '\n' -P "${REX_JOBS:-$(nproc)}" -I{} bash -c 'one "$1"' _ {} < "$list" | sort)"
[ -n "$report" ] && echo "$report"
bad=$(grep -cE "^(CRASH|TIMEOUT)" <<<"$report")
echo "scanned $(wc -l < "$list") files: $bad crashes/timeouts, $(grep -c '^SLOW' <<<"$report") slower than ${SLOW}s"
[ "$bad" -eq 0 ]
