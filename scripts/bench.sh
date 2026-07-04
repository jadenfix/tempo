#!/usr/bin/env bash
# Run the tempo latency benchmark suite and store a named criterion baseline.
#
# Usage:
#   scripts/bench.sh                 # run all benches, save baseline "local"
#   scripts/bench.sh main            # save baseline named "main"
#   scripts/bench.sh pr main         # run + compare against baseline "main"
#
# Criterion writes reports under target/criterion/. Compare two runs with:
#   scripts/bench.sh main   (on the base branch)
#   scripts/bench.sh pr main (on the candidate branch)
set -euo pipefail

cd "$(dirname "$0")/.."

BASELINE="${1:-local}"
COMPARE="${2:-}"

BENCHES=(
  "tempo-observe observe"
  "tempo-engine-host framing"
  "tempo-act quiescence"
  "tempo-policy policy"
  "tempo-session cassettes"
)

ARGS=(--save-baseline "$BASELINE")
if [[ -n "$COMPARE" ]]; then
  ARGS=(--baseline "$COMPARE")
fi

for entry in "${BENCHES[@]}"; do
  read -r crate bench <<<"$entry"
  cargo bench -p "$crate" --bench "$bench" -- "${ARGS[@]}"
done

echo
echo "criterion reports: target/criterion/"
echo "baseline saved as: ${BASELINE}${COMPARE:+ (compared against ${COMPARE})}"
