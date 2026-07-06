#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

# Raw engine accessibility/compiler-input types must stay in engine adapters or
# fixtures. tempod-side crates consume tempo-schema observations/diffs only.
raw_boundary_pattern='(accesskit::|AccessKit|TreeUpdate|AxNode|AxValue|AXNode|AXTree|FullAXTree|GetFullAXTree|GetPartialAxTree|RawElement|ObservationInput|ObservationCompiler|StableIdMapper|finalize_observation)'

scan_raw_boundary_leaks() {
  local found=1 file matches
  while IFS= read -r -d '' file; do
    if matches="$(grep -nE "$raw_boundary_pattern" "$file")"; then
      while IFS= read -r line; do
        printf '%s:%s\n' "$file" "$line"
      done <<<"$matches"
      found=0
    fi
  done < <(find "$@" -type f -name '*.rs' -print0)
  return "$found"
}

self_test_fixture="tests/fixtures/observation-boundary/raw-ax-leak.rs"
self_test="$(scan_raw_boundary_leaks "$self_test_fixture" || true)"
if [[ -z "$self_test" ]]; then
  cat >&2 <<'MSG'
Observation boundary guard self-test failed: the planted raw-AX leak was not
detected. The guard must fail closed if its scanner breaks.
MSG
  exit 2
fi

violations="$(
  scan_raw_boundary_leaks \
    crates/tempo-headless/src \
    crates/tempo-mcp/src \
    crates/tempo-bidi/src \
    crates/tempo-agent/src \
    crates/tempo-engine-host/src \
    crates/tempo-schema/src \
    || true
)"

if [[ -n "$violations" ]]; then
  cat >&2 <<'MSG'
Raw accessibility/compiler-input types crossed into tempod-side runtime crates.
Keep AccessKit/AX trees and tempo-observe raw compiler inputs inside engine
adapters or fixtures; runtime wire surfaces must carry tempo-schema
CompiledObservation/ObservationDiff values instead.
MSG
  printf '%s\n' "$violations" >&2
  exit 1
fi

require_grep() {
  local pattern="$1"
  local path="$2"
  local message="$3"
  if ! grep -Eq "$pattern" "$path"; then
    printf '%s\n' "$message" >&2
    exit 1
  fi
}

require_grep 'docs/OBSERVATION_COMPILE_LOCUS_ADR.md' \
  final.md \
  'final.md must link the observation compile locus ADR'
require_grep 'native Servo/out-of-process lane is deferred' \
  final.md \
  'final.md must scope native Servo engine-side observation compilation as deferred until wired'

require_grep '^tempo-observe[[:space:]]*=' \
  crates/tempo-engine-cdp/Cargo.toml \
  'tempo-engine-cdp must keep tempo-observe so CDP AX/DOM data is compiled before DriverResponse crosses into tempod'

servo_raw_imports="$(scan_raw_boundary_leaks crates/tempo-engine-servo/src || true)"
if [[ -n "$servo_raw_imports" ]] \
  && ! grep -Eq '^tempo-observe[[:space:]]*=' crates/tempo-engine-servo/Cargo.toml; then
  cat >&2 <<'MSG'
tempo-engine-servo mentions raw accessibility/compiler-input types but does not
depend on tempo-observe. The native lane must compile AccessKit-derived inputs
inside the engine process before DriverResponse crosses into tempod.
MSG
  printf '%s\n' "$servo_raw_imports" >&2
  exit 1
fi
