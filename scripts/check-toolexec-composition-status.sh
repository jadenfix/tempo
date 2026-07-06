#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

runtime_manifests=(
  crates/tempo-agent/Cargo.toml
  crates/tempo-headless/Cargo.toml
  crates/tempo-mcp/Cargo.toml
  crates/tempo-bidi/Cargo.toml
  crates/tempo-policy/Cargo.toml
)

runtime_dependents=()
for manifest in "${runtime_manifests[@]}"; do
  if grep -Eq '^[[:space:]]*tempo-toolexec[[:space:]]*=' "$manifest"; then
    runtime_dependents+=("$manifest")
  fi
done

require_grep() {
  local pattern="$1"
  local path="$2"
  local message="$3"
  if ! grep -Eq "$pattern" "$path"; then
    printf '%s\n' "$message" >&2
    exit 1
  fi
}

if ((${#runtime_dependents[@]} == 0)); then
  require_grep 'taint-to-beatbox live dispatch are not shipped preview guarantees' \
    final.md \
    'final.md must keep taint-to-beatbox live dispatch scoped as not shipped while tempo-toolexec has no runtime dependents'
  require_grep 'not a local preview guarantee' \
    final.md \
    'final.md must say the taint+sandbox composition is not a local preview guarantee'
  require_grep 'docs/TAINT_SANDBOX_ADR.md' \
    final.md \
    'final.md must link the taint-to-sandbox ADR while dispatch is deferred'
  require_grep 'real_beatboxd_tainted_canary_denies_import_egress' \
    tests/toolexec-live/tests/live.rs \
    'live beatbox canary test is missing'
  require_grep 'tests/toolexec-live/Cargo.toml' \
    .github/workflows/ci.yml \
    'CI must run the live beatbox canary package'
  exit 0
fi

printf 'runtime tempo-toolexec dependents detected:\n' >&2
printf '  %s\n' "${runtime_dependents[@]}" >&2
printf '%s\n' \
  'Update scripts/check-toolexec-composition-status.sh with the production-path tainted-dispatch sentinel before merging.' >&2
exit 1
