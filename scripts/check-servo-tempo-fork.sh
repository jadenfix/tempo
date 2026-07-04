#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

rust_const() {
  local name="$1"
  sed -nE "s/^pub const ${name}: \&str = \"([^\"]+)\";$/\1/p" \
    crates/tempo-engine-servo/src/lib.rs
}

repo="$(rust_const TEMPO_SERVO_FORK_REPOSITORY)"
rev="$(rust_const TEMPO_SERVO_FORK_REVISION)"
if [[ -z "$repo" || -z "$rev" ]]; then
  echo "failed to read Tempo Servo fork pin from crates/tempo-engine-servo/src/lib.rs" >&2
  exit 1
fi
lock_backup="$(mktemp)"
config_file="$(mktemp)"
had_lockfile=0
if [[ -f Cargo.lock ]]; then
  had_lockfile=1
  cp Cargo.lock "$lock_backup"
fi
cat >"$config_file" <<EOF
[patch.crates-io]
servo = { git = "$repo", rev = "$rev" }
EOF

restore_lockfile() {
  if [[ "$had_lockfile" -eq 1 ]]; then
    cp "$lock_backup" Cargo.lock
  else
    rm -f Cargo.lock
  fi
  rm -f "$lock_backup" "$config_file"
}
trap restore_lockfile EXIT

export CARGO_TARGET_DIR="${TEMPO_SERVO_TARGET_DIR:-target/servo-tempo-fork}"

cargo check \
  -p tempo-engine-servo \
  --no-default-features \
  --features servo-tempo \
  --config "$config_file" \
  "$@"
