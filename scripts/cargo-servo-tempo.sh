#!/usr/bin/env bash
set -euo pipefail

default_repo="https://github.com/jadenfix/servo"
repo="${TEMPO_SERVO_REPO:-$default_repo}"
audited_rev="tempo-servo-0.3"
ref="${TEMPO_SERVO_REF:-$audited_rev}"
path="${TEMPO_SERVO_PATH:-}"
allow_unaudited="${TEMPO_SERVO_ALLOW_UNAUDITED:-}"

if [[ $# -eq 0 ]]; then
  set -- check -p tempo-engine-servo --no-default-features --features servo-tempo
fi

if [[ -n "$path" || "$repo" != "$default_repo" || "$ref" != "$audited_rev" ]]; then
  case "$allow_unaudited" in
    1|true|TRUE|True|yes|YES|Yes|on|ON|On) ;;
    *)
      {
        echo "tempo: refusing unaudited Servo override."
        echo "tempo: Default uses audited Servo rev $audited_rev from $default_repo."
        echo "tempo: Set TEMPO_SERVO_ALLOW_UNAUDITED=1 to use TEMPO_SERVO_PATH, TEMPO_SERVO_REPO, or a non-audited TEMPO_SERVO_REF."
      } >&2
      exit 1
      ;;
  esac
fi

if [[ -n "$path" ]]; then
  cargo_config=(--config "patch.crates-io.servo.path=\"$path\"")
else
  if [[ "$ref" =~ ^[0-9a-fA-F]{40}$ ]]; then
    cargo_config=(
      --config "patch.crates-io.servo.git=\"$repo\""
      --config "patch.crates-io.servo.rev=\"$ref\""
    )
  else
    cargo_config=(
      --config "patch.crates-io.servo.git=\"$repo\""
      --config "patch.crates-io.servo.branch=\"$ref\""
    )
  fi
fi

log="$(mktemp "${TMPDIR:-/tmp}/tempo-servo-cargo.XXXXXX")"
trap 'rm -f "$log"' EXIT

set +e
cargo "${cargo_config[@]}" "$@" 2>&1 | tee "$log"
status="${PIPESTATUS[0]}"
set -e

if grep -Eiq 'patch .*servo.* was not used' "$log"; then
  {
    echo "tempo: Cargo did not use the Servo fork patch."
    echo "tempo: The fork package version likely does not satisfy tempo-engine-servo's pinned servo = 0.3.0 dependency."
    echo "tempo: Point TEMPO_SERVO_PATH or TEMPO_SERVO_REF at a 0.3.0-compatible branch, or intentionally update the vanilla gate."
  } >&2
  exit 1
fi

exit "$status"
