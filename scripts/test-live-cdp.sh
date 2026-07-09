#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="${1:---smoke}"
if [[ "$MODE" != "--smoke" && "$MODE" != "--full" ]]; then
  echo "usage: scripts/test-live-cdp.sh [--smoke|--full]" >&2
  exit 2
fi

if [[ -z "${TEMPO_CDP_CHROME:-}" ]]; then
  TEMPO_CDP_CHROME="$(scripts/setup-cdp-chrome.sh)"
  export TEMPO_CDP_CHROME
fi

"$TEMPO_CDP_CHROME" --version

export TMPDIR
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

if [[ "$MODE" == "--full" ]]; then
  cargo test -p tempo-engine-cdp live_cdp -- --nocapture --test-threads=1
  cargo test -p tempo-engine-cdp --test uds_driver -- --nocapture --test-threads=1
  cargo test -p tempo-engine-cdp --test tempod_live -- --nocapture --test-threads=1
else
  cargo test -p tempo-engine-cdp live_cdp_driver_navigates_observes_acts_and_screenshots -- --nocapture --test-threads=1
  cargo test -p tempo-engine-cdp live_cdp_driver_passes_conformance_v2 -- --nocapture --test-threads=1
  cargo test -p tempo-engine-cdp live_cdp_type_action_preserves_editor_semantics -- --nocapture --test-threads=1
  cargo test -p tempo-engine-cdp live_cdp_insert_text_type_action_preserves_editor_semantics -- --nocapture --test-threads=1
fi
cargo test -p tempo-agent live_cdp -- --nocapture --test-threads=1
