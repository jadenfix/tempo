#!/usr/bin/env bash
set -euo pipefail

# final.md requires Servo embedder types to stay behind tempo-engine-servo.
# This grep guard catches public Rust item signatures outside that crate that
# expose Servo/private embedder names.
pattern='^[[:space:]]*pub(\([^)]*\))?[[:space:]]+(async[[:space:]]+)?(struct|enum|trait|type|fn|const|static|use)[^\r\n]*\b(servo::|libservo|WebView|WebViewDelegate|WebResource|WebResourceLoad|RenderingContext|Constellation|Compositor|Embedder|ServoUrl)\b'

violations="$(
  rg -n \
    --glob '*.rs' \
    --glob '!crates/tempo-engine-servo/**' \
    "$pattern" \
    crates || true
)"

if [[ -n "$violations" ]]; then
  cat >&2 <<'MSG'
Servo embedder types leaked into a public API outside crates/tempo-engine-servo.
Keep libservo/private embedder types behind the engine boundary and expose only
tempo-driver/tempo-schema types across crates.
MSG
  printf '%s\n' "$violations" >&2
  exit 1
fi
