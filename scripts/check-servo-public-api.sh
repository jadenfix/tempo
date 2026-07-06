#!/usr/bin/env bash
set -euo pipefail

# final.md requires Servo embedder types to stay behind tempo-engine-servo.
# The T2 system-webview adapter owns generic WebView vocabulary, so this guard
# scans every other public Rust item signature for Servo/private embedder names.
pattern='^[[:space:]]*pub(\([^)]*\))?[[:space:]]+(async[[:space:]]+)?(struct|enum|trait|type|fn|const|static|use)[^[:cntrl:]]*([^[:alnum:]_]|::)(servo::|libservo|WebView|WebViewDelegate|WebResource|WebResourceLoad|RenderingContext|Constellation|Compositor|Embedder|ServoUrl)'

scan_public_rust_api() {
  local root file matches found=1
  for root in "$@"; do
    [[ -e "$root" ]] || continue
    while IFS= read -r -d '' file; do
      case "$file" in
        crates/tempo-engine-servo/*|*/crates/tempo-engine-servo/*) continue ;;
        crates/tempo-engine-webview/*|*/crates/tempo-engine-webview/*) continue ;;
      esac
      if matches="$(grep -nE "$pattern" "$file")"; then
        while IFS= read -r line; do
          printf '%s:%s\n' "$file" "$line"
        done <<<"$matches"
        found=0
      fi
    done < <(find "$root" -type f -name '*.rs' -print0)
  done
  return "$found"
}

self_test_fixture="tests/fixtures/servo-public-api/public-leak.rs"
self_test="$(
  scan_public_rust_api "$self_test_fixture" || true
)"
if [[ -z "$self_test" ]]; then
  cat >&2 <<'MSG'
Servo public API guard self-test failed: the planted fixture leak was not
detected. The guard must fail closed if its scanner breaks.
MSG
  exit 2
fi

violations="$(
  scan_public_rust_api crates || true
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
