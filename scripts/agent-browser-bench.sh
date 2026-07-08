#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="--full"
OUTPUT_DIR="${TEMPO_AGENT_BENCH_OUTPUT_DIR:-target/agent-browser-bench}"
ITERATIONS=()
GATES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --smoke | --full)
      MODE="$1"
      shift
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --iterations)
      ITERATIONS=(--iterations "$2")
      shift 2
      ;;
    --min-success-rate | --max-p95-wall-ms | --max-p95-model-input-tokens | --max-p95-rss-bytes)
      GATES+=("$1" "$2")
      shift 2
      ;;
    -h | --help)
      echo "usage: scripts/agent-browser-bench.sh [--smoke|--full] [--iterations N] [--min-success-rate N] [--max-p95-wall-ms N] [--max-p95-model-input-tokens N] [--max-p95-rss-bytes N] [--output-dir PATH]" >&2
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      echo "usage: scripts/agent-browser-bench.sh [--smoke|--full] [--iterations N] [--min-success-rate N] [--max-p95-wall-ms N] [--max-p95-model-input-tokens N] [--max-p95-rss-bytes N] [--output-dir PATH]" >&2
      exit 2
      ;;
  esac
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for the live browser benchmark harness" >&2
  exit 127
fi

if [[ -z "${TEMPO_CLI:-}" ]]; then
  cargo build -p tempo-cli
  TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
  if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    TEMPO_CLI="${TARGET_DIR}/${CARGO_BUILD_TARGET}/debug/tempo-cli"
  else
    TEMPO_CLI="${TARGET_DIR}/debug/tempo-cli"
  fi
  if [[ ! -x "$TEMPO_CLI" ]]; then
    while IFS= read -r DISCOVERED_TEMPO_CLI; do
      if [[ -x "$DISCOVERED_TEMPO_CLI" ]]; then
        TEMPO_CLI="$DISCOVERED_TEMPO_CLI"
        break
      fi
    done < <(find "$TARGET_DIR" -path "*/debug/tempo-cli" -type f -print 2>/dev/null || true)
  fi
  export TEMPO_CLI
fi
if [[ "$TEMPO_CLI" == */* ]]; then
  TEMPO_CLI_PATH="$TEMPO_CLI"
else
  TEMPO_CLI_PATH="$(command -v "$TEMPO_CLI" || true)"
fi
if [[ -z "$TEMPO_CLI_PATH" || ! -x "$TEMPO_CLI_PATH" ]]; then
  echo "TEMPO_CLI is not executable or on PATH: $TEMPO_CLI" >&2
  exit 127
fi

if [[ -z "${TEMPO_CDP_CHROME:-}" ]]; then
  TEMPO_CDP_CHROME="$(scripts/setup-cdp-chrome.sh)"
  export TEMPO_CDP_CHROME
fi

export TEMPO_CDP_NO_SANDBOX="${TEMPO_CDP_NO_SANDBOX:-1}"
export TEMPO_DURABLE_RETENTION="${TEMPO_DURABLE_RETENTION:-plaintext-unsafe}"

PY_ARGS=("$MODE")
if [[ ${#ITERATIONS[@]} -gt 0 ]]; then
  PY_ARGS+=("${ITERATIONS[@]}")
fi
if [[ ${#GATES[@]} -gt 0 ]]; then
  PY_ARGS+=("${GATES[@]}")
fi

python3 scripts/agent_browser_bench.py \
  "${PY_ARGS[@]}" \
  --chrome "$TEMPO_CDP_CHROME" \
  --output-dir "$OUTPUT_DIR"
