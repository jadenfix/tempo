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

if [[ -n "${TEMPO_AGENT_BENCH_PYTHON:-}" ]]; then
  PYTHON_BIN="$TEMPO_AGENT_BENCH_PYTHON"
elif [[ -x /opt/tempo-agent-bench/bin/python ]]; then
  PYTHON_BIN=/opt/tempo-agent-bench/bin/python
else
  PYTHON_BIN=python3
fi
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "$PYTHON_BIN is required for the live browser benchmark harness" >&2
  exit 127
fi
PYTHON_VERSION="$("$PYTHON_BIN" - <<'PY'
import sys
print(f"{sys.version_info.major}.{sys.version_info.minor}")
PY
)"
case "$PYTHON_VERSION" in
  3.11 | 3.12 | 3.13 | 3.14 | 3.15 | 3.16 | 3.17 | 3.18 | 3.19) ;;
  *)
    echo "Python >=3.11 is required for the real browser-use benchmark lane; got $PYTHON_VERSION from $PYTHON_BIN" >&2
    echo "Set TEMPO_AGENT_BENCH_PYTHON to a Python 3.11+ interpreter if your default python3 is older." >&2
    exit 1
    ;;
esac

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

"$PYTHON_BIN" scripts/agent_browser_bench.py \
  "${PY_ARGS[@]}" \
  --chrome "$TEMPO_CDP_CHROME" \
  --output-dir "$OUTPUT_DIR"
