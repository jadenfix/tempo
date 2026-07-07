#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="--full"
OUTPUT_DIR="${TEMPO_AGENT_BENCH_OUTPUT_DIR:-target/agent-browser-bench}"

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
    -h | --help)
      echo "usage: scripts/agent-browser-bench.sh [--smoke|--full] [--output-dir PATH]" >&2
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      echo "usage: scripts/agent-browser-bench.sh [--smoke|--full] [--output-dir PATH]" >&2
      exit 2
      ;;
  esac
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for the live browser benchmark harness" >&2
  exit 127
fi

if [[ -z "${TEMPO_CDP_CHROME:-}" ]]; then
  TEMPO_CDP_CHROME="$(scripts/setup-cdp-chrome.sh)"
  export TEMPO_CDP_CHROME
fi

export TEMPO_CDP_NO_SANDBOX="${TEMPO_CDP_NO_SANDBOX:-1}"
export TEMPO_DURABLE_RETENTION="${TEMPO_DURABLE_RETENTION:-plaintext-unsafe}"

python3 scripts/agent_browser_bench.py \
  "$MODE" \
  --chrome "$TEMPO_CDP_CHROME" \
  --output-dir "$OUTPUT_DIR"
