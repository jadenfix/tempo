#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$ROOT/scripts/linux-agent-gate.sh"

bash -n "$GATE"

python3 - "$GATE" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"linux-agent gate mode check failed: {message}")


match = re.search(
    r'if \[\[ "\$MODE" == "--full" \]\]; then\n(?P<full>.*?)\nelse\n(?P<smoke>.*?)\nfi',
    text,
    flags=re.S,
)
require(match is not None, 'missing full/smoke mode branch')

full = match.group('full')
smoke = match.group('smoke')
require('BENCH_MODE="--full"' in full, 'full mode must run benchmark --full')
require('BENCH_EXPECTED_ITERATIONS="5"' in full, 'full mode must validate five iterations')
require('BENCH_MODE="--smoke"' in smoke, 'smoke mode must run benchmark --smoke')
require('BENCH_EXPECTED_ITERATIONS="1"' in smoke, 'smoke mode must validate one iteration')
require('        ${BENCH_MODE} \\' in text, 'Docker command must expand BENCH_MODE on the host')
require(
    '        --expected-iterations ${BENCH_EXPECTED_ITERATIONS} \\' in text,
    'Docker command must expand BENCH_EXPECTED_ITERATIONS on the host',
)
PY

echo "linux-agent gate mode wiring ok"
