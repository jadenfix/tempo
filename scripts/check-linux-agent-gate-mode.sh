#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$ROOT/scripts/linux-agent-gate.sh"
WORKFLOW="$ROOT/.github/workflows/linux-agent-gate.yml"

bash -n "$GATE"

python3 - "$GATE" "$WORKFLOW" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()
workflow = Path(sys.argv[2]).read_text()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"linux-agent gate mode check failed: {message}")


def job_block(name: str) -> str:
    pattern = re.compile(
        rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:|\Z)",
        flags=re.M | re.S,
    )
    job_match = pattern.search(workflow)
    require(job_match is not None, f"workflow missing {name} job")
    return job_match.group("body")


def job_if(name: str, block: str) -> str:
    if_match = re.search(r"^    if: >-\n(?P<body>(?:^      .+\n)+)", block, flags=re.M)
    require(if_match is not None, f"{name} job missing folded job-level if")
    return " ".join(line.strip() for line in if_match.group("body").splitlines())


def artifact_names(block: str) -> set[str]:
    return set(re.findall(r"^          name: ([^\n]+)$", block, flags=re.M))


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
require(
    'TEMPO_LINUX_AGENT_CACHE_DIR' in text
    and 'cargo-registry:/usr/local/cargo/registry' in text
    and 'cargo-git:/usr/local/cargo/git' in text
    and 'target:/target' in text,
    'Docker command must support a host-backed Linux agent cache directory',
)
smoke_job = job_block("docker-smoke-amd64")
full_job = job_block("docker-full-amd64")
smoke_if = job_if("docker-smoke-amd64", smoke_job)
full_if = job_if("docker-full-amd64", full_job)
require(
    smoke_if == (
        "github.event_name == 'pull_request' || "
        "(github.event_name == 'workflow_dispatch' && inputs.mode == 'smoke')"
    ),
    f"smoke job has wrong event condition: {smoke_if}",
)
require(
    "github.event_name == 'schedule'" not in smoke_if,
    'scheduled workflow must not run the smoke-only job',
)
require(
    'TEMPO_LINUX_AGENT_PLATFORM: linux/amd64' in smoke_job,
    'smoke job must run on linux/amd64 Docker',
)
require(
    'TEMPO_LINUX_AGENT_REQUIRE_LIVE_CDP: "1"' in smoke_job,
    'smoke job must require live CDP',
)
require(
    'TEMPO_LINUX_AGENT_CACHE_DIR: .tempo-linux-agent-cache' in smoke_job,
    'smoke job must enable the host-backed Linux agent cache',
)
require(
    'uses: actions/cache@v4' in smoke_job
    and 'path: .tempo-linux-agent-cache' in smoke_job
    and 'linux-agent-' in smoke_job,
    'smoke job must cache Linux agent build artifacts',
)
require('run: scripts/linux-agent-gate.sh --smoke' in smoke_job, 'smoke job must run --smoke')
require(
    artifact_names(smoke_job) == {"linux-agent-browser-bench"},
    f"smoke job must keep only the established benchmark artifact name, got {artifact_names(smoke_job)}",
)
require(
    full_if == (
        "github.event_name == 'schedule' || "
        "(github.event_name == 'workflow_dispatch' && inputs.mode == 'full')"
    ),
    f"full job has wrong event condition: {full_if}",
)
require("github.event_name == 'pull_request'" not in full_if, 'PR events must not run the full job')
require(
    'TEMPO_LINUX_AGENT_PLATFORM: linux/amd64' in full_job,
    'full job must run on linux/amd64 Docker',
)
require(
    'TEMPO_LINUX_AGENT_REQUIRE_LIVE_CDP: "1"' in full_job,
    'full job must require live CDP',
)
require(
    'TEMPO_LINUX_AGENT_CACHE_DIR: .tempo-linux-agent-cache' in full_job,
    'full job must enable the host-backed Linux agent cache',
)
require(
    'uses: actions/cache@v4' in full_job
    and 'path: .tempo-linux-agent-cache' in full_job
    and 'linux-agent-' in full_job,
    'full job must cache Linux agent build artifacts',
)
require('run: scripts/linux-agent-gate.sh --full' in full_job, 'full job must run --full')
require(
    artifact_names(full_job) == {"linux-agent-browser-bench-full"},
    f"full job must upload only the full benchmark artifact, got {artifact_names(full_job)}",
)
PY

echo "linux-agent gate mode wiring ok"
