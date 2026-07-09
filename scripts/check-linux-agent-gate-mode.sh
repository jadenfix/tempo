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


require(
    "cancel-in-progress: true" in workflow
    and "github.event.pull_request.number || format('{0}-{1}-{2}', github.ref, inputs.mode || 'scheduled', inputs.benchmark_profile || 'default')" in workflow,
    'workflow concurrency must cancel superseded PR runs while allowing separate workflow_dispatch benchmark profiles to run in parallel',
)

match = re.search(
    r'if \[\[ "\$MODE" == "--full" \]\]; then\n(?P<full>.*?)\nelse\n(?P<smoke>.*?)\nfi',
    text,
    flags=re.S,
)
require(match is not None, 'missing full/smoke mode branch')

full = match.group('full')
smoke = match.group('smoke')
require('BENCH_MODE="--full"' in full, 'full mode must run benchmark --full')
require('BENCH_EXPECTED_ITERATIONS="7"' in full, 'full mode must validate seven iterations')
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
require(
    'BENCH_PROFILE="${TEMPO_LINUX_AGENT_BENCH_PROFILE:-default}"' in text
    and 'unsupported TEMPO_LINUX_AGENT_BENCH_PROFILE' in text
    and 'TEMPO_CDP_BENCH_PLAYWRIGHT_LIFECYCLE_ARGS=1' in text
    and 'TEMPO_CDP_KEY_EVENT_TYPE=1' in text
    and 'TEMPO_CDP_BENCH_INSERT_TEXT_TYPE=1' in text
    and 'TEMPO_CDP_BENCH_NO_INCOGNITO=1' in text
    and 'TEMPO_CDP_BENCH_ENABLE_CACHE=1' in text
    and 'TEMPO_CDP_BENCH_SUPPRESS_DESKTOP=1' in text
    and 'TEMPO_CDP_BENCH_CURRENT_THREAD_RUNTIME=1' in text
    and 'TEMPO_CDP_BENCH_NO_FORCED_COMPOSITOR=1' in text
    and 'TEMPO_CDP_BENCH_HEADLESS_FLAG=1' in text
    and 'TEMPO_CDP_BENCH_MIN_PROCESS=1' in text
    and 'TEMPO_CDP_BENCH_TRUSTED_POLICY=1' in text
    and 'TEMPO_CDP_BENCH_TRUSTED_LOOPBACK_DIRECT=1' in text
    and 'trusted-parity)' in text
    and 'trusted-browser-default)' in text
    and 'trusted-loopback-direct)' in text
    and 'trusted-min-process)' in text
    and 'agent-automation | all)' in text
    and 'TEMPO_CDP_BENCH_AGENT_AUTOMATION=1' in text
    and '-e "TEMPO_LINUX_AGENT_BENCH_PROFILE=${BENCH_PROFILE}"' in text,
    'Docker command must support named browser benchmark optimization profiles',
)
trusted_parity_match = re.search(
    r'^\s*trusted-parity\)\n(?P<body>.*?)\n\s*;;',
    text,
    flags=re.M | re.S,
)
require(trusted_parity_match is not None, 'Linux agent gate must wire trusted-parity profile')
trusted_parity = trusted_parity_match.group('body')
require(
    'TEMPO_CDP_BENCH_TRUSTED_POLICY=1' in trusted_parity
    and 'TEMPO_CDP_BENCH_NO_INCOGNITO=1' in trusted_parity
    and 'TEMPO_CDP_BENCH_PLAYWRIGHT_LIFECYCLE_ARGS=1' in trusted_parity,
    'trusted-parity profile must combine trusted policy, fresh profile, and lifecycle parity toggles',
)
trusted_browser_default_match = re.search(
    r'^\s*trusted-browser-default\)\n(?P<body>.*?)\n\s*;;',
    text,
    flags=re.M | re.S,
)
require(
    trusted_browser_default_match is not None,
    'Linux agent gate must wire trusted-browser-default profile',
)
trusted_browser_default = trusted_browser_default_match.group('body')
require(
    'TEMPO_CDP_BENCH_TRUSTED_POLICY=1' in trusted_browser_default
    and 'TEMPO_CDP_BENCH_NO_FORCED_COMPOSITOR=1' in trusted_browser_default,
    'trusted-browser-default profile must combine trusted policy and browser-default compositor toggles',
)
trusted_loopback_direct_match = re.search(
    r'^\s*trusted-loopback-direct\)\n(?P<body>.*?)\n\s*;;',
    text,
    flags=re.M | re.S,
)
require(
    trusted_loopback_direct_match is not None,
    'Linux agent gate must wire trusted-loopback-direct profile',
)
trusted_loopback_direct = trusted_loopback_direct_match.group('body')
require(
    'TEMPO_CDP_BENCH_TRUSTED_POLICY=1' in trusted_loopback_direct
    and 'TEMPO_CDP_BENCH_TRUSTED_LOOPBACK_DIRECT=1' in trusted_loopback_direct,
    'trusted-loopback-direct profile must combine trusted policy and direct loopback transport toggles',
)
trusted_min_process_match = re.search(
    r'^\s*trusted-min-process\)\n(?P<body>.*?)\n\s*;;',
    text,
    flags=re.M | re.S,
)
require(
    trusted_min_process_match is not None,
    'Linux agent gate must wire trusted-min-process profile',
)
trusted_min_process = trusted_min_process_match.group('body')
require(
    'TEMPO_CDP_BENCH_TRUSTED_POLICY=1' in trusted_min_process
    and 'TEMPO_CDP_BENCH_TRUSTED_LOOPBACK_DIRECT=1' in trusted_min_process
    and 'TEMPO_CDP_BENCH_MIN_PROCESS=1' in trusted_min_process,
    'trusted-min-process profile must combine direct loopback with min-process launch flags',
)
require(
    'TEMPO_LINUX_AGENT_DOCKER_CACHE_BACKEND' in text
    and 'docker buildx build' in text
    and '--driver docker-container' in text
    and 'docker buildx inspect "$BUILDER_NAME" --bootstrap' in text
    and 'docker buildx rm "$BUILDER_NAME"' in text
    and '--cache-to "type=gha,scope=${DOCKER_CACHE_SCOPE},mode=max"' in text
    and '--cache-from "type=gha,scope=${DOCKER_CACHE_SCOPE}"' in text
    and '--cache-to "type=local,dest=${DOCKER_CACHE_NEXT},mode=max"' in text
    and '--cache-from "type=local,src=${DOCKER_CACHE_DIR}"' in text,
    'Docker command must support GitHub Actions and local Docker layer cache backends',
)
require(
    'cargo test -p tempo-engine-cdp --test tempod_live tempod_http_mcp_and_bidi_drive_live_cdp_browser' in text,
    'Linux gate must run the broad tempod live MCP/BiDi smoke on every live-CDP path',
)
require(
    'cargo test -p tempo-headless --test tempod_process live_cdp' in text,
    'Linux gate must run the spawned tempod process live-CDP smoke',
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
    and '.tempo-linux-agent-cache' in smoke_job
    and 'linux-agent-' in smoke_job,
    'smoke job must cache Linux agent Cargo build artifacts',
)
require(
    'TEMPO_LINUX_AGENT_DOCKER_CACHE_BACKEND: gha' in smoke_job
    and 'TEMPO_LINUX_AGENT_DOCKER_CACHE_SCOPE:' in smoke_job,
    'smoke job must enable GitHub Actions Docker layer caching',
)
require(
    'Free Docker build space' in smoke_job
    and 'Free Docker build space' in full_job
    and 'docker system prune -af' in smoke_job
    and 'docker system prune -af' in full_job,
    'Linux agent workflow must free hosted-runner Docker build space before image import',
)
require(
    'benchmark_profile:' in workflow
    and 'key-events' in workflow
    and 'desktop' in workflow
    and 'runtime' in workflow
    and 'no-forced-compositor' in workflow
    and 'headless-flag' in workflow
    and 'min-process' in workflow
    and 'trusted-policy' in workflow
    and 'trusted-parity' in workflow
    and 'trusted-browser-default' in workflow
    and 'trusted-loopback-direct' in workflow
    and 'trusted-min-process' in workflow
    and 'agent-automation' in workflow
    and 'TEMPO_LINUX_AGENT_BENCH_PROFILE:' in smoke_job
    and "inputs.benchmark_profile || 'default'" in smoke_job,
    'smoke job must pass the workflow benchmark profile into the gate',
)
require(
    'TEMPO_CDP_BENCH_CURRENT_THREAD_RUNTIME=1' in text,
    'Linux agent gate must wire the runtime benchmark profile',
)
require(
    'scripts/agent_bench_runners/*.py' in smoke_job
    and 'scripts/requirements-agent-bench.txt' in smoke_job
    and 'scripts/validate-agent-bench-artifacts.py' in smoke_job,
    'smoke job cache key must include benchmark dependency and runner surface',
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
    and '.tempo-linux-agent-cache' in full_job
    and 'linux-agent-' in full_job,
    'full job must cache Linux agent Cargo build artifacts',
)
require(
    'TEMPO_LINUX_AGENT_DOCKER_CACHE_BACKEND: gha' in full_job
    and 'TEMPO_LINUX_AGENT_DOCKER_CACHE_SCOPE:' in full_job,
    'full job must enable GitHub Actions Docker layer caching',
)
require(
    'TEMPO_LINUX_AGENT_BENCH_PROFILE:' in full_job
    and "inputs.benchmark_profile || 'default'" in full_job,
    'full job must pass the workflow benchmark profile into the gate',
)
require(
    'scripts/agent_bench_runners/*.py' in full_job
    and 'scripts/requirements-agent-bench.txt' in full_job
    and 'scripts/validate-agent-bench-artifacts.py' in full_job,
    'full job cache key must include benchmark dependency and runner surface',
)
require('run: scripts/linux-agent-gate.sh --full' in full_job, 'full job must run --full')
require(
    artifact_names(full_job) == {"linux-agent-browser-bench-full"},
    f"full job must upload only the full benchmark artifact, got {artifact_names(full_job)}",
)
PY

echo "linux-agent gate mode wiring ok"
