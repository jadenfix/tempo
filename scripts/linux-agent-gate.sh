#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${TEMPO_LINUX_AGENT_IMAGE:-tempo-linux-agent:rust-1.96.1}"
MODE="${1:---smoke}"

case "$MODE" in
  --smoke | --full | --shell) ;;
  *)
    echo "usage: scripts/linux-agent-gate.sh [--smoke|--full|--shell]" >&2
    exit 2
    ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for the Linux agent gate" >&2
  exit 127
fi

if ! docker info >/dev/null 2>&1; then
  echo "docker daemon is not reachable; start Docker and rerun scripts/linux-agent-gate.sh" >&2
  exit 1
fi

DOCKER_ARCH="$(docker info --format '{{.Architecture}}')"
case "$DOCKER_ARCH" in
  aarch64 | arm64)
    DEFAULT_PLATFORM="linux/arm64"
    ;;
  x86_64 | amd64)
    DEFAULT_PLATFORM="linux/amd64"
    ;;
  *)
    echo "unsupported docker architecture: ${DOCKER_ARCH}" >&2
    echo "set TEMPO_LINUX_AGENT_PLATFORM explicitly if this host can run a supported Linux image" >&2
    exit 2
    ;;
esac

PLATFORM="${TEMPO_LINUX_AGENT_PLATFORM:-$DEFAULT_PLATFORM}"

docker build \
  --platform "$PLATFORM" \
  -f "$ROOT/docker/linux-agent.Dockerfile" \
  -t "$IMAGE" \
  "$ROOT"

COMMON_ENV=(
  -e PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  -e CARGO_TARGET_DIR=/target
  -e TEMPO_CDP_CHROME_CACHE=/target/chrome-for-testing
  -e TEMPO_CDP_NO_SANDBOX=1
)

COMMON_MOUNTS=(
  -v "$ROOT:/work"
  -v tempo-cargo-registry:/usr/local/cargo/registry
  -v tempo-cargo-git:/usr/local/cargo/git
  -v tempo-target-linux-agent:/target
)

if [[ "$MODE" == "--shell" ]]; then
  exec docker run --rm -it \
    --platform "$PLATFORM" \
    "${COMMON_ENV[@]}" \
    "${COMMON_MOUNTS[@]}" \
    -w /work \
    "$IMAGE" \
    bash
fi

if [[ "$MODE" == "--full" ]]; then
  INNER_MODE="--full"
else
  INNER_MODE="--smoke"
fi

docker run --rm \
  --platform "$PLATFORM" \
  "${COMMON_ENV[@]}" \
  "${COMMON_MOUNTS[@]}" \
  -w /work \
  "$IMAGE" \
  bash -c "set -euo pipefail
    rustc --version
    cargo --version
    cargo fmt --all --check
    cargo check --workspace --all-targets
    cargo test --workspace
    cargo test --manifest-path tests/toolexec-live/Cargo.toml
    cargo run -p tempo-cli -- scorecard --input fixtures/evals/ci-budget-pass.jsonl --min-success-rate 1 --max-fallback-rate 0
    cargo run -p tempo-cli -- observe-gate --input fixtures/observe/corpus-pass.json
    cargo run -p tempo-cli -- compat-lanes --input fixtures/compat/ci-scorecard-pass.json
    cargo run -p tempo-cli -- injection-gate --input fixtures/security/injection-pass.json
    cargo run -p tempo-cli -- taint-gate --input fixtures/security/taint-redteam-pass.json
    bash scripts/check-servo-public-api.sh
    bash scripts/check-no-solver.sh
    rm -f /tmp/tempo-chromium-preflight.out /tmp/tempo-chromium-preflight.err
    /usr/bin/chromium \
      --headless=new \
      --disable-gpu \
      --no-sandbox \
      --disable-dev-shm-usage \
      --remote-debugging-port=0 \
      about:blank \
      >/tmp/tempo-chromium-preflight.out \
      2>/tmp/tempo-chromium-preflight.err &
    chromium_pid=\$!
    sleep 3
    if kill -0 \"\$chromium_pid\" >/dev/null 2>&1; then
      kill \"\$chromium_pid\" >/dev/null 2>&1 || true
      wait \"\$chromium_pid\" >/dev/null 2>&1 || true
      TEMPO_CDP_CHROME=/usr/bin/chromium scripts/test-live-cdp.sh ${INNER_MODE}
      TEMPO_CDP_CHROME=/usr/bin/chromium scripts/agent-browser-bench.sh --smoke --output-dir /tmp/tempo-agent-browser-bench
    else
      wait \"\$chromium_pid\" >/dev/null 2>&1 || true
      echo \"warning: skipping Docker live-CDP smoke because container Chromium did not launch on ${PLATFORM}\" >&2
      echo \"warning: run scripts/test-live-cdp.sh --smoke on the host, or rerun this gate on a Linux host with a working Chromium/Chrome runtime\" >&2
      cat /tmp/tempo-chromium-preflight.err >&2 || true
      if [[ \"\${TEMPO_LINUX_AGENT_REQUIRE_LIVE_CDP:-}\" == \"1\" ]]; then
        exit 1
      fi
    fi
  "
