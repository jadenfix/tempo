#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${TEMPO_LINUX_AGENT_IMAGE:-tempo-linux-agent:rust-1.96.1}"
MODE="${1:---smoke}"
ALLOW_UNSAFE_HOST_ENV="${TEMPO_AGENT_BENCH_ALLOW_UNSAFE_HOST_ENV:-}"
BENCH_PROFILE="${TEMPO_LINUX_AGENT_BENCH_PROFILE:-default}"
UNSAFE_HOST_ENV_KEYS=(
  ANTHROPIC_API_KEY
  AWS_ACCESS_KEY_ID
  AWS_PROFILE
  AWS_ROLE_ARN
  AWS_SECRET_ACCESS_KEY
  AWS_SESSION_TOKEN
  AWS_WEB_IDENTITY_TOKEN_FILE
  GOOGLE_API_KEY
  GOOGLE_APPLICATION_CREDENTIALS
  OPENAI_API_KEY
  TEMPO_DURABLE_ENCRYPTION_KEY_HEX
  TEMPO_OTLP_ENDPOINT
  TEMPO_OTLP_JSONL
  TEMPO_TEMPOD_AUTH_TOKEN
  TEMPO_TEMPOD_AUTH_TOKEN_FILE
  TEMPO_THREAT_DOMAIN_AUDIT_JSONL
  TEMPO_THREAT_DOMAIN_CACHE_FILE
  TEMPO_THREAT_DOMAIN_FAILURE_MODE
  TEMPO_THREAT_DOMAIN_FILE
  TEMPO_THREAT_DOMAIN_MAX_STALE_SECONDS
  TEMPO_THREAT_DOMAIN_METADATA_CACHE_FILE
  TEMPO_THREAT_DOMAIN_METADATA_URL
  TEMPO_THREAT_DOMAIN_PUBLIC_KEYS
  TEMPO_THREAT_DOMAIN_REFRESH_INTERVAL_SECONDS
  TEMPO_THREAT_DOMAIN_SHA256
  TEMPO_THREAT_DOMAIN_URL
)

reject_unsafe_host_env() {
  if [[ "$ALLOW_UNSAFE_HOST_ENV" == "1" ]]; then
    return
  fi
  local present=()
  local key
  for key in "${UNSAFE_HOST_ENV_KEYS[@]}"; do
    if [[ -n "${!key:-}" ]]; then
      present+=("$key")
    fi
  done
  if (( ${#present[@]} > 0 )); then
    local joined
    printf -v joined '%s, ' "${present[@]}"
    joined="${joined%, }"
    echo "refusing to run Linux agent gate with ambient production/secret env vars: ${joined}" >&2
    echo "unset them, or set TEMPO_AGENT_BENCH_ALLOW_UNSAFE_HOST_ENV=1 for an intentional unsafe-env run" >&2
    exit 2
  fi
}

resolve_local_path() {
  local path="$1"
  case "$path" in
    /*) printf '%s\n' "$path" ;;
    *) printf '%s\n' "$ROOT/$path" ;;
  esac
}

require_cache_under_root() {
  local label="$1"
  local path="$2"
  if [[ "$ALLOW_UNSAFE_HOST_ENV" == "1" ]]; then
    return
  fi
  case "$path" in
    "$ROOT" | "$ROOT"/*) ;;
    *)
      echo "refusing ${label} outside repo root: ${path}" >&2
      echo "use a relative path under the repo, or set TEMPO_AGENT_BENCH_ALLOW_UNSAFE_HOST_ENV=1 for an intentional unsafe-cache run" >&2
      exit 2
      ;;
  esac
}

case "$MODE" in
  --smoke | --full | --shell) ;;
  *)
    echo "usage: scripts/linux-agent-gate.sh [--smoke|--full|--shell]" >&2
    exit 2
    ;;
esac

reject_unsafe_host_env

case "$BENCH_PROFILE" in
  default | lifecycle | key-events | insert-text | no-incognito | cache | desktop | runtime | no-forced-compositor | headless-flag | trusted-policy | agent-automation | all) ;;
  *)
    echo "unsupported TEMPO_LINUX_AGENT_BENCH_PROFILE: ${BENCH_PROFILE}" >&2
    echo "supported values: default, lifecycle, key-events, insert-text, no-incognito, cache, desktop, runtime, no-forced-compositor, headless-flag, trusted-policy, agent-automation, all" >&2
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

BUILD_ARGS=(
  --platform "$PLATFORM"
  -f "$ROOT/docker/linux-agent.Dockerfile"
  -t "$IMAGE"
)

DOCKER_CACHE_BACKEND="${TEMPO_LINUX_AGENT_DOCKER_CACHE_BACKEND:-}"
if [[ -z "$DOCKER_CACHE_BACKEND" && -n "${TEMPO_LINUX_AGENT_DOCKER_CACHE_DIR:-}" ]]; then
  DOCKER_CACHE_BACKEND="local"
fi

if [[ -n "$DOCKER_CACHE_BACKEND" ]]; then
  if ! docker buildx version >/dev/null 2>&1; then
    echo "docker buildx is required when Docker layer caching is enabled" >&2
    exit 127
  fi
  BUILD_CACHE_ARGS=()
  DOCKER_CACHE_DIR=""
  DOCKER_CACHE_NEXT=""
  case "$DOCKER_CACHE_BACKEND" in
    gha)
      DOCKER_CACHE_SCOPE="${TEMPO_LINUX_AGENT_DOCKER_CACHE_SCOPE:-linux-agent}"
      BUILD_CACHE_ARGS=(
        --cache-from "type=gha,scope=${DOCKER_CACHE_SCOPE}"
        --cache-to "type=gha,scope=${DOCKER_CACHE_SCOPE},mode=max"
      )
      ;;
    local)
      if [[ -z "${TEMPO_LINUX_AGENT_DOCKER_CACHE_DIR:-}" ]]; then
        echo "TEMPO_LINUX_AGENT_DOCKER_CACHE_DIR is required for local Docker layer caching" >&2
        exit 2
      fi
      DOCKER_CACHE_DIR="$(resolve_local_path "$TEMPO_LINUX_AGENT_DOCKER_CACHE_DIR")"
      require_cache_under_root "TEMPO_LINUX_AGENT_DOCKER_CACHE_DIR" "$DOCKER_CACHE_DIR"
      DOCKER_CACHE_NEXT="${DOCKER_CACHE_DIR}.next"
      mkdir -p "$(dirname "$DOCKER_CACHE_DIR")"
      rm -rf "$DOCKER_CACHE_NEXT"
      BUILD_CACHE_ARGS=(
        --cache-to "type=local,dest=${DOCKER_CACHE_NEXT},mode=max"
      )
      if [[ -f "$DOCKER_CACHE_DIR/index.json" ]]; then
        BUILD_CACHE_ARGS+=(--cache-from "type=local,src=${DOCKER_CACHE_DIR}")
      fi
      ;;
    *)
      echo "unsupported TEMPO_LINUX_AGENT_DOCKER_CACHE_BACKEND: ${DOCKER_CACHE_BACKEND}" >&2
      echo "supported values: gha, local" >&2
      exit 2
      ;;
  esac
  BUILDER_NAME="${TEMPO_LINUX_AGENT_BUILDX_BUILDER:-tempo-linux-agent-cache-$$}"
  BUILDER_CREATED=0
  if [[ -z "${TEMPO_LINUX_AGENT_BUILDX_BUILDER:-}" ]]; then
    docker buildx create \
      --name "$BUILDER_NAME" \
      --driver docker-container \
      --use \
      >/dev/null
    BUILDER_CREATED=1
  fi
  docker buildx inspect "$BUILDER_NAME" --bootstrap >/dev/null
  BUILD_STATUS=0
  docker buildx build \
    --builder "$BUILDER_NAME" \
    --load \
    "${BUILD_CACHE_ARGS[@]}" \
    "${BUILD_ARGS[@]}" \
    "$ROOT" || BUILD_STATUS=$?
  if [[ "$BUILDER_CREATED" == "1" ]]; then
    docker buildx rm "$BUILDER_NAME" >/dev/null 2>&1 || true
  fi
  if [[ "$BUILD_STATUS" != "0" ]]; then
    if [[ -n "$DOCKER_CACHE_NEXT" ]]; then
      rm -rf "$DOCKER_CACHE_NEXT"
    fi
    exit "$BUILD_STATUS"
  fi
  if [[ -n "$DOCKER_CACHE_DIR" ]]; then
    rm -rf "$DOCKER_CACHE_DIR"
    mv "$DOCKER_CACHE_NEXT" "$DOCKER_CACHE_DIR"
    chmod -R a+rwX "$DOCKER_CACHE_DIR" 2>/dev/null || true
  fi
else
  docker build \
    "${BUILD_ARGS[@]}" \
    "$ROOT"
fi

COMMON_ENV=(
  -e PATH=/opt/tempo-agent-bench/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  -e CARGO_TARGET_DIR=/target
  -e TEMPO_CDP_CHROME_CACHE=/target/chrome-for-testing
  -e TEMPO_CDP_NO_SANDBOX=1
  -e "TEMPO_LINUX_AGENT_BENCH_PROFILE=${BENCH_PROFILE}"
)

case "$BENCH_PROFILE" in
  lifecycle)
    COMMON_ENV+=(-e TEMPO_CDP_BENCH_PLAYWRIGHT_LIFECYCLE_ARGS=1)
    ;;
  key-events)
    COMMON_ENV+=(-e TEMPO_CDP_KEY_EVENT_TYPE=1)
    ;;
  insert-text)
    COMMON_ENV+=(-e TEMPO_CDP_BENCH_INSERT_TEXT_TYPE=1)
    ;;
  no-incognito)
    COMMON_ENV+=(-e TEMPO_CDP_BENCH_NO_INCOGNITO=1)
    ;;
  cache)
    COMMON_ENV+=(-e TEMPO_CDP_BENCH_ENABLE_CACHE=1)
    ;;
  desktop)
    COMMON_ENV+=(-e TEMPO_CDP_BENCH_SUPPRESS_DESKTOP=1)
    ;;
  runtime)
    COMMON_ENV+=(-e TEMPO_CDP_BENCH_CURRENT_THREAD_RUNTIME=1)
    ;;
  no-forced-compositor)
    COMMON_ENV+=(-e TEMPO_CDP_BENCH_NO_FORCED_COMPOSITOR=1)
    ;;
  headless-flag)
    COMMON_ENV+=(-e TEMPO_CDP_BENCH_HEADLESS_FLAG=1)
    ;;
  trusted-policy)
    COMMON_ENV+=(-e TEMPO_CDP_BENCH_TRUSTED_POLICY=1)
    ;;
  agent-automation | all)
    COMMON_ENV+=(
      -e TEMPO_CDP_BENCH_AGENT_AUTOMATION=1
      -e TEMPO_CDP_BENCH_PLAYWRIGHT_LIFECYCLE_ARGS=1
      -e TEMPO_CDP_BENCH_INSERT_TEXT_TYPE=1
      -e TEMPO_CDP_BENCH_NO_INCOGNITO=1
      -e TEMPO_CDP_BENCH_NO_FORCED_COMPOSITOR=1
    )
    ;;
esac

if [[ -n "${TEMPO_LINUX_AGENT_REQUIRE_LIVE_CDP:-}" ]]; then
  COMMON_ENV+=(-e "TEMPO_LINUX_AGENT_REQUIRE_LIVE_CDP=${TEMPO_LINUX_AGENT_REQUIRE_LIVE_CDP}")
fi

COMMON_MOUNTS=(
  -v "$ROOT:/work"
)

if [[ -n "${TEMPO_LINUX_AGENT_CACHE_DIR:-}" ]]; then
  CACHE_DIR="$(resolve_local_path "$TEMPO_LINUX_AGENT_CACHE_DIR")"
  require_cache_under_root "TEMPO_LINUX_AGENT_CACHE_DIR" "$CACHE_DIR"
  mkdir -p "$CACHE_DIR/cargo-registry" "$CACHE_DIR/cargo-git" "$CACHE_DIR/target"
  COMMON_ENV+=(-e "TEMPO_LINUX_AGENT_CACHE_DIR=${TEMPO_LINUX_AGENT_CACHE_DIR}")
  COMMON_MOUNTS+=(
    -v "$CACHE_DIR/cargo-registry:/usr/local/cargo/registry"
    -v "$CACHE_DIR/cargo-git:/usr/local/cargo/git"
    -v "$CACHE_DIR/target:/target"
  )
else
  COMMON_MOUNTS+=(
    -v tempo-cargo-registry:/usr/local/cargo/registry
    -v tempo-cargo-git:/usr/local/cargo/git
    -v tempo-target-linux-agent:/target
  )
fi

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
  BENCH_MODE="--full"
  BENCH_EXPECTED_ITERATIONS="7"
else
  INNER_MODE="--smoke"
  BENCH_MODE="--smoke"
  BENCH_EXPECTED_ITERATIONS="1"
fi

docker run --rm \
  --platform "$PLATFORM" \
  "${COMMON_ENV[@]}" \
  "${COMMON_MOUNTS[@]}" \
  -w /work \
  "$IMAGE" \
  bash -c "set -euo pipefail
    trap 'chmod -R a+rX /work/target/linux-agent-gate/agent-browser-bench 2>/dev/null || true; if [[ -n \"\${TEMPO_LINUX_AGENT_CACHE_DIR:-}\" ]]; then chmod -R a+rwX /usr/local/cargo/registry /usr/local/cargo/git /target 2>/dev/null || true; fi' EXIT
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
    CHROME_PATH=\"\${TEMPO_CDP_CHROME:-}\"
    if [[ -z \"\$CHROME_PATH\" ]]; then
      if ! CHROME_PATH=\"\$(scripts/setup-cdp-chrome.sh 2>/tmp/tempo-cft-setup.err)\"; then
        echo \"warning: Chrome for Testing setup failed for ${PLATFORM}; falling back to distro chromium preflight\" >&2
        cat /tmp/tempo-cft-setup.err >&2 || true
        CHROME_PATH=\"\$(command -v chromium || true)\"
        if [[ -z \"\$CHROME_PATH\" ]]; then
          echo \"warning: no fallback chromium binary found in container\" >&2
        fi
      fi
    fi
    if [[ -n \"\$CHROME_PATH\" ]]; then
      rm -f /tmp/tempo-chromium-preflight.out /tmp/tempo-chromium-preflight.err
      \"\$CHROME_PATH\" \
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
    fi
    if [[ -n \"\$CHROME_PATH\" ]] && kill -0 \"\$chromium_pid\" >/dev/null 2>&1; then
      kill \"\$chromium_pid\" >/dev/null 2>&1 || true
      wait \"\$chromium_pid\" >/dev/null 2>&1 || true
      cargo build -p tempo-engine-cdp --bin tempo-engined-cdp
      TEMPO_CDP_CHROME=\"\$CHROME_PATH\" scripts/test-live-cdp.sh ${INNER_MODE}
      TEMPO_CDP_CHROME=\"\$CHROME_PATH\" cargo test -p tempo-engine-cdp --test tempod_live tempod_http_mcp_and_bidi_drive_live_cdp_browser -- --nocapture --test-threads=1
      TEMPO_CDP_CHROME=\"\$CHROME_PATH\" cargo test -p tempo-headless --test tempod_process live_cdp -- --nocapture --test-threads=1
      BENCH_OUT=/work/target/linux-agent-gate/agent-browser-bench
      TEMPO_CDP_CHROME=\"\$CHROME_PATH\" scripts/agent-browser-bench.sh \
        ${BENCH_MODE} \
        --min-success-rate 1 \
        --output-dir \"\$BENCH_OUT\"
      scripts/validate-agent-bench-artifacts.py \
        --output-dir \"\$BENCH_OUT\" \
        --expected-iterations ${BENCH_EXPECTED_ITERATIONS} \
        --require-derived-artifacts
      chmod -R a+rX \"\$BENCH_OUT\"
    else
      if [[ -n \"\${chromium_pid:-}\" ]]; then
        wait \"\$chromium_pid\" >/dev/null 2>&1 || true
      fi
      echo \"warning: skipping Docker live-CDP smoke because container Chrome did not launch on ${PLATFORM}\" >&2
      echo \"warning: run scripts/test-live-cdp.sh --smoke on the host, or rerun this gate on a Linux host with a working Chrome runtime\" >&2
      cat /tmp/tempo-chromium-preflight.err >&2 || true
      if [[ \"\${TEMPO_LINUX_AGENT_REQUIRE_LIVE_CDP:-}\" == \"1\" ]]; then
        exit 1
      fi
    fi
  "
