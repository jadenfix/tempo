# tempo

An **AI-agent-native browser**, built from first principles in Rust.

Today's agentic browsers drive the web the way a human would — *screenshot → reason → one click → repeat*. That loop is slow, expensive, and prompt-injectable. tempo replaces it with **structured observation** (ranked, stably-identified, diff-able elements at ~2–5KB instead of a 40–500K-token DOM dump), **batched semantic actions** with a real page-settled signal, a planned **state-forking** lane for speculative parallel exploration, and an **API-first fast path** that skips rendering entirely when a site already speaks an agent protocol.

Honesty note on token claims: the big win is scoped to raw screenshot, raw CDP,
and full DOM/HTML loops. Tempo is not yet smaller than compact Playwright-MCP or
browser-use-style model-facing formats on the checked-in differential fixtures;
ADR 0008 tracks that as a separate lean-projection and diff-to-model goal.

Engine strategy is **Rust-first**: [Servo](https://servo.org) is the primary rendering engine; a headless-Chromium lane (CDP) is a per-origin fallback behind the same driver trait. tempo reuses the sibling **beater** stack (`../beater-agents`, `../beater.js`, `../beater.js-connect`, `../beatbox`).

Servo compatibility is explicit. The default `servo-vanilla` lane stays pinned
to the upstream-compatible Servo crate, while `scripts/cargo-servo-tempo.sh`
checks the audited `github.com/jadenfix/servo` fork rev used by Tempo-specific
integration work. Set `TEMPO_SERVO_PATH=../servo` for a local checkout, or
`TEMPO_SERVO_REPO` / `TEMPO_SERVO_REF` for another fork source; non-default
sources require `TEMPO_SERVO_ALLOW_UNAUDITED=1`.

## Platform Direction

Tempo tracks the platforms where upstream Servo is available: macOS, Linux, Windows, Android, and OpenHarmony. `tempo-engine-servo` exposes this as `servo_platform_support_matrix()` so Swift/macOS, Android, OpenHarmony, desktop, and other SDK wrappers can read the same source of truth.

Android and OpenHarmony use the Unix-domain-socket control plane in app-private storage. Windows is listed as an upstream Servo platform, but Tempo's local `tempod`/engine-host path is not Windows-ready until the Unix-only IPC code is replaced with a Windows-native transport adapter and matching cfg gates.

## Read this first

**[`final.md`](./final.md)** is the full engineering design — vision, first-principles requirements, component architecture, the Servo hook map, the dependency graph (what's parallel vs sequential), the beatbox sandbox integration, the Definition of Done (per-crate acceptance bars + milestone gates), risks, and verification.

When multiple agents are working, use **[`docs/agent-worktrees.md`](./docs/agent-worktrees.md)**
and `scripts/new-agent-worktree.sh` to create isolated PR-sized checkouts.

**[`docs/PLATFORMS.md`](./docs/PLATFORMS.md)** is the cross-platform plan — how the same agent contract ships on macOS, Windows, Android, and iOS via three engine tiers (embedded Servo, system webview, API-first no-engine), with per-hop latency budgets and per-tier RAM discipline as milestone gates.

## Layout

Cargo workspace under `crates/`. The implementation is split into contract, engine,
observation, action, network, runtime, protocol, shell, eval, and compatibility crates:

- `tempo-schema` and `tempo-driver` define the C1/C2/C3 contracts, conformance suite,
  and gated test-driver support.
- `tempo-engine-cdp`, `tempo-engine-servo`, `tempo-engine-host`, and `tempo-headless`
  provide the current engine boundaries, CDP lane, host supervision, UDS transport,
  tempod control plane, MCP, and default-off BiDi routing.
- `tempo-observe`, `tempo-taint`, `tempo-act`, `tempo-policy`, `tempo-net`,
  `tempo-session`, `tempo-agent`, `tempo-skills`, `tempo-speculate`, `tempo-toolexec`,
  `tempo-shell`, `tempo-evals`, `tempo-compat`, and `tempo-cli` carry the supporting
  browser, agent, security, replay, shell, evaluation, and operations layers.

```
cargo test --workspace   # contracts, conformance, runtime, protocol, and shell tests
```

Local live-CDP smoke tests need a Chrome/Chromium binary. To download Chrome for
Testing into `.local/` and run the browser-backed smoke gates:

```
scripts/test-live-cdp.sh
```

To run the broader live-CDP suite, including child browsing-context storage
isolation and agent resume/journal replay coverage:

```
scripts/test-live-cdp.sh --full
```

For the Linux-first agent gate, run the same agent/browser checks in a pinned
Rust + Chrome-for-Testing container:

```
scripts/linux-agent-gate.sh
```

The gate defaults to Docker's native Linux architecture (`linux/arm64` on Apple
Silicon Docker Desktop, `linux/amd64` on x86 Linux), uses Docker volumes for
Cargo and build artifacts, uses container Chromium for live-CDP checks, and
exercises the CLI/fixture/live-CDP path agents depend on. Set
`TEMPO_LINUX_AGENT_PLATFORM=linux/amd64` when you specifically need an x86 run.
Use `scripts/linux-agent-gate.sh --shell` to debug inside the same container, or
`scripts/linux-agent-gate.sh --full` to include the broader live-CDP suite and
the five-iteration agent/browser benchmark run.
On Apple Silicon Docker Desktop, distro Chromium may fail before CDP startup in
the Linux VM; the smoke gate then reports the browser preflight failure and skips
only the Docker live-CDP subgate. Set `TEMPO_LINUX_AGENT_REQUIRE_LIVE_CDP=1` to
make that preflight mandatory, and use `scripts/test-live-cdp.sh --smoke` on the
host for the macOS Chrome-for-Testing browser smoke.

Real agent/browser benchmark artifacts are generated with:

```
scripts/agent-browser-bench.sh --smoke --output-dir target/agent-browser-bench
```

That script requires Python 3.11 or newer for the real `browser-use` package
lane; set `TEMPO_AGENT_BENCH_PYTHON=/path/to/python3.11` if your default
`python3` is older. It builds `tempo-cli` once when `TEMPO_CLI` is not already
set, then the Python harness invokes the binary directly for the measured Tempo
run and derived artifacts. This keeps the latency/RSS comparison focused on
agent/browser runtime instead of repeated Cargo wrapper startup. The harness
serves `fixtures/evals/live_agent/checkout.html` and drives the same task
through Tempo CDP, raw Chrome CDP, synthetic CDP snapshots for continuity, and
three external subprocess baselines: `real-playwright` via Playwright's Python
API, `external-browser-use-dom-loop` as a browser-use-style indexed DOM loop,
and `real-browser-use` via the actual `browser-use` package's browser/session
and tool APIs. The `real-browser-use` lane is deterministic and no-LLM: it uses
browser-use's model-facing browser state plus built-in `input`/`click` tools,
not a hosted model credential or prompt contract. The harness writes:

- `agent-browser-bench.json[l]` with success, wall time, CPU time, sampled
  process-tree max RSS, step count, retry count, failure mode, and model-facing
  bytes/tokens. Tempo reports `model_input_*` from its compact taint-preserving
  prompt projection: set-of-marks handles such as `#1`, role, short
  provenance prefixes, and accessible name/value text. The full URL stays in
  the durable observation journal, not the prompt projection; when an engine
  supplies marks, stable `node_id` strings also stay out of the prompt
  projection, with `@node-id` fallback handles reserved for unmarked
  observations and resolved before execution. `max_observation_*` keeps that
  durable structured JSON cost visible. `observations` counts durable
  observations, while `max_compact_observation_*` records the same compact
  projection for every journaled observation so the report can compare compact
  agent-facing state separately from full audit JSON. `observations` counts durable
  observations, while
  `model_input_observations` counts the subset supplied to planning/deciding;
  post-action verification observations remain auditable and policy-relevant
  without inflating model prompt cost. Multi-observation model loops report
  total model-facing input in `model_input_*` and their largest single
  observation in `max_observation_*`.
- `agent-browser-bench-summary.json` with per-runner run count, success rate,
  failure-mode counts, retry totals, and p50/p95/max stats for latency, CPU,
  RSS, step count, and model-facing bytes/tokens. `--smoke` runs one iteration;
  `--full` runs five by default, and `--iterations N` overrides either mode.
- `agent-browser-bench-gaps.json` with deterministic category rankings and
  Tempo deltas against raw Chrome plus Playwright, browser-use-style, and real
  browser-use package agent baselines. It calls out gaps to close for success
  rate, latency, RSS,
  retries, failures, model-facing tokens, compact-observation tokens, largest
  durable observation tokens, and agent step count. CPU is reported row-level
  until every runner uses the same resource-accounting scope. Raw Chrome is
  deliberately excluded from observation-token and agent-step categories because
  it has no model-facing observation stream. Row-level total model-input token
  p95 is included only where the runner reports a comparable model-facing stream
  cost.
- `real-playwright.json`, `external-browser-use-dom-loop.json`, and
  `real-browser-use.json`, plus each runner's stdout/stderr logs, model-input
  text, and action trace, so CI proves the external subprocess lanes ran and
  leaves auditable model-facing evidence.
- `chrome-version.txt` and matching fields in the benchmark JSON so floating
  Chrome-for-Testing resolution is captured with each artifact set.
- `tempo-journal.sqlite`, `replay.json`, and `tempo-run.json` so the run is
  grounded in durable agent evidence.
- `eval-records.jsonl`, `scorecard.json`, and `amdahl.json`; `amdahl.json` is
  generated by the harness as a raw-Chrome-relative wall-clock comparison.

The Docker Linux gate runs this benchmark after live-CDP succeeds: smoke mode
runs one iteration, while `--full` runs the benchmark harness's five-iteration
default. Pull requests run the real `linux/amd64` Docker smoke gate; scheduled
workflow runs and manual `linux-agent-gate` dispatches with `mode=full` run
`scripts/linux-agent-gate.sh --full` and upload the full benchmark artifacts.
The
`scripts/validate-agent-bench-artifacts.py` validator then requires the six
expected runners, successful metrics, per-runner summary stats, model-input and
resource counters, comparative gap report, Chrome version capture, and the
derived journal, replay, scorecard, and baseline artifacts before the gate can
pass. The
`.github/workflows/linux-agent-gate.yml` workflow forces
`TEMPO_LINUX_AGENT_PLATFORM=linux/amd64` and
`TEMPO_LINUX_AGENT_REQUIRE_LIVE_CDP=1`, so the authoritative container live-CDP
and benchmark proof is real Linux amd64 CI. Apple Silicon local Docker remains a
build/test/fixture gate plus an explicit Chromium-preflight diagnostic; host
Chrome-for-Testing covers local live browser execution on macOS.

The GitHub workflows cache Cargo registry/git/target outputs per job. The
Docker Linux gate also honors `TEMPO_LINUX_AGENT_CACHE_DIR`: when set, the
container uses host-backed `cargo-registry`, `cargo-git`, and `target`
directories so Actions can persist the expensive Linux build products across
runs; without it, local runs keep using Docker named volumes.
The same gate honors `TEMPO_LINUX_AGENT_DOCKER_CACHE_BACKEND=gha` in CI for
BuildKit's GitHub Actions layer cache, so the Rust/Chromium/Python benchmark
image layers stay remote instead of being restored into the runner workspace.
Local runs can set `TEMPO_LINUX_AGENT_DOCKER_CACHE_BACKEND=local` with
`TEMPO_LINUX_AGENT_DOCKER_CACHE_DIR` for a filesystem-backed buildx cache.

The same Linux gate runs the live beatbox-backed `tempo-toolexec` tests. At the
pinned beatbox milestone the executable sandbox lane is W0 Wasm, so live tests
prove real HTTP execution, async jobs, import-egress denial, and filesystem
workspace/mount policy denial. Tempo also fetches beatbox's integration contract
and asserts that the `Exec` lane is `planned_fail_closed`, backed by an `os_jail`
contract and explicit next steps for command admission plus process, filesystem,
network, and teardown isolation. Agent CLI/process execution must stay on that
unavailable-lane path until beatbox publishes a runnable process sandbox; the W0
Wasm lane is bounded by wall time and fuel rather than an unenforceable native
CPU ceiling.

## Operations & governance

- Current shipped security posture is narrower than the long-term design in
  `final.md`: tempod is loopback-first unless remote binds are explicitly
  enabled with bearer auth; Web Bot Auth signing is opt-in in selected
  `tempo-net` dispatch paths, not universal for all API/MCP calls; stealth mode
  suppresses tempod/session history, telemetry exporters, and durable journals
  it controls, but it does not erase OS, browser-engine, proxy, DNS, or remote
  service logs; and beatbox-backed taint-to-sandbox dispatch is deferred until
  ADR 0001 is wired through a runtime caller. ADR 0005 freezes public
  fork/speculation tooling until an engine supports real fork semantics. ADR
  0006 keeps WebDriver BiDi compiled but disabled by default behind
  `TEMPO_BIDI=on` / `protocols.bidi_enabled=true`. ADR 0009 scopes confirmed
  daemon writes to REST session `act_batch` plus operator `confirmation_grant`;
  MCP and BiDi remain read/draft-only for confirmation-gated writes. ADR 0004
  records the currently shipped taint-channel, opaque-handle, lethal-trifecta,
  and linear-batch CFI primitives plus the runtime wiring still deferred.
- `tempo-telemetry` / `tempo-config` (paired observability PR) are the
  observability and configuration backbones; tempod serves Prometheus
  exposition at `GET /metrics`.
- `tempod` requires bearer auth on loopback and remote binds. Set
  `TEMPO_TEMPOD_AUTH_TOKEN` or `--auth-token` explicitly, or let the daemon
  create an owner-only runtime token file; shell clients read the same file by
  default. Confirming policy-gated REST writes requires a separate operator
  token (`TEMPO_TEMPOD_OPERATOR_TOKEN`, `--operator-token`, or the owner-only
  operator runtime token file). Loopback, Host, and Origin checks defend
  binding/CSRF edges, but they are not authentication on shared machines.
- Hosted identity/OAuth must stay delegated to the ecosystem control plane:
  Tempo consumes ecosystem-issued credentials and enforces product permissions;
  it does not own users, billing, orgs, API-key issuance, OAuth grants, JWKS, or
  token revocation. See
  [`docs/identity-and-oauth.md`](./docs/identity-and-oauth.md).
- Supply-chain policy lives in [`deny.toml`](./deny.toml) (checked in CI);
  tagged `v*` releases build stripped, thin-LTO `tempod` + `tempo-cli`
  binaries for macOS and Linux.
- See [`CONTRIBUTING.md`](./CONTRIBUTING.md) and [`SECURITY.md`](./SECURITY.md).
  Licensed [Apache-2.0](./LICENSE).
