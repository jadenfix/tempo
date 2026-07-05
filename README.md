# tempo

An **AI-agent-native browser**, built from first principles in Rust.

Today's agentic browsers drive the web the way a human would — *screenshot → reason → one click → repeat*. That loop is slow, expensive, and prompt-injectable. tempo replaces it with **structured observation** (ranked, stably-identified, diff-able elements at ~2–5KB instead of a 40–500K-token DOM dump), **batched semantic actions** with a real page-settled signal, **state forking** for speculative parallel exploration, and an **API-first fast path** that skips rendering entirely when a site already speaks an agent protocol.

Engine strategy is **CDP-first for the current developer preview, Servo-promotable by evidence**. The runnable local lane is headless Chromium through CDP; [Servo](https://servo.org) remains the Rust-native target lane behind the same driver trait and promotes only after the Servo gates in `final.md` pass. tempo reuses the sibling **beater** stack (`../beater-agents`, `../beater.js`, `../beater.js-connect`, `../beatbox`).

Servo compatibility is explicit. The default `servo-vanilla` lane stays pinned
to the upstream-compatible Servo crate, while `scripts/cargo-servo-tempo.sh`
checks the audited `github.com/jadenfix/servo` fork rev used by Tempo-specific
integration work. Set `TEMPO_SERVO_PATH=../servo` for a local checkout, or
`TEMPO_SERVO_REPO` / `TEMPO_SERVO_REF` for another fork source; non-default
sources require `TEMPO_SERVO_ALLOW_UNAUDITED=1`.

## Local CDP developer preview

Build the daemon and packaged CDP engine, then run `tempod` from the same binary
directory. With no `--engine-socket`, `tempod` defaults to `engine=cdp`,
auto-starts the sibling `tempo-engined-cdp` binary, and attaches over a private
Unix-domain socket:

```
cargo build -p tempo-headless -p tempo-engine-cdp
TEMPO_CDP_CHROME=/path/to/chrome \
  ./target/debug/tempod
```

Advanced users can still start an engine manually and attach to it:

```
SOCKET_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tempo-engined-cdp.XXXXXX")"
TEMPO_ENGINE_HOST_SOCKET="$SOCKET_DIR/engine.sock" \
TEMPO_CDP_CHROME=/path/to/chrome \
  ./target/debug/tempo-engined-cdp &
./target/debug/tempod --engine cdp --engine-socket "$SOCKET_DIR/engine.sock"
```

The preview binds `tempod` to `127.0.0.1:8787` by default. Servo, remote/fleet
operation, Windows-native IPC, crawler execution, cassette import, and
authenticated/private-account safety claims are roadmap/beta gates, not this
preview.

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
  tempod control plane, MCP, and BiDi routing.
- `tempo-observe`, `tempo-taint`, `tempo-act`, `tempo-policy`, `tempo-net`,
  `tempo-session`, `tempo-agent`, `tempo-skills`, `tempo-speculate`, `tempo-toolexec`,
  `tempo-shell`, `tempo-evals`, `tempo-compat`, and `tempo-cli` carry the supporting
  browser, agent, security, replay, shell, evaluation, and operations layers.
  `tempo-crawl` is a deferred SDK facade over `tempo-net` (zero in-tree consumers);
  `tempo-speculate` is deferred until replay-fork v1 lands (see final.md §3.2).

```
cargo test --workspace   # contracts, conformance, runtime, protocol, and shell tests
```

## Operations & governance

- `tempo-telemetry` / `tempo-config` (paired observability PR) are the
  observability and configuration backbones; tempod serves Prometheus
  exposition at `GET /metrics`.
- `tempod` requires bearer auth on loopback and remote binds. Set
  `TEMPO_TEMPOD_AUTH_TOKEN` or `--auth-token` explicitly, or let the daemon
  create an owner-only runtime token file; shell clients read the same file by
  default. Loopback, Host, and Origin checks defend binding/CSRF edges, but they
  are not authentication on shared machines.
- `--allow-remote` is a preview escape hatch, not production fleet support.
  Keep local preview runs on loopback unless you are explicitly testing remote
  binding. `TEMPO_STEALTH_MODE` suppresses tempod's in-memory history,
  telemetry, and idempotency cache; it does not promise OS, filesystem, or
  Chromium artifact erasure.
- Supply-chain policy lives in [`deny.toml`](./deny.toml) (checked in CI);
  tagged `v*` releases build stripped, thin-LTO `tempod` + `tempo-cli`
  binaries for macOS and Linux.
- See [`CONTRIBUTING.md`](./CONTRIBUTING.md) and [`SECURITY.md`](./SECURITY.md).
  Licensed [Apache-2.0](./LICENSE).
