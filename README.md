# tempo

An **AI-agent-native browser**, built from first principles in Rust.

Today's agentic browsers drive the web the way a human would — *screenshot → reason → one click → repeat*. That loop is slow, expensive, and prompt-injectable. tempo replaces it with **structured observation** (ranked, stably-identified, diff-able elements at ~2–5KB instead of a 40–500K-token DOM dump), **batched semantic actions** with a real page-settled signal, **state forking** for speculative parallel exploration, and an **API-first fast path** that skips rendering entirely when a site already speaks an agent protocol.

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

```
cargo test --workspace   # contracts, conformance, runtime, protocol, and shell tests
```
