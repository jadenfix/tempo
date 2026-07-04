# tempo everywhere — first-principles plan for macOS, Windows, Android, iOS

`final.md` defines what tempo *is*: structured observation, semantic batched
actions, state forking, API-first fast path. This document defines how that
product reaches **every device a person or agent owns**, with latency as the
governing constraint, and why a browser invented *today* — in a world with
200-IQ LLMs that today interact with browsers badly — ships in this shape.

## 1. First principles

A browser designed from scratch in 2026 would not start from "render HTML for
a human, bolt automation on later." It would start from three observations:

1. **The primary new user of the web is a model.** Models don't want pixels;
   they want ranked, stable, diff-able state (~2–5KB) and a transactional way
   to act on it. Humans want pixels. Both consume *the same page state*, so
   the engine must be one core with two projections — a render projection and
   an observation projection — not a human browser with a scraping sidecar.
2. **Latency is the product.** An agent loop is `observe → decide → act`,
   repeated. Every millisecond in observe/act multiplies by loop count; every
   byte in the observation multiplies by token cost and decode time. The
   correct budgets are per-hop budgets, set where physics allows: memory-lane
   IPC in single-digit µs, observation compile in single-digit ms, settle
   detection event-driven (not polled).
3. **Compute is asymmetric across devices.** A MacBook can run Servo + a local
   model; a phone must not pay a desktop's RAM bill. The architecture must
   let the *same agent contract* ride on three engine tiers without the
   caller knowing which tier answered.

## 2. The portable core ("tempo-core")

Everything above the engine boundary is already engine-agnostic Rust with no
platform assumptions — this is the asset the ports ride on:

- **Contracts**: `tempo-schema`, `tempo-driver` (C1/C2/C3 stay frozen; a port
  is conformant when it passes the same conformance suite).
- **Spine**: `tempo-observe`, `tempo-act`, `tempo-policy`, `tempo-taint`,
  `tempo-net`, `tempo-session`, `tempo-speculate`.
- **Protocol**: `tempo-mcp`, `tempo-bidi`, `tempo-handshake`.

Rule for all porting work: **no `#[cfg(target_os)]` above the engine/transport
boundary.** Platform code lives in two thin layers only:

- an **engine adapter** (which rendering engine, how it's supervised), and
- a **shell** (window, input, compositor surface, process/permission model).

## 3. Engine tiers (same driver contract, three cost points)

| Tier | Engine | Where | Cost point |
|------|--------|-------|-----------|
| T1 | Servo (Rust, embedded in-process) | macOS, Windows, Linux, Android | Full web compat lane, GPU compositor |
| T2 | System webview (WKWebView / WebView2 / Android WebView) | iOS (required by policy), plus low-RAM Android and fast-ship desktop | Zero engine bytes shipped; observation via injected agent runtime |
| T3 | No engine — API-first fast path (`tempo-net` + handshake) | every device, including watches/CI | Skips rendering entirely when the origin speaks an agent protocol |

T2 is not a compromise to apologize for — on iOS it is the only lawful lane,
and it is how tempo ships on all four platforms fast. The driver trait already
abstracts CDP vs Servo; a `tempo-engine-webview` adapter is the third
implementation of the same trait, with the observation compiler fed by an
injected accessibility/DOM extraction runtime (same contract as the CDP lane's
extraction script).

## 4. Platform shells

- **macOS (first)**: winit + wgpu surface for the Servo compositor; menu-bar
  daemon mode for headless agent fleets; Keychain-backed identity. tempod
  already runs here — the shell is a window over the same control plane.
- **Windows**: same winit/wgpu shell; WebView2 as the T2 lane; named-pipe
  transport replaces UDS behind the same framing (the `write_frame`/
  `read_frame` contract is transport-agnostic already).
- **Android**: NDK build of tempo-core (Rust cross-compiles cleanly; rusqlite
  bundles SQLite); Servo-on-Android for T1 on capable devices, WebView T2
  below a RAM threshold; binder-friendly local socket transport.
- **iOS**: tempo-core as a static lib behind a Swift shell; WKWebView T2 lane;
  Network Extension is *not* required because tempo's net layer proxies
  in-process; MCP served on localhost for on-device agent apps.

Milestone gates (same style as final.md §8): a platform "exists" when (1) the
conformance suite passes on-device, (2) the observe fixture gate passes, (3)
cold-start-to-first-observation and act-roundtrip latency budgets are met and
recorded by the benchmark suite in CI for that target.

## 5. Latency architecture (applies to every tier)

Measured floors first — `scripts/bench.sh` owns the numbers; targets below are
budgets the benches enforce, not aspirations:

| Hop | Budget | How |
|-----|--------|-----|
| observe compile (200 elements) | ≤ 1 ms | zero-alloc ranking, indexed diff/marks (PR series) |
| driver IPC round-trip (4KB) | ≤ 50 µs local | single-write framing, buffer reuse; shared-memory lane for screenshots |
| act → settled signal | event-driven | engine emits layout/frame/network generations; no fixed 50 ms polls |
| screenshot path | zero-copy | binary frames (no base64-in-JSON), region invalidation |
| cold start → first observation | ≤ 300 ms desktop / 800 ms mobile | engine snapshot + lazy subsystem init |

RAM discipline (phones are the constraint): observation pipeline reuses
buffers instead of cloning element vectors; cassette/journal lookups are
offset-indexed (no whole-file loads); mapper and cache structures are
generation-evicted (already true) and byte-bounded (to enforce per-tier).

## 6. Humans use it too

The same shell renders the T1/T2 surface for people. What changes vs a legacy
browser is that agent state is a first-class UI citizen: the set-of-marks
overlay, the taint/provenance of what the agent is about to submit, the
policy confirmation gates (`tempo-policy`) — rendered natively by the shell,
not injected into page DOM. One core, two projections; the human view is a
projection with pixels.

## 7. Sequencing

1. **Now**: land the benchmark harness + latency PR series (observation,
   IPC framing, cassette indexing, settle polling) — these shrink the core
   every port inherits.
2. **M+1**: macOS shell (winit/wgpu over the existing daemon); binary
   screenshot frames; event-driven settle from the Servo embedder.
3. **M+2**: Windows shell (named-pipe transport + WebView2 T2);
   `tempo-engine-webview` adapter passing conformance.
4. **M+3**: Android (NDK core, WebView T2 first, Servo T1 behind a device
   gate); per-tier RAM budgets enforced in CI.
5. **M+4**: iOS (static-lib core + WKWebView T2), on-device MCP; app-store
   packaging.

Each step is gated by the same evidence rule as final.md: conformance suite +
fixture gates + recorded latency budgets on the target device class.
