# tempo everywhere — first-principles plan for macOS, Windows, Android, iOS

`final.md` defines what tempo *is*: structured observation, semantic batched
actions, state forking, API-first fast path. This document defines how that
product reaches **every device a person or agent owns**, with latency as the
governing constraint, and why a browser invented *today* — in a world with
200-IQ LLMs that today interact with browsers badly — ships in this shape.

## 0. Current state and tracker reconciliation

This document is a directional, non-committal platform plan until the current
engine, shell, and daemon gates land. It is not evidence that a platform exists:
a platform exists only when the conformance suite, observe fixture gate, and
target latency/RAM budgets pass on that target.

Current repo state to reconcile before treating any milestone below as
committed implementation work:

- **Servo engine lane**: #246 tracks that `tempo-engine-servo` is still a
  compatibility/type-check shim, not a production libservo embed. T1 shell work
  must not assume the Servo lane already satisfies the final.md gates.
- **Human shell**: #247 tracks that `tempo-shell` is not yet a windowed
  winit/wgpu shell. It is currently a control-plane client, so shell milestones
  below are target state, not present-tense product state.
- **Daemon/protocol conformance**: #249 tracks that `tempod` still needs to
  converge on the final transport/protocol shape. Platform shell work must not
  hide that behind app packaging.
- **Cross-platform secure IPC**: #260 owns native secure transports and peer
  authentication. Windows named pipes, Android app-private sockets, and mobile
  packaging must satisfy that issue's security bar rather than bypass it.
- **Portable core CI**: the `windows-core` CI job checks the engine-agnostic
  crates on native `windows-latest`. That is the compatibility bar for the
  contract, observation/action, policy/taint, network, session, agent, MCP/BiDi,
  eval, and config layers; it intentionally excludes the Unix engine-host and
  tempod transport crates until #260 lands.
- **Servo availability source of truth**: #294 is the conservative platform
  availability matrix. Tempo follows upstream Servo availability for macOS,
  Linux, Windows, Android, and OpenHarmony; this document focuses on app/shell
  sequencing and keeps #294 as the code-backed truth.
- **Latency series**: #297, #298, #299, #300, #301, and #302 own the binary
  frame, event-driven settle, batched enrichment, per-driver IPC, CI benchmark,
  and benchmark-harness work. The latency table here summarizes those gates; it
  does not replace their acceptance criteria.

Concrete platform implementation issues should be filed before work starts on
the macOS windowed shell, Windows named-pipe transport, Android NDK/WebView port,
iOS static-lib/WKWebView shell, or `tempo-engine-webview`. Until those issues
exist and #246/#247/#249 are resolved, §7 is sequencing guidance rather than a
delivery commitment.

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
abstracts CDP vs Servo; `crates/tempo-engine-webview` is the T2 adapter shape
for host-owned WKWebView/WebView2/Android WebView surfaces. It feeds
`tempo-observe` from an injected accessibility/DOM extraction runtime and
keeps the private WebView locator map outside the agent-visible `NodeId`
contract.

## 4. Platform shells

- **macOS (first target)**: target state is a winit + wgpu surface for the
  Servo compositor, menu-bar daemon mode for headless agent fleets, and
  Keychain-backed identity. `tempod` can run locally today, but #247 and #249
  mean the windowed shell and spec-conformant daemon are still future work.
- **Windows**: target state is the same winit/wgpu shell, WebView2 as the T2
  lane, and a Windows-native transport behind the same frame contract.
  Named-pipe work is gated by #260 peer authentication and platform-specific
  cfg coverage; it is not a drop-in replacement until those checks exist.
- **Android**: target state is an NDK build of tempo-core, app-private local
  control sockets, WebView T2 below a RAM threshold, and Servo T1 on capable
  devices when #294 says the upstream Servo target is available. Android work
  must stay RAM-bounded and avoid desktop-only assumptions in shared crates.
- **iOS**: target state is tempo-core as a static lib behind a Swift shell,
  WKWebView T2, and localhost MCP for on-device agent apps. The scaffold lives
  in `crates/tempo-ios-core` and `platforms/ios/Tempo`; it deliberately excludes
  CDP, Servo, `tempo-engine-host`, `tempod`, the CLI, and the desktop shell from
  the normal iOS dependency graph. Network Extension should remain unnecessary
  unless a future issue proves an out-of-process net layer is required.

Milestone gates (same style as final.md §8): a platform "exists" when (1) the
conformance suite passes on-device, (2) the observe fixture gate passes, (3)
cold-start-to-first-observation and act-roundtrip latency budgets are met and
recorded by the benchmark suite in CI for that target.

## 5. Latency architecture (applies to every tier)

Measured floors first — `scripts/bench.sh` owns the numbers; targets below are
budgets the benches enforce, not aspirations. The implementation work is tracked
in #297-#302; this table is the platform-facing summary of those gates:

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

## 6. Two first-class users: agents and humans

tempo is **agent-first, not agent-only-by-default** — but it ships an explicit
agent-only mode where every human-facing subsystem is compiled out or never
initialized. One core, two projections; each projection gets first-principles
treatment rather than one being emulated on top of the other.

### Agent-only mode (the full-optimization path)

- No compositor, no window, no font/paint pipeline warm-up: the observation
  projection (`tempo-observe`) is the *only* output surface unless a
  screenshot is explicitly requested.
- Headless daemon (`tempod`) is the product: UDS/named-pipe control plane,
  MCP + BiDi + OpenAPI in front, N engines behind, state forking
  (`tempo-speculate`) for parallel exploration.
- Every latency budget in §5 is measured in this mode first — it is the mode
  with nothing to hide behind.

### Any LLM plugs in

The model is a *client*, never baked in. Three seams, all already in the tree:

- **MCP** (`tempo-mcp`): any MCP-speaking model/runtime drives tempo today.
- **Decider trait** (`tempo-agent`): the in-process loop is provider-abstracted
  (one trait; Anthropic client is just the first implementation) — plug in any
  local or hosted model without touching the loop.
- **OpenAPI/BiDi** (`tempo-headless`): generated SDKs for everything else.

The contract these seams expose (C1/C2/C3: observation, action, lifecycle) is
the product surface. A 200-IQ model and a 7B on-device model get the same
ranked, stable, diff-able state and the same transactional actions; they
differ only in how much of the budget they need.

### Human mode

The same shell renders the T1/T2 pixel surface for people, and the agent
state is a first-class UI citizen rather than an extension hack: the
set-of-marks overlay, taint/provenance of what an agent is about to submit,
and `tempo-policy` confirmation gates render natively in the shell, outside
page DOM (uninjectable by the page). Humans get the first-principles wins
too: the API-first fast path, speculative prefetch, and session replay are
speed and safety features for people, not just for models. Human mode is a
strict superset — flip it on and the agent plane keeps running underneath,
which is what the future of the internet looks like: people and their agents
using the same browser state, at the same time, with provenance.

## 7. Sequencing

This sequence is a dependency order, not a release promise. Each milestone must
be backed by a concrete implementation issue or PR before it is treated as
committed work.

1. **Now**: close the current-state blockers (#246, #247, #249), keep platform
   availability grounded in #294, and land the benchmark/latency series
   (#297-#302). These shrink and harden the core every port inherits.
2. **M+1**: macOS shell (winit/wgpu over a conformant local daemon); binary
   screenshot frames; event-driven settle from the Servo embedder.
3. **M+2**: Windows shell (secure named-pipe transport under #260 + WebView2
   T2); `tempo-engine-webview` adapter passing conformance.
4. **M+3**: Android (NDK core, WebView T2 first, Servo T1 behind #294/device
   gates); per-tier RAM budgets enforced in CI.
5. **M+4**: iOS (static-lib core + WKWebView T2), on-device MCP; app-store
   packaging.

Each step is gated by the same evidence rule as final.md: conformance suite +
fixture gates + recorded latency budgets on the target device class.
