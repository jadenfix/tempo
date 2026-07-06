# Code Review Invariants

Use this as the short human-readable companion to `AGENTS.md` and
`.claude/skills/review-pr/SKILL.md`. Reviews should be strict, but a blocker
needs a concrete traced failure, not a preference for more code.

## Contract Honesty

- Runtime-visible changes must update OpenAPI, schema docs, SDK-facing docs, and
  compatibility fixtures in the same slice.
- Raw crawl dispatch is a scheduler primitive, not a network execution
  capability. SDK/client paths should prefer connection-pinned capabilities that
  expose socket-safe request parts and an already-open stream. Any checked
  dispatch fallback must pin the connection to the checked socket instead of
  re-resolving the URL.
- Engine/control IPC must fail closed on platforms without an implemented
  peer-auth transport. Local-only is not enough; require same-user peer
  credentials, named-pipe ACLs, app-private sockets, or an explicit unsupported
  gate.
- Cassette and replay-fork import defaults must fail closed to authenticated
  durable retention. Plaintext replay helpers are compatibility/test fixtures
  only and must be explicitly named unsafe.
- Do not treat a tested bridge crate as shipped product composition. If a
  security claim depends on runtime wiring, require a production-path sentinel
  or keep the docs explicitly deferred.
- Untrusted OpenAPI or remote-tool descriptors must not become executable policy
  or secret material. Side-effect classes need trusted provenance, and
  Authorization, cookie, API-key, token, secret, or credential fields need
  explicit secret bindings rather than model-provided request values.
- Direct OpenAPI execution remains a blocker unless untrusted operations are
  confirmation-required by default and secret-like header/cookie/query/path/body
  parameters are rejected before request construction.
- Public enum-valued fields must advertise the exact runtime wire names. Generated
  clients must accept every value the server can emit.
- HTTP success is not operation success when the response body carries a status
  envelope. Clients must parse `step_error`, missing, unknown, and non-applied
  statuses before mutating local state.
- Security/privacy docs cannot rely on one top-level disclaimer to narrow later
  absolute claims. Wording such as "all", "every", "owns", "guarantees", or
  "resistance" needs local shipped-vs-roadmap scope where it appears.
- "Zero history", "zero trace", and "stealth" claims need test-backed sink
  coverage. Name the covered durable sinks, including journals, cassettes,
  telemetry, logs, engine profiles, browser cache/storage, crash reports, and OS
  temp files; state any OS, browser, network, or remote-service traces that are
  out of scope.
- Encryption claims must name protected data, key source, integrity mode,
  rotation/recovery behavior, and fail-closed handling for missing keys,
  unauthenticated data, and corrupt records.
- Stealth mode is local privacy, profile isolation, retention suppression, and
  policy enforcement. CAPTCHA solving, anti-bot bypass, or fingerprint-spoofing
  escalation are separate product/security decisions and should not be hidden
  under a generic stealth label.
- Taint-to-beatbox security is not proven by `tempo-toolexec` helpers alone. A
  shipped claim needs an agent-facing runtime path that preserves page
  provenance to the execution boundary and a live beatbox canary proving
  `net:Deny`, `secrets:[]`, and no egress.
- Raw accessibility/AX trees and `tempo-observe` compiler inputs must not cross
  into `tempod`-side runtime crates or public wire structs. Engine adapters own
  raw-to-compiled conversion; runtime surfaces consume `CompiledObservation` and
  `ObservationDiff`.

## Async State Ownership

- Do not replay stale UI snapshots into async workers or over completed worker
  results. Send narrow local deltas for fields the UI actually owns.
- A local convenience cache is not authoritative once the daemon, engine, or
  worker can mutate the same domain object.
- Cache and fast-path hooks that return snapshots, diffs, or observations must
  document the identity they bind to, such as sequence, base sequence, URL,
  frame, policy epoch, or capability token. Callers must reject cache misses or
  identity mismatches and re-derive state, with tests for stale and
  wrong-identity implementations.
- Client disconnect does not cancel already-started blocking work. Engine-driving
  `spawn_blocking` routes need cancellation before dispatch or their own
  live-work quota; an HTTP connection cap alone is not enough.
- Tests for async reconciliation should queue at least two operations with an
  intervening local mutation, so stale-result and stale-input paths are both
  covered.

## Launch And Path Inputs

- Environment-provided executable paths are not shell snippets. Do not preserve
  escape characters that only make sense in a shell; normalize and validate the
  path before handing it to process launch code.
- Live-engine tests should fail with a clear configuration error when a configured
  browser binary is missing, rather than falling through to a lower-level spawn
  error.

## Platform Discipline

- Shared crates must remain Android/mobile friendly: no desktop-only IPC,
  filesystem, process, RAM, or windowing assumptions above the engine/transport
  boundary.
- Tempo follows the code-backed Servo support matrix for every Servo-available
  target. Platform-specific behavior belongs in thin engine, transport, or shell
  adapters.
- A platform claim is not done until conformance, observation fixtures, and
  latency/RAM budgets pass on that target.

## Simplicity And Performance

- More code is not more optimized. Prefer the smallest change that makes an
  existing contract honest, proves the invariant, or removes a duplicated path.
- Treat hot-path allocation, serialization, copies, and extra round trips as
  correctness risks for an agent browser, not cosmetic performance nits.
