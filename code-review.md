# Code Review Invariants

Use this as the short human-readable companion to `AGENTS.md` and
`.claude/skills/review-pr/SKILL.md`. Reviews should be strict, but a blocker
needs a concrete traced failure, not a preference for more code.

## Contract Honesty

- Runtime-visible changes must update OpenAPI, schema docs, SDK-facing docs, and
  compatibility fixtures in the same slice.
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
- Public enum-valued fields must advertise the exact runtime wire names. Generated
  clients must accept every value the server can emit.
- HTTP success is not operation success when the response body carries a status
  envelope. Clients must parse `step_error`, missing, unknown, and non-applied
  statuses before mutating local state.
- Security/privacy docs cannot rely on one top-level disclaimer to narrow later
  absolute claims. Wording such as "all", "every", "owns", "guarantees", or
  "resistance" needs local shipped-vs-roadmap scope where it appears.
- Taint-to-beatbox security is not proven by `tempo-toolexec` helpers alone. A
  shipped claim needs an agent-facing runtime path that preserves page
  provenance to the execution boundary and a live beatbox canary proving
  `net:Deny`, `secrets:[]`, and no egress.

## Async State Ownership

- Do not replay stale UI snapshots into async workers or over completed worker
  results. Send narrow local deltas for fields the UI actually owns.
- A local convenience cache is not authoritative once the daemon, engine, or
  worker can mutate the same domain object.
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
