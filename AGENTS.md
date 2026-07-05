# Repository Agent Notes

Durable, reusable guidance for agents (and humans) working in tempo — an
AI-agent-native browser, a Cargo workspace under `crates/`. Keep entries here as
**reusable invariants or failure modes**, not one-off fixes: avoid issue
numbers, branch names, one-off file lines, and examples that will go stale
unless they are explicitly called out as examples. More code is not more
optimized — prefer the smallest change that proves the invariant, removes
duplicated paths, or makes an existing contract honest.

Orientation and setup live in [`CONTRIBUTING.md`](./CONTRIBUTING.md); the design
and Definition of Done live in [`final.md`](./final.md); Claude Code specifics in
[`CLAUDE.md`](./CLAUDE.md). This file is the durable-lessons layer on top.

## Quick reference (blocks CI if skipped)

- No `unsafe` (`unsafe_code = "forbid"`); no `unwrap`/`expect` including in tests
  (`clippy::unwrap_used`/`expect_used = "deny"`) — return `Result` and use `?`.
- `cargo fmt --all --check` and `cargo clippy --workspace -- -D warnings` pass.
- The PR body **must** contain (CI rejects it otherwise):
  ```
  1.) agent {agent number}
  2.) purpose: {one-line purpose, no placeholder}
  ```
- PRs stay single-purpose; a dependency change commits the `Cargo.lock` update with it.
- Verify sequentially per target dir, or give concurrent Cargo commands separate
  `CARGO_TARGET_DIR` values (see the target-race note below).

## Workflow & coordination

- Work in an isolated worktree and branch for each change. Do not rewrite, delete, or force-clean another agent's dirty worktree.
- Use `gh` for GitHub issue, PR, review, and merge state. Prefer one tight review pass and only a small follow-up loop when there is a concrete blocker.
- After any wait, force-push, PR body edit, CI rerun, or concurrent merge, re-check PR state, head SHA, base SHA, check rollup, and linked issue state with `gh` before reviewing or merging. Stale checks and closed/superseded PRs are not merge evidence.
- Run Cargo verification sequentially per target directory, or give concurrent commands separate `CARGO_TARGET_DIR` values. Missing rlibs, object files, or temp dirs from a shared fresh target are local harness races until reproduced with a clean sequential run.
- Before starting, scan open PRs for overlap with your files; prefer new crates/files over edits to contested ones (`tempo-headless/src/lib.rs` is high-traffic — rebase early and keep diffs additive). File an issue for anything broken you notice but don't fix in your PR.

## Preserving durable guidance

- When a review or incident exposes a persistent, non-overfit lesson, preserve it as general guidance. Read-only reviewers should report the candidate guidance in the review body; coordinators or follow-up authors should land accepted guidance here and in `.claude/skills/review-pr/SKILL.md` from a separate worktree/PR.
- Keep durable guidance phrased as reusable invariants or failure modes. Avoid issue numbers, branch names, one-off file lines, and examples that will go stale unless they are explicitly called out as examples.

## Contract & compatibility invariants

- Respect crate layering: a lower-layer contract crate must not depend upward on a higher-layer one. `tempo-schema` depends on nothing in the workspace; `observe`/`taint`/`policy` stay pure and depend only on `schema`; the driver contract stays engine-agnostic. A new upward edge is a design break, not a convenience.
- Runtime-visible contract changes must keep the public descriptions in sync. When routes, status codes, response fields, schemas, or agent/SDK surfaces change, update OpenAPI and generated-client-facing docs in the same slice.
- Adding a field to a public Rust schema struct is also a source-compat change. `serde(default)` protects old JSON payloads, but every workspace struct literal still needs a scan/update and downstream compile check.
- Compact wire-format changes must preserve compatibility in both directions. When default, empty, or omitted fields change, tests should prove compact serialization, populated serialization, and default-filled deserialization so older and newer SDKs keep agreeing.

## Security & trust-boundary invariants

- Do not commit realistic secret, token, password, or credential literals, even in tests. Build scanner-safe fixtures from clearly inert fragments while still proving redaction and non-leak behavior.
- Secret-bearing HTTP clients must validate configured base URLs before building requests. Production keys should go only to pinned secure origins; loopback or insecure fixtures need an explicitly named opt-in so tests do not normalize unsafe live configuration.
- Network policy decisions must bind to the concrete endpoint that will actually be used after DNS, proxy resolution, redirects, and retries. Validating only a URL string, hostname, or first resolved address leaves room for rebinding or alternate-socket bypasses.
- Operational metadata that exposes dependency state, capacity, policy, or topology is control-plane data. Guard it with the same auth/host/origin boundary unless the route is intentionally public and boring, like a static liveness check.

## Resource & availability invariants

- Stateful protocol surfaces need live-state quotas in addition to per-frame or per-body caps; repeated valid commands can be a resource attack even when each request is small.
- A size cap checked only after fully materializing remote-driven JSON, DOM, screenshot, log, or tool-result data is not a memory bound. Enforce the cap while reading, collecting, diffing, or serializing unless the producer is already independently bounded.
- Everything that can grow is bounded: input/response sizes, queues, maps, caches, retries, spawned tasks, and session/connection counts. Every engine/remote/subprocess round-trip has both a timeout and a recovery path (restart/reconnect with backoff), not a permanently terminal hang.

## Performance invariants (a hot-path regression is a correctness bug here)

- Reuse, don't recreate, on the per-action path: clients, sessions, connections, buffers, and metric handles. No per-call handshake, allocation, or registration where a cached one works; no redundant serialization, copy, or round-trip; no new global single-op bottleneck.
- Measure, don't guess: the hot paths (observation compile, transport framing, action quiescence, policy checks, cassette replay) have criterion benches. Use `scripts/bench.sh main` on the base and `scripts/bench.sh pr main` on the candidate to prove a change helps before claiming it does.
