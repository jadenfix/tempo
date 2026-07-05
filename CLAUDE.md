# CLAUDE.md

Guidance for Claude Code (and other coding agents) working in this repo.

**The durable rules live in [`AGENTS.md`](./AGENTS.md).** Read it first — this
file only adds the Claude-Code-specific orientation and points at the canonical
sources so nothing is duplicated (duplicated guidance drifts).

## What this is

tempo is an **AI-agent-native browser** built in Rust — a Cargo workspace under
`crates/`. Structured observation, batched semantic actions, state forking, and
an API-first fast path replace the screenshot→reason→click loop. The full design
is [`final.md`](./final.md); read §2 (requirements), §3 (architecture), and §8
(Definition of Done) before picking up work.

## Read-first, in order

1. [`AGENTS.md`](./AGENTS.md) — durable engineering invariants and agent workflow.
2. [`CONTRIBUTING.md`](./CONTRIBUTING.md) — toolchain, CI gates, PR conventions.
3. [`final.md`](./final.md) — the engineering design and Definition of Done.
4. [`.claude/skills/review-pr/SKILL.md`](./.claude/skills/review-pr/SKILL.md) —
   how PR review works here (invoked as `/review-pr <N>`).

## Non-negotiables that block CI (do not learn these the hard way)

- No `unsafe` (`unsafe_code = "forbid"`), no `unwrap`/`expect` — including in
  tests (`clippy::unwrap_used`/`expect_used = "deny"`). Return `Result` from
  tests and use `?`.
- `cargo fmt --all --check` and `cargo clippy --workspace -- -D warnings` must pass.
- The PR body **must** contain, verbatim shape (CI rejects it otherwise):
  ```
  1.) agent {agent number}
  2.) purpose: {one-line purpose, no placeholder}
  ```
- Keep PRs single-purpose; commit the `Cargo.lock` update with any dependency change.

## Verify like CI does

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
scripts/bench.sh                 # criterion latency suite; scripts/bench.sh pr main to compare
```

Run Cargo verification **sequentially per target dir**, or give concurrent
commands separate `CARGO_TARGET_DIR` values — a shared fresh target races and
the missing-rlib errors are harness artifacts, not real failures.

## Working in this repo

- Isolated worktree + branch per change (`scripts/new-agent-worktree.sh`). Never
  touch another agent's dirty worktree.
- Multiple agents work concurrently: scan open PRs for overlap before starting,
  prefer new files over edits to contested ones (`tempo-headless/src/lib.rs`
  especially), rebase early.
- Performance on hot paths (observation compile, framing, quiescence, cassette
  replay) is a correctness concern here — measure with the criterion benches
  above, don't guess. **More code is not more optimized.**
