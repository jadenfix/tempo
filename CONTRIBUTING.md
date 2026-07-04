# Contributing to tempo

tempo is an AI-agent-native browser. The design document is [`final.md`](final.md);
read §2 (requirements), §3 (architecture), and §8 (Definition of Done) before
picking up work — "done" is a testable exit bar, never "the code compiles."

## Toolchain

The repo pins Rust via [`rust-toolchain.toml`](rust-toolchain.toml) (currently
1.96.1, edition 2024). `rustup` picks it up automatically; no manual setup.

tempo builds standalone: `git clone && cargo build`. Sibling beater crates are
consumed as git dependencies pinned by rev, not by local path, so a fresh fork
compiles without any other checkout. Servo is optional and feature-gated
(`servo-vanilla` / `servo-tempo`); see the README for the fork/audit rules.

## Non-negotiable workspace invariants

Enforced by workspace lints and CI on every PR:

- `unsafe_code = "forbid"` — no unsafe anywhere in the workspace.
- `clippy::unwrap_used` / `clippy::expect_used = "deny"` — including tests;
  return `Result` from tests and use `?`.
- `cargo fmt --all --check` must pass; clippy runs with `-D warnings`.
- libservo types must never appear in public APIs outside `tempo-engine-servo`
  (`scripts/check-servo-public-api.sh`).
- A NodeId/selector miss is a **step error, never a transport error** (the
  grounding contract; conformance suite enforces it).

## CI gates your PR must pass

`.github/workflows/ci.yml` runs, in order: fmt → check → clippy → servo API
boundary → workspace tests → toolexec live tests → the fixture gates (eval
budget, observe, compat lanes, injection, taint) → servo vanilla + fork build
gates. A separate job runs the live-CDP conformance battery against real
Chrome and fails if those tests are skipped. Security-relevant changes
(observe / act / net / policy / taint / toolexec) are expected to extend the
injection and SSRF corpora, not just pass them.

Supply-chain checks (`.github/workflows/audit.yml`) run `cargo deny` for
advisories, bans, and source provenance on every PR touching dependencies.

## PR conventions

The PR body **must** include (CI rejects it otherwise):

```
1.) agent {agent number}
2.) purpose: {one-line purpose, no placeholder}
```

Keep PRs single-purpose. If your change touches `tempo-headless/src/lib.rs`,
check open PRs first — the daemon is a high-traffic file and several agents
work in parallel; rebase early and keep diffs additive where possible.

## Working as an agent (or alongside them)

Multiple coding agents contribute concurrently. Conventions that keep that
sane:

- Work in a dedicated worktree (`scripts/new-agent-worktree.sh`), never in a
  checkout another agent may be using.
- Before starting, scan open PRs for overlap with your files; prefer new
  crates/files over edits to contested ones.
- File an issue for anything broken you notice but don't fix in your PR.

## Releases

Tags matching `v*` trigger `.github/workflows/release.yml`, which builds
optimized `tempod` and `tempo-cli` binaries for macOS and Linux with the
workspace release profile (thin LTO, codegen-units=1, stripped symbols) and
attaches them, with SHA-256 checksums, to a GitHub release.
