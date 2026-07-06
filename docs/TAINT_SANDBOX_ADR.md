# ADR: Taint-To-Sandbox Dispatch

## Status

Accepted architecture, deferred runtime wiring for the local CDP preview.

The `tempo-toolexec` bridge and its live beatbox canary are real code and CI
coverage. The live `tempod`/agent CDP paths do not yet route page-tainted
compute through that bridge, so authenticated/private-account exfiltration
resistance must not be claimed as a shipped preview guarantee.

## Context

Tempo has two separate side-effect surfaces:

- Browser side effects: navigation, clicks, form input, script evaluation, and
  other browser actions. These stay behind `tempo-policy` confirmation and taint
  escalation.
- Non-browser compute: extraction transforms, page-derived post-processing,
  skill code, downloads, conversion, OCR, and other code or data transforms.
  These must not run in the agent loop or daemon address space when their inputs
  carry page provenance.

`tempo-toolexec` already builds the locked beatbox request required for
page-derived transforms: `NetPolicy::Deny`, no secrets, bounded resources,
double jail, deterministic mode when requested, and a journal idempotency key.
The missing architectural decision was where the live runtime must invoke that
bridge.

## Decision

The taint-to-sandbox dispatch locus is the runtime execution boundary in
`tempod`/headless, immediately before non-browser compute would materialize or
run on page-derived input. It is not owned by the model loop, not by
`tempo-policy`, and not by the pure `tempo-taint` crate.

Runtime callers must:

- Preserve C1 provenance spans on extraction/script-evaluation/tool inputs until
  the execution boundary.
- Route any non-browser compute with page-tainted spans through
  `tempo_toolexec::TaintedTransform` and `ToolExecClient::execute_tainted_transform`
  or `create_tainted_transform_job`.
- Keep browser actions on the existing policy path; beatbox governs compute
  side effects, not browser side effects.
- Record the beatbox result, isolation evidence, egress records, and
  idempotency key in the session/journal audit model.
- Fail closed when taint evidence is missing at that boundary. A caller may add
  taint, but it must not clear or unwrap page provenance before dispatch.

Layering stays one-way: `tempo-toolexec` remains a bridge crate, while
`tempo-headless`/`tempod` owns orchestration. Pure contract crates must not grow
upward dependencies on runtime or beatbox clients.

## Acceptance Evidence

The current bridge evidence is:

- `crates/tempo-toolexec` tests for request construction, taint predicates, and
  canary report evaluation.
- `tests/toolexec-live/tests/live.rs`:
  `real_beatboxd_tainted_canary_denies_import_egress`, which runs against a real
  beatbox server and proves the tainted transform path sends no canary traffic
  while reporting denied egress.
- CI runs `cargo test --manifest-path tests/toolexec-live/Cargo.toml`.

The future runtime-wiring PR that closes this deferred preview gap must add a
runtime integration test that starts from the actual `tempod`/headless
agent-facing entrypoint, feeds page-tainted input into a non-browser transform,
and proves the resulting work reaches beatbox with the same no-network,
no-secrets canary evidence. A unit test of `tempo-toolexec` alone is not enough
for that milestone.

## Consequences

- Product and security docs can describe the taint-to-beatbox composition as the
  accepted architecture and beta/remote gate, not as a local CDP preview
  guarantee.
- Reviews should block any PR that unwraps page-derived extraction or
  script-evaluation output to raw JSON/string before this boundary without
  carrying provenance or explicitly routing through the sandbox.
- Reviews should also block claims that M5-style prompt-injection exfiltration
  resistance is complete unless the live runtime integration test above exists
  and passes.
