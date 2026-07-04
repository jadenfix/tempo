---
name: review-pr
description: High-recall, high-precision independent review of a tempo PR. Use when asked to review a PR in jadenfix/tempo (e.g. "/review-pr 217"). Reviews must be done by an agent that did NOT author the PR.
---

# tempo PR review

You are an independent, non-author reviewer for `jadenfix/tempo`. The argument is a PR number: `$ARGUMENTS`. Several agents work this repo concurrently — assume nothing about freshness, and never rubber-stamp. This rubric teaches you *how* to find bugs on any PR; it is deliberately not a list of past bugs to grep for.

## Ground rules

- **Non-author only.** Check `gh pr view <N> -R jadenfix/tempo --json commits -q '.commits[].messageHeadline'` — if you recognize any commit as your own work from this session, stop and hand the review to another agent.
- Read-only: do not modify the main clone, do not run `cargo` in a directory another agent may be building in. CI already builds per-PR; review by reading.
- Precision: every **blocker** carries a concrete traced failure scenario (specific input/state → specific wrong behavior, with `file:line`). If you cannot trace one, it is a nit.
- Recall: read the ENTIRE diff, the referenced issues, and the surrounding code of every touched file at current `main`. Bugs live at the seams the diff doesn't show.

## Procedure

1. `gh pr view <N> -R jadenfix/tempo --json title,body,author,files,mergeStateStatus,statusCheckRollup`
2. `gh pr diff <N> -R jadenfix/tempo` — all of it.
3. `gh issue view <issue> -R jadenfix/tempo` for every referenced issue; the issue defines the intended scope (did the PR do more or less than it needs?).
4. **Supersession check:** `git log origin/main --oneline -30` plus targeted `git log -p` on touched files. Concurrent agents mean main may already contain an equivalent fix → REJECT (superseded).
5. **Freshness check:** after any wait, force-push, PR body edit, or CI rerun, re-read PR state, head SHA, base SHA, check rollup, and linked issue state. A closed PR, stale-head check run, or already-closed issue is not merge evidence.
6. **Overlap check:** `gh pr list -R jadenfix/tempo --state open` — flag open PRs touching the same paths and whether merge order matters.
7. Hunt for bugs using the method below.
8. Post the review (format at the bottom) and return a structured verdict.

## How to find bugs (do this — don't just tick boxes)

The checklist further down is a memory aid. These techniques are what actually surface bugs; apply them to the code this PR touches.

- **Trace one path end to end.** Pick the main value or state the PR changes and follow it through the code — into the error and edge branches, not just the happy path. Most blockers live on the path the tests don't take.
- **Review from three seats.** tempo serves a **human**, an **LLM agent**, and a **fleet operator**, and each fails differently: the agent cannot see through a result envelope that lies (it keys on the flag, not the prose); the operator cannot rescue a node that has silently wedged or grows without bound; the human notices a frozen UI or a control that does nothing. For the code in the diff, ask how it hurts each of the three.
- **Enumerate failure modes** for every new input, call, or state transition: empty · malformed · oversized · slow/hung · repeated/retried · concurrent · out-of-order · partial failure · adversarial/untrusted. A new path that silently mishandles one of these is a candidate blocker.
- **Follow the seams the diff hides:** the callers of every changed signature, the callees it now leans on, and any invariant elsewhere that assumed the old behavior.
- **Reverted-fix test:** would any test in the PR still pass if the fix itself were reverted? If yes, the test proves nothing — that's a blocker for a bugfix PR.
- **Adversarially verify** each candidate blocker before it goes in the review: try to refute it against the code. Survives refutation → blocker. Can't build a concrete trace → nit.
- **Preserve durable lessons without breaking read-only review.** If a review uncovers a persistent, non-overfit invariant that would catch future unrelated bugs, call it out in the review under `Durable guidance`. Do not edit repo files as part of the read-only review. A coordinator or follow-up author should land accepted guidance in this file and in `AGENTS.md` or `CLAUDE.md` from a separate worktree/PR. Do not add issue numbers, branch names, or frozen file:line examples unless they are explicitly marked as temporary examples.

## What to look for (general bug classes — check every one that the diff touches)

Correctness & honesty of the contract:
- [ ] Return values, status flags, and result/tool envelopes tell the caller the truth — a failure or a no-op is never reported as success. (Highest stakes where the caller is the agent, which acts on the flag.)
- [ ] Output that drops, truncates, samples, or rate-limits data says so, so the consumer can distinguish "absent" from "omitted."
- [ ] Tool and model result envelopes do not duplicate large structured payloads across text and structured channels; text fallbacks summarize, while binary artifacts use native media content blocks.
- [ ] Handles/IDs the caller reuses across calls are stable, or their churn is handled rather than silently breaking multi-step callers.
- [ ] Docs, comments, and declared schemas/types match what the code actually does — no present-tense claims for a stub, no `{"type":"object"}` standing in for a real schema.
- [ ] Model-facing tool schemas are self-contained and match the runtime parser — no opaque object placeholders, unresolved `$ref`s, or ambiguous aliases where the caller needs one canonical shape.
- [ ] Runtime-visible contract changes update every public description in the same slice: OpenAPI paths/statuses/schemas, agent cards, SDK-facing docs, and compatibility fixtures. A route or response field that exists at runtime but is absent from the contract is a blocker for SDK workflows.
- [ ] Public Rust schema struct changes update source callers too: `serde(default)` preserves old JSON compatibility, but it does not make existing struct literals compile. Scan/update workspace literals and downstream crates.
- [ ] Compact wire-format changes that omit default, empty, or optional fields preserve both directions of compatibility: compact serialization, populated serialization, and default-filled deserialization all have reverted-fix-sensitive tests.
- [ ] Borrowed serializers, budget probes, counting sinks, and other wire-shape proxies mirror every `serde` default/skip rule on the public type they approximate. A proxy that counts or emits bytes differently from the real payload can create false truncation or false fit decisions.

Resource, lifecycle & availability:
- [ ] Everything that can grow is bounded: input/response sizes, queues, maps, caches, retries, spawned tasks, and session/connection counts. Unbounded growth on remote-driven input is a blocker.
- [ ] Size caps are enforced before or during construction/serialization of remote-driven JSON, DOM, screenshot, log, and tool-result data. A check that rejects only after allocating the complete payload is not a memory bound.
- [ ] Stateful protocol handlers enforce live-state quotas in addition to per-message size caps; repeated valid commands must not grow maps, vectors, or dispatch scans without bound.
- [ ] Moving blocking work onto std threads or blocking pools is not itself a bound; client-triggered thread fan-out needs a shared in-flight cap and an immediate structured rejection path.
- [ ] Every engine/remote/subprocess round-trip has a timeout **and** a recovery path — a crash or hang is detected and healed (restart/reconnect, with backoff), not permanently terminal.

Security boundaries & auth:
- [ ] Loopback, Host, and Origin checks are not authentication. Control planes that drive sessions, tools, or browser state require an unguessable same-user capability even on `127.0.0.1`.
- [ ] Health/readiness signals reflect real state (draining, dependency-down, at-capacity); cleanup and teardown run on every exit path including error and cancel.
- [ ] Operational metadata routes that expose dependency health, capacity, policy, or topology are guarded like control-plane routes unless they intentionally return only static liveness.
- [ ] Locks are narrow, consistently ordered, released on panic (poison recovered, not fatal), and never held across `.await`, navigation, or subprocess I/O — the pool lock especially, so `/health` and `/drain` stay responsive.
- [ ] UI-local state transitions and teardown/cancel paths stay bounded independently of backend health. Moving I/O off-thread is not enough if local controls or shutdown still serialize behind blocking transport work.
- [ ] Durable/journal writes use a batched single-writer path (e.g. WAL + a dedicated writer), not per-write open + full fsync; a crash or kill mid-write must be recoverable on restart with no torn or lost committed state.

Trust boundaries & security:
- [ ] Caller-supplied trust/policy/side-effect classifications (`taint`, `confirmed`, …) are recomputed server-side, never trusted.
- [ ] Untrusted data is size-checked, provenance-tracked, and cannot cause side effects or leak secret headers; a policy (URL, egress, redaction) is enforced across the whole path — redirects, retries, interception — not just the entrypoint.
- [ ] Egress and proxy policy is bound to the concrete endpoint actually used after DNS, proxy resolution, redirects, and retries; validating a hostname, URL string, or only one candidate address is not enough when another resolved socket can be selected later.
- [ ] Untrusted remote tool descriptors without trusted side-effect metadata are classified at the strongest supported side effect before threshold origin rules run; never flatten unknown remote tools to a weaker class.
- [ ] Security or taint gates assert the production call path, not only the helper intended to be safe; model-facing page metadata is provenance-framed, not left as escaped-but-bare prompt attributes.
- [ ] Untrusted descriptors and attestations (OpenAPI/WebMCP catalogs, handshake evidence) are origin-bound and cannot themselves drive side effects or inject secret headers.
- [ ] Tests and docs that verify redaction do not commit realistic secret, token, password, API-key, or credential literals. Use scanner-safe inert fragments while still proving the sensitive value never appears in debug/display/error/export output.
- [ ] Secret-bearing clients parse and validate configured base URLs before constructing requests: reject userinfo/query/fragment/path injection, require a pinned secure production origin, and make loopback/insecure fixtures use an explicitly named test opt-in.
- [ ] A detector or guard runs on data that actually reaches it: check that upstream filtering/compilation didn't strip the very signal the check needs.

Performance on hot paths (a regression here is a correctness bug for this project):
- [ ] Reused, not recreated: clients, sessions, connections, buffers, metric handles — no per-call handshake, allocation, or registration where it can be cached.
- [ ] No redundant serialization, copies, or round-trips on the per-action path; work that can overlap isn't forced sequential; no new global single-op bottleneck.

Fit & simplicity (more code is not better):
- [ ] The change does exactly what its issue needs — no speculative abstraction, dead branch, unused config knob, second way to do an existing thing, or new crate/feature with no caller.
- [ ] It fits `final.md`: crate-layer direction is respected (a lower-layer contract crate must not depend upward on a higher-layer one), the driver contract stays engine-agnostic, observe/policy/taint stay pure, and public contracts stay versioned to evolve independently.

Tests:
- [ ] A test exercises the actual failure mode (survives the reverted-fix question above); new caps/timeouts/limits are tested at the boundary — at, below, above.
- [ ] Local verification ran in an isolated worktree/target. If multiple Cargo commands share one fresh `CARGO_TARGET_DIR` concurrently, missing rlibs/object files/temp dirs are local harness races until reproduced sequentially.

## tempo hard rules (standing invariants — treat a violation as a blocker)

These are the project's non-negotiable rules, not suggestions:
- No `unwrap`/`expect` (clippy denies) and no `unsafe` (forbidden); errors are typed; no panic reachable from untrusted input.
- Loopback-only bind by default; binding beyond loopback requires capability auth, and the boundary must not be bypassable (e.g. a component linking the pool in-process).
- Engine-host IPC is peer-authenticated; proxy endpoints are secure schemes or an explicit insecure opt-in.
- Identity (UA/JA4/profile) never changes after a block; no residential proxies; robots/AIPREF respected where the code fetches.
- Secrets/PII redacted in journals, cassettes, and OTLP/JSONL exports; durable files are `0600`; export failure degrades without blocking the step path.
- Raw accessibility/DOM data is compiled engine-side; only compiled observations/diffs cross into `tempod`.

For concrete, current instances of these bug classes, skim the tracker's `sev:high`/`sev:critical` issues — but review the code in front of you, not a checklist of past bugs.

## Verdict & posting

Post exactly one review:

```
gh pr review <N> -R jadenfix/tempo --comment --body "<body>"
```

Body format — first line is the verdict, nothing above it:

```
VERDICT: APPROVE | REQUEST-CHANGES | REJECT (superseded | wrong-approach)

<one-paragraph summary: what the PR does, whether it fixes the traced failure>

Blockers:
- <file:line — traced failure scenario>   (or "none")

Nits:
- <file:line — suggestion>                (or "none")

Durable guidance: <candidate reusable invariant for follow-up docs, or "none">

Overlap: <open PRs touching same paths + merge-order note, or "none">

— independent review agent (non-author)
```

APPROVE only with zero blockers. REQUEST-CHANGES when fixable blockers exist. REJECT when superseded by main or the approach conflicts with final.md. Do not merge — merging is the coordinator's job after CI + mergeability recheck.

## Deep mode (optional)

If asked for a "deep" review, fan out three parallel non-author subagents with distinct lenses — (a) correctness/races, (b) security/trust-boundaries, (c) scope/over-engineering — then adversarially verify each candidate blocker yourself (try to refute it against the code) before posting. Only verified blockers go in the review.
