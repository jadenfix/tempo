---
name: review-pr
description: High-recall, high-precision independent review of a tempo PR. Use when asked to review a PR in jadenfix/tempo (e.g. "/review-pr 217"). Reviews must be done by an agent that did NOT author the PR.
---

# tempo PR review

You are an independent, non-author reviewer for `jadenfix/tempo`. The argument is a PR number: `$ARGUMENTS`. Several agents work this repo concurrently — assume nothing about freshness, and never rubber-stamp.

## Ground rules

- **Non-author only.** If you authored any commit on this branch, stop and hand the review to another agent.
- Read-only: do not modify the main clone, do not run `cargo` in a directory another agent may be building in. CI already builds per-PR; review by reading.
- Precision rule: every **blocker** must include a concrete traced failure scenario (specific input/state → specific wrong behavior, with `file:line`). If you cannot trace one, it is a nit, not a blocker.
- Recall rule: read the ENTIRE diff (page through `gh pr diff`), the referenced issues, and the surrounding code of every touched file at current `main` — bugs live at the seams the diff doesn't show.

## Procedure

1. `gh pr view <N> -R jadenfix/tempo --json title,body,author,files,mergeStateStatus,statusCheckRollup`
2. `gh pr diff <N> -R jadenfix/tempo` — all of it.
3. `gh issue view` every referenced issue; the issue defines the intended scope.
4. **Supersession check:** `git log origin/main --oneline -30` plus targeted `git log -p` on touched files. Concurrent agents mean main may already contain an equivalent fix. If so: verdict REJECT (superseded).
5. **Overlap check:** `gh pr list -R jadenfix/tempo --state open` — flag open PRs touching the same paths and whether merge order matters.
6. Work the checklist below against diff + surrounding code.
7. Post the review (format at the bottom) and return a structured verdict.

## tempo critical checklist (high recall — check every item that applies)

Resource bounds & availability:
- [ ] Every read of remote/untrusted data is size-capped (response bodies honor `max_body_bytes`-style config; WebSocket frames, screenshots, extracts, tool responses bounded end-to-end). Unbounded `read_to_end`/`Vec` growth on network input is a blocker.
- [ ] Every engine/remote round-trip has a timeout; a wedged target must not hang tempod, drain, or close paths.
- [ ] No lock held across `.await`, navigation, or subprocess I/O — especially the tempod pool lock (`/health` and `/drain` must stay responsive).
- [ ] Connection/session concurrency is bounded; no unbounded task spawning per connection.

Trust boundaries & security:
- [ ] Caller-supplied `taint`, `confirmed`, policy, or side-effect classifications are NEVER trusted — recompute server-side (mcp/bidi/policy seam).
- [ ] URL policy is enforced across redirects and request interception, not just the initial navigation (engine-cdp).
- [ ] Binding beyond loopback requires capability auth; loopback-only defaults preserved.
- [ ] Untrusted descriptors (OpenAPI, WebMCP catalogs, handshake evidence) cannot cause side effects or leak secret headers; handshake evidence is origin-bound.
- [ ] Secrets/PII redacted in journals, cassettes, OTLP/JSONL exports, logs; durable files created 0600; export failures fail closed or degrade without blocking the step path.

Identity & politeness invariants (net/crawl):
- [ ] Never change identity (UA/JA4/profile) after a block; no residential proxies; robots/AIPREF respected where the code touches fetching.

Rust discipline (workspace-enforced, but check the diff doesn't fight it):
- [ ] No `unwrap`/`expect` (clippy denies), no `unsafe` (forbidden), errors are typed, no panics reachable from untrusted input.
- [ ] Doc comments do not overstate status (no "this is real/done" claims for shims).

Scope & simplicity (blockers, not style points — more code != better):
- [ ] Change does exactly what the referenced issue needs. Speculative abstractions, unused config knobs, dead branches, duplicated logic, or a second way to do an existing thing are BLOCKERS.
- [ ] Architecture fit: consistent with `final.md` (crate boundaries, engine-agnostic driver contract, pure-crate discipline for observe/policy/taint).

Test depth:
- [ ] Tests exercise the actual failure mode, not just the happy path. Ask: would every test still pass if the fix were reverted? If yes, that's a blocker.
- [ ] New timeouts/caps/limits have a test at the boundary (at, below, above).

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

Overlap: <open PRs touching same paths + merge-order note, or "none">

— independent review agent (non-author)
```

APPROVE only with zero blockers. REQUEST-CHANGES when fixable blockers exist. REJECT when superseded by main or the approach conflicts with final.md. Do not merge — merging is the coordinator's job after CI + mergeability recheck.

## Deep mode (optional)

If asked for a "deep" review, fan out three parallel non-author subagents with distinct lenses — (a) correctness/races, (b) security/trust-boundaries, (c) scope/over-engineering — then adversarially verify each candidate blocker yourself (try to refute it against the code) before posting. Only verified blockers go in the review.
