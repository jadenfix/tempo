---
name: tempo-gh-sweep
description: Repeatable GitHub cleanup workflow for jadenfix/tempo. Use when asked to resolve all Tempo GitHub PRs/issues, merge eligible PRs, triage or close issues, keep work isolated in git worktrees, and prove fixes with current-main merge checks plus e2e or production-path evidence.
---

# tempo GitHub sweep

Use this skill for long-running `jadenfix/tempo` cleanup passes where PRs and
issues must be driven toward zero.

## Ground Rules

- Treat GitHub as authoritative. Re-read `gh pr list` and `gh issue list` after
  every merge, push, body edit, rerun, or wait.
- Run repo commands only in isolated worktrees. Never use the shared main
  checkout for build, test, merge simulation, or edits.
- Keep one worktree per PR or issue: `.worktrees/tempo-pr<N>-review`,
  `.worktrees/tempo-pr<N>-merge`, or `.worktrees/tempo-issue<N>`.
- Before merging, require all of: non-draft, unchanged reviewed head SHA,
  mergeable/clean, green current checks, no unresolved blocker comments, and a
  local current-main merge check.
- If a PR body was fixed, trigger a fresh run with a push or close/reopen.
  Body-only edits do not make `pr-scope` evidence fresh.
- If no PRs are open, rank issues by `security`, `sev:high`, `correctness`,
  `dos`, then recent activity. Close only with concrete merged-code evidence.

## PR Loop

1. Inventory:
   - `gh pr list --repo jadenfix/tempo --state open --json number,title,isDraft,mergeable,mergeStateStatus,statusCheckRollup,updatedAt,url`
   - `gh issue list --repo jadenfix/tempo --state open --json number,title,labels,updatedAt,url --limit 200`
2. For each open PR, fetch into a review worktree and inspect:
   - `gh pr view <N> --json title,body,headRefOid,baseRefOid,isDraft,mergeable,mergeStateStatus,statusCheckRollup,commits,files`
   - `gh pr checks <N>`
   - `gh pr diff <N> --name-only`
   - `gh pr diff <N>`
   - `gh issue view <referenced issue>`
3. Build a merge-check worktree from fresh `origin/main`, merge the PR head
   there, and run tests for touched crates.
4. Prefer e2e or production-path checks when available:
   - live route/API tests for `tempod` or headless behavior
   - live CDP tests for browser/engine behavior
   - CLI/daemon invocation for user-facing workflows
   - issue-specific regression tests only when a true e2e path is not practical
5. Merge only after a final fresh state read verifies the same head SHA and green
   checks.

## Issue Loop

- Close fixed issues with a comment naming the merged PR/commit and the evidence
  that proves the close condition.
- For partially fixed issues, leave them open and add a status comment
  separating shipped guardrails from remaining close conditions.
- When implementing an issue, create a focused branch from fresh `origin/main`,
  keep the diff scoped, include e2e or production-path evidence, and open a PR
  instead of pushing directly to main.

## Completion Audit

Before reporting completion:

- `gh pr list --repo jadenfix/tempo --state open`
- `gh issue list --repo jadenfix/tempo --state open --limit 200`
- Confirm every remaining open item is either actually resolved or has an
  explicit blocker/status comment.
- Do not claim zero PRs/issues unless those commands return none.
