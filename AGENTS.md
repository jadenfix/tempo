# Repository Agent Notes

- Work in an isolated worktree and branch for each change. Do not rewrite, delete, or force-clean another agent's dirty worktree.
- Use `gh` for GitHub issue, PR, review, and merge state. Prefer one tight review pass and only a small follow-up loop when there is a concrete blocker.
- After any wait, force-push, PR body edit, CI rerun, or concurrent merge, re-check PR state, head SHA, base SHA, check rollup, and linked issue state with `gh` before reviewing or merging. Stale checks and closed/superseded PRs are not merge evidence.
- Run Cargo verification sequentially per target directory, or give concurrent commands separate `CARGO_TARGET_DIR` values. Missing rlibs, object files, or temp dirs from a shared fresh target are local harness races until reproduced with a clean sequential run.
- When a review or incident exposes a persistent, non-overfit lesson, preserve it as general guidance. Read-only reviewers should report the candidate guidance in the review body; coordinators or follow-up authors should land accepted guidance here and in `.claude/skills/review-pr/SKILL.md` from a separate worktree/PR.
- Keep durable guidance phrased as reusable invariants or failure modes. Avoid issue numbers, branch names, one-off file lines, and examples that will go stale unless they are explicitly called out as examples.
- Runtime-visible contract changes must keep the public descriptions in sync. When routes, status codes, response fields, schemas, or agent/SDK surfaces change, update OpenAPI and generated-client-facing docs in the same slice.
- Do not commit realistic secret, token, password, or credential literals, even in tests. Build scanner-safe fixtures from clearly inert fragments while still proving redaction and non-leak behavior.
- Operational metadata that exposes dependency state, capacity, policy, or topology is control-plane data. Guard it with the same auth/host/origin boundary unless the route is intentionally public and boring, like a static liveness check.
- More code is not more optimized. Prefer the smallest change that proves the invariant, removes duplicated paths, or makes an existing contract honest.
