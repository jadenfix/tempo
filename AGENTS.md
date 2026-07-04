# Repository Agent Notes

- Work in an isolated worktree and branch for each change. Do not rewrite, delete, or force-clean another agent's dirty worktree.
- Use `gh` for GitHub issue, PR, review, and merge state. Prefer one tight review pass and only a small follow-up loop when there is a concrete blocker.
- When a review or incident exposes a persistent, non-overfit lesson, preserve it as general guidance. Put agent coordination rules here and review-specific invariants in `.claude/skills/review-pr/SKILL.md`.
- Keep durable guidance phrased as reusable invariants or failure modes. Avoid issue numbers, branch names, one-off file lines, and examples that will go stale unless they are explicitly called out as examples.
- More code is not more optimized. Prefer the smallest change that proves the invariant, removes duplicated paths, or makes an existing contract honest.
