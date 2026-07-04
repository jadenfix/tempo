# Agent Worktrees

Tempo work often has several agents editing at once. Each agent should work in a
separate Git worktree so branch state, build output, and uncommitted files stay
scoped to one PR-sized slice.

Start new implementation work from a clean sibling worktree:

```sh
scripts/new-agent-worktree.sh crawl-frontier
cd ../tempo-crawl-frontier
```

The helper creates branch `codex/crawl-frontier` from `origin/main` by default
and places the checkout next to the current repository. Use a second argument
when work must intentionally stack on another branch:

```sh
scripts/new-agent-worktree.sh sdk-openapi origin/main
```

Before committing, stage only the files that belong to that slice:

```sh
git status -sb
git diff --stat
git add <paths>
```

Do not work directly in another agent's dirty checkout. If a change depends on
another PR, either stack from that branch explicitly or wait until it lands.
