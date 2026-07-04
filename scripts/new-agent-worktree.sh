#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: scripts/new-agent-worktree.sh <slug> [base-ref]

Creates an isolated sibling worktree for agent work.

Examples:
  scripts/new-agent-worktree.sh crawl-frontier
  scripts/new-agent-worktree.sh sdk-openapi origin/main

Environment:
  TEMPO_WORKTREE_ROOT       Parent directory for new worktrees.
  TEMPO_WORKTREE_NO_FETCH   Set to 1 to skip fetching the base ref.
USAGE
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 2
fi

raw_slug="$1"
base_ref="${2:-origin/main}"
repo_root="$(git rev-parse --show-toplevel)"
common_dir="$(git rev-parse --git-common-dir)"
case "$common_dir" in
  /*) ;;
  *) common_dir="$repo_root/$common_dir" ;;
esac
repo_common_root="$(dirname "$common_dir")"
repo_name="$(basename "$repo_common_root")"
default_parent="$(dirname "$repo_common_root")"
worktree_root="${TEMPO_WORKTREE_ROOT:-$default_parent}"

slug="$(printf '%s' "$raw_slug" \
  | tr '[:upper:]' '[:lower:]' \
  | sed -E 's/[^a-z0-9._-]+/-/g; s/^-+//; s/-+$//')"

if [[ -z "$slug" ]]; then
  echo "tempo: worktree slug must contain at least one letter or number" >&2
  exit 2
fi

branch="codex/$slug"
path="$worktree_root/$repo_name-$slug"

if ! git check-ref-format --branch "$branch" >/dev/null 2>&1; then
  echo "tempo: generated branch is not valid: $branch" >&2
  exit 2
fi

if git show-ref --verify --quiet "refs/heads/$branch"; then
  echo "tempo: branch already exists: $branch" >&2
  exit 1
fi

if git show-ref --verify --quiet "refs/remotes/origin/$branch"; then
  echo "tempo: remote branch already exists: origin/$branch" >&2
  exit 1
fi

if [[ "${TEMPO_WORKTREE_NO_FETCH:-}" != "1" ]] &&
  git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1; then
  echo "tempo: remote branch already exists: origin/$branch" >&2
  exit 1
fi

if [[ -e "$path" ]]; then
  echo "tempo: worktree path already exists: $path" >&2
  exit 1
fi

if [[ "${TEMPO_WORKTREE_NO_FETCH:-}" != "1" ]]; then
  case "$base_ref" in
    origin/*)
      base_branch="${base_ref#origin/}"
      git fetch origin "+refs/heads/$base_branch:refs/remotes/origin/$base_branch"
      ;;
    refs/remotes/origin/*)
      base_branch="${base_ref#refs/remotes/origin/}"
      git fetch origin "+refs/heads/$base_branch:refs/remotes/origin/$base_branch"
      ;;
    *)
      git fetch origin "$base_ref"
      ;;
  esac
fi

git worktree add -b "$branch" "$path" "$base_ref"

{
  echo "tempo: created isolated worktree"
  echo "  branch: $branch"
  echo "  path:   $path"
  echo "  next:   cd \"$path\""
}
