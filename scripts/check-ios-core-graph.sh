#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

target="${1:-aarch64-apple-ios}"
blocked='tempo-engine-(host|cdp|servo)|tempo-headless|tempo-shell|tempo-cli'

graph="$(cargo tree --locked --target "$target" -e normal -p tempo-ios-core)"

if printf '%s\n' "$graph" | rg "$blocked"; then
  printf 'tempo-ios-core normal dependency graph contains a blocked desktop/process crate\n' >&2
  exit 1
fi

printf 'tempo-ios-core graph ok for %s\n' "$target"
