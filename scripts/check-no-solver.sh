#!/usr/bin/env bash
set -euo pipefail

# Ethical invariant (#244): tempo DETECTS CAPTCHA / auth-wall states and hands
# the session to a human — it NEVER integrates a CAPTCHA-solving service or any
# automated challenge-answering. This grep guard fails CI if a known third-party
# solving service, endpoint, or "auto-solve" hook appears anywhere in the tree.
#
# Detection heuristics recognise challenges; they never answer them. Vendor names
# used as widget markers (recaptcha/hcaptcha/turnstile) are expected and are NOT
# matched here — this guard targets solver *services* and solve/bypass verbs.
#
# Uses POSIX `grep` (always present) — never ripgrep, which is not installed on
# the CI runner and would make this a silent no-op. A missing/broken scan tool is
# a HARD FAILURE, and a self-test proves the pattern actually trips before the
# real scan runs, so a broken guard cannot pass.

# Known CAPTCHA-solving services and give-away solve/bypass hooks. Extended regex,
# matched case-insensitively.
PATTERN='2captcha|rucaptcha|anti-?captcha|capsolver|capmonster|deathbycaptcha|death-by-captcha|bestcaptchasolver|azcaptcha|captchaai|nopecha|endcaptcha|imagetyperz|captchasolutions|9kw|captcha[_-]?solver|solve[_-]?captcha|solve_recaptcha|solve_hcaptcha|captcha[_-]?bypass|bypass[_-]?captcha|captcha_solving_service|automatic_captcha'

# Repository paths to scan. Includes non-.rs files, the root manifest, tests, and
# CI workflow definitions.
SCAN_PATHS=(crates scripts tests .github Cargo.toml)

require_grep() {
  if ! command -v grep >/dev/null 2>&1; then
    echo "check-no-solver: grep not found — cannot enforce the no-solver invariant" >&2
    exit 1
  fi
}

# Run the scan over the given paths. Prints matching "file:line:text" lines.
# Exits the whole script on a real grep error (rc > 1) so a broken tool never
# masquerades as "no violations".
run_scan() {
  local out rc
  set +e
  out="$(
    grep -rInEi \
      --binary-files=without-match \
      --exclude='check-no-solver.sh' \
      --exclude='final.md' \
      -e "$PATTERN" \
      "$@" 2>/dev/null
  )"
  rc=$?
  set -e
  if [[ $rc -gt 1 ]]; then
    echo "check-no-solver: scan tool error (grep exit $rc)" >&2
    exit 1
  fi
  printf '%s' "$out"
}

self_test() {
  local dir hit
  dir="$(mktemp -d)"
  # Plant a solver name the guard MUST catch.
  printf 'let client = Capsolver::new();\n2captcha_api_key = "x"\n' >"$dir/planted.rs"
  hit="$(run_scan "$dir")"
  rm -rf "$dir"
  if [[ -z "$hit" ]]; then
    echo "check-no-solver: SELF-TEST FAILED — guard did not trip on a planted solver name." >&2
    echo "The scan is not working (missing tool / broken pattern); refusing to report success." >&2
    exit 1
  fi
}

main() {
  require_grep
  self_test

  local violations
  violations="$(run_scan "${SCAN_PATHS[@]}")"
  if [[ -n "$violations" ]]; then
    cat >&2 <<'MSG'
A CAPTCHA-solving service or auto-solve hook appears in the tree.
tempo NEVER integrates a solver (#244): CAPTCHA / auth-wall states must
hard-pause and hand off to a human. Remove the solver integration.
MSG
    printf '%s\n' "$violations" >&2
    exit 1
  fi
  echo "check-no-solver: OK (self-test tripped; no solver integration found)"
}

main "$@"
