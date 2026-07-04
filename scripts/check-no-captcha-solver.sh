#!/usr/bin/env bash
set -euo pipefail

# Ethical invariant (#244): tempo DETECTS CAPTCHA / auth-wall states and hands
# the session to a human — it NEVER integrates a CAPTCHA-solving service or any
# automated challenge-answering. This grep guard fails CI if a known third-party
# solving service, endpoint, or "auto-solve" hook appears anywhere in the tree.
#
# `detect_human_takeover` and the `#244` markers are the *opposite* of a solver,
# so vendor names appearing as detection heuristics (recaptcha/hcaptcha/turnstile
# as widget markers) are expected and NOT matched here — this guard targets
# solver *services* and solve verbs, not challenge recognition.

# Known CAPTCHA-solving services and give-away solve hooks. Matched
# case-insensitively as whole tokens.
pattern='2captcha|anti-captcha|anticaptcha|anticaptcha\.com|capsolver|capmonster|deathbycaptcha|death-by-captcha|bestcaptchasolver|captcha[_-]?solver|solvecaptcha|solve_captcha|captcha_solving_service|automatic_captcha'

violations="$(
  rg -in \
    --glob '*.rs' \
    --glob '*.toml' \
    --glob '*.md' \
    --glob '!**/final.md' \
    --glob '!scripts/check-no-captcha-solver.sh' \
    "$pattern" \
    crates scripts 2>/dev/null || true
)"

if [[ -n "$violations" ]]; then
  cat >&2 <<'MSG'
A CAPTCHA-solving service or auto-solve hook appears in the tree.
tempo NEVER integrates a solver (#244): CAPTCHA / auth-wall states must
hard-pause and hand off to a human. Remove the solver integration.
MSG
  printf '%s\n' "$violations" >&2
  exit 1
fi
