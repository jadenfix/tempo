# Live Agent Browser Benchmark Fixture

This directory contains the local page and action plan used by
`scripts/agent-browser-bench.sh`.

The harness drives the same checkout task through:

- Tempo CDP via `tempo-cli run-cdp-task`.
- Raw Chrome CDP selector actions.
- A synthetic Playwright-MCP-style accessibility snapshot path, captured from
  Chrome's live Accessibility domain.
- A synthetic browser-use-style DOM serializer path, captured from the live page
  DOM.
- A real external Playwright subprocess (`real-playwright`) using the Python
  Playwright API against the same Chrome executable.
- A browser-use-style external DOM loop
  (`external-browser-use-dom-loop`) that observes indexed interactive DOM lines
  and acts from those observations. This is a deterministic browser-use-format
  control loop, not the full browser-use LLM agent package.

The generated benchmark artifact records success, wall time, CPU time, sampled
process-tree max RSS, step count, retry count, failure mode, and model-facing
bytes/tokens for each runner. Tempo reports `model_input_*` from its compact
taint-preserving prompt projection and keeps durable structured JSON cost in
`max_observation_*`. `observations` counts durable observations, while
`model_input_observations` counts the subset supplied to planning/deciding;
post-action verification observations remain auditable and policy-relevant
without inflating model prompt cost. Multi-observation model loops report total
model-facing input in `model_input_*` and largest single-observation size in
`max_observation_*`.
`--full` repeats the case five times by default and writes
`agent-browser-bench-summary.json` with per-runner success rate, failure-mode
counts, retry totals, and p50/p95/max stats. It also writes
`agent-browser-bench-gaps.json`, a deterministic comparison report that ranks
Tempo against raw Chrome, Playwright, and browser-use-style baselines for
success, latency, RSS, retries, failures, model-facing tokens, largest durable
observation tokens, and agent step count. CPU is reported row-level until every
runner uses the same resource-accounting scope. Row-level total model-input
token p95 is included where a runner reports a comparable model-facing stream
cost. It
also emits Tempo `session-eval`, `replay`, `scorecard`, and `amdahl` artifacts
from the real journal, external runner model-input/action traces, and
`chrome-version.txt` so benchmark runs stay tied to durable agent evidence.
