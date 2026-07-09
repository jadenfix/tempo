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
- A real external `browser-use` package subprocess (`real-browser-use`) that
  observes browser-use's model-facing state and drives the built-in
  browser-use `input` and `click` tools without requiring an LLM credential.

The generated benchmark artifact records success, wall time, CPU time, sampled
process-tree max RSS, step count, retry count, failure mode, and model-facing
bytes/tokens for each runner. Tempo reports `model_input_*` from its compact
taint-preserving prompt projection: set-of-marks handles such as `#1`, role,
short provenance prefixes, and accessible name/value text. The full URL stays in
the durable observation journal, not the prompt projection; when an engine
supplies marks, stable `node_id` strings also stay out of the prompt projection,
with `@node-id` fallback handles reserved for unmarked observations and resolved
before execution. `max_observation_*` keeps that durable structured JSON cost visible.
`max_compact_observation_*` records the same compact projection for every
journaled observation so compact agent-facing state is ranked separately from
full audit JSON. `observations` counts durable observations, while
`model_input_observations` counts the subset supplied to planning/deciding;
post-action verification observations remain auditable and policy-relevant
without inflating model prompt cost. Multi-observation model loops report total
model-facing input in `model_input_*` and largest single-observation size in
`max_observation_*`.
`--full` repeats the case five times by default and writes
`agent-browser-bench-summary.json` with per-runner success rate, failure-mode
counts, retry totals, and p50/p95/max stats. It also writes
`agent-browser-bench-gaps.json`, a deterministic comparison report that ranks
Tempo against raw Chrome, Playwright, browser-use-style, and real browser-use
package baselines for
success, latency, CPU, RSS, retries, failures, CDP runtime metrics, Web
Performance navigation/resource/paint/long-task metrics, model-facing tokens,
durable and model-facing observation counts, largest durable observation tokens,
and agent step count. The stable CDP dashboard fields cover the comparable
document/frame/listener/node/layout/script/task/heap subset, and any additional
numeric CDP metrics Chrome returns are preserved and ranked as `browser_cdp_*`
gap categories. Web Performance fields include detailed navigation phase
timings, resource transfer/encoded/decoded bytes, resource duration totals/maxes,
paint timing, and long-task count/duration/max. Row-level total model-input
token p95 is included where a runner reports a comparable model-facing stream
cost. `agent-browser-bench-status.md`
renders the same ranking and gap data as a
stable Markdown report for quick artifact review. It
also emits Tempo `session-eval`, `replay`, `scorecard`, and `amdahl` artifacts
from the real journal, external runner model-input/action traces, and
`chrome-version.txt` so benchmark runs stay tied to durable agent evidence.
