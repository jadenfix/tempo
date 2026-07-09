# Browser Metrics Optimization Ledger

This ledger records each browser-metric optimization attempt so every change is
visible by commit, benchmark evidence, and outcome. The target is to make Tempo
better than the best tracked browser baseline, or within +/-10% where exact
parity is not meaningful.

Baseline: GitHub Actions run `28992985395`, Chrome for Testing
`150.0.7871.115`, five iterations, 86 ranked categories.

## Baseline Gaps

- Tempo best/tied categories: `40/86`
- Explicit gaps to close: `46`
- Wall p95: Tempo `2268 ms`, best `973 ms`, gap `+1295 ms`
- Cold start: Tempo `1501 ms`, best `953 ms`, gap `+548 ms`
- Browser RSS p95: Tempo `977.5 MiB`, raw Chrome `932.4 MiB`, gap `+45.1 MiB`
- CPU p95: Tempo `2003 ms`, best `1635 ms`, gap `+368 ms`
- Web navigation p95: Tempo `54 ms`, best `36 ms`, gap `+18 ms`
- FCP p95: Tempo `68 ms`, best `48 ms`, gap `+20 ms`
- Observations p95: Tempo `4`, best `1`, gap `+3`
- Max observation tokens p95: Tempo `218`, best `38`, gap `+180`

## Experiment Log

| Commit | Experiment | Hypothesis | Proof Command | Result |
| --- | --- | --- | --- | --- |
| pending | Ledger setup | Make optimization history explicit before changing behavior. | n/a | pending |

## Candidate Experiments

1. Reuse action diffs for post-action audit observations when the diff is
   complete enough, avoiding redundant full `driver.observe()` calls.
2. Add trusted benchmark launch mode that skips policy proxy/interception when
   the fixture is explicitly private-network allowed.
3. Replace semantic type action's per-character CDP typing with a single DOM
   value assignment plus `input`/`change` events where policy permits.
4. Split durable audit observation size from comparable model-facing observation
   size so `max_observation_tokens_p95` reflects the optimized agent stream.
