# tempo performance doctrine

**The claim we are building toward:** tempo is the fastest and most memory-efficient browser in the world **for agent workloads** — measured as tasks per minute, tokens per task, dollars per task, and concurrent sessions per GB — and it holds that title permanently, because every one of those numbers is ratcheted in CI and can never regress.

This doctrine is grounded in the measured reality of this repo (file:line cites throughout). It defines: the crown metrics, what we deliberately do not claim, the best-of-every-browser technique map, the Amdahl-ordered optimization priority, and the never-regress ratchet that turns today's budgets into permanent floors.

## 1. What "fastest browser ever" means here — and what it doesn't

The honest frame (final.md §12.1): a browser-use-style agent step costs ~3 s, of which the LLM decode is ~90% and engine work (observe+act+settle) is 0.05–0.25 s. **The browser that wins for agents is not the one that renders fastest — it is the one that makes the model read fewer bytes, emit fewer tokens, and take fewer round-trips.** That is tempo's home turf: structured ≤4KB observations instead of 40–500K-token DOM dumps (final.md:31), batched actions with a real settled signal, diffs instead of re-dumps, and an API-first lane that skips rendering entirely.

We claim, and ratchet, the **agent-workload crown**:

| Crown metric | Today's anchor | Direction |
| --- | --- | --- |
| Tokens per task (scripted suite, per eval class) | §10 per-task ceilings (final.md:490) | ratchet down |
| Wall-time per task / steps per task (scripted suite) | ~68 s/task competitor baseline (final.md §12.1) | ratchet down |
| Observation size: ≤4KB / ≤1.5K tok p50, ≤8KB p95 | `EvalBudget::default` (tempo-evals lib.rs:97-112) | ratchet down below the bar |
| observe p50 ≤150 ms / p95 ≤500 ms; act→quiescent p50 ≤1.2 s | same | ratchet down below the bar |
| Concurrent sessions per GB RSS; RSS per idle session | bounded pools exist (headless lib.rs:85-102), byte caps "to enforce" (PLATFORMS.md:160) | ratchet up / down |
| Cold start → first observation ≤300 ms desktop / 800 ms mobile | PLATFORMS.md:155 | ratchet down |

We do **not** claim Speedometer/JetStream/MotionMark supremacy. Rendering throughput is inherited from the engine lane (Servo upstream; Chromium via CDP) and human-browsing benchmarks measure a workload tempo does not serve. Chasing them would spend our effort on the 6% (engine) instead of the 90% (model I/O) — the Amdahl table (final.md:526-556) forbids it. If a rendering-bound bottleneck ever appears **in an agent task trace**, it enters the priority list through the measurement harness (#481), not through vanity benchmarks.

## 2. Best of every browser — the technique map

Take each engine's crown jewel, keep it protocol-shaped, and add the agent-native tricks no browser has:

| Source | Their best idea | tempo's version | Where |
| --- | --- | --- | --- |
| **Firefox Quantum / Stylo** | Parallel styling & layout in Rust | Inherited natively — Stylo *is* Servo DNA; the primary engine lane is this bet | `tempo-engine-servo`, final.md engine strategy |
| **Chromium** | Site isolation & process-per-site; mature remote protocol | Engine-host process boundary with peer-credential UDS auth + per-session ephemeral profiles; CDP lane as per-origin fallback behind the same driver trait | `tempo-engine-host` (lib.rs:142), PLATFORMS.md:176 |
| **WebKit / Safari** | Memory-pressure discipline: cache eviction, compaction, tight per-tab RSS | Flat-memory invariants: offset-indexed cassettes ("resident memory stays flat regardless of cassette sizes", tempo-session lib.rs:507-511), ring-evicted session events (headless lib.rs:552), generation-evicted mappers — plus §6's per-tier byte caps as enforced ratchet metrics | tempo-session, tempo-headless, PLATFORMS.md:157-160 |
| **Chromium prerender / speculation rules** | Speculative navigation | State forking + speculative parallel exploration — gated by evidence: ships on-by-default only at ≥15% wall-clock reduction on the multi-branch suite (final.md:490) | `tempo-speculate`, #457 |
| **Every engine's compositor** | Event-driven frame pipeline, no polling | Composite quiescence: network idle ∧ layout/frame generations ∧ pending JS, O(1) isolated-world sampling with ramped 25/50 ms polls replacing O(page) hash-pulls | tempo-act lib.rs:281-399, tempo-engine-cdp lib.rs:1135-1218 |
| **HTTP/2 & pipelining** | Batch the round-trips | Multi-action batches verified by ONE post-batch diff, with partial-apply/replay-safety distinction | tempo-act lib.rs:26-196, #478 |
| **No browser has these** | — | Ranked, stable-ID, diff-able ≤4KB observations (≥99% ID survival); taint-tracked provenance; API-first no-engine lane; cassette replay | tempo-observe, tempo-taint, tempo-net, tempo-session |

## 3. Amdahl-ordered priorities (spend effort where the seconds are)

Priority = measured cost × feasibility, from final.md §12. Every item lands with its metric ratcheted from day one.

1. **Tokens & round-trips (the 90%):**
   a. Live-lane observation quality — route live CDP through the compiler (ranking, marks, budgets, shadow/iframe recall): #477, first slice #486. Until then `main` is missing the compiler tail on the live lane, and every downstream number is understated.
   b. Diffs actually delivered to the model (#447) — the wire format is ready and URL-guarded (tempo-schema lib.rs:98; cross-URL diffs forced to full replacement, tempo-observe lib.rs:796).
   c. Multi-action batches + zero-LLM helpers + stuck fingerprinting (#478) — fewer steps beats faster steps.
   d. Real tokenizer for the budget gate: today's count is `bytes/4` (tempo-observe lib.rs:1156). A heuristic that under-counts lets regressions hide inside the bar; the evaluator should count with the target model's tokenizer, keeping bytes as the deterministic dual.
2. **Screenshot path (~0.8 s/step, ~27% when vision is on):** zero-copy binary frames end-to-end, SIMD encode (#479; PLATFORMS.md:154).
3. **Overlap the model and the engine:** decide/settle overlap and speculative observe-under-decode (design-only today, final.md:550; live-engine forking #457). Ships only past the ≥15% speculation gate.
4. **Local ranker on GPU/ANE (#480)** — cuts model-facing bytes at the source.
5. **Engine µs work (the 6%):** IPC framing ≤50 µs (PLATFORMS.md:152), observe compile ≤1 ms/200 elements (PLATFORMS.md:151), allocation cuts. Ratcheted by the existing criterion benches; optimized when profiles say so, not before.
6. **Measure-it first (#481):** the per-step token+latency Amdahl table on the live lane is itself a deliverable — every priority above re-ranks on its output.

`main` now has a live-CDP measurement path for this: the CI live lane runs a
real `run-decided-task`, converts its durable session journal through
`tempo-cli session-eval`, then feeds that JSONL record to `tempo-cli e2e-budget`.
That proves real browser observations/actions produce eval-compatible
`step_count`, `round_trips`, `llm_round_trips_per_completed_task`, token
totals, observe/action latency samples, and wall time. Provider `prefill_ms`
and `decode_ms` remain explicit pending instrumentation: current
`DecisionUsage` records token counts and cache reads, but not provider latency
splits.

## 4. Memory doctrine (the "most efficient" half of the claim)

RAM discipline today is structural — buffer reuse, offset indexes, ring eviction, bounded pools (`MAX_TEMPOD_SESSIONS = 1024`, headless lib.rs:102; per-session event/idempotency caps lib.rs:85-87; OTLP queue 256, lib.rs:3243). PLATFORMS.md:160 marks per-tier byte-bounding "to enforce." The doctrine makes it enforced and ratcheted:

- **Sessions-per-GB** becomes a first-class benchmark: N idle + M active scripted sessions, assert RSS; ratchet N up and RSS down.
- **Per-tier byte caps** (desktop/mobile per PLATFORMS.md:75) become config-enforced limits with at/below/above boundary tests — a phone must not pay a desktop's RAM bill.
- **Flat-memory invariants become tests:** cassette/journal lookups must stay O(1)-resident as file size grows (the tempo-session promise, lib.rs:507-511); a test drives a 100× cassette and asserts resident-set flatness via the telemetry gauge.
- Killed-but-resident pool entries (headless lib.rs:99) get an eviction story before the 1024 cap is ever the binding constraint in production.

## 5. The ratchet: from budget bars to permanent floors

Today the numeric bars live in three synchronized places — PLATFORMS.md:149-160 (per-hop), final.md:490 (§10), and the executable copy `EvalBudget::default` (tempo-evals lib.rs:97-112, with telemetry histogram buckets deliberately aligned at 0.15/0.5/1.2 s, tempo-telemetry metrics.rs:11-17). CI enforces the fixture-driven budget gates (`scorecard`, `observe-gate`) but `bench-smoke` asserts **no thresholds**, and **no baseline is committed anywhere**. final.md:457 already anticipates the fix ("fail the build on regression … once the evaluator is in the required check set"); #517 wires telemetry snapshots into the evaluators. The ecosystem-wide design is [ecosystem/docs/perf-ratchet-pipeline.md](https://github.com/jadenfix/ecosystem/blob/main/docs/perf-ratchet-pipeline.md); tempo is rollout slice 1. Concretely:

- **Budget vs baseline, two different lines.** The §10 bars are *ceilings* (product promises — never crossed). The committed `perf/baseline.json` is the *ratchet* (best-achieved — never re-approached). A change that stays under the ceiling but above the baseline still fails. `EvalBudget` becomes the single executable source; a CI check asserts PLATFORMS.md/final.md tables match it, ending three-way drift by construction.
- **Counters ratchet at zero tolerance:** observation bytes & tokens on the fixture corpora (`fixtures/evals/`, `fixtures/observe/`, the differential matrix vs browser-use DOM dumps and playwright-a11y in `fixtures/evals/differential/`), steps and model round-trips per scripted task, bytes over the driver IPC per step, stable-ID survival ≥99%, diff-vs-full-observation ratio. Deterministic fixtures ⇒ same number every run ⇒ `candidate ≤ baseline`, hard fail.
- **Timings ratchet via paired A/B:** `scripts/bench.sh` already does named criterion baselines (`bench.sh main && bench.sh pr main`); the gate builds merge-base and candidate, interleaves runs on the same pinned runner, and fails on a consistent paired regression >3–5% — plus the absolute §10 ceilings. Never single-run, never cross-machine.
- **Gate honesty:** every ratchet run includes a deliberately-degraded build (e.g. an env-flag that disables budget truncation or adds a redundant serialize) that MUST fail the gate, or the job itself fails — the pipeline proves per-run that it can catch a dip.
- **Ratchet tightening is automatic:** post-merge, metrics that improved beyond noise get a bot PR lowering `perf/baseline.json` (non-author review rules apply). Loosening requires a human editing the baseline in the same diff, `perf-tradeoff` label, justification in the PR body. Silent regression becomes structurally impossible.
- **Competitive scoreboard:** the differential fixtures already encode the comparison (tempo vs browser-use DOM dump vs playwright a11y snapshot, per page). Extend to task level: same scripted tasks through a Chromium+Playwright screenshot-loop harness vs tempo, publishing tokens/task, steps/task, wall-time/task, RSS. That table — regenerated in CI, ratcheted like everything else — *is* the "fastest agent browser" claim, with receipts.

## 6. Rollout (PR-sized slices, each independently shippable)

1. `perf/baseline.json` + ratchet script wiring `bench.sh` + the counter fixtures into a required CI check, with the gate-honesty fixture. (This document's companion slice.)
2. Single-source the budgets: evaluators read `EvalBudget`; docs tables checked against it in CI.
3. Sessions-per-GB + RSS benchmark and per-tier byte-cap enforcement (closes PLATFORMS.md:160 "to enforce").
4. Real-tokenizer counting in `tempo-evals` alongside the bytes counter.
5. Task-level competitive harness + published scoreboard.
6. Wire per-step Amdahl telemetry (#481/#517) so the priority list in §3 re-ranks on live data.

**Definition of done for this doctrine:** a PR that adds one redundant serialization to the observe path, or one extra model round-trip to a scripted task, or 5% RSS to an idle session, fails CI in this repo — automatically, with the metric, baseline, and delta printed. From that day forward, "the most optimized browser for agents" is not a slogan; it is the only state the repo can be in.
