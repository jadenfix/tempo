# Synthetic skill-replay-after-drift fixtures (#362)

This directory holds the fixture pairs consumed by `tempo_evals::skill_drift_corpus_report`
(and `replay_skill_after_drift`, `read_drift_page_fixture`).

## This is a SYNTHETIC PROXY, not a live drift measurement

The real claim — "a recorded skill/cassette still resolves after a site
genuinely changes" — needs two time-separated live crawls of an actual site.
That is explicitly gated, non-hermetic work tracked by **#363**
("Differential comparison vs live ..." umbrella; skill/cassette live drift is
one of its deferred items) and is **not attempted here**.

Every fixture pair below is hand-authored to *simulate* one kind of
DOM/selector drift. Nothing in this directory or in `tempo_evals`'s
skill-drift code should be read as evidence about real-world drift
resilience — it only characterizes how tempo's own stable-id/skill-replay
primitives behave under a controlled, synthetic edit.

## What "replay" actually means here

tempo has no HTML parser or live replay engine in this metric's dependency
set (`tempo-skills`, `tempo-observe`), and this PR does not add one. Fixture
pages are therefore JSON `tempo_observe::ObservationInput` files — the same
already-parsed raw-element shape `tempo-observe`'s own corpus tests use under
`fixtures/observe/corpus-pass.json` — not raw HTML/DOM text. Parsing real
HTML and running selector queries against it would be a new, non-hermetic
engine; out of scope by requirement.

"Replay a recorded skill" means, precisely:

1. Compute the target element's `NodeId` against the `*-pre.json` page using
   a fresh `tempo_observe::StableIdMapper` (this is what an engine adapter
   would have handed an authoring session when the skill was first recorded).
2. Bake that `NodeId` into a real one-step `tempo_skills::SkillDefinition`
   (a `Click` action) and run tempo's actual, only skill-expansion path,
   `SkillDefinition::compile`, to get the concrete `Action::Click { node }` a
   persisted skill file would carry.
3. Compute the stable ids for the `*-post.json` ("post-drift") page using
   **another fresh** `StableIdMapper` — deliberately not carrying mapper
   state across `pre`/`post`, because a genuine time-separated re-crawl
   (#363's real subject) would not have session continuity either.
4. `replay_success_after_drift` = whether the `NodeId` from step 2 is present
   in the id set from step 3.

## Why this is the right primitive (not an invented one)

`tempo_skills::SkillDefinition::compile` is pure template substitution: a
recorded step's target is a literal (or once-bound-parameter) `NodeId`
string, and `compile` does not look anything up against a live page at all.
The part of tempo that *can* survive or fail to survive drift is therefore
not `compile` itself but the `NodeId` it bakes in, which comes from
`tempo_observe::StableIdMapper`'s fingerprint rule: identity is derived from
a stable DOM hint if the engine supplied one, else from `role + name + value`
— deliberately independent of DOM position/order/bounds.

## The three cases

| case                     | drift simulated                                              | expected outcome |
|--------------------------|---------------------------------------------------------------|------------------|
| `case1-moved-position`   | same button/link, reordered in the element list + moved bounds (simulated relayout) | **survives** — fingerprint (role+name+value) is unchanged by position |
| `case2-renamed-target`   | same button position/role, accessible name changed ("Add to cart" -> "Buy now") | **fails** — the name is part of the fingerprint, so a rename allocates a new `NodeId` |
| `case3-removed-target`   | the original button is genuinely gone; an unrelated new button ("Sign up for newsletter") appears elsewhere on the page | **fails** — the recorded fingerprint is absent from the post-drift page entirely |

This is a genuinely mixed, non-trivial result (1 survive / 2 fail), not an
"everything trivially survives" or "everything trivially fails" outcome — see
the honesty note below for the one important caveat.

## Honesty note: "renamed" and "replaced" are indistinguishable here

Under tempo's current fingerprint scheme, a renamed element (case 2) and a
genuinely different, same-shaped replacement element are indistinguishable —
both simply fail to match the old fingerprint. This is an accurate
characterization of a real limitation, not a strawman: tempo's `NodeId` is a
content-derived fingerprint, not a persistent DOM node identity, so a mere
label change on the "same" widget looks exactly like removal-and-replacement
to this scheme. A live, continuously-tracked session *could* still resolve a
rename via the engine's native `source_id`
(`StableIdMapper::by_source`/`by_fingerprint` correlation within one running
mapper), but that requires session continuity a genuine time-separated
re-crawl would not have either — which is why this metric deliberately uses a
fresh mapper per fixture page rather than one shared across `pre`/`post`
(see step 3 above). No fixture here is authored to fake a nuance the format
doesn't actually have.

## Regeneration

These are static, versioned, hand-authored fixtures, edited directly and
reviewed like any other fixture under `fixtures/`. There is no capture
script (unlike `fixtures/evals/differential/`'s documented offline-capture
seam) because there is nothing to capture from: these pages were never real,
only ever intentionally-constructed drift examples.
