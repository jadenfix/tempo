# Differential observation-size/recall fixtures (#361)

This directory holds the fixture set consumed by `tempo_evals::differential_report`
(the hermetic core of #241, per #361). It covers two fixture pages, each captured
into four RECORDED, static, versioned JSON files:

| file suffix                | what it is                                                              |
|-----------------------------|--------------------------------------------------------------------------|
| `-tempo.json`               | tempo `CompiledObservation` (schema `tempo-schema` v2.0.0)                |
| `-playwright-a11y.json`     | a Playwright-MCP-style `browser_snapshot` accessibility-tree dump         |
| `-browser-use-dom.json`     | a browser-use-style `dom/serializer` flat indexed element list           |
| `-oracle.json`              | the ground-truth interactive-element set (CDP AX tree oracle)            |

Pages:

- `page1-checkout-*` — a checkout form (pay button, email field, terms link,
  a custom-styled "Remember me" toggle).
- `page2-search-*` — a product search/listing page (search box, an "in stock"
  filter, two add-to-cart buttons, a JS-routed "next page" pager).

## These are hand-authored, not live captures

**Important:** every file in this directory is hand-authored to be a plausible,
representative recorded serialization of what each tool would actually emit —
it is NOT produced by invoking a live Playwright MCP server or a live
browser-use process at test time (or ever, in this PR). Live invocation of
third-party frameworks is out of scope here and tracked separately as gated,
non-hermetic work under #363 ("Differential comparison vs *live* Playwright-MCP
and browser-use, beyond #361's static versioned-fixture comparison").

A real capture pipeline would run each tool once, offline, against a real
rendered page and commit the result as a new versioned fixture. That seam is
named but deliberately NOT built in this PR:

```
scripts/capture-baseline-snapshots/   # NOT implemented here — documented seam only
```

When it exists, it would (roughly):
1. Launch a fixture page (e.g. via a local static server) once per page.
2. Drive tempo's own observe path and dump the resulting `CompiledObservation`.
3. Drive a real Playwright MCP `browser_snapshot` call against the same page
   and dump its raw a11y-tree JSON.
4. Drive a real browser-use `dom/serializer` pass against the same page and
   dump its raw flat element-list JSON.
5. Capture a CDP `Accessibility.getFullAXTree` snapshot as the oracle and
   hand-verify (or script-verify) the ground-truth interactive-element list.
6. Commit all four outputs as a new `pageN-<slug>-*.json` fixture set here,
   bumping any existing set only via a reviewed diff (these are meant to be
   revert-sensitive, like every other fixture under `fixtures/`).

Until that script exists, regeneration is a manual, reviewed process; these
fixtures are not regenerated automatically by CI or by any test in this repo.

## Extraction rules used by `tempo-evals`

- **tempo**: every element in `elements[]` contributes one identity
  `(role, joined name text)`.
- **Playwright-style tree**: every node whose `role` is in a fixed
  interactive-role allowlist (`button`, `link`, `textbox`, `searchbox`,
  `checkbox`, `radio`, `combobox`, `switch`, `slider`, `menuitem`, `tab`) and
  has a non-empty `name` contributes one identity. Structural/decorative roles
  (`WebArea`, `generic`, `heading`, `paragraph`, `img`, `list`, `listitem`,
  `navigation`, ...) are walked for their children but never counted
  themselves.
- **browser-use-style flat list**: every array entry with `"interactive":
  true` and a non-empty `name` contributes one identity, using the fixture's
  tag-derived `role` field.
- **oracle**: every entry in `elements[]` is ground truth, full stop. The
  oracle set here is scoped to *task-relevant* interactive elements for the
  fixture page (the checkout form / the search-and-cart controls) — not
  incidental global page chrome (site header nav, footer links) that appears
  identically on every page and is not specific to the task. This mirrors
  tempo's actual documented design: `tempo-observe` ranks and budgets
  elements (final.md §8.1/§10, `CompiledObservation`'s target ≤4KB/≤1.5K
  tokens p50), so low-rank generic chrome that doesn't help complete the task
  is exactly what gets dropped once the task-relevant elements already fit
  the budget. The recorded tempo fixtures reflect that real behavior; the two
  baselines below intentionally still include full-page header/footer chrome,
  because a raw a11y-tree dump or DOM serializer pass has no such
  ranking/budgeting step.

Identity comparison (for recall) is `(role, name)` after trimming and
lowercasing both sides — coarse on purpose, since the goal is "did the agent's
observation surface this actionable thing", not a byte-exact match across
three unrelated JSON schemas.

Byte/token counts are computed over each format's *compact* (whitespace-free)
JSON re-serialization — parse the fixture, then `serde_json::to_vec` it — the
same method `tempo-evals` already uses for `EvalRecord::max_observation_bytes`
and `estimated_tokens` (`~4 bytes/token`, a documented heuristic, not a real
tokenizer). This keeps the comparison about payload content, not about how the
checked-in fixture file happens to be indented.

## Honesty note on the result

On these two fixture pages:

- **tokens**: tempo's compiled observation is smaller than *both* baselines on
  *both* pages. This reflects tempo's actual design (a flat, ranked,
  interactive-elements-only schema) versus a full nested a11y tree that also
  carries structural/decorative nodes (Playwright-style), and a flat DOM list
  that also carries xpath + raw attribute dictionaries per element
  (browser-use-style).
- **recall**: tempo ties the Playwright-style baseline at 1.0 on both pages.
  This is reported honestly, not fudged upward for tempo: a real Playwright
  MCP snapshot is itself backed by the browser's real accessibility tree, so
  it is expected to also find a `role="checkbox"` div or a `role="link"` span
  correctly — there is no fair basis in these fixtures to claim tempo "wins"
  recall against an equally AX-tree-backed baseline. Where tempo *does* score
  strictly higher on recall is against the browser-use-style baseline (0.75
  and 0.8 respectively), reflecting a real, documented class of gap in
  heuristic DOM/JS-based interactivity detection: elements that are
  semantically interactive (native `role`/`tabindex` present) but do not match
  a static tag/style/click-handler heuristic (a custom `<div role="checkbox">`
  toggle, a `<span role="link" tabindex="0">` pager control) can be missed by
  a serializer that isn't reading the engine's real accessibility tree.
