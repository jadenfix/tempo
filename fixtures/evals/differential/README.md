# Differential observation-size/recall fixtures (#361)

This directory holds the fixture set consumed by `tempo_evals::differential_report`
(the hermetic core of #241, per #361). It covers two fixture pages, each captured
into four RECORDED, static, versioned files:

| file suffix                  | what it is                                                                        |
|------------------------------|-----------------------------------------------------------------------------------|
| `-tempo.json`                | tempo `CompiledObservation` (schema `tempo-schema` v2.0.0), the JSON tempo sends a model |
| `-playwright-a11y.yaml`      | a Playwright-MCP-style `browser_snapshot` accessibility snapshot, in its real compact aria-YAML wire format |
| `-browser-use-dom.txt`       | a browser-use-style `dom/serializer` output, in its real compact indexed bracket-line wire format |
| `-oracle.json`               | the ground-truth task-relevant interactive-element set (CDP AX tree oracle)        |

Pages:

- `page1-checkout-*` — a checkout form (email field, a custom `<div role=checkbox
  tabindex=0>` "Remember me" toggle, terms link, pay button), inside a page with
  a global site header nav and footer nav.
- `page2-search-*` — a product search/listing page (search box, sort combobox,
  an "in stock" filter, two add-to-cart buttons, a `<span role=link tabindex=0>`
  "next page" pager), again inside global header/footer chrome.

## Real compact wire formats (not internal JSON)

Each baseline is stored in the **real, LLM-facing compact wire format** that the
tool actually hands a model — NOT a verbose internal JSON tree:

- **Playwright MCP** emits a compact YAML accessibility snapshot, one node per
  line: `- role "name" [ref=eN]`, nested by indentation, with plain text nodes
  as `- text: ...`. (An earlier revision of this fixture wrongly counted a
  bloated JSON tree with `xpath` + full attribute dicts + a `"children": []` on
  every leaf, which massively overstated the baseline's token cost. #361 review
  caught that; it is fixed here.)
- **browser-use** emits a compact indexed bracket-line serialization:
  `[i]<tag attrs>accessible name</tag>` for each interactive element,
  interleaved with plain visible-text lines for page copy, bracketed by
  `[Start of page]` / `[End of page]`.

`tempo-evals` counts each baseline's `compact_bytes` as the byte length of that
wire text (trailing whitespace trimmed) — i.e. exactly what the model reads and
pays tokens for — and extracts its interactive elements by parsing the *same*
text. Both numbers come from one committed artifact, so there is no hidden
second list to fudge.

Tempo is counted the way the crate already counts observation budgets
everywhere else: `serde_json::to_vec(&CompiledObservation).len()` (see
`tempo-agent`'s observation byte budget and `tempo-agent::decider`, which sends
the observation to the model as JSON). Tokens are `estimated_tokens(bytes)` =
`~4 bytes/token`, a documented heuristic (not a real tokenizer), applied
identically to all three formats.

## These are hand-authored, not live captures

**Important:** every file in this directory is hand-authored to be a plausible,
representative recorded serialization of what each tool would emit — it is NOT
produced by invoking a live Playwright MCP server or a live browser-use process
at test time (or ever, in this PR). Live invocation of third-party frameworks
is out of scope here and tracked separately as gated, non-hermetic work under
#363 ("Differential comparison vs *live* Playwright-MCP and browser-use, beyond
#361's static versioned-fixture comparison").

A real capture pipeline would run each tool once, offline, against a real
rendered page and commit the result as a new versioned fixture. That seam is
named but deliberately NOT built in this PR:

```
scripts/capture-baseline-snapshots/   # NOT implemented here — documented seam only
```

When it exists, it would (roughly):
1. Launch a fixture page (e.g. via a local static server) once per page.
2. Drive tempo's own observe path and dump the resulting `CompiledObservation`.
3. Drive a real Playwright MCP `browser_snapshot` call and dump its aria-YAML.
4. Drive a real browser-use `dom/serializer` pass and dump its bracket-lines.
5. Capture a CDP `Accessibility.getFullAXTree` snapshot as the oracle and
   derive the ground-truth interactive-element list from it (see below).
6. Commit all four outputs as a new `pageN-<slug>-*` fixture set here, bumping
   any existing set only via a reviewed diff (these are meant to be
   revert-sensitive, like every other fixture under `fixtures/`).

Until that script exists, regeneration is a manual, reviewed process; these
fixtures are not regenerated automatically by CI or by any test in this repo.

## Oracle derivation (recall ground truth)

The oracle is the set of **task-relevant interactive elements**: every element
in the page's primary content region (`<main>`) that a CDP AX tree would report
with an interactive role or that is keyboard-focusable. Global site chrome (the
`<header>` nav and `<footer>` nav, identical on every page and not part of this
page's task) is excluded. The oracle is derived from the page's HTML/AX
semantics — the interactive widgets of the task flow — *independently of tempo's
own observation*, so tempo's recall is validated, not guaranteed by
construction.

Caveat (single author): because one author wrote both the oracle and the tempo
fixture, "independent" here means "derived from the page's interactivity rules,
not copied from tempo's element list" — not a separately-tooled capture. The
real capture pipeline above would produce the oracle from an actual
`Accessibility.getFullAXTree` dump, closing that gap.

## Extraction / matching rules

- **tempo**: every element in `CompiledObservation.elements` contributes one
  identity `(role, joined name text)`.
- **Playwright aria-YAML**: every line `- <role> "<name>" [...]` whose `<role>`
  is in the interactive-role allowlist (`button`, `link`, `textbox`,
  `searchbox`, `checkbox`, `radio`, `combobox`, `switch`, `slider`, `menuitem`,
  `tab`) contributes one identity. Structural/text lines (`- banner:`,
  `- navigation "...":`, `- heading "..."`, `- text: ...`, `- img "..."`) are
  counted toward the byte payload but never surface an interactive element.
- **browser-use bracket-lines**: every `[i]<tag attrs>name</tag>` line
  contributes one identity; the role is the explicit `role=` attribute if
  present, else derived from the tag (`a`→link, `button`→button, `select`→
  combobox, `input[type=…]`→textbox/searchbox/checkbox/radio). This matches
  browser-use's real `is_interactive`, which treats a native interactive tag,
  an interactive ARIA `role=`, OR a `tabindex` as sufficient — so a
  `<div role=checkbox tabindex=0>` and a `<span role=link tabindex=0>` are
  detected, not skipped. Plain text lines surface nothing.
- **oracle**: every entry in `elements[]` is ground truth.

Identity comparison (for recall) is `(role, name)` after trimming and
lowercasing both sides — coarse on purpose, since the goal is "did the
observation surface this actionable thing", not a byte-exact match across three
unrelated wire formats.

## Honesty note on the recall result

On both fixture pages, **all three formats tie at recall 1.0** against the
oracle. This is the honest result:

- Both Playwright MCP (aria snapshot) and browser-use (with `is_interactive`
  applied correctly) surface every task-relevant interactive element, including
  the `<div role=checkbox>` toggle and the `<span role=link>` pager — these
  carry an interactive ARIA role AND a `tabindex`, exactly the signals both
  tools key on. An earlier revision of this fixture set marked those two as
  non-interactive for browser-use and claimed a 0.75 / 0.8 browser-use recall
  gap; that was a **strawman** (a reviewer checking browser-use's real
  `clickable_elements` / `is_interactive` source would refute it), and it has
  been removed. There is no genuine, upstream-defensible recall gap on these
  fixtures, so none is claimed.
- tempo also surfaces every oracle element (recall 1.0). Its ranking/budget
  would only start dropping elements on a page large enough to exceed budget;
  these pages fit, so nothing is dropped and recall is full.

The revert-sensitive recall *math* is covered by tests that drop a known
element and confirm recall falls below 1.0.

## Honesty note on the token result

This is the important correction from the #361 review. Counted in the tools'
**real compact wire formats**, tempo's `CompiledObservation` JSON is **not
smaller — it is modestly heavier** than both baselines:

| page          | tempo (bytes/tokens) | playwright-mcp | browser-use |
|---------------|----------------------|----------------|-------------|
| page1-checkout| 813 / 204            | 704 / 176      | 587 / 147   |
| page2-search  | 1280 / 320           | 1246 / 312     | 926 / 232   |

Why: each tempo element carries stable-handle (`node_id`), taint-provenance,
`rank`, and `bounds` metadata that a plain aria-YAML line or a bracket-line does
not. That per-element premium (~100+ bytes/element vs ~30–40) outweighs the
bytes tempo saves by emitting only the ranked, task-relevant subset instead of
the whole page. All three stay within ~1.4x of each other — same order of
magnitude — but tempo does **not** win tokens here.

This does not contradict tempo's thesis; it scopes it. tempo's headline "10–50x
lower token cost" (final.md §10) is measured against **raw** CDP/DOM full-HTML
dumps, which are far larger than these already-compact compaction tools. That
raw-dump comparison is not fixtured here (it belongs with the live slice, #363).
Against Playwright-MCP and browser-use specifically, the honest finding is:
tempo matches them on task-relevant recall and pays a small token premium for
carrying grounding + taint + rank metadata the pure-text baselines omit. If a
future change gives tempo a lean LLM-only projection, this metric is exactly
what would measure the improvement.
