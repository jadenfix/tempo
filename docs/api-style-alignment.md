# Tempo API — AIP-style alignment with the Tempera stack

> Status: design README. Proposes that `tempod`'s HTTP control plane + MCP surface
> adopt the **unified Google-AIP contract language** used across the Tempera
> stack, canonically defined in
> [`tempera-dev/data-engine`'s `API_STYLE.md`](https://github.com/tempera-dev/data-engine/pull/1).
> No code here; this is the target contract + migration mapping. Tempo stays
> standalone and local-first — alignment is about contract *shape*, not adding a
> dependency.
>
> Companion to the same alignment proposed for `cradle` (beatbox) and `palette`
> (Beater). One language, four services.

---

## 1. Why align

Today each Tempera service speaks a slightly different HTTP dialect. Aligning to
one AIP language means: **one client SDK per language works across all of them**,
one MCP client sees a uniform tool catalog, and one drift gate proves each
service's served OpenAPI equals its committed contract. `data-engine` is the
reference implementation; `API_STYLE.md` extracts the rules so Tempo adopts them
verbatim rather than reinterpreting.

The governing rule on every side is the same: **contract first (OpenAPI / MCP),
native optional.**

---

## 2. Tempo today (current shape — not AIP)

`tempod` (loopback control plane, bearer auth) currently exposes
(`crates/tempo-headless/src/lib.rs`, router ~line 4799):

```
GET    /health, /ready, /openapi.json
GET/POST /mcp                            (Streamable HTTP JSON-RPC)
GET/POST /bidi                           (websocket + BiDi)
GET/POST /sessions                       (list / create)
DELETE /sessions/{id}                    (kill)
POST   /sessions/{id}/adopt
POST   /sessions/{id}/handoff
GET    /sessions/{id}/manager
POST   /sessions/{id}/surfaces           (+ register/unregister)
GET    /sessions/{id}/observe
POST   /sessions/{id}/act_batch
POST   /sessions/{id}/mcp
GET    /sessions/{id}/screenshot
GET    /sessions/{id}/events             (+ /events/stream)
POST   /sessions/{id}/runs
GET    /v1/traces                        (outbound OTLP export — separate)
```

**Gaps vs the unified language:**
- No `projects/{project}/` parent scoping; resources are flat under `/sessions`.
- No dotted `operationId` convention (`sessions.observe`, …) — OpenAPI is served
  at `/openapi.json` but operationIds aren't the canonical `<collection>.<verb>`.
- Actions are snake_case sub-paths (`act_batch`) not AIP custom verbs (`:act`).
- No shared error envelope (the canonical `error.code/status/details/retryable`
  shape from `API_STYLE.md` §6).
- `/runs` + `/events` polling is a bespoke long-running model, not the shared
  `Operation` shape (`API_STYLE.md` §8).
- No `Idempotency-Key` on mutating ops (create / act / run); no `If-Match`/ETag.
- `/openapi.json` is generated at runtime, not committed + drift-gated.

**Already conformant:** bearer auth on loopback, an MCP surface at `/mcp`, an
OpenAPI document is served, stable resource names (`sessions`, `runs`, `events`,
`surfaces`).

---

## 3. Target mapping (current → AIP)

Tempo is local-first/loopback, so it uses a single default project parent
(`projects/default/`) to keep the shape uniform without inventing multi-tenancy.
A `project` here is just the AIP parent segment — it can stay `default` for the
local daemon.

| Current | AIP target | operationId |
|---|---|---|
| `POST /sessions` | `POST /v1/{parent=projects/*}/sessions` | `sessions.create` |
| `GET /sessions` | `GET /v1/{parent=projects/*}/sessions` | `sessions.list` |
| `DELETE /sessions/{id}` | `POST /v1/{name=projects/*/sessions/*}:kill` | `sessions.kill` |
| `POST /sessions/{id}/adopt` | `POST /v1/{name=.../sessions/*}:adopt` | `sessions.adopt` |
| `POST /sessions/{id}/handoff` | `POST /v1/{name=.../sessions/*}:handoff` | `sessions.handoff` |
| `GET /sessions/{id}/observe` | `GET  /v1/{name=.../sessions/*}:observe` | `sessions.observe` |
| `POST /sessions/{id}/act_batch` | `POST /v1/{name=.../sessions/*}:act` | `sessions.act` |
| `GET /sessions/{id}/screenshot` | `GET  /v1/{name=.../sessions/*}:screenshot` | `sessions.screenshot` |
| `POST /sessions/{id}/surfaces` | `POST /v1/{parent=.../sessions/*}/surfaces` | `surfaces.register` |
| `GET /sessions/{id}/events` (+ stream) | `GET /v1/{parent=.../sessions/*}/events` | `events.list` (+ `:stream` SSE) |
| `POST /sessions/{id}/runs` | `POST /v1/{parent=.../sessions/*}/runs` → returns `Operation` | `runs.create` |
| (poll runs/events) | `GET /v1/{name=projects/*/operations/*}` | `operations.get` |

Custom verbs use `:` (`:act`, `:observe`, `:adopt`, `:handoff`, `:kill`), matching
data-engine's `:ingest`/`:emit`/`:run` and AIP custom-method guidance.

---

## 4. What changes (concrete, per `API_STYLE.md`)

1. **Parent scoping**: nest under `projects/{project}/...` (default `projects/default/`
   for the local daemon). Keeps list/create parent-scoped like every sibling.
2. **operationId** = `<collection>.<verb>` (e.g. `sessions.act`, `runs.create`).
   MCP tool name = operationId, 1:1 (`API_STYLE.md` §13).
3. **Custom verbs** `:act`, `:observe`, `:adopt`, `:handoff`, `:kill`, `:screenshot`
   (replace snake_case sub-paths).
4. **Shared error envelope** (`API_STYLE.md` §6) verbatim — `error.code/status/
   message/details/request_id/retryable`, canonical codes only. No ad-hoc error
   JSON.
5. **`Operation` model** for `/runs` (and any act/observe that can exceed
   timeout): return `projects/.../operations/{id}`, poll `operations.get`,
   cancel `:cancel`. `events/stream` stays as the live SSE tail on the session.
6. **`Idempotency-Key`** header on all mutating ops (create/act/run/adopt/handoff);
   **`If-Match` + ETag** on any mutable session state; **`update_mask`** on patches.
7. **Cursor pagination** on `sessions.list` and `events.list` (`page_size`,
   `page_token`, `next_page_token`, `total_size`).
8. **Committed OpenAPI + drift gate**: check the generated `openapi.json` into the
   repo and add a CI gate that `GET /openapi.json` == committed doc (the same gate
   data-engine/cradle/palette run). Regen clients in any contract PR.
9. **Headers**: keep `Authorization: Bearer <token>` (already there); add
   `x-request-id` echoed on responses; RFC3339 UTC timestamps.
10. **MCP**: one tool per `operationId`, `structuredContent` on results,
    `isError:true` on failures, derived from the OpenAPI (no hand-maintained
    catalog mirror).

---

## 5. What stays Tempo-specific (AIP allows this)

The **language** is shared; the **resources** are Tempo's own. AIP does not
require identical resource hierarchies — only identical conventions. So Tempo
keeps: `sessions`, `runs`, `events`, `surfaces`, the BiDi/websocket transport,
the `/bidi` and `/mcp` streaming endpoints, the CDP/Servo engine split, and the
local-first loopback posture. None of that conflicts with the contract language.

The outbound OTLP path (`POST /v1/traces` to a collector) is export telemetry,
not part of the control-plane contract — it stays as-is.

---

## 6. Migration notes

- Per the ecosystem `AGENTS.md`, breaking contract changes are allowed now (the
  stack is pre-1.0 and uniformity is preferred over compat shims). Land the
  renames in one slice: routes + operationIds + OpenAPI regen + clients + MCP +
  the drift gate, with the `tempo` CLI updated in the same PR.
- Keep a thin compat layer only if a downstream consumer (e.g. a `tempo-shell`
  script) can't move in the same slice; drop it once aligned.
- Coordinate the `Operation` model + error envelope with `cradle` and `palette`
  so the four services ship the same shapes in the same window.

---

## 7. Reference

- Canonical language: [`tempera-dev/data-engine` → `API_STYLE.md`](https://github.com/tempera-dev/data-engine/pull/1)
  (data-engine is the reference implementation; its `api/openapi.yaml` is the
  byte-for-byte oracle).
- Transfer checklist: `API_STYLE.md` §16.
- Sibling alignment PRs: `cradle` `docs/api-style-alignment.md`, `palette`
  (AIP migration target noted in `API_STYLE.md` §15).
