# tempo

An **AI-agent-native browser**, built from first principles in Rust.

Today's agentic browsers drive the web the way a human would — *screenshot → reason → one click → repeat*. That loop is slow, expensive, and prompt-injectable. tempo replaces it with **structured observation** (ranked, stably-identified, diff-able elements at ~2–5KB instead of a 40–500K-token DOM dump), **batched semantic actions** with a real page-settled signal, **state forking** for speculative parallel exploration, and an **API-first fast path** that skips rendering entirely when a site already speaks an agent protocol.

Engine strategy is **Rust-first**: [Servo](https://servo.org) is the primary rendering engine; a headless-Chromium lane (CDP) is a per-origin fallback behind the same driver trait. tempo reuses the sibling **beater** stack (`../beater-agents`, `../beater.js`, `../beater.js-connect`, `../beatbox`).

## Read this first

**[`final.md`](./final.md)** is the full engineering design — vision, first-principles requirements, component architecture, the Servo hook map, the dependency graph (what's parallel vs sequential), the beatbox sandbox integration, the Definition of Done (per-crate acceptance bars + milestone gates), risks, and verification.

## Layout

Cargo workspace under `crates/`. The two **freeze-first contracts** are implemented:

- `tempo-schema` — **C1/C2**: `CompiledObservation`, `Action`/`ActionBatch`, taint spans, diffs.
- `tempo-driver` — **C3**: the engine-agnostic `DriverTrait` v2 + `MockDriver` + conformance suite.

Everything else is a scaffolded stub with its responsibility and Definition of Done documented in `final.md`.

```
cargo test --workspace   # contracts + MockDriver conformance
```
