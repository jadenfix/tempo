# ADR: Observation Compile Locus

## Status

Accepted architecture, with the native Servo/out-of-process lane deferred until
its engine-side compiler wiring lands.

The current shipped preview lane is CDP. In that lane, `tempo-engine-cdp` links
`tempo-observe` and returns `CompiledObservation` / `ObservationDiff` through the
driver and engine-host protocol. The native Servo `tempo-engined` lane is still a
target lane, so production claims about Servo raw AccessKit trees never crossing
into `tempod` are not shipped until that lane owns the compiler in-process.

## Decision

Observation compilation has one owner per engine lane:

| Lane | Compile locus | Status |
|---|---|---|
| CDP preview (`tempo-engined-cdp`) | `tempo-engine-cdp` converts CDP/AX/DOM facts into `tempo-observe` inputs and emits `tempo-schema` observations/diffs before daemon IPC. | Shipped preview lane. |
| Native Servo (`tempo-engined`) | `tempo-engine-servo` / native engine process converts AccessKit `TreeUpdate` data into `tempo-observe` inputs and emits `tempo-schema` observations/diffs before daemon IPC. | Deferred target lane. |
| TestDriver / fixtures | Test-only drivers and fixture gates may construct `CompiledObservation` directly or through `tempo-observe`. | Test-only. |
| `tempod`, MCP, BiDi, agent runtime | Consume only `CompiledObservation`, `ObservationDiff`, screenshots, and typed driver results. They must not receive raw AccessKit/AX trees or `tempo-observe` raw compiler inputs over their public/runtime wire surfaces. | Runtime invariant. |

`tempo-observe` remains a pure compiler library. Runtime crates may call
non-boundary utilities such as set-of-marks image compositing, but they must not
become the place where raw engine accessibility trees are compiled for native
out-of-process engines.

## Acceptance Evidence

Before claiming the native Servo/out-of-process lane satisfies the architecture:

- The native engine crate/process must link `tempo-observe` and compile
  AccessKit-derived raw candidates before the engine-host wire boundary.
- The engine-host wire protocol must carry only `tempo-schema` observations,
  diffs, screenshots, and typed command/result envelopes.
- A boundary guard must reject raw AccessKit/AX types and raw `tempo-observe`
  compiler inputs in `tempod`-side crates.
- An integration test must drive the native/out-of-process lane and prove
  observation data returned to `tempod` is already compiled.

## Consequences

- CDP preview documentation can claim compiled observations cross its driver
  boundary because the CDP adapter owns that compile step today.
- Native Servo documentation must keep the engine-side compiler as a target-lane
  gate until its process actually owns the compile step.
- Reviews should block new runtime wire structs, public APIs, or tempod-side
  handlers that expose raw AccessKit, AX tree, `RawElement`, `ObservationInput`,
  or `StableIdMapper` values outside engine/fixture code.
