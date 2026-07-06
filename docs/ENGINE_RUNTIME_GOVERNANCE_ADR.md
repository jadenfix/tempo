# ADR: Engine And Runtime Governance

## Status

Accepted architecture for the local developer preview.

This ADR records three related decisions:

- CDP is the default shipped engine lane until Servo promotion evidence exists.
- `tempo-shell` uses `tempod` as the session authority over loopback; in-process
  daemon linking is not the canonical topology.
- C1, C2, C3, and the engine-host wire protocol are independently governed
  public contracts, even while the current code still carries compatibility
  aliases from the original combined schema version.

## Context

`final.md` describes the destination architecture, while the runnable preview is
currently a local CDP stack: `tempod` starts or attaches to `tempo-engined-cdp`,
serves loopback HTTP/MCP/BiDi with bearer auth, and exposes `DriverTrait` through
the engine-host IPC boundary.

The native Servo lane remains the Rust-native target because it is the only lane
that can eventually own the full embedded-browser and engine-side observation
pipeline. It has not yet passed the M-vanilla/M4 gates required for preview
default status.

The human shell has a similar preview/destination split. The product topology is
one session authority per host (`tempod`) with native shells registering and
adopting shared sessions over loopback. The current `tempo-shell` crate still
links `tempo-headless` for model/test reuse and internal client types; that link
must not be interpreted as permission to bypass the daemon boundary in shipped
shells.

Contract governance also needed an explicit decision. `tempo-schema` originally
exposed one `SCHEMA_VERSION` for both C1 observation and C2 action types, and the
engine-host IPC protocol did not document a separately versioned wire contract.
That is too coarse for forkers and out-of-process engines.

## Decision

### Engine Default

CDP is the preview default. Servo is the target lane and may become the default
only after objective promotion gates pass.

Required Servo promotion evidence:

- M-vanilla proves a real Servo engine process can navigate, observe, screenshot,
  execute semantic input, and run script evaluation over the C3 driver boundary.
- M4 cross-engine differential evidence shows Servo/CDP parity on the committed
  conformance and eval slices.
- The native Servo lane owns observation compilation before daemon IPC, matching
  `docs/OBSERVATION_COMPILE_LOCUS_ADR.md`.
- `tempo-engine-servo` keeps Servo embedding types private and exposes only Tempo
  contracts across public crate and IPC surfaces.

CDP sunset can start only after the Servo lane is the default for local preview,
CI carries Servo as a required gate, and fallback rates are measured rather than
assumed.

### Shell Topology

`tempod` is the session authority. Native shells connect to `tempod` over
loopback, register foreground surfaces, subscribe to session events, request
adoption leases, render native confirmation UI, and hand control back through
daemon APIs.

Production shell code must not rely on in-process `SessionPool` ownership to
skip bearer auth, Host/Origin checks, policy gates, taint state, or event
journaling. The long-term client shape is a thin `tempo-tempod-client` crate
containing typed session, event, run, and surface clients without pulling in the
daemon server stack.

### Contract Versioning

These contracts are independently governed:

| Contract | Owner crate/surface | Compatibility rule |
|---|---|---|
| C1 ObservationSchema | `tempo-schema` observation and diff types | Version independently from actions when observation fields or semantics change. |
| C2 ActionSchema | `tempo-schema` action and action-batch types | Version independently from observations when action semantics change. |
| C3 DriverTrait | `tempo-driver` trait, conformance suite, and TestDriver | Version independently from schema payload changes when driver behavior or required capabilities change. |
| Engine IPC wire protocol | `tempo-engine-host` frame envelope and handshake | Version independently from C3 so mismatched out-of-process engines fail closed before command dispatch. |

`SCHEMA_VERSION` remains a compatibility alias for current JSON payloads until
the implementation splits C1/C2 constants in code. New contract work should add
or update the independent version constant it changes rather than treating the
combined schema alias as sufficient.

The engine-host protocol must negotiate or validate its wire version before a
daemon accepts a driver connection. A version mismatch is a transport setup
failure, not a late command error.

## Consequences

- Product docs should say "CDP-first preview, Servo-promotable by evidence"
  rather than "Servo is the shipped primary engine."
- Shell reviews should block new preview paths that make in-process daemon
  access the shipped browser topology.
- Runtime and engine reviews should block unversioned IPC envelope changes once
  the wire-version constant and handshake land.
- `tempo-shell` may keep temporary dependencies needed for tests or model reuse,
  but those dependencies should shrink toward a `tempo-tempod-client` boundary.

## Acceptance Evidence

This ADR closes the decision gap. Follow-up implementation work should provide:

- a code-level C1/C2/C3/wire-version split with compatibility tests,
- an engine-host handshake rejection test for wire-version mismatch,
- a `tempo-tempod-client` extraction plan or crate,
- Servo promotion dashboards/tests before any default-engine change,
- docs that keep preview guarantees separate from target-lane claims.
