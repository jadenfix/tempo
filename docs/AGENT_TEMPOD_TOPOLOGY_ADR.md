# ADR: Agent And Tempod Topology

## Status

Accepted architecture for local decided-run orchestration.

`tempod` is the session authority and owns decided runs in-process. External
agents may ask `tempod` to start, inspect, cancel, or resume runs through the
control plane, but they do not push raw run events into tempod through a second
HTTP producer.

## Context

The agent loop and the daemon have two different durable identities:
`tempo-session::SessionId` names journal records, while `TempodSessionId` names a
daemon-managed browser session, ownership state, event log, and attached driver.
Treating an external decided runner as an HTTP event producer would create two
writers for the same browser story: the runner's local journal and tempod's
session event stream.

`tempod` already carries the critical runtime state that a decided run must
respect:

- session ownership and foreground handoff,
- active-run exclusion for human, MCP, BiDi, and act-batch writers,
- per-driver operation gates around engine IPC,
- connection and body caps on the public control plane,
- bearer auth plus Host/Origin boundary checks before handlers run,
- the per-session event stream consumed by shell and manager clients.

The cheaper production shape is therefore not a new unauthenticated event
producer route. It is an in-process run manager under tempod's existing session
authority.

## Decision

`tempod` starts decided runs in-process through `POST /sessions/{id}/runs`.

The route:

- authenticates and bounds the request through the existing tempod router,
- runs behind the blocking-route worker limiter, so long-lived agent work is
  shed rather than queued when that local capacity is exhausted,
- resolves the `TempodSessionId` to the attached session driver,
- marks the session as agent-owned with an `AgentRunId`,
- drops the pool lock before running driver IPC,
- runs `AgentRunner::run_decided_task` against that attached driver,
- maps the agent result back to tempod run state,
- records human-takeover pauses on the session event stream.

The agent journal uses the tempod run id and tempod session id as its durable
run/session names. That keeps one tempod run as the authority linking manager
state, shell-visible ownership, and the agent journal path.

The out-of-process HTTP producer topology is deferred. If it is added later, it
must feed the same internal producer function as the in-process route after
auth, session existence, active-run ownership, replay ordering, and body caps are
checked. It must not publish directly into the event log or accept caller-owned
session ids as authority.

This amends #373's earlier "wire the decided run over HTTP" framing: the
shipping bridge is tempod-owned in-process orchestration plus tempod-owned event
publication. HTTP remains the external control surface for starting and
observing runs, not the internal producer mechanism for journal events.

## Consequences

- `/sessions/{id}/runs` is the preview entry point for tempod-owned decided
  runs.
- The event bridge work should attach journal-derived model decisions and step
  triples to this in-process run path, not invent a separate source of truth.
- The current in-process run report does not yet return every `StepTriple` or
  `ModelDecision`, so the next producer slice needs either a runner callback or
  a journal-replay step that emits into tempod's typed event log in journal
  order.
- Shell and manager clients keep using `/sessions/{id}/events` and `/runs/*`;
  they do not need to know whether the run's decider is scripted or model-backed.
- Human handoff remains explicit: a waiting run can be resumed only after the
  human surface hands ownership back to the agent.

## Acceptance Evidence

The minimal topology spike is a router-level test for
`POST /sessions/{id}/runs` that drives an attached engine driver through a real
scripted decided run. It proves the route reaches the attached driver and
returns through tempod run state without routing through a fixture-only pool
helper.

Follow-up event producer work must prove:

- model decisions and step triples from the real decided run become typed
  `TempodSessionEvent` records,
- unknown, killed, or non-owned sessions are rejected before event publication,
- the observed event order matches the agent journal order,
- public docs and OpenAPI stay synchronized with any new event fields or routes.
