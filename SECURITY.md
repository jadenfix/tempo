# Security Policy

tempo drives real browsers with real credentials on behalf of agents; we treat
security reports as the highest-priority inbound work.

## Reporting a vulnerability

Please use **GitHub private vulnerability reporting** (Security → Report a
vulnerability on this repository). If that is unavailable, email
`jaden@roe-ai.com` with `[tempo security]` in the subject. Do not open public
issues for exploitable bugs.

You should receive an acknowledgement within 72 hours. Coordinated disclosure
is appreciated; we will credit reporters in the fix PR unless you ask
otherwise.

## Scope — what counts as a vulnerability here

In rough priority order:

1. **Prompt-injection / taint bypasses** — any way page-derived content can be
   emitted with `system`/`user` provenance, or a tainted parameter can reach a
   Send/Purchase/Delete side effect without confirmation escalation.
2. **Sandbox escapes** — tainted-content transforms reaching the network or
   secrets despite `net: Deny` / `secrets: []` beatbox policies.
3. **SSRF** — driving the engine or `tempo-net` to loopback, link-local, or
   private ranges past `UrlPolicy`.
4. **Origin-guard / DNS-rebinding bypasses** — reaching tempod
   session/control routes (including the metrics exposition, where present)
   from a hostile web origin.
5. **Secret leakage** — credentials or session material appearing in journals,
   cassettes, OTLP export, logs, or metrics.
6. **Cross-session isolation failures** — cookie/storage/profile leakage
   between sessions.

Crash-only bugs without a security consequence are ordinary issues — please
file them normally.

## Standing security invariants

These are review targets and CI gates where the corresponding implementation is
wired (see `final.md` §8.3): the injection red-team corpus must produce zero
unconfirmed Send/Purchase/Delete; the SSRF suite and policy-gate property tests
run on any PR touching observe/act/net/policy/taint/toolexec; `unsafe_code` is
forbidden workspace-wide. Shipped preview guarantees are the scoped guarantees
listed in `README.md` and `final.md`; roadmap gates do not imply shipped
protections until their evidence is green. In particular, ADR 0001 keeps
mandatory tainted-compute dispatch through beatbox deferred until a
production-path agent/headless integration test proves it, even though the
`tempo-toolexec` bridge and live beatbox canary are already tested.
