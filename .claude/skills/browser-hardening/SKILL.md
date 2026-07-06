---
name: browser-hardening
description: Safe browser security hardening workflow for jadenfix/tempo. Use when planning, implementing, reviewing, or documenting browser-grade protections such as URL/egress policy, DNS-rebinding defenses, threat feeds, risky-download blocking, sandbox/profile isolation, challenge human handoff, signed feed updates, or Safari/Brave-like security claims. Also use when a request mentions stealth, CAPTCHA bypass, anti-bot bypass, antivirus parity, Web Bot Auth, browser identity, or browser security posture so the work stays inside legitimate protection boundaries.
---

# Tempo browser hardening

## Safety boundary

Keep the implementation aligned with browser-grade user protection. Do not build CAPTCHA solving, bot-check bypass, stealth anti-detection, human impersonation, residential-proxy routing, browser fingerprint spoofing, or hidden automation identity.

Translate unsafe or ambiguous requests into safe controls:

- "Stealth" means minimizing exploit surface, redacting telemetry, and keeping policy decisions auditable; it does not mean evading site detection.
- "Safari/Brave-like security" means sandboxing, private-network blocking, threat intelligence, download risk gates, strict transport options, partitioned state, and transparent identity.
- "Antivirus grade" means signed, fresh, auditable threat-intelligence enforcement; do not claim OS antivirus parity unless the evidence supports that exact claim.
- CAPTCHA, auth wall, bot-check, or rate-limit states must require human takeover or a declared integration path, never automated solving or bypass.

## First-principles model

Enforce security at multiple layers because any single check can be bypassed:

- URL policy: reject malformed, unsupported, loopback, private, link-local, multicast, metadata, and other disallowed targets before navigation.
- Concrete endpoint policy: re-check DNS-resolved sockets, proxy targets, redirects, retries, and engine interception paths.
- Threat intelligence: parse exact/suffix rules from trusted feeds; apply them before dispatch; keep audit records count-only.
- Download safety: block executable-like or installer-like downloads by default unless a trusted human/policy explicitly allows them.
- Identity safety: keep user-driven and agent-declared traffic explicit; never mutate UA/profile/fingerprint after a block to sneak past a site.
- Challenge safety: record challenge observations and route to human takeover.
- Runtime safety: preserve sandbox defaults, profile isolation, loopback/capability auth, resource caps, and redaction.
- Supply-chain safety: for production feeds, require HTTPS, SSRF preflight, size limits, digest binding, Ed25519 signatures, freshness, owner-only cache files, fail-closed defaults, and current-key-signed rotation.

## Implementation workflow

1. Start from the contract in `tempo-net` if the rule is shared across engines or control-plane paths.
2. Thread the contract through `tempo-headless` session creation, navigation, REST actions, event emission, OpenAPI schemas, and operator docs when runtime-visible behavior changes.
3. Apply the same policy in CDP and Servo engine lanes for subresources, redirects, downloads, and concrete resolved sockets.
4. Make blocks structured and auditable: stable error code, target/action context, and sanitized telemetry with no feed domains, page URLs, secrets, payloads, CAPTCHA data, or bypass hints.
5. Prefer fail-closed behavior for configured security dependencies unless an explicitly named operator option selects fail-open.
6. Keep locks narrow and never hold pool locks across network fetches, browser navigation, subprocess I/O, or long-running validation.
7. Add tests that prove the actual boundary: SSRF/private targets, DNS rebinding, threat-domain exact/suffix rules, risky downloads, strict HTTPS mode, feed verification failure, challenge handoff, and audit redaction.
8. Update `docs/browser-hardening.md` and `docs/issues/0004-browser-hardening-policy.md` when behavior, env vars, acceptance criteria, or validation commands change.

## Review checklist

- Does every network path enforce policy on the endpoint actually used, not only the input URL string?
- Can redirects, retries, proxy resolution, engine interception, or DNS rebinding reach a blocked address?
- Are threat-feed failures, stale caches, bad signatures, invalid key rotations, and cache-write failures explicit and auditable?
- Are cache files owner-only and symlink-resistant before they are trusted?
- Are public schemas, SDK-facing docs, and OpenAPI updated for every runtime-visible contract change?
- Are telemetry and audit records count-only and free of domains, URLs, page data, secrets, request payloads, and challenge details?
- Would the tests fail if the hardening rule were removed?
- Does the change avoid any claim or behavior that implies CAPTCHA bypass, anti-bot evasion, spoofing, or OS antivirus parity?

## Validation commands

Run focused validation before claiming completion:

```sh
cargo fmt --all --check
cargo test -p tempo-net browser_hardening
cargo test -p tempo-net threat_domain
cargo test -p tempo-headless browser_hardening
cargo test -p tempo-headless signed_threat_domain
cargo test -p tempo-engine-cdp cdp_browser_hardening
cargo test -p tempo-engine-cdp policy_proxy_blocks_browser_hardening
cargo test -p tempo-engine-servo servo_network_adapter_blocks
```
