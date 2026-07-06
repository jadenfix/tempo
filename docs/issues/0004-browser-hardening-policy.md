# Browser Hardening Policy

## Problem

Tempo needs browser-grade security controls for agent and human browsing without
claiming to bypass CAPTCHAs, bot checks, or other site protections. The right
first-principles target is the same class of protection users expect from
modern browsers: unsafe URL blocking, isolated state, transparent identity,
challenge handoff, sandboxed engines, and auditable decisions.

## Non-goals

- Do not implement CAPTCHA solving or anti-bot bypass.
- Do not spoof Safari, Brave, Chrome, or a human user agent.
- Do not hide automation identity when traffic is agent-driven.
- Do not embed a fake antivirus claim; malware protection must be policy-backed
  and auditable.

## First-principles model

Security is enforced at separate layers because no single signal is enough:

- Navigation safety: block private-network, loopback, link-local, metadata, and
  malformed URL targets before the engine navigates.
- DNS safety: pin and re-check resolved sockets so rebinding cannot bypass the
  URL policy.
- Threat intelligence: reject configured exact/suffix threat domains before
  dispatch.
- Download safety: block executable-like downloads by default until a human or
  trusted policy explicitly allows them.
- Identity safety: keep user-driven and agent-declared traffic explicit, with
  Web Bot Auth available for declared agent traffic.
- Challenge safety: detect CAPTCHA/auth/bot-check states and require human
  takeover instead of attempting automated bypass.
- Runtime safety: keep browser profiles partitioned, control-plane auth
  enabled for remote binds, sandboxing enabled by default, and telemetry
  redacted.

## Implementation Plan

1. Land `tempo-net::BrowserHardeningPolicy` as the shared contract.
2. Thread the policy through `SessionPool`, `TempodServerConfig`, and attached
   engine-driver creation.
3. Apply the policy before `create_session_shared` initial navigation and BiDi
   `browsingContext.navigate`.
4. Expose blocked hardening decisions through typed session events and OpenAPI.
5. Teach CDP and Servo adapters to consume the same policy for subresource
   dispatch, download handling, and engine-specific sandbox settings.
6. Add a threat-domain provider trait with offline test fixtures and an optional
   production updater.
7. Add conformance tests covering SSRF, rebinding, threat-domain blocks,
   executable download blocks, strict HTTPS mode, profile isolation, challenge
   detection, and human takeover events.

## Current Status

- Landed: `tempo-net::BrowserHardeningPolicy` with standard/strict modes,
  threat-domain blocks, risky-download blocks, strict HTTPS top-level
  navigation, transparent identity, and human-takeover challenge handling.
- Landed: `tempod` session creation, BiDi/driver navigation, and REST
  `Action::Goto` batch policy now consume the shared hardening policy.
- Landed: structured `browser_hardening` 403 responses for blocked navigation.
- Landed: typed `browser_hardening_blocked` session events for in-session
  blocked actions.
- Landed: OpenAPI schemas for `BrowserHardeningError` and
  `TempodBrowserHardeningBlock`.
- Landed: CDP request interception and the CDP policy proxy consume
  `BrowserHardeningPolicy`, so risky-download and threat-domain checks can run
  inside the engine lane in addition to top-level tempod checks.
- Landed: `tempo-net` threat-domain provider primitives with a static provider
  and sanitized provider audit summaries.
- Landed: line-oriented offline threat-domain feeds can be loaded by tempod via
  `TEMPO_THREAT_DOMAIN_FILE`; loaded feeds emit sanitized count-only audit
  telemetry.
- Landed: count-only threat-feed audit history can be persisted to JSONL via
  `TEMPO_THREAT_DOMAIN_AUDIT_JSONL`; records exclude feed domains and page data.
- Landed: Servo network adapter dispatch consumes `BrowserHardeningPolicy` for
  subresource requests, redirects, DNS-rebound socket checks, risky-download
  blocks, and threat-domain blocks.
- Landed: `TEMPO_THREAT_DOMAIN_URL` can load an HTTPS-only threat-domain
  snapshot at tempod startup with SSRF preflight, no redirects, response-size
  limits, UTF-8 validation, and sanitized count-only audit records.
- Landed: remote threat-domain snapshots can be pinned with
  `TEMPO_THREAT_DOMAIN_SHA256`, cached through
  `TEMPO_THREAT_DOMAIN_CACHE_FILE`, and bounded by
  `TEMPO_THREAT_DOMAIN_MAX_STALE_SECONDS` for stale-cache fallback; cache
  fallback rejects symlinks and non-owner-only files.
- Landed: `TEMPO_THREAT_DOMAIN_FAILURE_MODE` makes remote threat-feed failure
  behavior explicit; the default fail-closed mode installs a deny-all browser
  URL policy when configured protection cannot be trusted, while `fail-open`
  must be explicitly selected.
- Landed: remote threat-feed cache-write failures emit sanitized warning
  telemetry and count-only audit metadata via `cache_write_failed`; records
  still exclude feed domains, feed URLs, and page data.
- Landed: signed threat-feed metadata verification primitives support Ed25519
  signatures, operator-pinned public keys, SHA-256 feed digest binding,
  freshness checks, and current-key-signed next-key material validation.
- Landed: verified signed threat-feed cache primitives persist metadata and
  feed bytes separately with owner-only permissions and re-verify signature,
  digest, and freshness before cached state can be reused.
- Landed: verified threat-feed key-rotation state can be applied only after
  current-key-signed metadata carries a complete valid next-key pair; duplicate
  key ids are rejected.
- Landed: verified signed threat-feed policy snapshots are built completely
  before assignment, so policy/trust-root state is swapped only after signature,
  digest, freshness, feed parsing, and key-rotation checks all succeed.
- Landed: one-shot signed threat-feed refresh can fetch HTTPS-only signed
  metadata/feed pairs, invoke the verified snapshot swap, and optionally persist
  verified metadata/feed caches while reporting cache-write failure separately.
- Landed: opt-in periodic signed threat-feed scheduler starts from tempod env,
  validates operator-pinned trust roots, fetches metadata/feed outside the pool
  lock, then locks only for the verified policy snapshot swap.
- Landed: conformance fixtures cover shared browser-hardening controls
  (private-network/SSRF, DNS-rebinding sockets, threat domains, risky
  downloads, and allow cases) plus signed production threat-intelligence exact
  and suffix rules.
- Landed: operator documentation in `docs/browser-hardening.md` covers safe
  non-goals, local and remote threat feeds, signed refresh configuration,
  auditing, and validation commands.
- Landed: repo-local `.claude/skills/browser-hardening` guidance captures the
  recurring safe hardening workflow, first-principles model, review checklist,
  and validation commands for future agents.
- Validated: focused formatting and browser-hardening Cargo checks pass after
  fixing compile failures in the signed-feed test helpers and decided-agent
  action-retention path.

## Signed Threat Feed Updater Design

Tempo should not claim "antivirus" parity unless feed provenance and freshness
are enforceable. The production updater should use a signed metadata envelope
around the existing line-oriented feed:

- Metadata shape: `version`, `issued_at`, `expires_at`, `feed_sha256`,
  `key_id`, and `signature`.
- Signature algorithm: Ed25519 over a canonical JSON payload excluding the
  `signature` field.
- Trust roots: one or more pinned public keys configured by operator-managed
  files or build-time distribution.
- Rotation: metadata may name a `next_key_id` and `next_public_key`; rotation
  only becomes active after the current key signs it.
- Freshness: expired metadata follows `TEMPO_THREAT_DOMAIN_FAILURE_MODE`.
- Cache: signed metadata and feed bytes are cached separately with owner-only
  permissions; cache fallback must verify signature, digest, and freshness.
- Audit: export only `provider_id`, `version`, `key_id`, rule counts,
  cache/freshness status, and failure categories; never export feed domains,
  page URLs, or request payloads.
- Refresh cadence: periodic refresh runs out-of-band from request dispatch and
  atomically swaps a verified `BrowserHardeningPolicy` snapshot.

## Acceptance Criteria

- A strict hardening policy blocks cleartext top-level navigation.
- Private-network, loopback, metadata, and DNS-rebound targets remain blocked.
- Threat-listed domains are blocked before network dispatch.
- Executable-like downloads are blocked by default.
- Challenge detection records a human-takeover event and does not auto-solve.
- Agent-declared traffic remains transparent and can be signed with Web Bot
  Auth.
- Engine sandbox opt-outs remain explicit and auditable.

## Validation Checklist

Run these before closing the issue:

- Formatting: `cargo fmt --all --check`
- Shared policy conformance: `cargo test -p tempo-net browser_hardening`
- Threat feed parsing/audit: `cargo test -p tempo-net threat_domain`
- Tempod hardening and signed-feed path:
  `cargo test -p tempo-headless browser_hardening`
- Tempod production threat-intelligence fixtures:
  `cargo test -p tempo-headless signed_threat_domain`
- CDP engine hardening:
  `cargo test -p tempo-engine-cdp cdp_browser_hardening`
- CDP policy proxy hardening:
  `cargo test -p tempo-engine-cdp policy_proxy_blocks_browser_hardening`
- Servo engine hardening:
  `cargo test -p tempo-engine-servo servo_network_adapter_blocks`

Evidence required for completion:

- All listed commands pass.
- Any compile failures from new signed-feed dependencies are fixed.
- Audit output remains count-only and does not include feed domains, feed URLs,
  page URLs, request payloads, secrets, or CAPTCHA/bot-check bypass data.
- The implementation continues to require human takeover for challenges rather
  than attempting automated solving or evasion.
