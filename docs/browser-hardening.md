# Browser Hardening and Threat Feeds

Tempo browser hardening is a protection layer, not an anti-bot or CAPTCHA
bypass layer. It blocks unsafe navigation, private-network targets,
DNS-rebinding sockets, configured threat domains, and executable-like downloads
before browser dispatch where possible.

## Non-goals

- Do not solve or bypass CAPTCHAs, bot checks, login walls, or site challenges.
- Do not spoof Safari, Brave, Chrome, or a human user agent.
- Do not hide agent traffic. Agent-declared traffic should remain transparent.
- Do not claim OS antivirus parity. Malware/phishing protection must be
  policy-backed, auditable, and feed-driven.

## Default Controls

- Private, loopback, link-local, multicast, metadata, malformed, and unsupported
  URL targets are blocked by the shared URL policy.
- DNS-resolved sockets are rechecked so DNS rebinding cannot bypass URL checks.
- Risky download paths such as executable installers are blocked by default.
- Threat-domain exact and suffix rules are checked before dispatch.
- CAPTCHA/auth/bot-check observations require human takeover.
- Structured `browser_hardening` errors and `browser_hardening_blocked` events
  report blocks without attempting evasion.

## Offline Threat Feed

Set `TEMPO_THREAT_DOMAIN_FILE` to a local line-oriented feed:

```text
# comments and blank lines are ignored
malware.example
*.phishing.example
.tracker.example
```

Rules:

- `example.com` is an exact domain rule.
- `*.example.com` and `.example.com` are suffix rules.
- URL-shaped entries are rejected.
- Duplicate rules are deduplicated.

## HTTPS Threat Feed Snapshot

Set `TEMPO_THREAT_DOMAIN_URL` to load a remote HTTPS feed at startup.

Protection on the feed fetch:

- HTTPS only.
- SSRF/private-target preflight.
- Redirects are not followed.
- Response size is capped.
- UTF-8 is required.
- Optional SHA-256 pinning via `TEMPO_THREAT_DOMAIN_SHA256`.

Optional cache controls:

- `TEMPO_THREAT_DOMAIN_CACHE_FILE`: owner-only feed cache path.
- `TEMPO_THREAT_DOMAIN_MAX_STALE_SECONDS`: maximum stale cache age.
- `TEMPO_THREAT_DOMAIN_FAILURE_MODE`: `fail-closed` by default, or explicit
  `fail-open`.

Fail-closed behavior installs a deny-all browser URL policy when configured
remote protection cannot be trusted or loaded.

## Signed Production Feed Refresh

For production-style threat intelligence, configure signed metadata and a feed:

- `TEMPO_THREAT_DOMAIN_METADATA_URL`: HTTPS metadata URL.
- `TEMPO_THREAT_DOMAIN_URL`: HTTPS feed URL.
- `TEMPO_THREAT_DOMAIN_PUBLIC_KEYS`: comma-separated `key_id=base64_public_key`
  trust roots.
- `TEMPO_THREAT_DOMAIN_REFRESH_INTERVAL_SECONDS`: refresh cadence, minimum 60
  seconds, default 6 hours.
- `TEMPO_THREAT_DOMAIN_METADATA_CACHE_FILE`: owner-only metadata cache path.
- `TEMPO_THREAT_DOMAIN_CACHE_FILE`: owner-only feed cache path.

Signed metadata includes:

- `version`
- `issued_at_ms`
- `expires_at_ms`
- `feed_sha256`
- `key_id`
- `signature`
- optional `next_key_id`
- optional `next_public_key`

The signature is Ed25519 over the canonical metadata payload excluding
`signature`. Tempo applies a refreshed policy only after signature, trust-root,
digest, freshness, feed parsing, and key-rotation checks all pass. Fetching runs
outside the request path; the pool lock is held only for the verified snapshot
swap.

## Audit and Privacy

Set `TEMPO_THREAT_DOMAIN_AUDIT_JSONL` to persist count-only feed audit records.

Audit records may include provider id, rule counts, source, env name, and cache
failure status. They must not include feed domains, feed URLs, page URLs, request
payloads, secrets, CAPTCHA state, or bot-check bypass data.

## Validation

Run these before treating hardening changes as complete:

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

