# Identity and OAuth Boundary

Tempo is a product surface and browser runtime. It must consume credentials from a
single ecosystem control plane and enforce the resulting permissions; it must not
become a separate identity, billing, or OAuth authority.

## Ownership

- The ecosystem control plane owns users, sessions, orgs, projects,
  environments, roles, billing state, OAuth clients, OAuth grants, API keys,
  token issuance, token revocation, token introspection/JWKS, connector status,
  product registry, entitlements, and audit logs.
- The public-site/account console owns the first-mile UX: login/signup, consent,
  connected apps, org/project/environment picking, API-key management, billing,
  and human-readable scope selection.
- Tempo owns browser behavior, local tempod/session behavior, agent/runtime
  policy, browser/MCP enforcement, usage events, and product-specific permission
  checks.
- Palette and other product backends are resource servers. They trust
  ecosystem-issued credentials and enforce scopes, audiences, org/project/env
  claims, billing entitlements, and revocation status.

Tempo's local tempod bearer token is a local control-plane protection for the
daemon and shell clients. It is not the hosted OAuth issuer and must not be
treated as an ecosystem access token.

## Credential Contract

Hosted Tempo auth should accept only ecosystem-issued credentials:

- Short-lived access tokens.
- Rotating refresh tokens, held outside model-visible state.
- Scoped grants such as `tempo:use`, `tempo:browser`, `mcp:invoke`,
  `trace:write`, or finer-grained product scopes as the shared permission model
  settles.
- Product/resource audiences, for example `tempo` or a concrete hosted resource
  server.
- Org, project, and environment claims from the central selection flow.
- Revocation and expiration semantics from the central issuer.

Tempo should support API keys as an advanced setup path only when those keys are
created, rotated, scoped, and revoked by the ecosystem control plane.

## Runtime Rules

- Do not ask an LLM, page script, MCP tool, or CLI subprocess to obtain OAuth
  credentials.
- Do not scrape OAuth codes, browser cookies, refresh tokens, API keys, or
  bearer tokens from page text.
- Do not serialize secrets into observations, compact model input, journals,
  benchmark artifacts, action traces, stdout/stderr logs, or tool arguments.
- Do not infer org/project/environment from hidden tenant headers for hosted
  users. Use claims and an explicit central selection helper.
- If a structured endpoint requires login, missing scope, or renewed consent,
  Tempo should surface a typed login/permission-required result and hand off to
  the central account console.
- Revoked, expired, wrong-org, missing-scope, and plan-limit failures should map
  to stable error codes that match the shared SDK and public-site connection UI.

## MCP and Structured Fast Path

The structured MCP lane may skip rendering when a site exposes an agent protocol.
That optimization must not bypass identity boundaries.

For hosted/product MCP calls:

- Unauthenticated MCP discovery may remain public when the resource server
  intentionally exposes it.
- Authenticated MCP tool calls must use an explicit scoped grant from the
  ecosystem issuer or API-key fallback from the same issuer.
- OAuth consent, PKCE, refresh, revocation, and connected-app status belong to
  the ecosystem/public-site flow, not to Tempo's model loop.
- Tempo should never replay ambient browser cookies into remote MCP calls unless
  a brokered product contract explicitly permits that audience and scope.

## Local Development and Tests

OAuth work should be tested against an isolated control-plane fixture or local
ecosystem stack, not production credentials. The needed coverage is:

- OAuth discovery metadata is consumed from the configured issuer.
- PKCE authorization succeeds through the account console or fixture.
- Access-token audiences and scopes are enforced.
- Refresh-token rotation works and old refresh tokens fail.
- Revoked tokens fail.
- Missing scopes fail with the shared error code.
- Wrong org/project/environment claims fail.
- Tempo browser login recovers expired sessions through the central flow.
- MCP discovery works without auth where intended, while MCP tool calls require
  the expected scope.
- Benchmark and journal artifacts remain secret-free.

The shared SDK should provide issuer URLs, JWKS/introspection clients, scope
constants, claim names, token refresh helpers, API-key helpers,
org/project/environment selection, and normalized auth errors so Tempo does not
reimplement the permission model.
