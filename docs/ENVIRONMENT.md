# Tempo Environment Variables

This is the operator-facing registry for `TEMPO_*` variables. `tempo-config`
owns the layered startup configuration for `tempod`; lower-level crates still
own a few runtime-specific variables until those knobs move into the shared
config file.

| Variable | Owner | Purpose |
| --- | --- | --- |
| `TEMPO_CONFIG` | `tempo-config` | JSON config file path. |
| `TEMPO_BIND_ADDR` | `tempo-config` | `tempod` listen address. |
| `TEMPO_ENGINE` | `tempo-config` | Engine kind: `cdp` or `servo`. |
| `TEMPO_ENGINE_SOCKET` | `tempo-config` | UDS path to a pre-started engine host. |
| `TEMPO_LOG` | `tempo-config` / `tempo-telemetry` | Minimum structured-log level: `trace`, `debug`, `info`, `warn`, or `error`. |
| `TEMPO_METRICS` | `tempo-config` | Enable or disable Prometheus exposition. |
| `TEMPO_TEMPOD_AUTH_TOKEN` | `tempo-headless` | Bearer token accepted by `tempod` and used by shell clients. |
| `TEMPO_TEMPOD_AUTH_TOKEN_FILE` | `tempo-headless` | Owner-only runtime token file path. |
| `TEMPO_STEALTH_MODE` | `tempo-headless` / `tempo-session` | Privacy mode that suppresses Tempo-owned durable state and telemetry paths. |
| `TEMPO_OTLP_ENDPOINT` | `tempo-headless` | OTLP/HTTP trace export endpoint. |
| `TEMPO_OTLP_JSONL` | `tempo-headless` | JSONL trace export fallback path. |
| `TEMPO_ENGINE_HOST_SOCKET` | `tempo-engine-host` | Engine daemon UDS path used by the host wire protocol. |
| `TEMPO_ENGINE_HOST_TOKEN` | `tempo-engine-host` | Engine IPC auth token. |
| `TEMPO_CDP_CHROME` | `tempo-engine-cdp` | Chrome or Chromium binary path for the CDP lane. |
| `TEMPO_CDP_NO_SANDBOX` | `tempo-engine-cdp` | Explicit Chromium `--no-sandbox` opt-in for constrained CI/container fixtures. |
| `TEMPO_DURABLE_RETENTION` | `tempo-session` | Journal/cassette retention policy. |
| `TEMPO_DURABLE_ENCRYPTION_KEY_HEX` | `tempo-session` | AEAD key for encrypted journal/cassette retention. |
| `TEMPO_LIVE_MODEL` | `tempo-agent` | Opt-in live LLM tests when set to `1`. |

Servo-source selection is documented separately in the README because it is a
supply-chain compatibility lane rather than a runtime operator setting:
`TEMPO_SERVO_PATH`, `TEMPO_SERVO_REPO`, `TEMPO_SERVO_REF`, and
`TEMPO_SERVO_ALLOW_UNAUDITED`.
