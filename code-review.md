# Code Review Notes

- PR #540: portable compile concern fixed by gating the Unix-socket integration test with `#[cfg(unix)]` and adding a non-Unix placeholder test so target-specific checks remain explicit.
- Prefer avoiding hardcoded `/tmp` paths in runtime logic that may run from alternate temp locations; use shared helpers (e.g., `auto_cdp_runtime_base_dir`).
- Cross-platform acceptance remains explicitly out-of-scope for UDS engine transport; docs and CLI errors should continue to state this clearly.
