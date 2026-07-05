# Claude Notes

- Persistent platform risk: the engine control plane is Unix-domain-socket based (`tempo-engine-host`/`tempo-headless`) and is not Windows transport-compatible today.
- PR #540 auto-start CDP path should stay Unix-only unless/ until native named-pipe transport is implemented; ensure explicit error messaging and conditional compile gates stay aligned.
- The new `auto_started_cdp_engine_waits_for_socket_and_attaches` test should avoid hardcoded `/tmp` and rely on shared runtime temp-dir helpers.
