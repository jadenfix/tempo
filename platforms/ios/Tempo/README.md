# Tempo iOS Shell

This scaffold keeps WKWebView owned by Swift and uses Rust for Tempo contracts.

- Rust static library: `crates/tempo-ios-core`
- WebView adapter contract: `crates/tempo-engine-webview`
- Swift shell source: `Tempo/`
- App resource copy of the injected observer: `Tempo/Resources/tempo-webview-observe.js`

The Swift bridge can load capabilities, the injected observation runtime, and
WebView snapshot compilation from `tempo-ios-core` when built with
`TEMPO_RUST_LINKED`. SwiftPM tests use the same payload shape with a source-level
fallback so the shell can be checked without a linked staticlib.

Validation from the repo root:

```sh
cargo check -p tempo-ios-core --lib
cargo test -p tempo-ios-core
scripts/check-ios-core-graph.sh
```

Native shell status:

- `project.yml` is an XcodeGen manifest for a signed iOS app target.
- `Package.swift` exposes the app source as a Swift package target for reducer
  tests and source browsing.
- `Tempo/TempoRustBridge.swift` owns the Swift/Rust bridge facade. The C ABI
  currently exports capabilities, the observation script, and WebView snapshot
  compilation; session/control-plane APIs remain a follow-up bridge surface.
