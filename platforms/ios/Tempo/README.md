# Tempo iOS Shell

This scaffold keeps WKWebView owned by Swift and uses Rust for Tempo contracts.

- Rust static library: `crates/tempo-ios-core`
- WebView adapter contract: `crates/tempo-engine-webview`
- Swift shell source: `Tempo/`
- App resource copy of the injected observer: `Tempo/Resources/tempo-webview-observe.js`

The current bridge is intentionally source-level only. C/Swift ABI exports need
a dedicated FFI slice because the workspace forbids unsafe code.

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
- `Tempo/TempoRustBridge.swift` is a placeholder bridge facade. C ABI exports
  are intentionally not generated in this slice because the Rust workspace
  forbids unsafe code and the bridge needs its own contract review.
