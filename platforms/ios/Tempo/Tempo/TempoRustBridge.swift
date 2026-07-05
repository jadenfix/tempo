import Foundation

struct TempoCoreCapabilities: Equatable {
    let schemaVersion: String
    let engineLane: String
    let staticLibrary: Bool
    let nativeFork: Bool
}

struct TempoRustBridge {
    func capabilities() -> TempoCoreCapabilities {
        TempoCoreCapabilities(
            schemaVersion: "2.0.0",
            engineLane: "wkwebview_t2",
            staticLibrary: true,
            nativeFork: false
        )
    }

    func observationScript() -> String {
        if let url = Bundle.main.url(forResource: "tempo-webview-observe", withExtension: "js"),
           let source = try? String(contentsOf: url) {
            return source
        }
        #if SWIFT_PACKAGE
        if let url = Bundle.module.url(forResource: "tempo-webview-observe", withExtension: "js"),
           let source = try? String(contentsOf: url) {
            return source
        }
        #endif
        return "window.__tempoCollectObservation = window.__tempoCollectObservation || function(){ return { url: window.location.href, elements: [] }; };"
    }
}
