import Foundation

#if TEMPO_RUST_LINKED
@_silgen_name("tempo_ios_core_capabilities_json")
private func tempo_ios_core_capabilities_json() -> UnsafeMutablePointer<CChar>?

@_silgen_name("tempo_ios_core_observation_script")
private func tempo_ios_core_observation_script() -> UnsafeMutablePointer<CChar>?

@_silgen_name("tempo_ios_core_string_free")
private func tempo_ios_core_string_free(_ value: UnsafeMutablePointer<CChar>?)
#endif

struct TempoCoreCapabilities: Codable, Equatable {
    let schemaVersion: String
    let engineLane: String
    let staticLibrary: Bool
    let nativeFork: Bool
}

struct TempoRustBridge {
    func capabilities() -> TempoCoreCapabilities {
        #if TEMPO_RUST_LINKED
        if let json = rustString(tempo_ios_core_capabilities_json()),
           let data = json.data(using: .utf8),
           let capabilities = try? JSONDecoder.tempoSnakeCase.decode(TempoCoreCapabilities.self, from: data) {
            return capabilities
        }
        #endif
        TempoCoreCapabilities(
            schemaVersion: "2.0.0",
            engineLane: "wkwebview_t2",
            staticLibrary: true,
            nativeFork: false
        )
    }

    func observationScript() -> String {
        #if TEMPO_RUST_LINKED
        if let source = rustString(tempo_ios_core_observation_script()) {
            return source
        }
        #endif
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

    #if TEMPO_RUST_LINKED
    private func rustString(_ pointer: UnsafeMutablePointer<CChar>?) -> String? {
        guard let pointer else {
            return nil
        }
        defer { tempo_ios_core_string_free(pointer) }
        return String(cString: pointer)
    }
    #endif
}

private extension JSONDecoder {
    static var tempoSnakeCase: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }
}
