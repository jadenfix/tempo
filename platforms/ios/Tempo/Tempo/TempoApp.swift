import SwiftUI

@main
struct TempoApp: App {
    @StateObject private var model = TempoBrowserModel()

    var body: some Scene {
        WindowGroup {
            BrowserShellView(model: model)
        }
    }
}
