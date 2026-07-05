import Foundation
import SwiftUI

@MainActor
final class TempoBrowserModel: ObservableObject {
    @Published var tabs: [TempoTab]
    @Published var selectedTabID: UUID
    @Published var addressText: String
    @Published var manager = ManagerPanelState()
    @Published var lastError: String?
    @Published var webViewCommand: WebViewCommand?

    private let bridge: TempoRustBridge

    init(bridge: TempoRustBridge = TempoRustBridge()) {
        let firstTab = TempoTab()
        self.tabs = [firstTab]
        self.selectedTabID = firstTab.id
        self.addressText = firstTab.url?.absoluteString ?? ""
        self.bridge = bridge
        seedPreviewSessions()
    }

    var selectedTab: TempoTab? {
        tabs.first { $0.id == selectedTabID }
    }

    var selectedTabBinding: Binding<TempoTab> {
        Binding(
            get: { self.selectedTab ?? TempoTab(url: nil) },
            set: { updated in
                guard let index = self.tabs.firstIndex(where: { $0.id == updated.id }) else {
                    return
                }
                self.tabs[index] = updated
            }
        )
    }

    var observationScript: String {
        bridge.observationScript()
    }

    func updateSelectedTab(_ mutate: (inout TempoTab) -> Void) {
        guard let index = tabs.firstIndex(where: { $0.id == selectedTabID }) else {
            return
        }
        mutate(&tabs[index])
        addressText = tabs[index].url?.absoluteString ?? ""
    }

    func selectTab(_ id: UUID) {
        guard tabs.contains(where: { $0.id == id }) else {
            return
        }
        selectedTabID = id
        addressText = selectedTab?.url?.absoluteString ?? ""
    }

    func newTab() {
        let tab = TempoTab()
        tabs.append(tab)
        selectTab(tab.id)
    }

    func closeSelectedTab() {
        guard tabs.count > 1, let index = tabs.firstIndex(where: { $0.id == selectedTabID }) else {
            return
        }
        tabs.remove(at: index)
        selectedTabID = tabs[min(index, tabs.count - 1)].id
        addressText = selectedTab?.url?.absoluteString ?? ""
    }

    func navigateToAddress() {
        guard let url = normalizedURL(from: addressText) else {
            lastError = "Invalid URL"
            return
        }
        updateSelectedTab { tab in
            tab.url = url
            tab.title = url.host() ?? url.absoluteString
            tab.isLoading = true
        }
    }

    func goBack() {
        webViewCommand = .back
    }

    func goForward() {
        webViewCommand = .forward
    }

    func reload() {
        webViewCommand = .reload
    }

    func stopLoading() {
        webViewCommand = .stop
    }

    func pageDidFinish(url: URL?, title: String?, canGoBack: Bool, canGoForward: Bool) {
        updateSelectedTab { tab in
            tab.url = url ?? tab.url
            tab.title = title?.isEmpty == false ? title! : tab.url?.host() ?? "Tempo"
            tab.canGoBack = canGoBack
            tab.canGoForward = canGoForward
            tab.isLoading = false
        }
    }

    func pageDidStart() {
        updateSelectedTab { $0.isLoading = true }
    }

    func apply(_ event: ManagerEvent) {
        manager.apply(event)
        syncTabsFromManager()
    }

    func adoptSelectedSession() {
        guard let session = manager.selectedSession else {
            return
        }
        adopt(session)
    }

    func selectSession(_ sessionID: String) {
        manager.selectedSessionID = sessionID
    }

    func adopt(_ session: TempoSessionSummary) {
        if let existing = tabs.first(where: { $0.sessionID == session.id }) {
            selectTab(existing.id)
            updateSelectedTab { tab in
                tab.owner = .human
                tab.runState = session.runState
            }
        } else {
            var tab = TempoTab(url: session.url)
            tab.sessionID = session.id
            tab.title = session.title
            tab.owner = .human
            tab.runState = session.runState
            tab.marksVisible = session.marksVisible
            tab.tainted = session.tainted
            tabs.append(tab)
            selectTab(tab.id)
        }
        apply(.ownerChanged(sessionID: session.id, owner: .human))
    }

    func handoffSelectedSession() {
        guard let sessionID = selectedTab?.sessionID ?? manager.selectedSessionID else {
            return
        }
        apply(.ownerChanged(sessionID: sessionID, owner: .agent))
        apply(.runStateChanged(sessionID: sessionID, state: .running))
    }

    func toggleMarksForSelectedTab() {
        updateSelectedTab { tab in
            tab.marksVisible.toggle()
            if let sessionID = tab.sessionID {
                manager.updateMarks(sessionID: sessionID, visible: tab.marksVisible)
            }
        }
    }

    func resolvePendingConfirmation(approved: Bool) {
        guard let confirmation = manager.pendingConfirmation else {
            return
        }
        if approved {
            apply(.journal(AgentJournalEntry(
                id: UUID().uuidString,
                sequence: UInt64(manager.journal.count + 1),
                sessionID: confirmation.sessionID,
                message: "confirmed \(confirmation.kind.rawValue)",
                timestamp: Date()
            )))
        }
        apply(.confirmationResolved(
            sessionID: confirmation.sessionID,
            confirmationID: confirmation.id
        ))
    }

    private func normalizedURL(from text: String) -> URL? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        if let url = URL(string: trimmed), url.scheme != nil {
            return url
        }
        return URL(string: "https://\(trimmed)")
    }

    private func syncTabsFromManager() {
        for session in manager.sessions {
            guard let index = tabs.firstIndex(where: { $0.sessionID == session.id }) else {
                continue
            }
            tabs[index].owner = session.owner
            tabs[index].runState = session.runState
            tabs[index].tainted = session.tainted
            tabs[index].marksVisible = session.marksVisible
        }
    }

    private func seedPreviewSessions() {
        let session = TempoSessionSummary(
            id: "local-preview",
            title: "Agent Session",
            url: URL(string: "https://example.com"),
            owner: .agent,
            runState: .waitingForHuman,
            tainted: true,
            marksVisible: true,
            pendingConfirmation: PendingConfirmation(
                id: "confirm-preview",
                sessionID: "local-preview",
                kind: .send,
                title: "Send",
                detail: "local preview"
            )
        )
        manager.apply(.sessionSnapshot([session]))
        if let confirmation = session.pendingConfirmation {
            manager.apply(.confirmationRequested(confirmation))
        }
        manager.apply(.journal(AgentJournalEntry(
            id: "journal-preview",
            sequence: 1,
            sessionID: session.id,
            message: "waiting for human",
            timestamp: Date()
        )))
    }
}

private extension ManagerPanelState {
    mutating func updateMarks(sessionID: String, visible: Bool) {
        guard let index = sessions.firstIndex(where: { $0.id == sessionID }) else {
            return
        }
        sessions[index].marksVisible = visible
    }
}
