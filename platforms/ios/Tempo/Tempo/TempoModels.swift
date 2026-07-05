import Foundation

enum ControlOwner: String, Codable, Equatable, CaseIterable {
    case none
    case agent
    case human
}

enum AgentRunState: String, Codable, Equatable {
    case idle
    case running
    case paused
    case waitingForHuman
    case completed
    case failed
}

enum ConfirmationKind: String, Codable, Equatable {
    case send
    case purchase
    case delete
    case write
}

enum WebViewCommand: Equatable {
    case back
    case forward
    case reload
    case stop
}

struct PendingConfirmation: Identifiable, Codable, Equatable {
    let id: String
    let sessionID: String
    let kind: ConfirmationKind
    let title: String
    let detail: String
}

struct AgentJournalEntry: Identifiable, Codable, Equatable {
    let id: String
    let sequence: UInt64
    let sessionID: String
    let message: String
    let timestamp: Date
}

struct TempoSessionSummary: Identifiable, Codable, Equatable {
    let id: String
    var title: String
    var url: URL?
    var owner: ControlOwner
    var runState: AgentRunState
    var tainted: Bool
    var marksVisible: Bool
    var pendingConfirmation: PendingConfirmation?
}

struct TempoTab: Identifiable, Equatable {
    let id: UUID
    var sessionID: String?
    var title: String
    var url: URL?
    var owner: ControlOwner
    var runState: AgentRunState
    var isLoading: Bool
    var canGoBack: Bool
    var canGoForward: Bool
    var marksVisible: Bool
    var tainted: Bool
    var lastObservationElementCount: Int

    init(url: URL? = URL(string: "https://example.com")) {
        self.id = UUID()
        self.sessionID = nil
        self.title = "Tempo"
        self.url = url
        self.owner = .human
        self.runState = .idle
        self.isLoading = false
        self.canGoBack = false
        self.canGoForward = false
        self.marksVisible = false
        self.tainted = false
        self.lastObservationElementCount = 0
    }
}

enum ManagerEvent: Equatable {
    case sessionSnapshot([TempoSessionSummary])
    case journal(AgentJournalEntry)
    case humanTakeover(sessionID: String)
    case ownerChanged(sessionID: String, owner: ControlOwner)
    case runStateChanged(sessionID: String, state: AgentRunState)
    case confirmationRequested(PendingConfirmation)
    case confirmationResolved(sessionID: String, confirmationID: String)
    case taintChanged(sessionID: String, tainted: Bool)
}

struct ManagerPanelState: Equatable {
    var sessions: [TempoSessionSummary] = []
    var selectedSessionID: String?
    var journal: [AgentJournalEntry] = []
    var pendingConfirmation: PendingConfirmation?
    var takeoverSessionID: String?

    var selectedSession: TempoSessionSummary? {
        sessions.first { $0.id == selectedSessionID }
    }

    mutating func apply(_ event: ManagerEvent) {
        switch event {
        case .sessionSnapshot(let sessions):
            self.sessions = sessions
            if selectedSessionID == nil || !sessions.contains(where: { $0.id == selectedSessionID }) {
                selectedSessionID = sessions.first?.id
            }
        case .journal(let entry):
            journal.append(entry)
            journal.sort { $0.sequence < $1.sequence }
            if journal.count > 200 {
                journal.removeFirst(journal.count - 200)
            }
        case .humanTakeover(let sessionID):
            takeoverSessionID = sessionID
            selectedSessionID = sessionID
            updateSession(sessionID) { session in
                session.runState = .waitingForHuman
                session.owner = .agent
            }
        case .ownerChanged(let sessionID, let owner):
            updateSession(sessionID) { $0.owner = owner }
        case .runStateChanged(let sessionID, let state):
            updateSession(sessionID) { $0.runState = state }
        case .confirmationRequested(let confirmation):
            pendingConfirmation = confirmation
            selectedSessionID = confirmation.sessionID
            updateSession(confirmation.sessionID) { $0.pendingConfirmation = confirmation }
        case .confirmationResolved(let sessionID, let confirmationID):
            if pendingConfirmation?.id == confirmationID {
                pendingConfirmation = nil
            }
            updateSession(sessionID) { $0.pendingConfirmation = nil }
        case .taintChanged(let sessionID, let tainted):
            updateSession(sessionID) { $0.tainted = tainted }
        }
    }

    private mutating func updateSession(_ sessionID: String, mutate: (inout TempoSessionSummary) -> Void) {
        guard let index = sessions.firstIndex(where: { $0.id == sessionID }) else {
            return
        }
        mutate(&sessions[index])
    }
}
