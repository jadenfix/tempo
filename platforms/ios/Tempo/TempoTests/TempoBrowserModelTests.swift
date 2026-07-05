import XCTest
@testable import Tempo

@MainActor
final class TempoBrowserModelTests: XCTestCase {
    func testAdoptCreatesHumanOwnedTabForSession() {
        let model = TempoBrowserModel()
        let session = TempoSessionSummary(
            id: "session-1",
            title: "Checkout",
            url: URL(string: "https://example.com/checkout"),
            owner: .agent,
            runState: .waitingForHuman,
            tainted: true,
            marksVisible: true,
            pendingConfirmation: nil
        )

        model.apply(.sessionSnapshot([session]))
        model.adopt(session)

        XCTAssertEqual(model.selectedTab?.sessionID, "session-1")
        XCTAssertEqual(model.selectedTab?.owner, .human)
        XCTAssertTrue(model.selectedTab?.tainted == true)
        XCTAssertTrue(model.selectedTab?.marksVisible == true)
    }

    func testHandoffReturnsSelectedSessionToAgent() {
        let model = TempoBrowserModel()
        let session = TempoSessionSummary(
            id: "session-2",
            title: "Login",
            url: URL(string: "https://example.com/login"),
            owner: .agent,
            runState: .waitingForHuman,
            tainted: false,
            marksVisible: false,
            pendingConfirmation: nil
        )

        model.apply(.sessionSnapshot([session]))
        model.adopt(session)
        model.handoffSelectedSession()

        XCTAssertEqual(model.selectedTab?.owner, .agent)
        XCTAssertEqual(model.selectedTab?.runState, .running)
    }

    func testConfirmationResolutionClearsPendingState() {
        let model = TempoBrowserModel()
        let confirmation = PendingConfirmation(
            id: "confirm-1",
            sessionID: "local-preview",
            kind: .send,
            title: "Send",
            detail: "fixture"
        )

        model.apply(.confirmationRequested(confirmation))
        XCTAssertEqual(model.manager.pendingConfirmation?.id, "confirm-1")

        model.resolvePendingConfirmation(approved: true)

        XCTAssertNil(model.manager.pendingConfirmation)
        XCTAssertTrue(model.manager.journal.contains { $0.message == "confirmed send" })
    }
}
