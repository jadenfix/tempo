import XCTest
@testable import Tempo

@MainActor
final class TempoBrowserModelTests: XCTestCase {
    func testAdoptCreatesHumanOwnedTabForSession() {
        let model = TempoBrowserModel(seedPreview: false)
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
        let model = TempoBrowserModel(seedPreview: false)
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
        let model = TempoBrowserModel(seedPreview: false)
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

    func testObservationPayloadUpdatesSelectedTabSummary() {
        let model = TempoBrowserModel(seedPreview: false)
        let payload: [String: Any] = [
            "url": "https://example.com/form",
            "elements": [[
                "locator": "#email",
                "source_id": "email-source",
                "stable_hint": "email|textbox|Email",
                "role": "textbox",
                "name": [["provenance": "page", "text": "Email"]],
                "value": [["provenance": "page", "text": "person@example.com"]],
                "bounds": [0.0, 0.0, 120.0, 24.0],
                "visible": true,
                "enabled": true,
                "interactive": true,
            ]],
        ]

        model.ingestObservationPayload(payload)

        XCTAssertEqual(model.selectedTab?.url?.absoluteString, "https://example.com/form")
        XCTAssertEqual(model.selectedTab?.lastObservationElementCount, 1)
    }

    func testObservationPayloadCanTargetInactiveTab() {
        let model = TempoBrowserModel(seedPreview: false)
        let firstID = model.selectedTabID
        model.newTab()
        let secondID = model.selectedTabID
        model.selectTab(firstID)

        let payload: [String: Any] = [
            "url": "https://example.com/second",
            "elements": [],
        ]
        model.ingestObservationPayload(payload, for: secondID)

        XCTAssertEqual(model.selectedTabID, firstID)
        XCTAssertNotEqual(model.selectedTab?.url?.absoluteString, "https://example.com/second")
        XCTAssertEqual(
            model.tabs.first(where: { $0.id == secondID })?.url?.absoluteString,
            "https://example.com/second"
        )
    }

    func testPreviewManagerControlsDoNotFakeServerMutations() {
        let model = TempoBrowserModel(seedPreview: true)
        let originalOwner = model.manager.selectedSession?.owner

        model.adoptSelectedSession()
        model.handoffSelectedSession()
        model.resolvePendingConfirmation(approved: true)

        XCTAssertTrue(model.manager.previewOnly)
        XCTAssertEqual(model.manager.selectedSession?.owner, originalOwner)
        XCTAssertNil(model.selectedTab?.sessionID)
        XCTAssertTrue(model.lastError?.contains("Preview manager data only") == true)
        XCTAssertNotNil(model.manager.pendingConfirmation)
    }
}
