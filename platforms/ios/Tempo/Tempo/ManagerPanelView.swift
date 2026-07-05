import SwiftUI

struct ManagerPanelView: View {
    @ObservedObject var model: TempoBrowserModel

    var body: some View {
        VStack(spacing: 0) {
            ManagerHeader(model: model)
            Divider()
            HStack(spacing: 0) {
                SessionList(model: model)
                    .frame(width: 190)
                Divider()
                JournalView(entries: model.manager.journal)
                Divider()
                ConfirmationView(model: model)
                    .frame(width: 190)
            }
        }
        .background(Color.tempoSecondarySystemBackground)
    }
}

private struct ManagerHeader: View {
    @ObservedObject var model: TempoBrowserModel

    var body: some View {
        HStack(spacing: 10) {
            Label(model.manager.selectedSession?.runState.rawValue ?? "idle", systemImage: "waveform.path.ecg")
                .font(.caption)
                .lineLimit(1)
            Spacer()
            Button(action: model.adoptSelectedSession) {
                Image(systemName: "hand.raised")
            }
            .disabled(model.manager.selectedSession == nil)
            .accessibilityLabel("Adopt")

            Button(action: model.handoffSelectedSession) {
                Image(systemName: "arrow.uturn.forward")
            }
            .disabled(model.manager.selectedSession == nil && model.selectedTab?.sessionID == nil)
            .accessibilityLabel("Handoff")

            Button(action: model.toggleMarksForSelectedTab) {
                Image(systemName: model.selectedTab?.marksVisible == true ? "number.square.fill" : "number.square")
            }
            .accessibilityLabel("Marks")
        }
        .buttonStyle(.borderless)
        .padding(.horizontal, 12)
        .frame(height: 40)
    }
}

private struct SessionList: View {
    @ObservedObject var model: TempoBrowserModel

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 4) {
                ForEach(model.manager.sessions) { session in
                    Button {
                        model.selectSession(session.id)
                    } label: {
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Image(systemName: session.owner == .agent ? "cpu" : "person")
                                Text(session.title)
                                    .font(.caption)
                                    .lineLimit(1)
                                Spacer(minLength: 0)
                            }
                            HStack(spacing: 6) {
                                Text(session.runState.rawValue)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                if session.tainted {
                                    Image(systemName: "exclamationmark.shield")
                                        .foregroundStyle(.red)
                                }
                                if session.pendingConfirmation != nil {
                                    Image(systemName: "checkmark.shield")
                                        .foregroundStyle(.orange)
                                }
                            }
                        }
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(session.id == model.manager.selectedSessionID ? Color.tempoTertiarySystemFill : Color.clear)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(8)
        }
    }
}

private struct JournalView: View {
    let entries: [AgentJournalEntry]

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 6) {
                    ForEach(entries) { entry in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Text("#\(entry.sequence)")
                                .font(.caption2.monospacedDigit())
                                .foregroundStyle(.secondary)
                            Text(entry.message)
                                .font(.caption)
                                .lineLimit(2)
                            Spacer(minLength: 0)
                        }
                        .id(entry.id)
                    }
                }
                .padding(10)
            }
            .onChange(of: entries.last?.id) { _, id in
                if let id {
                    proxy.scrollTo(id, anchor: .bottom)
                }
            }
        }
    }
}

private struct ConfirmationView: View {
    @ObservedObject var model: TempoBrowserModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let confirmation = model.manager.pendingConfirmation {
                Label(confirmation.title, systemImage: "checkmark.shield")
                    .font(.caption)
                    .lineLimit(1)
                Text(confirmation.kind.rawValue)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                Text(confirmation.detail)
                    .font(.caption2)
                    .lineLimit(3)
                HStack {
                    Button {
                        model.resolvePendingConfirmation(approved: false)
                    } label: {
                        Image(systemName: "xmark")
                    }
                    .accessibilityLabel("Deny")

                    Button {
                        model.resolvePendingConfirmation(approved: true)
                    } label: {
                        Image(systemName: "checkmark")
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityLabel("Approve")
                }
            } else {
                Label("Clear", systemImage: "checkmark.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(10)
    }
}
