import SwiftUI

struct BrowserShellView: View {
    @ObservedObject var model: TempoBrowserModel

    var body: some View {
        VStack(spacing: 0) {
            BrowserToolbar(model: model)
            TabStripView(model: model)
            Divider()
            ZStack(alignment: .topTrailing) {
                WebViewContainer(
                    tab: model.selectedTabBinding,
                    command: $model.webViewCommand,
                    observationScript: model.observationScript
                )
                SurfaceBadges(tab: model.selectedTab)
                    .padding(10)
            }
            Divider()
            ManagerPanelView(model: model)
                .frame(maxHeight: 260)
        }
        .background(Color(.systemBackground))
    }
}

private struct BrowserToolbar: View {
    @ObservedObject var model: TempoBrowserModel

    var body: some View {
        HStack(spacing: 8) {
            Button(action: model.goBack) {
                Image(systemName: "chevron.backward")
            }
            .disabled(model.selectedTab?.canGoBack != true)
            .accessibilityLabel("Back")

            Button(action: model.goForward) {
                Image(systemName: "chevron.forward")
            }
            .disabled(model.selectedTab?.canGoForward != true)
            .accessibilityLabel("Forward")

            TextField("Search or URL", text: $model.addressText)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
                .submitLabel(.go)
                .onSubmit(model.navigateToAddress)
                .padding(.horizontal, 10)
                .frame(height: 36)
                .background(Color(.secondarySystemBackground))
                .clipShape(RoundedRectangle(cornerRadius: 8))

            Button(action: model.selectedTab?.isLoading == true ? model.stopLoading : model.reload) {
                Image(systemName: model.selectedTab?.isLoading == true ? "xmark" : "arrow.clockwise")
            }
            .accessibilityLabel(model.selectedTab?.isLoading == true ? "Stop" : "Reload")

            Button(action: model.newTab) {
                Image(systemName: "plus")
            }
            .accessibilityLabel("New Tab")

            Button(action: model.closeSelectedTab) {
                Image(systemName: "xmark.square")
            }
            .disabled(model.tabs.count <= 1)
            .accessibilityLabel("Close Tab")
        }
        .buttonStyle(.borderless)
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }
}

private struct TabStripView: View {
    @ObservedObject var model: TempoBrowserModel

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                ForEach(model.tabs) { tab in
                    Button {
                        model.selectTab(tab.id)
                    } label: {
                        HStack(spacing: 6) {
                            Image(systemName: tab.owner == .agent ? "cpu" : "person")
                            Text(tab.title)
                                .lineLimit(1)
                                .font(.caption)
                        }
                        .padding(.horizontal, 10)
                        .frame(height: 32)
                        .background(tab.id == model.selectedTabID ? Color(.tertiarySystemFill) : Color.clear)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 12)
            .padding(.bottom, 6)
        }
    }
}

private struct SurfaceBadges: View {
    let tab: TempoTab?

    var body: some View {
        HStack(spacing: 8) {
            if tab?.tainted == true {
                Label("Tainted", systemImage: "exclamationmark.shield")
                    .labelStyle(.titleAndIcon)
                    .font(.caption2)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(Color.red.opacity(0.9))
                    .foregroundStyle(.white)
                    .clipShape(Capsule())
            }
            if tab?.marksVisible == true {
                Label("Marks", systemImage: "number.square")
                    .labelStyle(.titleAndIcon)
                    .font(.caption2)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(Color.blue.opacity(0.9))
                    .foregroundStyle(.white)
                    .clipShape(Capsule())
            }
        }
    }
}
