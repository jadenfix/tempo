import SwiftUI
import WebKit

struct WebViewContainer: UIViewRepresentable {
    @Binding var tab: TempoTab
    @Binding var command: WebViewCommand?

    let observationScript: String

    func makeCoordinator() -> Coordinator {
        Coordinator(parent: self)
    }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        configuration.userContentController.addUserScript(WKUserScript(
            source: observationScript,
            injectionTime: .atDocumentEnd,
            forMainFrameOnly: false
        ))

        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = true
        webView.scrollView.keyboardDismissMode = .interactive
        context.coordinator.load(tab.url, in: webView)
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        context.coordinator.parent = self
        if let command {
            context.coordinator.apply(command, to: webView)
            DispatchQueue.main.async {
                self.command = nil
            }
            return
        }
        if tab.url != webView.url && !tab.isLoading {
            context.coordinator.load(tab.url, in: webView)
        }
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        var parent: WebViewContainer
        private var lastRequestedURL: URL?

        init(parent: WebViewContainer) {
            self.parent = parent
        }

        func load(_ url: URL?, in webView: WKWebView) {
            guard let url else {
                return
            }
            guard lastRequestedURL != url else {
                return
            }
            lastRequestedURL = url
            webView.load(URLRequest(url: url))
        }

        func apply(_ command: WebViewCommand, to webView: WKWebView) {
            switch command {
            case .back:
                if webView.canGoBack {
                    webView.goBack()
                }
            case .forward:
                if webView.canGoForward {
                    webView.goForward()
                }
            case .reload:
                webView.reload()
            case .stop:
                webView.stopLoading()
            }
        }

        func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
            parent.tab.isLoading = true
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            updateTab(from: webView, isLoading: false)
            webView.evaluateJavaScript("window.__tempoCollectObservation && window.__tempoCollectObservation()") { _, _ in }
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            updateTab(from: webView, isLoading: false)
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            updateTab(from: webView, isLoading: false)
        }

        private func updateTab(from webView: WKWebView, isLoading: Bool) {
            parent.tab.url = webView.url ?? parent.tab.url
            parent.tab.title = webView.title?.isEmpty == false
                ? webView.title!
                : parent.tab.url?.host() ?? "Tempo"
            parent.tab.canGoBack = webView.canGoBack
            parent.tab.canGoForward = webView.canGoForward
            parent.tab.isLoading = isLoading
        }
    }
}
