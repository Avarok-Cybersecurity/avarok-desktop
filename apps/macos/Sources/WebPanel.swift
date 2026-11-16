// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit
import WebKit

/// A tab's web panel: http://127.0.0.1:<port>/<path>?token=<token>, the URL tray-core built from
/// the handshake line of the agent this host launched. Navigation off that origin is refused, so
/// a link in the panel opens in the browser instead of inside the host.
final class WebPanel: NSViewController, WKNavigationDelegate {
    private let tab: VerifiedTab
    private let agents: AgentRunner
    private let windows: ActivationPolicyController
    private var web: WKWebView?
    private var url: URL?

    init(tab: VerifiedTab, agents: AgentRunner, windows: ActivationPolicyController) {
        self.tab = tab
        self.agents = agents
        self.windows = windows
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) { nil }

    override func loadView() {
        view = NSView()
        agents.panelURL(for: tab) { [weak self] url in
            guard let self else { return }
            guard let url else {
                self.replace(with: MessagePanel(text: "\(self.tab.title) is not running, so its panel cannot open.").view)
                return
            }
            self.url = url
            let web = WebPanel.webView(delegate: self)
            web.load(URLRequest(url: url))
            self.web = web
            self.replace(with: web)
        }
    }

    /// The same panel in a window of its own, which brings the Dock icon while it is open.
    @objc func openInWindow() {
        guard let url else { return }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 900, height: 640),
                              styleMask: [.titled, .closable, .resizable, .miniaturizable], backing: .buffered, defer: false)
        window.title = tab.title
        let web = WebPanel.webView(delegate: self)
        web.load(URLRequest(url: url))
        window.contentView = web
        window.center()
        windows.opened(window)
    }

    private static func webView(delegate: WKNavigationDelegate) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        // Per-launch tokens: nothing a panel stores should outlive the host's session with it.
        configuration.websiteDataStore = .nonPersistent()
        let web = WKWebView(frame: .zero, configuration: configuration)
        web.navigationDelegate = delegate
        return web
    }

    /// The panel below a one-button bar: "Open in Window" once there is something to open.
    private func replace(with child: NSView) {
        view.subviews.forEach { $0.removeFromSuperview() }
        let bar: CGFloat = 28
        let button = NSButton(title: "Open in Window", target: self, action: #selector(openInWindow))
        button.bezelStyle = .recessed
        button.controlSize = .small
        button.isEnabled = url != nil
        button.sizeToFit()
        button.frame.origin = NSPoint(x: view.bounds.width - button.frame.width - 8, y: view.bounds.height - bar + 4)
        button.autoresizingMask = [.minXMargin, .minYMargin]
        child.frame = NSRect(x: 0, y: 0, width: view.bounds.width, height: view.bounds.height - bar)
        child.autoresizingMask = [.width, .height]
        view.addSubview(child)
        view.addSubview(button)
    }

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let target = action.request.url else { decisionHandler(.cancel); return }
        let ours = target.scheme == "http" && target.host == "127.0.0.1" && target.port == url?.port
        if ours { decisionHandler(.allow); return }
        if target.scheme == "https" { NSWorkspace.shared.open(target) }
        decisionHandler(.cancel)
    }
}
