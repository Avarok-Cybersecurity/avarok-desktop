// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit
import SwiftUI

/// The panel for a verified tab: a SwiftUI module compiled into this host when the manifest
/// names one, otherwise the agent's own web panel in a WKWebView (the universal fallback).
enum Panels {
    /// `panel.native.macos_module` → the panel. A module this build lacks is said so, never guessed.
    static let native: [String: (VerifiedTab) -> NSViewController] = [
        "CitadelPanel": { tab in NSHostingController(rootView: CitadelPanelView(model: CitadelPanelModel(tab: tab))) },
        "CertifiedCopyPanel": { tab in NSHostingController(rootView: CertifiedCopyPanelView(model: CertifiedCopyModel(tab: tab))) },
    ]

    static func make(for tab: VerifiedTab, agents: AgentRunner, windows: ActivationPolicyController) -> NSViewController {
        switch tab.panel {
        case .native(let module):
            return native[module]?(tab) ?? MessagePanel(text: "\(tab.title)'s panel (\(module)) is not in this version of Avarok.")
        case .web:
            return WebPanel(tab: tab, agents: agents, windows: windows)
        }
    }
}

/// One line of text in place of a panel.
final class MessagePanel: NSViewController {
    private let text: String
    init(text: String) {
        self.text = text
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) { nil }

    override func loadView() {
        let label = NSTextField(wrappingLabelWithString: text)
        label.alignment = .center
        label.textColor = .secondaryLabelColor
        let box = NSView()
        label.translatesAutoresizingMaskIntoConstraints = false
        box.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: box.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: box.centerYAnchor),
            label.widthAnchor.constraint(lessThanOrEqualTo: box.widthAnchor, constant: -32),
        ])
        view = box
    }
}
