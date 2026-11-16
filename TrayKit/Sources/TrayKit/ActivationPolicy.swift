// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit

/// A menu-bar app has no Dock icon (`.accessory`) except while one of its windows is open
/// (`.regular`), so the window can be found with Cmd-Tab and the Dock. Every window the app
/// opens goes through `opened(_:)`; its close is observed, never assumed.
public final class ActivationPolicyController {
    /// The one rule, kept pure so it can be read and tested on its own.
    public static func policy(openWindows: Int) -> NSApplication.ActivationPolicy {
        openWindows > 0 ? .regular : .accessory
    }

    private let app: NSApplication
    private var open: [ObjectIdentifier: NSObjectProtocol] = [:]

    public init(app: NSApplication) {
        self.app = app
        apply()
    }

    public var openWindowCount: Int { open.count }

    /// Shows `window` and keeps the Dock icon while it is open.
    public func opened(_ window: NSWindow) {
        let key = ObjectIdentifier(window)
        guard open[key] == nil else { window.makeKeyAndOrderFront(nil); return }
        window.isReleasedWhenClosed = false
        open[key] = NotificationCenter.default.addObserver(
            forName: NSWindow.willCloseNotification, object: window, queue: .main
        ) { [weak self] _ in self?.closed(key) }
        apply()
        app.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    private func closed(_ key: ObjectIdentifier) {
        open.removeValue(forKey: key).map(NotificationCenter.default.removeObserver)
        apply()
    }

    private func apply() {
        let wanted = ActivationPolicyController.policy(openWindows: open.count)
        if app.activationPolicy() != wanted { app.setActivationPolicy(wanted) }
    }
}
