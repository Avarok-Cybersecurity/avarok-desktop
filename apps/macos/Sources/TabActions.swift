// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit

/// A manifest action: open the tab's app (by bundle id, after the signature check again), with
/// its URL fragment when it names one.
enum TabActions {
    static func perform(_ action: VerifiedTab.Action, of tab: VerifiedTab, log: HostLog) {
        guard action.opensBundle else { return }
        guard let app = BundleSignature.installed(bundleID: tab.agent.bundleID, teamID: tab.agent.teamID) else {
            log.write("\(tab.id): \(action.id) not run; the app failed the signature check")
            return
        }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        if let fragment = action.fragment {
            // The app's own main window, at the fragment (such as "#/"), as an Apple event argument.
            configuration.arguments = ["--open-fragment", fragment]
        }
        NSWorkspace.shared.openApplication(at: app, configuration: configuration) { _, error in
            if let error { log.write("\(tab.id): \(action.id) failed: \(error)") }
        }
    }
}
