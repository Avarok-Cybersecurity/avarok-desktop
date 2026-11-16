// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit
import TrayKit
import XCTest

/// A Dock icon only while a window is open, read back from the real NSApplication.
final class ActivationPolicyTests: XCTestCase {
    func testTheDockIconAppearsOnlyWhileAWindowIsOpen() {
        let app = NSApplication.shared
        let policy = ActivationPolicyController(app: app)
        XCTAssertEqual(app.activationPolicy(), .accessory)
        let window = NSWindow(contentRect: NSRect(x: 200, y: 200, width: 240, height: 120),
                              styleMask: [.titled, .closable], backing: .buffered, defer: false)
        policy.opened(window)
        XCTAssertEqual(app.activationPolicy(), .regular)
        XCTAssertEqual(policy.openWindowCount, 1)
        window.close()
        spin(until: { app.activationPolicy() == .accessory }, seconds: 2)
        XCTAssertEqual(app.activationPolicy(), .accessory)
        XCTAssertEqual(policy.openWindowCount, 0)
        // Becoming an accessory deactivates the app a moment later; let that happen here, not
        // in whichever test runs next.
        spin(until: { !app.isActive }, seconds: 2)
    }

    func testTheRule() {
        XCTAssertEqual(ActivationPolicyController.policy(openWindows: 0), .accessory)
        XCTAssertEqual(ActivationPolicyController.policy(openWindows: 2), .regular)
    }
}
