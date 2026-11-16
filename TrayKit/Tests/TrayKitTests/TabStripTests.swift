// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit
import TrayCoreBridge
import TrayKit
import XCTest

/// The strip shows exactly the tabs tray-core verified: the real verifier, through the C ABI,
/// over the frozen contract fixtures. The code-signature check is the one stand-in (the
/// fixtures' apps are not installed); it accepts the fixtures' team only.
final class TabStripTests: XCTestCase {
    private let installs = [
        ("valid-web-panel.json", "net.avarok.certifiedcopy.json"),
        ("valid-native-panel.json", "net.avarok.citadel-agent.json"),
        ("invalid-missing-sig.json", "net.avarok.unsigned.json"),
        ("invalid-port-below-1024.json", "net.avarok.low-port.json"),
        ("valid-web-panel.json", "net.avarok.renamed.json"),
    ]

    private func strip(trusting publishers: TrayCore.Publishers, team: String) throws -> (TabStrip, TrayCore.Discovery) {
        let dir = try Fixtures.tabDirectory(installs)
        defer { try? FileManager.default.removeItem(at: dir) }
        let found = try TrayCore.tabs(in: dir, trusting: publishers, host: .init(name: "Avarok", startsAtLogin: true)) { _, t in t == team }
        let popover = TabPopover(size: NSSize(width: 300, height: 200)) { _ in NSViewController(nibName: nil, bundle: nil) }
        popover.show(Fixtures.trayTabs(found.tabs))
        return (popover.strip, found)
    }

    func testTheStripShowsExactlyTheVerifiedTabs() throws {
        let (strip, found) = try strip(trusting: Fixtures.testPublishers(), team: "ABCDE12345")
        XCTAssertEqual(strip.buttons.map(\.title), ["CertifiedCopy", "Citadel Workspaces"])
        XCTAssertEqual(strip.buttons.map { $0.accessibilityIdentifier() },
                       ["tab:net.avarok.certifiedcopy", "tab:net.avarok.citadel-agent"])
        XCTAssertEqual(found.refused.map(\.file).sorted(),
                       ["net.avarok.low-port.json", "net.avarok.renamed.json", "net.avarok.unsigned.json"])
        XCTAssertEqual(found.tabs.first?.panel, .web(port: 4823, path: "/panel/"))
        XCTAssertEqual(found.tabs.last?.panel, .native(module: "CitadelPanel"))
        XCTAssertEqual(strip.selected, "net.avarok.certifiedcopy")
        XCTAssertEqual(found.menu.first, .header(title: "CertifiedCopy", status: nil))
        XCTAssertTrue(found.menu.contains(.action(title: "Open CertifiedCopy", checked: nil,
                                                  action: .tab(tab: "net.avarok.certifiedcopy", action: "open-main"))))
        XCTAssertTrue(found.menu.contains(.action(title: "Start at Login", checked: true, action: .toggleLogin)))
        XCTAssertEqual(found.menu.last, .action(title: "Quit Avarok", checked: nil, action: .quit))
    }

    func testAnAppThatFailsTheOSCheckHasNoTab() throws {
        let (strip, found) = try strip(trusting: Fixtures.testPublishers(), team: "ZZZZZ99999")
        XCTAssertTrue(strip.buttons.isEmpty)
        XCTAssertEqual(found.refused.count, installs.count)
    }

    func testTheShippedHostDoesNotTrustTheContractTestKey() throws {
        let (strip, _) = try strip(trusting: TrayCore.avarokPublishers(), team: "ABCDE12345")
        XCTAssertTrue(strip.buttons.isEmpty)
    }

    func testSelectingATabShowsItsPanel() throws {
        var shown: [String] = []
        let popover = TabPopover(size: NSSize(width: 300, height: 200)) { tab in
            shown.append(tab.id)
            return NSViewController(nibName: nil, bundle: nil)
        }
        popover.show([TrayTab(id: "a.b", title: "A", templatePNG: nil), TrayTab(id: "c.d", title: "C", templatePNG: nil)])
        popover.strip.buttons[1].performClick(nil)
        XCTAssertEqual(shown, ["a.b", "c.d"])
        XCTAssertEqual(popover.strip.buttons.map(\.state), [.off, .on])
    }

    func testAHandshakeLineGivesTheLoopbackPanelURL() {
        let token = String(repeating: "k", count: 43)
        XCTAssertEqual(TrayCore.panelURL(port: 4823, path: "/panel/", line: "AVAROK_PANEL_TOKEN=\(token)")?.absoluteString,
                       "http://127.0.0.1:4823/panel/?token=\(token)")
        XCTAssertNil(TrayCore.panelURL(port: 4823, path: "/panel/", line: "ready"))
    }
}
