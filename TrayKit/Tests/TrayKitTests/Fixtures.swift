// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit
import Foundation
import TrayCoreBridge
import TrayKit

/// The frozen contract fixtures, read from tray-core's one copy of them.
enum Fixtures {
    static let contract = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().appendingPathComponent("crates/tray-core/tests/contract")

    /// The contract's TEST publisher (tray-tab-kat.json), never a production key.
    static func testPublishers() throws -> TrayCore.Publishers {
        let kat = try JSONSerialization.jsonObject(with: Data(contentsOf: contract.appendingPathComponent("tray-tab-kat.json"))) as? [String: Any]
        let key = try XCTUnwrapString((kat?["publisher"] as? [String: Any])?["pk_hex"])
        return TrayCore.publishers([(name: "Avarok Cybersecurity", keyHex: key)])
    }

    /// A fresh tab directory holding `installs` (fixture name → installed file name).
    static func tabDirectory(_ installs: [(String, String)]) throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("traykit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        for (fixture, file) in installs {
            try FileManager.default.copyItem(
                at: contract.appendingPathComponent("tray-tab-manifest").appendingPathComponent(fixture),
                to: dir.appendingPathComponent(file))
        }
        return dir
    }

    static func trayTabs(_ tabs: [VerifiedTab]) -> [TrayTab] {
        tabs.map { TrayTab(id: $0.id, title: $0.title, templatePNG: $0.icon) }
    }
}

struct MissingValue: Error {}

func XCTUnwrapString(_ value: Any?) throws -> String {
    guard let s = value as? String else { throw MissingValue() }
    return s
}

/// Runs the main run loop until `done` or `seconds` pass, so AppKit can deliver events.
func spin(until done: () -> Bool, seconds: TimeInterval) {
    let deadline = Date().addingTimeInterval(seconds)
    while !done() && Date() < deadline {
        RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.01))
    }
}
