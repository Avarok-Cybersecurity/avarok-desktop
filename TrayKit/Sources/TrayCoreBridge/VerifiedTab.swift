// SPDX-License-Identifier: MIT OR Apache-2.0
import Foundation

/// A tab tray-core verified: signed by a pinned publisher, every field checked, its app passed
/// the OS code-signature check. Only `TrayCore.tabs` makes one.
public struct VerifiedTab: Equatable, Identifiable {
    public let id: String
    public let title: String
    /// A template PNG for the menu bar.
    public let icon: Data
    public let agent: Agent
    public let panel: Panel
    public let actions: [Action]

    public struct Agent: Equatable {
        public let bundleID: String
        public let teamID: String
        public let argv: [String]
        public let port: UInt16
        public let crashCap: UInt8
    }

    public enum Panel: Equatable {
        /// Served by the tab's agent at http://127.0.0.1:<port><path>, opened with the token the
        /// agent printed on stdout.
        case web(port: UInt16, path: String)
        /// A SwiftUI panel compiled into the host, by module name.
        case native(module: String)
    }

    public struct Action: Equatable {
        public let id: String
        public let title: String
        public let opensBundle: Bool
        public let fragment: String?
    }
}

/// A manifest that was not accepted, and why: for the log, never a tab.
public struct RefusedTab: Equatable {
    public let file: String
    public let reason: String
}

enum TabDecodeError: Error, Equatable {
    case missing(String)
}

extension VerifiedTab {
    init(cbor c: CBOR) throws {
        func need<T>(_ value: T?, _ name: String) throws -> T {
            guard let value else { throw TabDecodeError.missing(name) }
            return value
        }
        let agent = try need(c["agent"], "agent")
        let panel = try need(c["panel"], "panel")
        id = try need(c["id"]?.text, "id")
        title = try need(c["title"]?.text, "title")
        icon = try need(c["icon"]?.bytes, "icon")
        self.agent = Agent(
            bundleID: try need(agent["bundle_id"]?.text, "agent.bundle_id"),
            teamID: try need(agent["team_id"]?.text, "agent.team_id"),
            argv: try need(agent["argv"]?.array, "agent.argv").map { try need($0.text, "agent.argv[]") },
            port: try need(agent["port"]?.uint.flatMap { UInt16(exactly: $0) }, "agent.port"),
            crashCap: try need(agent["crash_cap"]?.uint.flatMap { UInt8(exactly: $0) }, "agent.crash_cap")
        )
        switch try need(panel["kind"]?.text, "panel.kind") {
        case "web":
            self.panel = .web(
                port: try need(panel["port"]?.uint.flatMap { UInt16(exactly: $0) }, "panel.port"),
                path: try need(panel["path"]?.text, "panel.path"))
        case "native":
            self.panel = .native(module: try need(panel["module"]?.text, "panel.module"))
        case let other:
            throw TabDecodeError.missing("panel.kind \(other)")
        }
        actions = try need(c["actions"]?.array, "actions").map { a in
            Action(
                id: try need(a["id"]?.text, "action.id"),
                title: try need(a["title"]?.text, "action.title"),
                opensBundle: try need(a["open_bundle"]?.bool, "action.open_bundle"),
                fragment: a["fragment"]?.text)
        }
    }
}
