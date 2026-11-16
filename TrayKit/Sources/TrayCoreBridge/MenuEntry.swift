// SPDX-License-Identifier: MIT OR Apache-2.0
import Foundation

/// One line of the right-click menu, as tray-core's `tabs::entries` laid it out.
public enum MenuEntry: Equatable {
    case header(title: String, status: String?)
    case action(title: String, checked: Bool?, action: MenuAction)
    case separator

    init(cbor c: CBOR) throws {
        switch c["kind"]?.text {
        case "header":
            guard let title = c["title"]?.text else { throw TabDecodeError.missing("menu.title") }
            self = .header(title: title, status: c["status"]?.text)
        case "separator":
            self = .separator
        case "action":
            guard let title = c["title"]?.text, let action = c["action"] else { throw TabDecodeError.missing("menu.action") }
            self = .action(title: title, checked: c["checked"]?.bool, action: try MenuAction(cbor: action))
        case let other:
            throw TabDecodeError.missing("menu.kind \(other ?? "nil")")
        }
    }
}

/// What choosing a menu line does. `tab` and `restart` name a tab in the same reply.
public enum MenuAction: Equatable {
    case tab(tab: String, action: String)
    case restart(tab: String)
    case toggleLogin, showLog, checkUpdates, quit

    init(cbor c: CBOR) throws {
        switch c["kind"]?.text {
        case "tab":
            guard let tab = c["tab"]?.text, let action = c["action"]?.text else { throw TabDecodeError.missing("menu.tab") }
            self = .tab(tab: tab, action: action)
        case "restart":
            guard let tab = c["tab"]?.text else { throw TabDecodeError.missing("menu.restart") }
            self = .restart(tab: tab)
        case "toggle-login": self = .toggleLogin
        case "show-log": self = .showLog
        case "check-updates": self = .checkUpdates
        case "quit": self = .quit
        case let other: throw TabDecodeError.missing("menu.action \(other ?? "nil")")
        }
    }
}
