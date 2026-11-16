// SPDX-License-Identifier: MIT OR Apache-2.0
import ServiceManagement

/// Start at login, through SMAppService (the host is the login item, not a helper).
enum LoginItem {
    static var isEnabled: Bool { SMAppService.mainApp.status == .enabled }

    static func toggle(log: HostLog) {
        do {
            if isEnabled { try SMAppService.mainApp.unregister() } else { try SMAppService.mainApp.register() }
        } catch {
            log.write("start at login could not be changed: \(error)")
        }
    }
}
