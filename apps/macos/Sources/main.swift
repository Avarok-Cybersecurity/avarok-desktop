// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit

// The Avarok menu-bar host: one status item whose popover holds a tab for each verified app.
let app = NSApplication.shared
let host = Host(app: app)
app.delegate = host
app.run()
