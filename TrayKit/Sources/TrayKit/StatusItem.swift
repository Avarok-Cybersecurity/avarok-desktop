// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit

/// The one menu-bar item: a left click toggles the tab popover, a right click shows the menu
/// the host builds at that moment (from tray-core's menu model).
public final class StatusItem: NSObject {
    private let item: NSStatusItem
    public let popover: TabPopover
    private let menu: () -> NSMenu

    public init(icon: NSImage?, toolTip: String, popover: TabPopover, menu: @escaping () -> NSMenu) {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        self.popover = popover
        self.menu = menu
        super.init()
        icon?.isTemplate = true
        item.button?.image = icon
        item.button?.toolTip = toolTip
        item.button?.target = self
        item.button?.action = #selector(clicked)
        item.button?.sendAction(on: [.leftMouseUp, .rightMouseUp])
    }

    public var button: NSStatusBarButton? { item.button }

    @objc private func clicked() {
        guard let button = item.button else { return }
        if NSApp.currentEvent?.type == .rightMouseUp {
            popover.close()
            item.menu = menu()
            button.performClick(nil)
            item.menu = nil
        } else {
            popover.toggle(relativeTo: button)
        }
    }

    deinit { NSStatusBar.system.removeStatusItem(item) }
}
