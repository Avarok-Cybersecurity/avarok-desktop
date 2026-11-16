// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit

/// Calls `onOutside` for a mouse-down anywhere but the `inside` window: a global monitor for
/// clicks in other apps (which a background app's transient popover never hears) and a local
/// one for this app's other windows and the menu bar; switching to another app counts too.
/// Held only while the popover is shown; the monitors go when this does.
final class OutsideClicks {
    private var monitors: [Any] = []
    private var resigned: NSObjectProtocol?

    /// `anchor` is the view the popover hangs from (the status item's button): a click on it is
    /// its own toggle, so closing here would only see the popover reopen.
    init(inside: @escaping () -> NSWindow?, anchor: NSView, onOutside: @escaping () -> Void) {
        weak var anchor: NSView? = anchor
        let mask: NSEvent.EventTypeMask = [.leftMouseDown, .rightMouseDown, .otherMouseDown]
        if let global = NSEvent.addGlobalMonitorForEvents(matching: mask, handler: { _ in onOutside() }) {
            monitors.append(global)
        }
        if let local = NSEvent.addLocalMonitorForEvents(matching: mask, handler: { event in
            if OutsideClicks.isOutside(event.window, inside: inside()) && !OutsideClicks.lands(event, on: anchor) { onOutside() }
            return event
        }) {
            monitors.append(local)
        }
        resigned = NotificationCenter.default.addObserver(
            forName: NSApplication.didResignActiveNotification, object: nil, queue: .main
        ) { _ in onOutside() }
    }

    /// A click belongs to the popover when it lands in the popover's window or a window it
    /// owns (a menu it opened, a sheet).
    static func isOutside(_ clicked: NSWindow?, inside: NSWindow?) -> Bool {
        guard let inside else { return false }
        var window = clicked
        while let w = window {
            if w === inside { return false }
            window = w.parent
        }
        return true
    }

    static func lands(_ event: NSEvent, on view: NSView?) -> Bool {
        guard let view, let window = view.window, event.window === window else { return false }
        return view.bounds.contains(view.convert(event.locationInWindow, from: nil))
    }

    deinit {
        monitors.forEach(NSEvent.removeMonitor)
        resigned.map(NotificationCenter.default.removeObserver)
    }
}
