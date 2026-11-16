// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit

/// The popover under the status item: the tab strip on top, the selected tab's panel below.
/// It closes on any click outside it, in this app or another.
public final class TabPopover: NSObject, NSPopoverDelegate {
    public static let identifier = "avarok-tab-popover"
    public let strip = TabStrip()
    private let popover = NSPopover()
    private let host = PopoverContent()
    private let panel: (TrayTab) -> NSViewController
    private let size: NSSize
    private var outside: OutsideClicks?

    /// `panel` makes the view controller for a tab when it is selected; `size` is the panel's.
    public init(size: NSSize, panel: @escaping (TrayTab) -> NSViewController) {
        self.panel = panel
        self.size = size
        super.init()
        // Not .transient: that closes only on clicks while this app is active, and only on
        // some of them. OutsideClicks is the one rule for every click, in this app or another.
        popover.behavior = .applicationDefined
        popover.animates = false
        popover.delegate = self
        popover.contentViewController = host
        host.install(strip: strip)
        strip.onSelect = { [weak self] tab in self?.showPanel(for: tab) }
    }

    public var isShown: Bool { popover.isShown }

    /// The popover's own window while it is shown.
    public var window: NSWindow? { popover.isShown ? host.view.window : nil }

    public func show(_ tabs: [TrayTab]) { strip.show(tabs) }

    public func toggle(relativeTo view: NSView) {
        if popover.isShown { close() } else { open(relativeTo: view) }
    }

    public func open(relativeTo view: NSView) {
        popover.contentSize = NSSize(width: size.width, height: size.height + host.stripHeight)
        // An accessory app is not active, and a transient popover only hears outside clicks
        // while its app is; activating also lets the panel take key.
        NSApp.activate(ignoringOtherApps: true)
        popover.show(relativeTo: view.bounds, of: view, preferredEdge: .minY)
        host.view.window?.makeKey()
        host.view.window?.contentView?.setAccessibilityIdentifier(TabPopover.identifier)
        outside = OutsideClicks(inside: { [weak self] in self?.window }, anchor: view, onOutside: { [weak self] in self?.close() })
    }

    public func close() {
        guard popover.isShown else { return }
        popover.performClose(nil)
    }

    public func popoverDidClose(_ notification: Notification) { outside = nil }

    private func showPanel(for tab: TrayTab) { host.show(panel(tab)) }
}

/// The strip above a container whose child is the selected tab's panel.
private final class PopoverContent: NSViewController {
    private let container = NSView()
    private var current: NSViewController?
    let stripHeight: CGFloat = 36

    override func loadView() { view = NSView() }

    func install(strip: TabStrip) {
        strip.translatesAutoresizingMaskIntoConstraints = false
        container.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(strip)
        view.addSubview(container)
        NSLayoutConstraint.activate([
            strip.topAnchor.constraint(equalTo: view.topAnchor),
            strip.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            strip.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            strip.heightAnchor.constraint(equalToConstant: stripHeight),
            container.topAnchor.constraint(equalTo: strip.bottomAnchor),
            container.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            container.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            container.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }

    func show(_ child: NSViewController) {
        current?.view.removeFromSuperview()
        current?.removeFromParent()
        addChild(child)
        child.view.frame = container.bounds
        child.view.autoresizingMask = [.width, .height]
        container.addSubview(child.view)
        current = child
    }
}
