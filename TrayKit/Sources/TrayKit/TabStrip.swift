// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit

/// The row of tabs across the top of the popover: one button per tab, in the order given, the
/// selected one highlighted. Plain AppKit so the strip can be read back exactly.
public final class TabStrip: NSView {
    public static let identifier = "avarok-tab-strip"
    public private(set) var tabs: [TrayTab] = []
    public private(set) var selected: String?
    public var onSelect: (TrayTab) -> Void = { _ in }
    private let stack = NSStackView()

    public init() {
        super.init(frame: .zero)
        stack.orientation = .horizontal
        stack.spacing = 4
        stack.edgeInsets = NSEdgeInsets(top: 6, left: 8, bottom: 6, right: 8)
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor),
            stack.topAnchor.constraint(equalTo: topAnchor),
            stack.bottomAnchor.constraint(equalTo: bottomAnchor),
        ])
        setAccessibilityIdentifier(TabStrip.identifier)
        setAccessibilityRole(.tabGroup)
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) { nil }

    /// The buttons on screen, left to right.
    public var buttons: [NSButton] { stack.arrangedSubviews.compactMap { $0 as? NSButton } }

    /// Replaces the tabs. The selection survives when its tab still exists, else moves to the first.
    public func show(_ tabs: [TrayTab]) {
        self.tabs = tabs
        stack.arrangedSubviews.forEach { $0.removeFromSuperview() }
        for (index, tab) in tabs.enumerated() {
            let button = NSButton(title: tab.title, target: self, action: #selector(clicked(_:)))
            button.tag = index
            button.image = tab.icon
            button.imagePosition = tab.icon == nil ? .noImage : .imageLeading
            button.bezelStyle = .recessed
            button.setButtonType(.pushOnPushOff)
            button.setAccessibilityIdentifier("tab:\(tab.id)")
            stack.addArrangedSubview(button)
        }
        let keep = tabs.first { $0.id == selected } ?? tabs.first
        selected = nil
        if let keep { select(keep.id) }
    }

    public func select(_ id: String) {
        guard let index = tabs.firstIndex(where: { $0.id == id }) else { return }
        let changed = selected != id
        selected = id
        for button in buttons { button.state = button.tag == index ? .on : .off }
        if changed { onSelect(tabs[index]) }
    }

    @objc private func clicked(_ sender: NSButton) {
        guard tabs.indices.contains(sender.tag) else { return }
        select(tabs[sender.tag].id)
    }
}
