// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit
import TrayKit
import XCTest

/// A click outside the popover closes it; one inside does not. The clicks are real mouse-down
/// events queued on the application and delivered by its run loop, as AppKit delivers a person's.
final class OutsideClickTests: XCTestCase {
    private var anchor: NSWindow!
    private var popover: TabPopover!
    private let anchorFrame = NSRect(x: 180, y: 260, width: 20, height: 20)

    /// Once per class, an active regular app that stays so: an activation change in flight
    /// (another test's policy switch) would arrive as "resigned active" mid-test, which rightly
    /// closes the popover and would make these tests measure the wrong rule.
    override class func setUp() {
        super.setUp()
        NSApplication.shared.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        spin(until: { NSApp.isActive }, seconds: 3)
    }

    override func setUp() {
        super.setUp()
        anchor = NSWindow(contentRect: NSRect(x: 300, y: 300, width: 400, height: 300),
                          styleMask: [.titled], backing: .buffered, defer: false)
        anchor.isReleasedWhenClosed = false
        anchor.makeKeyAndOrderFront(nil)
        popover = TabPopover(size: NSSize(width: 240, height: 120)) { _ in NSViewController(nibName: nil, bundle: nil) }
        popover.show([TrayTab(id: "a.b", title: "A", templatePNG: nil)])
        let button = NSView(frame: anchorFrame)
        anchor.contentView?.addSubview(button)
        popover.open(relativeTo: button)
        spin(until: { self.popover.isShown }, seconds: 2)
    }

    override func tearDown() {
        popover.close()
        anchor.close()
        super.tearDown()
    }

    fileprivate func click(in window: NSWindow, at point: NSPoint) {
        let event = NSEvent.mouseEvent(with: .leftMouseDown, location: point, modifierFlags: [],
                                       timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: window.windowNumber,
                                       context: nil, eventNumber: 0, clickCount: 1, pressure: 1)!
        NSApp.postEvent(event, atStart: false)
        // Drain the queue through nextEvent/sendEvent, the path a person's click takes.
        let deadline = Date().addingTimeInterval(0.5)
        while Date() < deadline, let next = NSApp.nextEvent(matching: .any, until: Date().addingTimeInterval(0.05), inMode: .default, dequeue: true) {
            NSApp.sendEvent(next)
        }
    }

    func testAClickOutsideClosesThePopover() {
        XCTAssertTrue(popover.isShown)
        click(in: anchor, at: NSPoint(x: 20, y: 20))
        spin(until: { !self.popover.isShown }, seconds: 2)
        XCTAssertFalse(popover.isShown)
    }

    func testAClickInsideKeepsItOpen() throws {
        let window = try XCTUnwrap(popover.window)
        click(in: window, at: NSPoint(x: 10, y: 10))
        XCTAssertTrue(popover.isShown)
    }
}

extension OutsideClickTests {
    /// The status item's own click toggles the popover; the monitor must not close it first.
    func testAClickOnTheAnchorIsLeftToItsToggle() {
        XCTAssertTrue(popover.isShown, "shown before the click")
        click(in: anchor, at: NSPoint(x: anchorFrame.midX, y: anchorFrame.midY))
        XCTAssertTrue(popover.isShown)
    }
}
