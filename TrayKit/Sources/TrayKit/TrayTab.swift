// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit

/// One tab in the strip: what TrayKit needs to draw it, nothing about where it came from.
public struct TrayTab: Equatable, Identifiable {
    public let id: String
    public let title: String
    /// A template image (monochrome with alpha), drawn to match the menu bar.
    public let icon: NSImage?

    public init(id: String, title: String, templatePNG: Data?) {
        self.id = id
        self.title = title
        let image = templatePNG.flatMap(NSImage.init(data:))
        image?.isTemplate = true
        icon = image
    }
}
