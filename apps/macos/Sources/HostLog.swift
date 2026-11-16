// SPDX-License-Identifier: MIT OR Apache-2.0
import Foundation

/// ~/Library/Logs/Avarok/<name>.log, started over when it passes tray-core's 10 MiB limit.
final class HostLog {
    static let limit: UInt64 = 10 * 1024 * 1024
    let url: URL
    private let queue = DispatchQueue(label: "net.avarok.desktop.log")

    init(name: String) {
        let dir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/Avarok", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        url = dir.appendingPathComponent("\(name).log")
        let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? UInt64) ?? 0
        if size > HostLog.limit || !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil)
        }
    }

    func write(_ line: String) {
        let stamped = "\(ISO8601DateFormatter().string(from: Date())) \(line)\n"
        queue.async { [url] in
            do {
                let handle = try FileHandle(forWritingTo: url)
                defer { try? handle.close() }
                try handle.seekToEnd()
                try handle.write(contentsOf: Data(stamped.utf8))
            } catch {
                // The log is where failures go; when it cannot be written, the system log is.
                NSLog("Avarok: %@ could not be written (%@): %@", url.path, "\(error)", line)
            }
        }
    }
}
