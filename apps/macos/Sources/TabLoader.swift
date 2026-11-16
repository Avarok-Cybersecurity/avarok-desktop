// SPDX-License-Identifier: MIT OR Apache-2.0
import Foundation

/// The per-user tab directory, watched; every change re-runs tray-core's discovery.
final class TabLoader {
    private let directory: URL
    private let log: HostLog
    private var watch: DispatchSourceFileSystemObject?
    var onChange: () -> Void = {}

    /// ~/Library/Application Support/Avarok/tabs (contract §1).
    static func userTabDirectory() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Avarok/tabs", isDirectory: true)
    }

    init(directory: URL, log: HostLog) {
        self.directory = directory
        self.log = log
    }

    /// Verified tabs, trusting only the publishers this build pins, with the OS code-signature
    /// check for every app a manifest names.
    func load(startsAtLogin: Bool, hostName: String) throws -> TrayCore.Discovery {
        try TrayCore.tabs(in: directory, trusting: TrayCore.avarokPublishers(),
                          host: .init(name: hostName, startsAtLogin: startsAtLogin)) { bundle, team in
            BundleSignature.installed(bundleID: bundle, teamID: team) != nil
        }
    }

    func start() {
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        } catch {
            log.write("the tab directory \(directory.path) could not be created: \(error)")
            return
        }
        let fd = open(directory.path, O_EVTONLY)
        guard fd >= 0 else {
            log.write("the tab directory \(directory.path) cannot be watched (errno \(errno))")
            return
        }
        let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: [.write, .rename, .delete], queue: .main)
        source.setEventHandler { [weak self] in self?.onChange() }
        source.setCancelHandler { close(fd) }
        source.resume()
        watch = source
    }

    deinit { watch?.cancel() }
}
