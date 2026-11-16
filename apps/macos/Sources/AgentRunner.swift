// SPDX-License-Identifier: MIT OR Apache-2.0
import Foundation

/// Launches each verified tab's agent and reads its stdout. A web panel's URL comes only from a
/// handshake line printed by a process this host started (§5.4 (3)); tray-core parses the line.
///
/// Not yet here: tray-core's supervision state machine (crash cap, back-off). An agent that
/// exits stays exited until "Restart" or the next launch of the host.
final class AgentRunner {
    private struct Running {
        let process: Process
        var panelURL: URL?
    }

    private let log: HostLog
    private var running: [String: Running] = [:]
    private var waiting: [String: [(URL?) -> Void]] = [:]

    init(log: HostLog) { self.log = log }

    /// Starts agents for tabs that have none, stops agents whose tab is gone.
    func keep(_ tabs: [VerifiedTab]) {
        let ids = Set(tabs.map(\.id))
        for (id, agent) in running where !ids.contains(id) {
            agent.process.terminate()
            running[id] = nil
        }
        for tab in tabs where running[tab.id] == nil { launch(tab) }
    }

    func restart(_ tab: VerifiedTab) {
        running.removeValue(forKey: tab.id)?.process.terminate()
        launch(tab)
    }

    func stopAll() {
        running.values.forEach { $0.process.terminate() }
        running.removeAll()
    }

    /// The panel URL once the agent has printed its token; `done` runs on the main queue, with
    /// nil when the agent is not running.
    func panelURL(for tab: VerifiedTab, _ done: @escaping (URL?) -> Void) {
        guard let agent = running[tab.id] else { done(nil); return }
        if let url = agent.panelURL { done(url) } else { waiting[tab.id, default: []].append(done) }
    }

    private func launch(_ tab: VerifiedTab) {
        // Checked again at launch: the bundle may have changed since the manifest was verified.
        guard let bundle = BundleSignature.installed(bundleID: tab.agent.bundleID, teamID: tab.agent.teamID),
              let executable = Bundle(url: bundle)?.executableURL else {
            log.write("\(tab.id): its app is not installed signed by team \(tab.agent.teamID)")
            return
        }
        let process = Process()
        process.executableURL = executable
        process.arguments = tab.agent.argv
        let out = Pipe()
        process.standardOutput = out
        process.standardError = FileHandle.nullDevice
        let agentLog = HostLog(name: tab.id)
        var pending = Data()
        out.fileHandleForReading.readabilityHandler = { [weak self] handle in
            pending.append(handle.availableData)
            while let newline = pending.firstIndex(of: 0x0A) {
                let line = String(decoding: pending[pending.startIndex..<newline], as: UTF8.self)
                pending.removeSubrange(pending.startIndex...newline)
                DispatchQueue.main.async { self?.read(line, from: tab, log: agentLog) }
            }
        }
        process.terminationHandler = { [weak self] p in
            out.fileHandleForReading.readabilityHandler = nil
            DispatchQueue.main.async { self?.exited(tab, status: p.terminationStatus, process: p) }
        }
        do {
            try process.run()
            running[tab.id] = Running(process: process, panelURL: nil)
        } catch {
            log.write("\(tab.id): \(executable.path) did not start: \(error)")
        }
    }

    private func read(_ line: String, from tab: VerifiedTab, log agentLog: HostLog) {
        if case .web(let port, let path) = tab.panel, running[tab.id]?.panelURL == nil,
           let url = TrayCore.panelURL(port: port, path: path, line: line) {
            // Never logged: the token is the panel's credential.
            running[tab.id]?.panelURL = url
            waiting.removeValue(forKey: tab.id)?.forEach { $0(url) }
            return
        }
        agentLog.write(line)
    }

    private func exited(_ tab: VerifiedTab, status: Int32, process: Process) {
        guard running[tab.id]?.process === process else { return }
        running[tab.id] = nil
        waiting.removeValue(forKey: tab.id)?.forEach { $0(nil) }
        log.write("\(tab.id): its agent exited with status \(status)")
    }
}
