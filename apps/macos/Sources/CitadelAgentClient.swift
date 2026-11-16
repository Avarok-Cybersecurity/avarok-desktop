// SPDX-License-Identifier: MIT OR Apache-2.0
import Foundation

/// One account the Citadel agent stores on this Mac.
struct CitadelAccount: Identifiable, Equatable {
    var id: UInt64 { cid }
    /// Permanent per account, so a row keeps its identity across reads.
    let cid: UInt64
    let username: String
    let fullName: String
    let workspaceHost: String?
    let connected: Bool
}

/// Reads the accounts from the Citadel agent over its loopback WebSocket control plane: wait for
/// ServiceConnectionAccepted, ask GetAccountInformation and GetSessions (both read-only, neither
/// returns a secret), join the two, close. The agent pushes nothing to a connection without a
/// session, so the panel asks again on a timer while it is shown.
final class CitadelAgentClient {
    private let url: URL
    private let timeout: TimeInterval

    /// `wss://local.avarok.net:<port>/`: the name the agent's loopback certificate is for.
    init(port: UInt16, timeout: TimeInterval) {
        url = URL(string: "wss://local.avarok.net:\(port)/")!
        self.timeout = timeout
    }

    /// `done` runs on the main queue with the accounts, or nil when the agent did not answer.
    func read(_ done: @escaping ([CitadelAccount]?) -> Void) {
        let task = URLSession.shared.webSocketTask(with: url)
        let queue = DispatchQueue(label: "net.avarok.desktop.citadel")
        var accounts: [UInt64: (String, String, String?)]?
        var live: Set<UInt64>?
        var finished = false
        func finish(_ result: [CitadelAccount]?) {
            queue.async {
                guard !finished else { return }
                finished = true
                task.cancel(with: .normalClosure, reason: nil)
                DispatchQueue.main.async { done(result) }
            }
        }
        func next() {
            task.receive { result in
                queue.async {
                    guard case .success(let message) = result, let reply = Reply(message) else { return finish(nil) }
                    switch reply {
                    case .accepted:
                        Self.send(task, "GetAccountInformation", ["cid": NSNull()])
                        Self.send(task, "GetSessions", [:])
                    case .accounts(let a): accounts = a
                    case .sessions(let s): live = s
                    case .other: break
                    }
                    if let accounts, let live {
                        finish(accounts.map { CitadelAccount(cid: $0.key, username: $0.value.0, fullName: $0.value.1,
                                                             workspaceHost: $0.value.2, connected: live.contains($0.key)) })
                    } else {
                        next()
                    }
                }
            }
        }
        task.resume()
        next()
        queue.asyncAfter(deadline: .now() + timeout) { finish(nil) }
    }

    /// serde's externally tagged form: `{"Request": {"<Variant>": {"request_id": ..., ...}}}`.
    private static func send(_ task: URLSessionWebSocketTask, _ variant: String, _ fields: [String: Any]) {
        var body = fields
        body["request_id"] = UUID().uuidString.lowercased()
        guard let data = try? JSONSerialization.data(withJSONObject: ["Request": [variant: body]]) else { return }
        task.send(.string(String(decoding: data, as: UTF8.self))) { _ in }
    }

    private enum Reply {
        case accepted
        case accounts([UInt64: (String, String, String?)])
        case sessions(Set<UInt64>)
        case other

        init?(_ message: URLSessionWebSocketTask.Message) {
            let data: Data
            switch message {
            case .string(let s): data = Data(s.utf8)
            case .data(let d): data = d
            @unknown default: return nil
            }
            guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                  let response = root["Response"] as? [String: Any], let (variant, value) = response.first else { return nil }
            let body = value as? [String: Any] ?? [:]
            switch variant {
            case "ServiceConnectionAccepted": self = .accepted
            case "GetAccountInformationResponse":
                var out: [UInt64: (String, String, String?)] = [:]
                // CIDs are map keys, so JSON strings here.
                for (key, entry) in body["accounts"] as? [String: Any] ?? [:] {
                    guard let cid = UInt64(key), let e = entry as? [String: Any], let name = e["username"] as? String else { continue }
                    let host = (e["server_host"] as? String).flatMap { $0.isEmpty || $0.count > 259 ? nil : $0 }
                    out[cid] = (name, e["full_name"] as? String ?? "", host)
                }
                self = .accounts(out)
            case "GetSessionsResponse":
                let list = body["sessions"] as? [[String: Any]] ?? []
                self = .sessions(Set(list.compactMap { ($0["cid"] as? NSNumber)?.uint64Value }))
            default: self = .other
            }
        }
    }
}
