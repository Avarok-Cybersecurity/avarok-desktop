// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit
import SwiftUI

/// The CertifiedCopy tab: the phones its agent can see, read from the agent's loopback HTTP API
/// (`GET /api/devices`). The host shows what the agent says and understands nothing more; every
/// action opens CertifiedCopy itself (the boundary CertifiedCopy's host contract draws).
final class CertifiedCopyModel: ObservableObject {
    struct Device: Identifiable, Equatable {
        let id: String
        let name: String
        let attached: Bool
    }

    @Published private(set) var devices: [Device] = []
    @Published private(set) var answered: Bool?
    let tab: VerifiedTab
    private var timer: Timer?

    init(tab: VerifiedTab) { self.tab = tab }

    private var endpoint: URL { URL(string: "http://127.0.0.1:\(tab.agent.port)/api/devices")! }

    func appeared() {
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in self?.refresh() }
    }

    func disappeared() {
        timer?.invalidate()
        timer = nil
    }

    private func refresh() {
        var request = URLRequest(url: endpoint)
        request.timeoutInterval = 3
        URLSession.shared.dataTask(with: request) { [weak self] data, response, _ in
            let ok = (response as? HTTPURLResponse)?.statusCode == 200
            let list = ok ? data.flatMap(CertifiedCopyModel.parse) : nil
            DispatchQueue.main.async {
                guard let self else { return }
                self.answered = list != nil
                if let list { self.devices = list }
            }
        }.resume()
    }

    /// `{"devices": [{"key", "label"|"name", "attached"|"transport"}]}`; a device without a key is skipped.
    static func parse(_ data: Data) -> [Device]? {
        guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let list = root["devices"] as? [[String: Any]] else { return nil }
        return list.compactMap { raw in
            guard let key = raw["key"] as? String else { return nil }
            let name = (raw["label"] as? String) ?? (raw["name"] as? String) ?? "Phone"
            return Device(id: key, name: name, attached: (raw["attached"] as? Bool) ?? (raw["transport"] != nil))
        }
    }

    func openApp() {
        guard let main = tab.actions.first(where: \.opensBundle) else { return }
        TabActions.perform(main, of: tab, log: HostLog(name: tab.id))
    }
}

struct CertifiedCopyPanelView: View {
    @ObservedObject var model: CertifiedCopyModel

    var body: some View {
        VStack(spacing: 0) {
            switch model.answered {
            case nil: Note(title: "Starting\u{2026}", detail: nil)
            case false?: Note(title: "CertifiedCopy is not answering", detail: "Open CertifiedCopy to start it.")
            case true? where model.devices.isEmpty: Note(title: "Plug in a phone", detail: "It will appear here, ready to copy.")
            case true?:
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(model.devices) { device in
                            HStack {
                                Image(systemName: "iphone").frame(width: 28)
                                Text(device.name).font(.system(size: 14, weight: .medium)).lineLimit(1)
                                Spacer()
                                Text(device.attached ? "Connected" : "Not connected").font(.system(size: 11)).foregroundColor(.secondary)
                            }
                            .padding(.horizontal, 14).frame(height: 52)
                            .contentShape(Rectangle()).onTapGesture(perform: model.openApp)
                            Divider()
                        }
                    }
                }
            }
            Divider()
            Button("Open \(model.tab.title)", action: model.openApp).buttonStyle(.link).padding(10)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear(perform: model.appeared)
        .onDisappear(perform: model.disappeared)
        .accessibilityIdentifier("certifiedcopy-panel")
    }
}
