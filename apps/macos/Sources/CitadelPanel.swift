// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit
import SwiftUI

/// The Citadel tab: the accounts on this Mac, connected first, each opening Citadel Workspaces.
final class CitadelPanelModel: ObservableObject {
    @Published private(set) var accounts: [CitadelAccount] = []
    /// Nothing is said about accounts until the agent has been asked once.
    @Published private(set) var state: State = .asking
    enum State: Equatable { case asking, answered, unreachable }

    let tab: VerifiedTab
    private let client: CitadelAgentClient
    private var timer: Timer?

    init(tab: VerifiedTab) {
        self.tab = tab
        client = CitadelAgentClient(port: tab.agent.port, timeout: 5)
    }

    var sorted: [CitadelAccount] {
        accounts.sorted { $0.connected != $1.connected ? $0.connected : $0.username.localizedCaseInsensitiveCompare($1.username) == .orderedAscending }
    }

    func appeared() {
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in self?.refresh() }
    }

    func disappeared() {
        timer?.invalidate()
        timer = nil
    }

    private func refresh() {
        client.read { [weak self] found in
            guard let self else { return }
            if let found { self.accounts = found; self.state = .answered } else { self.state = .unreachable }
        }
    }

    /// The Citadel app knows the workspace; the host only brings it forward.
    func open() {
        guard let main = tab.actions.first(where: \.opensBundle) else { return }
        TabActions.perform(main, of: tab, log: HostLog(name: tab.id))
    }
}

struct CitadelPanelView: View {
    @ObservedObject var model: CitadelPanelModel

    var body: some View {
        VStack(spacing: 0) {
            switch model.state {
            case .asking: Note(title: "Asking the Citadel agent\u{2026}", detail: nil)
            case .unreachable: Note(title: "The Citadel agent is not answering", detail: "It starts with Citadel Agent; the log says why it stopped.")
            case .answered where model.accounts.isEmpty: Note(title: "No accounts on this Mac", detail: "Sign in to a workspace and it will appear here.")
            case .answered:
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(model.sorted) { account in
                            AccountLine(account: account, open: model.open)
                            Divider()
                        }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear(perform: model.appeared)
        .onDisappear(perform: model.disappeared)
        .accessibilityIdentifier("citadel-panel")
    }
}

private struct AccountLine: View {
    let account: CitadelAccount
    let open: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Circle().fill(Color.accentColor.opacity(0.25)).frame(width: 36, height: 36)
                .overlay(Text(String((account.fullName.isEmpty ? account.username : account.fullName).prefix(1)).uppercased()).font(.headline))
            VStack(alignment: .leading, spacing: 2) {
                Text(account.username).font(.system(size: 14, weight: .medium)).lineLimit(1)
                Text(account.workspaceHost ?? (account.fullName.isEmpty ? "Workspace unknown" : account.fullName))
                    .font(.system(size: 11)).foregroundColor(.secondary).lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: 8)
            if account.connected {
                Label("Connected", systemImage: "circle.fill").font(.system(size: 11)).foregroundColor(.green)
            } else {
                Button("Log in", action: open).controlSize(.small).accessibilityLabel("Log in as \(account.username)")
            }
        }
        .padding(.horizontal, 14).frame(height: 60)
        .contentShape(Rectangle())
        .onTapGesture(perform: open)
    }
}

/// A short title and an optional line under it, centred, in place of a list.
struct Note: View {
    let title: String
    let detail: String?

    var body: some View {
        VStack(spacing: 6) {
            Spacer()
            Text(title).font(.system(size: 14, weight: .medium))
            if let detail { Text(detail).font(.system(size: 12)).foregroundColor(.secondary).multilineTextAlignment(.center) }
            Spacer()
        }
        .padding(.horizontal, 24)
    }
}
