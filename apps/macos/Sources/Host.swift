// SPDX-License-Identifier: MIT OR Apache-2.0
import AppKit

/// Owns the status item, the tabs and the agents. Tabs come only from tray-core (TrayCore.tabs),
/// re-read whenever the tab directory changes.
final class Host: NSObject, NSApplicationDelegate {
    static let name = "Avarok"
    private let app: NSApplication
    private let policy: ActivationPolicyController
    private let loader: TabLoader
    private let agents: AgentRunner
    private let log: HostLog
    private var status: StatusItem?
    private var discovery = TrayCore.Discovery(tabs: [], refused: [], menu: [])

    init(app: NSApplication) {
        self.app = app
        policy = ActivationPolicyController(app: app)
        log = HostLog(name: "host")
        loader = TabLoader(directory: TabLoader.userTabDirectory(), log: log)
        agents = AgentRunner(log: log)
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let popover = TabPopover(size: NSSize(width: PanelSize.width, height: PanelSize.height)) { [weak self] tab in
            guard let self, let verified = self.discovery.tabs.first(where: { $0.id == tab.id }) else {
                return MessagePanel(text: "This tab is no longer installed.")
            }
            return Panels.make(for: verified, agents: self.agents, windows: self.policy)
        }
        let icon = NSImage(systemSymbolName: "square.grid.2x2", accessibilityDescription: Host.name)
        status = StatusItem(icon: icon, toolTip: Host.name, popover: popover) { [weak self] in
            self?.menu() ?? NSMenu()
        }
        loader.onChange = { [weak self] in self?.reload() }
        loader.start()
        reload()
    }

    private func reload() {
        do {
            discovery = try loader.load(startsAtLogin: LoginItem.isEnabled, hostName: Host.name)
        } catch {
            log.write("the tabs could not be read: \(error)")
            discovery = TrayCore.Discovery(tabs: [], refused: [], menu: [])
        }
        discovery.refused.forEach { log.write("refused \($0.file): \($0.reason)") }
        agents.keep(discovery.tabs)
        status?.popover.show(discovery.tabs.map { TrayTab(id: $0.id, title: $0.title, templatePNG: $0.icon) })
    }

    private func menu() -> NSMenu {
        let menu = NSMenu()
        for entry in discovery.menu {
            switch entry {
            case .separator: menu.addItem(.separator())
            case .header(let title, let status):
                let item = NSMenuItem(title: status.map { "\(title) — \($0)" } ?? title, action: nil, keyEquivalent: "")
                item.isEnabled = false
                menu.addItem(item)
            case .action(let title, let checked, let action):
                let item = NSMenuItem(title: title, action: #selector(chosen(_:)), keyEquivalent: "")
                item.target = self
                item.representedObject = ChosenAction(action)
                checked.map { item.state = $0 ? .on : .off }
                menu.addItem(item)
            }
        }
        return menu
    }

    @objc private func chosen(_ sender: NSMenuItem) {
        guard let action = (sender.representedObject as? ChosenAction)?.action else { return }
        switch action {
        case .tab(let tab, let id):
            guard let tab = discovery.tabs.first(where: { $0.id == tab }),
                  let chosen = tab.actions.first(where: { $0.id == id }) else { return }
            TabActions.perform(chosen, of: tab, log: log)
        case .restart(let tab):
            discovery.tabs.first { $0.id == tab }.map(agents.restart)
        case .toggleLogin:
            LoginItem.toggle(log: log)
            reload()
        case .showLog: NSWorkspace.shared.open(log.url)
        case .checkUpdates: log.write("update checks are not wired into the macOS host yet")
        case .quit: app.terminate(nil)
        }
    }

    func applicationWillTerminate(_ notification: Notification) { agents.stopAll() }
}

/// NSMenuItem.representedObject takes an object; MenuAction is an enum.
private final class ChosenAction {
    let action: MenuAction
    init(_ action: MenuAction) { self.action = action }
}

enum PanelSize {
    static let width: CGFloat = 380
    static let height: CGFloat = 460
}
