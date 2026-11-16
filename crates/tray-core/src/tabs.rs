// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tray menu, as data: generalised from Citadel's Windows `shell_menu.rs` (which was the Mac
//! menu bar's right-click menu, item for item) from one fixed app to any set of verified tabs.
//!
//! Each tab contributes a section: its title, its manifest's actions, and "Restart" only while
//! its agent has `failed` (the one state supervision will not leave by itself). The host's own
//! items follow. The widget carries [`MenuAction::id`] and hands it back when chosen;
//! [`MenuAction::from_id`] only accepts an id that names a tab and action in the current set.

use crate::model::{Tab, TabId};
use crate::supervise::AgentState;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuAction {
    Tab { tab: TabId, action: String },
    RestartAgent(TabId),
    ToggleLogin,
    ShowLog,
    CheckUpdates,
    Quit,
}

const FIXED: [MenuAction; 4] = [
    MenuAction::ToggleLogin,
    MenuAction::ShowLog,
    MenuAction::CheckUpdates,
    MenuAction::Quit,
];

impl MenuAction {
    pub fn id(&self) -> String {
        match self {
            Self::Tab { tab, action } => format!("tab/{tab}/{action}"),
            Self::RestartAgent(tab) => format!("restart/{tab}"),
            Self::ToggleLogin => "toggle-login".to_owned(),
            Self::ShowLog => "show-log".to_owned(),
            Self::CheckUpdates => "check-updates".to_owned(),
            Self::Quit => "quit".to_owned(),
        }
    }

    pub fn from_id(id: &str, tabs: &[Tab]) -> Option<Self> {
        if let Some(fixed) = FIXED.iter().find(|fixed| fixed.id() == id) {
            return Some(fixed.clone());
        }
        let find = |tab: &str| tabs.iter().find(|t| t.id.as_str() == tab);
        if let Some(tab) = id.strip_prefix("restart/") {
            return find(tab).map(|t| Self::RestartAgent(t.id.clone()));
        }
        let (tab, action) = id.strip_prefix("tab/")?.split_once('/')?;
        let tab = find(tab)?;
        tab.actions
            .iter()
            .any(|a| a.id == action)
            .then(|| Self::Tab {
                tab: tab.id.clone(),
                action: action.to_owned(),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// A tab's name, not selectable; `status` says why its agent is not running.
    Header {
        title: String,
        status: Option<String>,
    },
    Action {
        action: MenuAction,
        title: String,
        /// `Some` for an item with a check mark.
        checked: Option<bool>,
    },
    Separator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuState<'a> {
    pub agents: &'a BTreeMap<TabId, AgentState>,
    pub start_at_login: bool,
    /// The host's name in "Quit <host>".
    pub host_name: &'a str,
}

/// The menu, top to bottom.
pub fn entries(tabs: &[Tab], state: &MenuState<'_>) -> Vec<Entry> {
    let item = |action, title: String| Entry::Action {
        action,
        title,
        checked: None,
    };
    let mut menu = Vec::new();
    for tab in tabs {
        let agent = state.agents.get(&tab.id);
        menu.push(Entry::Header {
            title: tab.title.clone(),
            status: agent.and_then(status),
        });
        for action in &tab.actions {
            let chosen = MenuAction::Tab {
                tab: tab.id.clone(),
                action: action.id.clone(),
            };
            menu.push(item(chosen, action.title.clone()));
        }
        if matches!(agent, Some(AgentState::Failed { .. })) {
            let restart = MenuAction::RestartAgent(tab.id.clone());
            menu.push(item(restart, format!("Restart {}", tab.title)));
        }
        menu.push(Entry::Separator);
    }
    menu.push(Entry::Action {
        action: MenuAction::ToggleLogin,
        title: "Start at Login".to_owned(),
        checked: Some(state.start_at_login),
    });
    menu.push(item(MenuAction::ShowLog, "Show Log".to_owned()));
    menu.push(item(
        MenuAction::CheckUpdates,
        "Check for Updates\u{2026}".to_owned(),
    ));
    menu.push(Entry::Separator);
    menu.push(item(MenuAction::Quit, format!("Quit {}", state.host_name)));
    menu
}

/// What a header says about its agent; nothing while all is well.
pub fn status(state: &AgentState) -> Option<String> {
    match state {
        AgentState::Failed { reason } => Some(reason.clone()),
        AgentState::External => Some("Another copy is running".to_owned()),
        AgentState::BackingOff { .. } => Some("Restarting\u{2026}".to_owned()),
        _ => None,
    }
}
