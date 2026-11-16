// SPDX-License-Identifier: MIT OR Apache-2.0
//! tray-core's menu model as muda items. Each item's id is [`MenuAction::id`], so a chosen item
//! maps back through [`MenuAction::from_id`] against the current tabs and nothing else.

use tray_core::tabs::Entry;
use tray_icon::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};

pub fn build(entries: &[Entry]) -> Result<Menu, String> {
    let menu = Menu::new();
    for entry in entries {
        let added = match entry {
            Entry::Header { title, status } => {
                let text = status
                    .as_ref()
                    .map_or_else(|| title.clone(), |s| format!("{title} \u{2014} {s}"));
                menu.append(&MenuItem::new(text, false, None))
            }
            Entry::Separator => menu.append(&PredefinedMenuItem::separator()),
            Entry::Action {
                action,
                title,
                checked: Some(on),
            } => menu.append(&CheckMenuItem::with_id(action.id(), title, true, *on, None)),
            Entry::Action {
                action,
                title,
                checked: None,
            } => menu.append(&MenuItem::with_id(action.id(), title, true, None)),
        };
        added.map_err(|e| e.to_string())?;
    }
    Ok(menu)
}
