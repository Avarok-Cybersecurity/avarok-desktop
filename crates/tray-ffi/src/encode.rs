// SPDX-License-Identifier: MIT OR Apache-2.0
//! The CBOR the Swift host decodes. Text keys, unsigned integers, text, bytes, booleans, arrays,
//! maps: the subset TrayKit's decoder reads.
//!
//! ```text
//! tabs reply   = {"tabs": [tab], "refused": [{"file": text, "reason": text}], "menu": [entry]}
//!              | {"error": text}
//! entry        = {"kind": "header", "title", ? "status"} | {"kind": "separator"}
//!              | {"kind": "action", "title", ? "checked": bool, "action": menu action}
//! menu action  = {"id", "kind": "tab", "tab", "action"} | {"id", "kind": "restart", "tab"}
//!              | {"id", "kind": "toggle-login" | "show-log" | "check-updates" | "quit"}
//! tab          = {"id", "title", "icon": bytes, "agent": agent, "panel": panel, "actions": [action]}
//! agent        = {"bundle_id", "team_id", "argv": [text], "port": uint, "crash_cap": uint}
//! panel        = {"kind": "web", "port": uint, "path": text} | {"kind": "native", "module": text}
//! action       = {"id", "title", "open_bundle": bool, ? "fragment": text}
//! publishers   = [[name, key hex]]
//! ```

use ciborium::Value;
use tray_core::discover::Discovered;
use tray_core::model::{Action, PanelSpec, Program, Tab};
use tray_core::tabs::{Entry, MenuAction};

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
}

pub fn to_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    // Writing a Value into a Vec cannot fail: there is no I/O and every Value is encodable.
    ciborium::into_writer(value, &mut out).unwrap_or_else(|e| unreachable!("CBOR into Vec: {e}"));
    out
}

pub fn discovered(found: &Discovered, menu: &[Entry]) -> Value {
    let refused = found
        .refused
        .iter()
        .map(|(file, why)| {
            map(vec![
                ("file", text(file)),
                ("reason", text(&why.to_string())),
            ])
        })
        .collect();
    map(vec![
        ("tabs", Value::Array(found.tabs.iter().map(tab).collect())),
        ("refused", Value::Array(refused)),
        ("menu", Value::Array(menu.iter().map(entry).collect())),
    ])
}

fn entry(e: &Entry) -> Value {
    match e {
        Entry::Header { title, status } => {
            let mut fields = vec![("kind", text("header")), ("title", text(title))];
            if let Some(status) = status {
                fields.push(("status", text(status)));
            }
            map(fields)
        }
        Entry::Separator => map(vec![("kind", text("separator"))]),
        Entry::Action {
            action,
            title,
            checked,
        } => {
            let mut fields = vec![
                ("kind", text("action")),
                ("title", text(title)),
                ("action", menu_action(action)),
            ];
            if let Some(checked) = checked {
                fields.push(("checked", Value::Bool(*checked)));
            }
            map(fields)
        }
    }
}

fn menu_action(a: &MenuAction) -> Value {
    let id = ("id", text(&a.id()));
    match a {
        MenuAction::Tab { tab, action } => map(vec![
            id,
            ("kind", text("tab")),
            ("tab", text(tab.as_str())),
            ("action", text(action)),
        ]),
        MenuAction::RestartAgent(tab) => map(vec![
            id,
            ("kind", text("restart")),
            ("tab", text(tab.as_str())),
        ]),
        MenuAction::ToggleLogin => map(vec![id, ("kind", text("toggle-login"))]),
        MenuAction::ShowLog => map(vec![id, ("kind", text("show-log"))]),
        MenuAction::CheckUpdates => map(vec![id, ("kind", text("check-updates"))]),
        MenuAction::Quit => map(vec![id, ("kind", text("quit"))]),
    }
}

pub fn error(why: &str) -> Value {
    map(vec![("error", text(why))])
}

fn tab(t: &Tab) -> Value {
    let (bundle_id, team_id) = match &t.agent.program {
        Program::MacBundle { bundle_id, team_id } => (bundle_id.as_str(), team_id.as_str()),
        // The C ABI verifies for macOS only, so a tab here always holds a bundle.
        Program::WindowsExe { .. } | Program::LinuxExec { .. } => ("", ""),
    };
    let tray_core::model::ReadyProbe::Tcp { port } = t.agent.ready;
    let agent = map(vec![
        ("bundle_id", text(bundle_id)),
        ("team_id", text(team_id)),
        (
            "argv",
            Value::Array(t.agent.argv.iter().map(|a| text(a)).collect()),
        ),
        ("port", Value::Integer(port.into())),
        ("crash_cap", Value::Integer(t.agent.crash_cap.into())),
    ]);
    let panel = match &t.panel {
        PanelSpec::Web { port, path, .. } => map(vec![
            ("kind", text("web")),
            ("port", Value::Integer((*port).into())),
            ("path", text(path)),
        ]),
        PanelSpec::Native { macos_module } => map(vec![
            ("kind", text("native")),
            ("module", text(macos_module)),
        ]),
    };
    map(vec![
        ("id", text(t.id.as_str())),
        ("title", text(&t.title)),
        ("icon", Value::Bytes(t.icon.clone())),
        ("agent", agent),
        ("panel", panel),
        (
            "actions",
            Value::Array(t.actions.iter().map(action).collect()),
        ),
    ])
}

fn action(a: &Action) -> Value {
    let mut entries = vec![
        ("id", text(&a.id)),
        ("title", text(&a.title)),
        ("open_bundle", Value::Bool(a.launch.macos_open_bundle)),
    ];
    if let Some(fragment) = &a.launch.url_fragment {
        entries.push(("fragment", text(fragment)));
    }
    map(entries)
}

pub fn publishers(list: &[(String, String)]) -> Value {
    Value::Array(
        list.iter()
            .map(|(name, key)| Value::Array(vec![text(name), text(key)]))
            .collect(),
    )
}

/// The `[[name, key hex]]` list the host passed in.
pub fn parse_publishers(bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    let value: Value = ciborium::from_reader(bytes).map_err(|e| e.to_string())?;
    let Value::Array(items) = value else {
        return Err("the publisher list is not an array".to_owned());
    };
    items
        .into_iter()
        .map(|item| match item {
            Value::Array(pair) => match pair.as_slice() {
                [Value::Text(name), Value::Text(key)] => Ok((name.clone(), key.clone())),
                _ => Err("a publisher is not [name, key]".to_owned()),
            },
            _ => Err("a publisher is not [name, key]".to_owned()),
        })
        .collect()
}
