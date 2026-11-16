// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tab menu and the single-instance handshake.
mod common;

use common::{OS_OK, Publisher, bytes, manifest_doc};
use std::cell::RefCell;
use std::collections::BTreeMap;
use tray_core::model::{Tab, TabId};
use tray_core::ports::{InstanceLock, LockOutcome, PortError, WakeChannel};
use tray_core::signature::TAB_MANIFEST_CONTEXT;
use tray_core::single_instance::{LockName, MAX_WAKE_BYTES, Role, Wake, claim};
use tray_core::supervise::AgentState;
use tray_core::tabs::{Entry, MenuAction, MenuState, entries};
use tray_core::verify::{Platform, Verifier};

fn tab(id: &str, title: &str) -> Tab {
    let mut doc = manifest_doc(id);
    doc["title"] = serde_json::json!(title);
    let signed = Publisher::avarok().sign(doc, TAB_MANIFEST_CONTEXT);
    let verifier = Verifier {
        platform: Platform::MacOs,
        trusted: Publisher::avarok().trusted(),
    };
    verifier
        .verify(&format!("{id}.json"), &bytes(&signed), &OS_OK)
        .unwrap()
}

fn titles(menu: &[Entry]) -> Vec<String> {
    menu.iter()
        .map(|e| match e {
            Entry::Header { title, status } => format!(
                "[{title}{}]",
                status.as_ref().map_or(String::new(), |s| format!(": {s}"))
            ),
            Entry::Action {
                title,
                checked: Some(on),
                ..
            } => format!("{title} ({on})"),
            Entry::Action { title, .. } => title.clone(),
            Entry::Separator => "-".to_owned(),
        })
        .collect()
}

#[test]
fn each_tab_contributes_a_section_and_restart_only_when_failed() {
    let tabs = [
        tab("net.avarok.certifiedcopy", "CertifiedCopy"),
        tab("net.avarok.citadel", "Citadel"),
    ];
    let failed = AgentState::Failed {
        reason: "It keeps stopping.".to_owned(),
    };
    let agents = BTreeMap::from([(tabs[1].id.clone(), failed)]);
    let state = MenuState {
        agents: &agents,
        start_at_login: true,
        host_name: "Avarok",
    };
    assert_eq!(
        titles(&entries(&tabs, &state)),
        [
            "[CertifiedCopy]",
            "Open CertifiedCopy",
            "-",
            "[Citadel: It keeps stopping.]",
            "Open CertifiedCopy",
            "Restart Citadel",
            "-",
            "Start at Login (true)",
            "Show Log",
            "Check for Updates\u{2026}",
            "-",
            "Quit Avarok",
        ]
    );
}

#[test]
fn with_no_tabs_only_the_hosts_own_items_remain() {
    let agents = BTreeMap::new();
    let state = MenuState {
        agents: &agents,
        start_at_login: false,
        host_name: "Avarok",
    };
    assert_eq!(
        titles(&entries(&[], &state)),
        [
            "Start at Login (false)",
            "Show Log",
            "Check for Updates\u{2026}",
            "-",
            "Quit Avarok"
        ]
    );
}

#[test]
fn every_menu_id_round_trips_and_stale_ids_are_refused() {
    let tabs = [tab("net.avarok.certifiedcopy", "CertifiedCopy")];
    let failed = AgentState::Failed {
        reason: "x".to_owned(),
    };
    let agents = BTreeMap::from([(tabs[0].id.clone(), failed)]);
    let state = MenuState {
        agents: &agents,
        start_at_login: false,
        host_name: "Avarok",
    };
    for entry in entries(&tabs, &state) {
        if let Entry::Action { action, .. } = entry {
            assert_eq!(MenuAction::from_id(&action.id(), &tabs), Some(action));
        }
    }
    for stale in [
        "tab/net.avarok.gone/open-main",
        "tab/net.avarok.certifiedcopy/delete-all",
        "restart/net.avarok.gone",
        "tab/net.avarok.certifiedcopy",
        "",
        "quit ",
    ] {
        assert_eq!(MenuAction::from_id(stale, &tabs), None, "{stale}");
    }
}

#[test]
fn wake_messages_round_trip_and_anything_else_is_ignored() {
    let id = TabId::parse("net.avarok.citadel").unwrap();
    for wake in [Wake::Show, Wake::ShowTab(id)] {
        assert_eq!(Wake::decode(&wake.encode()), Some(wake));
    }
    let long = format!("avarok-wake-v1 show-tab net.{}", "a".repeat(MAX_WAKE_BYTES));
    for junk in [
        "show",
        "avarok-wake-v1 quit",
        "avarok-wake-v1 show-tab ../x",
        "avarok-wake-v1 show ",
        long.as_str(),
    ] {
        assert_eq!(Wake::decode(junk.as_bytes()), None, "{junk}");
    }
}

struct Lock(LockOutcome);
impl InstanceLock for Lock {
    fn try_acquire(&mut self, _: &LockName) -> Result<LockOutcome, PortError> {
        Ok(self.0)
    }
}

#[derive(Default)]
struct Channel(RefCell<Vec<Vec<u8>>>);
impl WakeChannel for Channel {
    fn send(&self, _: &LockName, message: &[u8]) -> Result<(), PortError> {
        self.0.borrow_mut().push(message.to_vec());
        Ok(())
    }
}

#[test]
fn the_first_launch_is_primary_and_a_second_wakes_it() {
    let name = LockName::new("net.avarok.desktop", "501").unwrap();
    let channel = Channel::default();
    assert_eq!(
        claim(
            &mut Lock(LockOutcome::Acquired),
            &channel,
            &name,
            &Wake::Show
        ),
        Ok(Role::Primary)
    );
    assert!(channel.0.borrow().is_empty());
    assert_eq!(
        claim(
            &mut Lock(LockOutcome::HeldElsewhere),
            &channel,
            &name,
            &Wake::Show
        ),
        Ok(Role::Forwarded)
    );
    assert_eq!(channel.0.borrow().as_slice(), [Wake::Show.encode()]);
}

#[test]
fn a_lock_name_cannot_carry_a_path() {
    assert!(LockName::new("net.avarok.desktop", "../../tmp").is_err());
    assert!(LockName::new("net/avarok", "501").is_err());
    assert_eq!(
        LockName::new("net.avarok.desktop", "S-1-5-21")
            .unwrap()
            .as_str(),
        "net.avarok.desktop.S-1-5-21"
    );
}
