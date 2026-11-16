// SPDX-License-Identifier: MIT OR Apache-2.0
//! The safe core of the C ABI against the frozen contract fixtures in tray-core (one copy).

use ciborium::Value;
use std::path::{Path, PathBuf};
use tray_core::manifest::AppSection;
use tray_core::ports::{CodeSignature, PortError};

/// The OS code-signature port: the one call a native test cannot make for an app that is not
/// installed. It accepts the contract fixtures' team and nothing else.
struct TeamCheck(&'static str);
impl CodeSignature for TeamCheck {
    fn verify(&self, app: &AppSection) -> Result<(), PortError> {
        (app.macos_team_id.as_deref() == Some(self.0))
            .then_some(())
            .ok_or_else(|| PortError("unsigned".to_owned()))
    }
}

const HOST: tray_ffi::core::HostState<'static> = tray_ffi::core::HostState {
    start_at_login: false,
    host_name: b"Avarok",
};

fn contract() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tray-core/tests/contract")
}

fn test_publishers() -> Vec<u8> {
    let kat: serde_json::Value =
        serde_json::from_slice(&std::fs::read(contract().join("tray-tab-kat.json")).unwrap())
            .unwrap();
    let key = kat["publisher"]["pk_hex"].as_str().unwrap();
    tray_ffi::encode::to_bytes(&tray_ffi::encode::publishers(&[(
        "Avarok Cybersecurity".to_owned(),
        key.to_owned(),
    )]))
}

fn install(dir: &Path, fixture: &str, id: &str) {
    let from = contract().join("tray-tab-manifest").join(fixture);
    std::fs::copy(from, dir.join(format!("{id}.json"))).unwrap();
}

fn get<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
        .unwrap()
}

#[test]
fn the_tab_directory_comes_back_as_cbor_with_exactly_the_verified_tabs() {
    let dir = std::env::temp_dir().join(format!("tray-ffi-core-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    install(&dir, "valid-web-panel.json", "net.avarok.certifiedcopy");
    install(&dir, "valid-native-panel.json", "net.avarok.citadel-agent");
    install(&dir, "invalid-missing-sig.json", "net.avarok.unsigned");
    let reply = tray_ffi::core::tabs(
        dir.to_str().unwrap().as_bytes(),
        &test_publishers(),
        HOST,
        &TeamCheck("ABCDE12345"),
    );
    let reply: Value = ciborium::from_reader(reply.as_slice()).unwrap();
    let menu: Vec<&str> = get(&reply, "menu")
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| {
            e.as_map()
                .unwrap()
                .iter()
                .find(|(k, _)| k.as_text() == Some("title"))
        })
        .map(|(_, v)| v.as_text().unwrap())
        .collect();
    assert_eq!(
        menu,
        [
            "CertifiedCopy",
            "Open CertifiedCopy",
            "Citadel Workspaces",
            "Start at Login",
            "Show Log",
            "Check for Updates\u{2026}",
            "Quit Avarok"
        ]
    );
    let ids: Vec<&str> = get(&reply, "tabs")
        .as_array()
        .unwrap()
        .iter()
        .map(|t| get(t, "id").as_text().unwrap())
        .collect();
    assert_eq!(
        ids,
        ["net.avarok.certifiedcopy", "net.avarok.citadel-agent"]
    );
    let refused = get(&reply, "refused").as_array().unwrap();
    assert_eq!(refused.len(), 1);
    let native = &get(&reply, "tabs").as_array().unwrap()[1];
    assert_eq!(
        get(get(native, "panel"), "module").as_text(),
        Some("CitadelPanel")
    );
    let none = tray_ffi::core::tabs(
        dir.to_str().unwrap().as_bytes(),
        &test_publishers(),
        HOST,
        &TeamCheck("ZZZZZ99999"),
    );
    let none: Value = ciborium::from_reader(none.as_slice()).unwrap();
    assert!(get(&none, "tabs").as_array().unwrap().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_shipped_publishers_are_the_pinned_avarok_key_and_an_empty_list_trusts_nothing() {
    let list = tray_ffi::encode::parse_publishers(&tray_ffi::core::avarok_publishers()).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].0, tray_core::signature::AVAROK_PUBLISHER_NAME);
    let empty = tray_ffi::encode::to_bytes(&tray_ffi::encode::publishers(&[]));
    let reply = tray_ffi::core::tabs(b"/nonexistent", &empty, HOST, &TeamCheck("ABCDE12345"));
    let reply: Value = ciborium::from_reader(reply.as_slice()).unwrap();
    assert!(
        get(&reply, "error")
            .as_text()
            .unwrap()
            .contains("no publisher")
    );
}

#[test]
fn a_handshake_line_becomes_the_panel_url_and_anything_else_becomes_nothing() {
    let token = "k".repeat(43);
    let url = tray_ffi::core::panel_url(
        4823,
        b"/panel/",
        format!("AVAROK_PANEL_TOKEN={token}").as_bytes(),
    );
    assert_eq!(
        url,
        format!("http://127.0.0.1:4823/panel/?token={token}").into_bytes()
    );
    assert!(tray_ffi::core::panel_url(4823, b"/panel/", b"hello").is_empty());
}
