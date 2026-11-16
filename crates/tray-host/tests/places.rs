// SPDX-License-Identifier: MIT OR Apache-2.0
//! Where the host looks for tabs, from an explicit environment.

use std::path::PathBuf;
use tray_core::verify::Platform;
use tray_host::places::{platform, tab_directory};

fn env(vars: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    move |name| {
        vars.iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| (*v).to_owned())
    }
}

#[test]
fn each_platform_reads_its_own_directory_and_a_missing_variable_is_an_error() {
    let linux = platform("linux", &env(&[("HOME", "/home/ada")])).unwrap();
    assert_eq!(
        tab_directory(&linux, &env(&[])).unwrap(),
        PathBuf::from("/home/ada/.local/share/avarok/tabs")
    );
    assert_eq!(
        tab_directory(&linux, &env(&[("XDG_DATA_HOME", "/data")])).unwrap(),
        PathBuf::from("/data/avarok/tabs")
    );
    assert!(platform("linux", &env(&[])).is_err());
    assert!(tab_directory(&Platform::Windows, &env(&[])).is_err());
    assert_eq!(
        tab_directory(
            &Platform::Windows,
            &env(&[("LOCALAPPDATA", "C:\\Users\\ada\\AppData\\Local")])
        )
        .unwrap(),
        PathBuf::from("C:\\Users\\ada\\AppData\\Local")
            .join("Avarok")
            .join("tabs")
    );
    assert!(
        platform("macos", &env(&[]))
            .unwrap_err()
            .contains("Avarok.app")
    );
}

#[test]
fn a_windows_app_is_refused_until_authenticode_is_wired() {
    use tray_core::ports::CodeSignature;
    let os = tray_host::signature::HostSignature::for_platform(&Platform::Windows).unwrap();
    let app: tray_core::manifest::AppSection = serde_json::from_value(serde_json::json!({
        "windows_exe": "%ProgramFiles%\\X\\x.exe", "windows_publisher_thumbprint": "ab".repeat(32),
        "macos_bundle_id": null, "macos_team_id": null, "linux_exec": null
    }))
    .unwrap();
    assert!(os.verify(&app).is_err());
}
