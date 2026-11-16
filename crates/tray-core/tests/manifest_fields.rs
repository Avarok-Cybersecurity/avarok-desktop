// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tab-manifest verifier, field rules: each refusal of a validly signed manifest on its own.
mod common;

use common::{FILE, OS_OK, linux, verdict, verifier};
use serde_json::json;
use tray_core::verify::{Platform, Refusal};
#[test]
fn linux_paths_outside_the_install_roots_are_refused() {
    for path in [
        "/tmp/certifiedcopy",
        "/usr/../tmp/x",
        "/usr/bin/../../etc/x",
        "/usr//bin/x",
        "/home/ada/.localx/bin",
        "usr/bin/x",
        "/home/bob/.local/bin/x",
    ] {
        let got = verdict(linux(), |d| d["app"]["linux_exec"] = json!(path));
        assert_eq!(
            got.unwrap_err(),
            Refusal::PathEscape(path.to_owned()),
            "{path}"
        );
    }
    assert!(
        verdict(linux(), |d| d["app"]["linux_exec"] =
            json!("/home/ada/.local/bin/cc"))
        .is_ok()
    );
}

#[test]
fn windows_paths_outside_the_install_roots_are_refused() {
    for path in [
        "C:\\Windows\\evil.exe",
        "%ProgramFiles%\\..\\evil.exe",
        "%ProgramFiles%\\CC\\..\\..\\evil.exe",
        "%ProgramFiles%\\CC\\cc.bat",
        "%ProgramFiles%\\CC/../x.exe",
        "%APPDATA%\\x.exe",
        "%ProgramFiles%\\C:\\x.exe",
    ] {
        let got = verdict(Platform::Windows, |d| d["app"]["windows_exe"] = json!(path));
        assert_eq!(
            got.unwrap_err(),
            Refusal::PathEscape(path.to_owned()),
            "{path}"
        );
    }
}

#[test]
fn an_id_that_could_escape_the_tab_directory_is_refused() {
    for id in [
        "../net.avarok.x",
        "net/avarok",
        "Net.Avarok.X",
        "avarok",
        "net..avarok",
    ] {
        let got = verdict(Platform::MacOs, |d| d["id"] = json!(id));
        assert_eq!(got.unwrap_err(), Refusal::BadId(id.to_owned()), "{id}");
    }
}

#[test]
fn a_manifest_under_another_tabs_file_name_is_refused() {
    let got = verdict(Platform::MacOs, |d| d["id"] = json!("net.avarok.other"));
    assert!(matches!(got.unwrap_err(), Refusal::FileNameMismatch { .. }));
}

#[test]
fn an_oversize_manifest_is_refused_before_it_is_parsed() {
    let mut big = b"{\"pad\":\"".to_vec();
    big.resize(64 * 1024 + 1, b'a');
    let got = verifier(Platform::MacOs).verify(FILE, &big, &OS_OK);
    assert!(matches!(
        got.unwrap_err(),
        Refusal::Oversize {
            what: "manifest",
            ..
        }
    ));
}

#[test]
fn an_oversize_icon_is_refused() {
    let got = verdict(Platform::MacOs, |d| {
        d["icon_template_png"] = json!(common::icon_png(16 * 1024))
    });
    assert!(matches!(
        got.unwrap_err(),
        Refusal::Oversize { what: "icon", .. }
    ));
    assert!(
        verdict(Platform::MacOs, |d| d["icon_template_png"] =
            json!(common::icon_png(16 * 1024 - 8)))
        .is_ok()
    );
}

#[test]
fn a_bad_bundle_id_is_refused() {
    for id in [
        "certifiedcopy",
        "net.avarok.cc;rm",
        "net..cc",
        "net.avarok/cc",
    ] {
        let got = verdict(Platform::MacOs, |d| d["app"]["macos_bundle_id"] = json!(id));
        assert_eq!(
            got.unwrap_err(),
            Refusal::BadBundleId(id.to_owned()),
            "{id}"
        );
    }
}

#[test]
fn a_panel_off_the_agents_loopback_port_is_refused() {
    for url in [
        "http://evil.example:4823/panel/",
        "http://127.0.0.1:4824/panel/",
        "https://127.0.0.1:4823/panel/",
        "http://127.0.0.1:4823@evil/",
        "http://127.0.0.1:48230/",
    ] {
        let got = verdict(Platform::MacOs, |d| d["panel"]["url"] = json!(url));
        assert_eq!(
            got.unwrap_err(),
            Refusal::NotLoopback(url.to_owned()),
            "{url}"
        );
    }
}

#[test]
fn an_unknown_field_is_refused_rather_than_ignored() {
    let got = verdict(Platform::MacOs, |d| {
        d["agent"]["env"] = json!({"DYLD_INSERT_LIBRARIES": "x"})
    });
    assert!(matches!(got.unwrap_err(), Refusal::Malformed(_)));
    let got = verdict(Platform::MacOs, |d| d["panel"]["extra"] = json!(1));
    assert!(matches!(got.unwrap_err(), Refusal::Malformed(_)));
}

#[test]
fn an_unknown_format_and_an_out_of_range_cap_are_refused() {
    assert_eq!(
        verdict(Platform::MacOs, |d| d["format"] = json!(2)).unwrap_err(),
        Refusal::UnsupportedFormat(2)
    );
    for cap in [0, 11] {
        let got = verdict(Platform::MacOs, |d| d["agent"]["crash_cap"] = json!(cap));
        assert!(matches!(got.unwrap_err(), Refusal::BadField(_)), "{cap}");
    }
}
