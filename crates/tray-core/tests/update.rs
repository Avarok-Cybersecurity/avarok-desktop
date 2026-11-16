// SPDX-License-Identifier: MIT OR Apache-2.0
//! Update checks: the signed feed, the download digest, the staged app's OS signature.
mod common;

use common::{Os, Publisher, bytes};
use serde_json::{Value, json};
use sha3::{Digest, Sha3_256};
use tray_core::signature::{SignedRefusal, TAB_MANIFEST_CONTEXT, UPDATE_MANIFEST_CONTEXT};
use tray_core::update::{
    UpdateDecision, UpdateRefusal, Version, check, verify_download, verify_staged,
};

const BUILD: &[u8] = b"the new build";
const TARGET: &str = "aarch64-apple-darwin";

fn feed(version: &str) -> Value {
    json!({
        "format": 1, "product": "avarok-desktop", "version": version,
        "notes_url": "https://avarok.net/desktop/releases",
        "assets": [{ "target": TARGET, "url": "https://downloads.avarok.net/Avarok.dmg",
                     "sha3_256": hex::encode(Sha3_256::digest(BUILD)), "size": BUILD.len() }]
    })
}

fn decide(doc: Value, context: &str) -> Result<UpdateDecision, UpdateRefusal> {
    let avarok = Publisher::avarok();
    let signed = avarok.sign(doc, context);
    check(
        &bytes(&signed),
        &avarok.trusted(),
        "avarok-desktop",
        Version(0, 1, 0),
        TARGET,
    )
}

#[test]
fn a_newer_signed_release_is_offered_and_its_download_verifies() {
    let Ok(UpdateDecision::Available { version, asset, .. }) =
        decide(feed("0.2.0"), UPDATE_MANIFEST_CONTEXT)
    else {
        panic!("no update offered");
    };
    assert_eq!(version, Version(0, 2, 0));
    assert_eq!(verify_download(&asset, BUILD), Ok(()));
    assert_eq!(
        verify_download(&asset, b"the new buil!"),
        Err(UpdateRefusal::DigestMismatch)
    );
    assert!(matches!(
        verify_download(&asset, b"short"),
        Err(UpdateRefusal::SizeMismatch { .. })
    ));
}

#[test]
fn the_same_or_an_older_version_is_never_offered() {
    for v in ["0.1.0", "0.0.9"] {
        assert_eq!(
            decide(feed(v), UPDATE_MANIFEST_CONTEXT),
            Ok(UpdateDecision::UpToDate),
            "{v}"
        );
    }
}

#[test]
fn a_tab_manifest_signature_is_not_an_update_signature() {
    let got = decide(feed("0.2.0"), TAB_MANIFEST_CONTEXT);
    assert_eq!(
        got,
        Err(UpdateRefusal::Signature(SignedRefusal::BadSignature))
    );
}

#[test]
fn a_feed_signed_by_a_stranger_is_refused() {
    let signed =
        Publisher::new(9, "Avarok Cybersecurity").sign(feed("9.9.9"), UPDATE_MANIFEST_CONTEXT);
    let got = check(
        &bytes(&signed),
        &Publisher::avarok().trusted(),
        "avarok-desktop",
        Version(0, 1, 0),
        TARGET,
    );
    assert_eq!(
        got,
        Err(UpdateRefusal::Signature(SignedRefusal::ForeignPublisher))
    );
}

#[test]
fn plain_http_another_product_and_bad_versions_are_refused() {
    let mut http = feed("0.2.0");
    http["assets"][0]["url"] = json!("http://downloads.avarok.net/Avarok.dmg");
    assert!(matches!(
        decide(http, UPDATE_MANIFEST_CONTEXT),
        Err(UpdateRefusal::NotHttps(_))
    ));
    let mut other = feed("0.2.0");
    other["product"] = json!("certifiedcopy");
    assert!(matches!(
        decide(other, UPDATE_MANIFEST_CONTEXT),
        Err(UpdateRefusal::WrongProduct(_))
    ));
    for v in ["0.2", "0.2.0-beta", "v0.2.0", "0.2.0.1", "+1.0.0"] {
        assert!(
            matches!(
                decide(feed(v), UPDATE_MANIFEST_CONTEXT),
                Err(UpdateRefusal::BadVersion(_))
            ),
            "{v}"
        );
    }
    let mut none = feed("0.2.0");
    none["assets"][0]["target"] = json!("x86_64-pc-windows-msvc");
    assert_eq!(
        decide(none, UPDATE_MANIFEST_CONTEXT),
        Err(UpdateRefusal::NoAssetForTarget)
    );
}

#[test]
fn the_staged_app_must_pass_the_os_check() {
    let app = serde_json::from_value(
        json!({"macos_bundle_id": "net.avarok.desktop", "macos_team_id": "ABCDE12345",
        "windows_exe": null, "windows_publisher_thumbprint": null, "linux_exec": null}),
    )
    .unwrap();
    assert_eq!(verify_staged(&common::OS_OK, &app), Ok(()));
    assert_eq!(
        verify_staged(&Os(Some("not notarised")), &app),
        Err(UpdateRefusal::CodeSignature("not notarised".to_owned()))
    );
}
