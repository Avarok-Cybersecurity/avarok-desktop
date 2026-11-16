// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tab-manifest verifier, signature and trust: one accepted manifest per platform, then each signature refusal.
mod common;

use common::{FILE, ID, OS_OK, Os, Publisher, bytes, linux, manifest_doc, verdict, verifier};
use serde_json::json;
use tray_core::model::{PanelSpec, Program};
use tray_core::signature::{SignedRefusal, TAB_MANIFEST_CONTEXT, UPDATE_MANIFEST_CONTEXT};
use tray_core::verify::{Platform, Refusal};
#[test]
fn a_signed_manifest_becomes_a_tab_on_each_platform() {
    let mac = verdict(Platform::MacOs, |_| {}).unwrap();
    assert!(matches!(mac, Program::MacBundle { ref team_id, .. } if team_id == "ABCDE12345"));
    assert!(matches!(
        verdict(Platform::Windows, |_| {}).unwrap(),
        Program::WindowsExe { .. }
    ));
    assert!(matches!(
        verdict(linux(), |_| {}).unwrap(),
        Program::LinuxExec { .. }
    ));
    let signed = Publisher::avarok().sign(manifest_doc(ID), TAB_MANIFEST_CONTEXT);
    let tab = verifier(Platform::MacOs)
        .verify(FILE, &bytes(&signed), &OS_OK)
        .unwrap();
    assert_eq!(
        tab.panel,
        PanelSpec::Web {
            port: 4823,
            path: "/panel/".to_owned(),
            token: tray_core::model::PanelToken::StdoutHandshake,
        }
    );
    assert_eq!(tab.actions[0].id, "open-main");
}

#[test]
fn an_unsigned_manifest_is_refused() {
    let mut doc = Publisher::avarok().sign(manifest_doc(ID), TAB_MANIFEST_CONTEXT);
    doc.as_object_mut().unwrap().remove("sig");
    let got = verifier(Platform::MacOs).verify(FILE, &bytes(&doc), &OS_OK);
    assert_eq!(
        got.unwrap_err(),
        Refusal::Signature(SignedRefusal::Unsigned)
    );
}

#[test]
fn a_foreign_publisher_is_refused_even_when_its_signature_is_valid() {
    let stranger = Publisher::new(9, tray_core::signature::AVAROK_PUBLISHER_NAME);
    let doc = stranger.sign(manifest_doc(ID), TAB_MANIFEST_CONTEXT);
    let got = verifier(Platform::MacOs).verify(FILE, &bytes(&doc), &OS_OK);
    assert_eq!(
        got.unwrap_err(),
        Refusal::Signature(SignedRefusal::ForeignPublisher)
    );
}

#[test]
fn a_pinned_key_under_another_name_is_refused() {
    let mut doc = Publisher::avarok().sign(manifest_doc(ID), TAB_MANIFEST_CONTEXT);
    doc["publisher"]["name"] = json!("Avarok Cybersecurity Ltd");
    let got = verifier(Platform::MacOs).verify(FILE, &bytes(&doc), &OS_OK);
    assert_eq!(
        got.unwrap_err(),
        Refusal::Signature(SignedRefusal::PublisherNameMismatch)
    );
}

#[test]
fn a_field_changed_after_signing_is_refused() {
    let mut doc = Publisher::avarok().sign(manifest_doc(ID), TAB_MANIFEST_CONTEXT);
    doc["app"]["linux_exec"] = json!("/usr/bin/evil");
    let got = verifier(linux()).verify(FILE, &bytes(&doc), &OS_OK);
    assert_eq!(
        got.unwrap_err(),
        Refusal::Signature(SignedRefusal::BadSignature)
    );
}

#[test]
fn an_update_manifest_signature_does_not_pass_as_a_tab_manifest() {
    let doc = Publisher::avarok().sign(manifest_doc(ID), UPDATE_MANIFEST_CONTEXT);
    let got = verifier(Platform::MacOs).verify(FILE, &bytes(&doc), &OS_OK);
    assert_eq!(
        got.unwrap_err(),
        Refusal::Signature(SignedRefusal::BadSignature)
    );
}

#[test]
fn key_order_and_whitespace_do_not_change_what_was_signed() {
    let doc = Publisher::avarok().sign(manifest_doc(ID), TAB_MANIFEST_CONTEXT);
    let pretty = serde_json::to_vec_pretty(&doc).unwrap();
    assert!(
        verifier(Platform::MacOs)
            .verify(FILE, &pretty, &OS_OK)
            .is_ok()
    );
}

#[test]
fn the_os_code_signature_verdict_is_final() {
    let doc = Publisher::avarok().sign(manifest_doc(ID), TAB_MANIFEST_CONTEXT);
    let got = verifier(Platform::MacOs).verify(FILE, &bytes(&doc), &Os(Some("team mismatch")));
    assert_eq!(
        got.unwrap_err(),
        Refusal::CodeSignature("team mismatch".to_owned())
    );
}

#[test]
fn a_host_with_no_pinned_publishers_refuses_to_build_its_trust_list() {
    assert_eq!(
        tray_core::signature::TrustedPublishers::new(&[]).unwrap_err(),
        SignedRefusal::NoPinnedPublishers
    );
}

#[test]
fn the_shipped_host_trusts_the_minted_avarok_key() {
    assert!(tray_core::signature::TrustedPublishers::avarok().is_ok());
}

#[test]
fn a_pinned_key_spelled_in_uppercase_is_not_the_pinned_key() {
    let mut doc = Publisher::avarok().sign(manifest_doc(ID), TAB_MANIFEST_CONTEXT);
    let upper = doc["publisher"]["mldsa65_public_key"]
        .as_str()
        .unwrap()
        .to_ascii_uppercase();
    doc["publisher"]["mldsa65_public_key"] = json!(upper);
    let got = verifier(Platform::MacOs).verify(FILE, &bytes(&doc), &OS_OK);
    assert_eq!(
        got.unwrap_err(),
        Refusal::Signature(SignedRefusal::ForeignPublisher)
    );
    let pinned = Publisher::avarok().key_hex().to_ascii_uppercase();
    assert!(matches!(
        tray_core::signature::TrustedPublishers::new(&[("Avarok Cybersecurity", &pinned)]),
        Err(SignedRefusal::MalformedKey(_))
    ));
}
