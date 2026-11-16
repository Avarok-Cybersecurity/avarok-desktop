// SPDX-License-Identifier: MIT OR Apache-2.0
//! The frozen batch-1116 contract fixtures (`tests/contract/`, copied unchanged from
//! `docs/contracts/batch-1116/` in the parent repository) run through the real verifiers, signed
//! by the contract's TEST publisher key. Every valid fixture passes; every invalid one is refused
//! with the refusal the table names, on every platform, because a field's shape never depends on
//! which OS reads it.
mod common;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::OS_OK;
use ml_dsa::{MlDsa65, Seed, SigningKey};
use std::path::PathBuf;
use tray_core::canonical;
use tray_core::signature::{AVAROK_PUBLISHER_NAME, SignedRefusal, TrustedPublishers};
use tray_core::signature::{TAB_MANIFEST_CONTEXT, UPDATE_MANIFEST_CONTEXT};
use tray_core::update::{self, UpdateDecision, UpdateRefusal, Version};
use tray_core::verify::{Platform, Refusal, Verifier};

fn contract_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contract")
}

pub fn kat() -> serde_json::Value {
    let text = std::fs::read(contract_dir().join("tray-tab-kat.json")).unwrap();
    serde_json::from_slice(&text).unwrap()
}

fn contract_trust() -> TrustedPublishers {
    let pk = kat()["publisher"]["pk_hex"].as_str().unwrap().to_owned();
    TrustedPublishers::new(&[(AVAROK_PUBLISHER_NAME, pk.as_str())]).unwrap()
}

fn fixture(dir: &str, name: &str) -> Vec<u8> {
    std::fs::read(contract_dir().join(dir).join(name)).unwrap()
}

/// The frozen invalid fixtures carry the valid document's signature, so as shipped they only
/// reach the signature gate. Re-signing each with the contract's published TEST seed, under the
/// key and name it already claims, makes the rule its name promises the one that refuses it. A
/// fixture with no `sig`, or one that cannot be canonicalised, is left as it is.
fn resigned(bytes: &[u8], context: &str) -> Vec<u8> {
    let mut doc: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let Ok(message) = canonical::signed_bytes(&doc, "sig") else {
        return bytes.to_vec();
    };
    if doc.get("sig").is_none() {
        return bytes.to_vec();
    }
    let xi: [u8; 32] = hex::decode(kat()["publisher"]["xi_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sig = SigningKey::<MlDsa65>::from_seed(&Seed::from(xi))
        .expanded_key()
        .sign_deterministic(&message, context.as_bytes())
        .unwrap();
    doc["sig"] = URL_SAFE_NO_PAD.encode(sig.encode().as_slice()).into();
    serde_json::to_vec(&doc).unwrap()
}

fn fixture_names(dir: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(contract_dir().join(dir))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    names
}

fn platforms() -> [Platform; 3] {
    [
        Platform::MacOs,
        Platform::Windows,
        Platform::Linux {
            home: "/home/ada".to_owned(),
        },
    ]
}

/// The refusal each invalid tab fixture must produce, by variant.
fn expected_tab_refusal(name: &str) -> fn(&Refusal) -> bool {
    match name {
        "invalid-missing-sig.json" => |r| *r == Refusal::Signature(SignedRefusal::Unsigned),
        "invalid-publisher-key-not-hex.json" => {
            |r| *r == Refusal::Signature(SignedRefusal::ForeignPublisher)
        }
        "invalid-app-null-field.json" => {
            |r| matches!(r, Refusal::Signature(SignedRefusal::NotCanonical(_)))
        }
        "invalid-format-2.json" => |r| *r == Refusal::UnsupportedFormat(2),
        "invalid-id-not-reverse-dns.json" | "invalid-id-path-escape.json" => {
            |r| matches!(r, Refusal::BadId(_))
        }
        "invalid-panel-kind.json"
        | "invalid-ready-kind.json"
        | "invalid-unknown-app-field.json"
        | "invalid-unknown-field.json" => |r| matches!(r, Refusal::Malformed(_)),
        "invalid-panel-not-loopback.json" => |r| matches!(r, Refusal::NotLoopback(_)),
        "invalid-icon-oversize.json" => |r| matches!(r, Refusal::Oversize { what: "icon", .. }),
        "invalid-linux-exec-outside-roots.json"
        | "invalid-windows-exe-dotdot.json"
        | "invalid-windows-exe-outside-roots.json" => |r| matches!(r, Refusal::PathEscape(_)),
        "invalid-app-empty.json" => |r| matches!(r, Refusal::IncompleteApp(_)),
        _ => |r| matches!(r, Refusal::BadField(_)),
    }
}

#[test]
fn every_tab_fixture_gets_the_verdict_its_name_promises_on_every_platform() {
    let names = fixture_names("tray-tab-manifest");
    assert_eq!(names.len(), 30, "the frozen set has 2 valid and 28 invalid");
    let mut wrong = Vec::new();
    for platform in platforms() {
        let verifier = Verifier {
            platform: platform.clone(),
            trusted: contract_trust(),
        };
        for name in &names {
            let shipped = fixture("tray-tab-manifest", name);
            let file = manifest_file_name(&shipped);
            let valid = name.starts_with("valid-");
            if !valid && verifier.verify(&file, &shipped, &OS_OK).is_ok() {
                wrong.push(format!("{name} {platform:?}: accepted as shipped"));
            }
            let got = verifier.verify(&file, &resigned(&shipped, TAB_MANIFEST_CONTEXT), &OS_OK);
            let native_off_mac = name == "valid-native-panel.json" && platform != Platform::MacOs;
            let ok = match &got {
                Ok(_) => valid && !native_off_mac,
                Err(r) if native_off_mac => *r == Refusal::NoAppForPlatform,
                Err(r) => !valid && expected_tab_refusal(name)(r),
            };
            if !ok {
                wrong.push(format!("{name} {platform:?}: {got:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The file name the fixture's own id asks for, so only the field under test can fail.
fn manifest_file_name(bytes: &[u8]) -> String {
    let doc: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    format!("{}.json", doc["id"].as_str().unwrap_or("x"))
}

fn decide(bytes: &[u8], current: Version) -> Result<UpdateDecision, UpdateRefusal> {
    update::check(
        bytes,
        &contract_trust(),
        "net.avarok.certifiedcopy",
        current,
        "macos-aarch64",
    )
}

fn expected_update_refusal(name: &str) -> fn(&UpdateRefusal) -> bool {
    match name {
        "invalid-missing-sig.json" => |r| *r == UpdateRefusal::Signature(SignedRefusal::Unsigned),
        "invalid-http-asset.json" | "invalid-http-notes.json" => {
            |r| matches!(r, UpdateRefusal::NotHttps(_))
        }
        "invalid-version-prefix.json" | "invalid-version-two-parts.json" => {
            |r| matches!(r, UpdateRefusal::BadVersion(_))
        }
        _ => |r| matches!(r, UpdateRefusal::Malformed(_)),
    }
}

#[test]
fn every_update_fixture_gets_its_verdict_whether_or_not_it_is_newer() {
    let names = fixture_names("update-manifest");
    assert_eq!(names.len(), 11, "the frozen set has 1 valid and 10 invalid");
    let mut wrong = Vec::new();
    for current in [Version(1, 0, 0), Version(9, 9, 9)] {
        for name in &names {
            let shipped = fixture("update-manifest", name);
            let valid = name.starts_with("valid-");
            if !valid && decide(&shipped, current).is_ok() {
                wrong.push(format!("{name} {current}: accepted as shipped"));
            }
            let got = decide(&resigned(&shipped, UPDATE_MANIFEST_CONTEXT), current);
            let ok = match &got {
                Ok(UpdateDecision::Available { .. }) => valid && current < Version(1, 2, 3),
                Ok(UpdateDecision::UpToDate) => valid && current >= Version(1, 2, 3),
                Err(r) => !valid && expected_update_refusal(name)(r),
            };
            if !ok {
                wrong.push(format!("{name} {current}: {got:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
