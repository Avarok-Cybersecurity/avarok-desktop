// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every known-answer value in the frozen `tray-tab-kat.json`: the TEST key from its published
//! seed, the deterministic CBOR each fixture signs, the deterministic ML-DSA-65 signature over it
//! under each context, the decoded icon and the asset digest. A value that drifts here means a
//! signer in another language would no longer produce manifests this host accepts.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ml_dsa::{KeyExport, Keypair, MlDsa65, Seed, SigningKey};
use std::path::PathBuf;
use tray_core::canonical;
use tray_core::signature::{
    AVAROK_PUBLISHER_NAME, TAB_MANIFEST_CONTEXT, TrustedPublishers, UPDATE_MANIFEST_CONTEXT,
};
use tray_core::update::{self, UpdateDecision, Version};
use tray_core::verify::{Platform, Verifier};

struct AcceptAll;
impl tray_core::ports::CodeSignature for AcceptAll {
    fn verify(
        &self,
        _app: &tray_core::manifest::AppSection,
    ) -> Result<(), tray_core::ports::PortError> {
        Ok(())
    }
}

fn read(rel: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/contract")
            .join(rel),
    )
    .unwrap()
}

fn json(rel: &str) -> serde_json::Value {
    serde_json::from_slice(&read(rel)).unwrap()
}

fn hex_field(v: &serde_json::Value, path: &[&str]) -> Vec<u8> {
    let s = path.iter().fold(v, |v, k| &v[*k]).as_str().unwrap();
    hex::decode(s).unwrap()
}

fn test_key(kat: &serde_json::Value) -> SigningKey<MlDsa65> {
    let xi: [u8; 32] = hex_field(kat, &["publisher", "xi_hex"]).try_into().unwrap();
    SigningKey::<MlDsa65>::from_seed(&Seed::from(xi))
}

#[test]
fn the_published_seed_expands_to_the_published_key() {
    let kat = json("tray-tab-kat.json");
    let pk = test_key(&kat).verifying_key().to_bytes();
    assert_eq!(pk.as_slice(), hex_field(&kat, &["publisher", "pk_hex"]));
}

/// (fixture, KAT path to its signed CBOR, context)
const CASES: &[(&str, &[&str], &str)] = &[
    (
        "tray-tab-manifest/valid-web-panel.json",
        &["tab_manifest", "web_panel_signed_cbor_hex"],
        TAB_MANIFEST_CONTEXT,
    ),
    (
        "tray-tab-manifest/valid-native-panel.json",
        &["tab_manifest", "native_panel_signed_cbor_hex"],
        TAB_MANIFEST_CONTEXT,
    ),
    (
        "update-manifest/valid-release.json",
        &["update_manifest", "signed_cbor_hex"],
        UPDATE_MANIFEST_CONTEXT,
    ),
];

#[test]
fn each_fixture_signs_the_published_cbor_and_the_signature_is_reproduced() {
    let kat = json("tray-tab-kat.json");
    assert_eq!(kat["tab_manifest"]["context"], TAB_MANIFEST_CONTEXT);
    assert_eq!(kat["update_manifest"]["context"], UPDATE_MANIFEST_CONTEXT);
    let key = test_key(&kat);
    for (file, cbor_path, context) in CASES {
        let doc = json(file);
        let cbor = canonical::signed_bytes(&doc, "sig").unwrap();
        assert_eq!(cbor, hex_field(&kat, cbor_path), "{file}");
        let sig = key
            .expanded_key()
            .sign_deterministic(&cbor, context.as_bytes())
            .unwrap();
        let sig = URL_SAFE_NO_PAD.encode(sig.encode().as_slice());
        assert_eq!(doc["sig"].as_str().unwrap(), sig, "{file}");
    }
}

#[test]
fn the_icon_and_the_asset_decode_to_their_published_bytes() {
    let kat = json("tray-tab-kat.json");
    let pk = kat["publisher"]["pk_hex"].as_str().unwrap().to_owned();
    let trusted = TrustedPublishers::new(&[(AVAROK_PUBLISHER_NAME, pk.as_str())]).unwrap();
    let verifier = Verifier {
        platform: Platform::MacOs,
        trusted: trusted.clone(),
    };
    let tab = verifier
        .verify(
            "net.avarok.certifiedcopy.json",
            &read("tray-tab-manifest/valid-web-panel.json"),
            &AcceptAll,
        )
        .unwrap();
    assert_eq!(tab.icon, hex_field(&kat, &["icon_png_hex"]));
    let Ok(UpdateDecision::Available { asset, .. }) = update::check(
        &read("update-manifest/valid-release.json"),
        &trusted,
        "net.avarok.certifiedcopy",
        Version(1, 0, 0),
        "macos-aarch64",
    ) else {
        panic!("the valid release is not offered");
    };
    let bytes = hex_field(&kat, &["update_manifest", "asset_bytes_hex"]);
    assert_eq!(update::verify_download(&asset, &bytes), Ok(()));
    assert!(update::verify_download(&asset, b"assex").is_err());
}
