// SPDX-License-Identifier: MIT OR Apache-2.0
//! The signed bytes are RFC 8949 deterministic CBOR; discovery verifies each file on its own.
mod common;

use common::{Dir, OS_OK, Publisher, bytes, manifest_doc};
use serde_json::json;
use tray_core::canonical::{CanonicalError, signed_bytes};
use tray_core::discover::discover;
use tray_core::signature::TAB_MANIFEST_CONTEXT;
use tray_core::verify::{Platform, Refusal, Verifier};

#[test]
fn keys_sort_by_their_encoding_and_sig_is_left_out() {
    // {"b": 1, "aa": [true], "sig": "x"}: "b" (0x61 0x62) sorts before "aa" (0x62 0x61 0x61).
    let doc = json!({ "aa": [true], "sig": "x", "b": 1 });
    let expected = [0xa2, 0x61, b'b', 0x01, 0x62, b'a', b'a', 0x81, 0xf5];
    assert_eq!(signed_bytes(&doc, "sig").unwrap(), expected);
}

#[test]
fn integers_use_their_shortest_form_and_floats_are_refused() {
    assert_eq!(
        signed_bytes(&json!({"n": 500}), "sig").unwrap(),
        [0xa1, 0x61, b'n', 0x19, 0x01, 0xf4]
    );
    assert_eq!(
        signed_bytes(&json!({"n": -1}), "sig").unwrap(),
        [0xa1, 0x61, b'n', 0x20]
    );
    assert_eq!(
        signed_bytes(&json!({"n": 1.5}), "sig"),
        Err(CanonicalError::Float)
    );
    assert_eq!(
        signed_bytes(&json!([1]), "sig"),
        Err(CanonicalError::NotAnObject)
    );
}

#[test]
fn one_bad_file_costs_only_its_own_tab_and_an_oversize_one_is_never_read() {
    let avarok = Publisher::avarok();
    let good = |id: &str| bytes(&avarok.sign(manifest_doc(id), TAB_MANIFEST_CONTEXT));
    let mut dir = Dir::default();
    dir.files
        .insert("net.avarok.b.json".into(), good("net.avarok.b"));
    dir.files
        .insert("net.avarok.a.json".into(), good("net.avarok.a"));
    dir.files.insert(
        "net.avarok.c.json".into(),
        bytes(&manifest_doc("net.avarok.c")),
    );
    dir.files
        .insert("net.avarok.huge.json".into(), vec![b' '; 64 * 1024 + 1]);
    dir.files.insert("notes.txt".into(), b"ignored".to_vec());
    let verifier = Verifier {
        platform: Platform::MacOs,
        trusted: avarok.trusted(),
    };
    let found = discover(&dir, &verifier, &OS_OK).unwrap();
    let ids: Vec<_> = found.tabs.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(ids, ["net.avarok.a", "net.avarok.b"]);
    assert_eq!(found.refused.len(), 2);
    assert!(matches!(found.refused[0], (ref f, Refusal::Signature(_)) if f == "net.avarok.c.json"));
    assert!(
        matches!(found.refused[1], (ref f, Refusal::Oversize { .. }) if f == "net.avarok.huge.json")
    );
    assert!(
        !dir.reads
            .borrow()
            .iter()
            .any(|f| f == "net.avarok.huge.json" || f == "notes.txt")
    );
}
