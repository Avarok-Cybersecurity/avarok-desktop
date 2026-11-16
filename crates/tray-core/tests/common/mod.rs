// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared by the integration tests: a deterministic publisher key, manifest fixtures signed the
//! way a publisher signs them, and in-memory stand-ins for the OS ports.
//!
//! Why these doubles: each one replaces exactly one operating-system call (a code-signature
//! check, a directory listing, a lock) that a native test cannot make portably. Everything the
//! core decides still runs for real against them.
#![allow(dead_code, reason = "each test binary uses a different subset")]

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ml_dsa::{KeyExport, Keypair, MlDsa65, Seed, SigningKey};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::BTreeMap;
use tray_core::canonical;
use tray_core::manifest::AppSection;
use tray_core::model::Program;
use tray_core::ports::{CodeSignature, DirEntry, PortError, TabDirectory};
use tray_core::signature::TAB_MANIFEST_CONTEXT;
use tray_core::signature::{AVAROK_PUBLISHER_NAME, TrustedPublishers};
use tray_core::verify::{Platform, Refusal, Verifier};

pub struct Publisher {
    key: SigningKey<MlDsa65>,
    pub name: String,
}

impl Publisher {
    /// Fixed seeds keep fixtures reproducible; `n` picks a distinct key per publisher.
    pub fn new(n: u8, name: &str) -> Self {
        let seed = Seed::from([n; 32]);
        Self {
            key: SigningKey::<MlDsa65>::from_seed(&seed),
            name: name.to_owned(),
        }
    }

    pub fn avarok() -> Self {
        Self::new(7, AVAROK_PUBLISHER_NAME)
    }

    pub fn key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes().as_slice())
    }

    pub fn trusted(&self) -> TrustedPublishers {
        TrustedPublishers::new(&[(self.name.as_str(), self.key_hex().as_str())]).unwrap()
    }

    /// Fills `publisher` with this key and `sig` with its signature under `context`.
    pub fn sign(&self, mut doc: Value, context: &str) -> Value {
        doc["publisher"] = json!({ "name": self.name, "mldsa65_public_key": self.key_hex() });
        if let Value::Object(fields) = &mut doc {
            fields.remove("sig");
        }
        let message = canonical::signed_bytes(&doc, "sig").unwrap();
        let sig = self
            .key
            .expanded_key()
            .sign_deterministic(&message, context.as_bytes())
            .unwrap();
        doc["sig"] = Value::String(URL_SAFE_NO_PAD.encode(sig.encode().as_slice()));
        doc
    }
}

pub fn icon_png(extra: usize) -> String {
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend(std::iter::repeat_n(0u8, extra));
    STANDARD.encode(png)
}

/// A manifest that passes every rule on every platform, before signing.
pub fn manifest_doc(id: &str) -> Value {
    json!({
        "format": 1,
        "id": id,
        "title": "CertifiedCopy",
        "icon_template_png": icon_png(32),
        "app": {
            "macos_bundle_id": "net.avarok.certifiedcopy",
            "macos_team_id": "ABCDE12345",
            "windows_exe": "%ProgramFiles%\\CertifiedCopy\\certifiedcopy.exe",
            "windows_publisher_thumbprint": "ab".repeat(32),
            "linux_exec": "/usr/bin/certifiedcopy"
        },
        "agent": { "argv": ["--port", "4823"], "ready": { "kind": "tcp", "port": 4823 }, "crash_cap": 5 },
        "panel": { "kind": "web", "url": "http://127.0.0.1:4823/panel/", "token": "stdout-handshake" },
        "actions": [ { "id": "open-main", "title": "Open CertifiedCopy",
                       "launch": { "macos_open_bundle": true, "url_fragment": "#/" } } ]
    })
}

pub fn bytes(doc: &Value) -> Vec<u8> {
    serde_json::to_vec(doc).unwrap()
}

/// The OS code-signature port: accepts, or refuses with a reason.
pub struct Os(pub Option<&'static str>);

impl CodeSignature for Os {
    fn verify(&self, _app: &AppSection) -> Result<(), PortError> {
        self.0.map_or(Ok(()), |why| Err(PortError(why.to_owned())))
    }
}

pub const OS_OK: Os = Os(None);

/// The tab directory, in memory; `reads` records which files were actually read.
#[derive(Default)]
pub struct Dir {
    pub files: BTreeMap<String, Vec<u8>>,
    pub reads: RefCell<Vec<String>>,
}

impl TabDirectory for Dir {
    fn list(&self) -> Result<Vec<DirEntry>, PortError> {
        Ok(self
            .files
            .iter()
            .map(|(name, b)| DirEntry {
                file_name: name.clone(),
                len: b.len() as u64,
            })
            .collect())
    }

    fn read(&self, file_name: &str, max_bytes: u64) -> Result<Vec<u8>, PortError> {
        self.reads.borrow_mut().push(file_name.to_owned());
        let b = self
            .files
            .get(file_name)
            .ok_or(PortError("gone".to_owned()))?;
        Ok(b[..b.len().min(max_bytes as usize + 1)].to_vec())
    }
}

pub const ID: &str = "net.avarok.certifiedcopy";
pub const FILE: &str = "net.avarok.certifiedcopy.json";

pub fn linux() -> Platform {
    Platform::Linux {
        home: "/home/ada".to_owned(),
    }
}

pub fn verifier(platform: Platform) -> Verifier {
    Verifier {
        platform,
        trusted: Publisher::avarok().trusted(),
    }
}

/// Signs `edit(fixture)` with Avarok's key and verifies it as `FILE` on `platform`.
pub fn verdict(platform: Platform, edit: impl FnOnce(&mut Value)) -> Result<Program, Refusal> {
    let mut doc = manifest_doc(ID);
    edit(&mut doc);
    let signed = Publisher::avarok().sign(doc, TAB_MANIFEST_CONTEXT);
    verifier(platform)
        .verify(FILE, &bytes(&signed), &OS_OK)
        .map(|t| t.agent.program)
}
