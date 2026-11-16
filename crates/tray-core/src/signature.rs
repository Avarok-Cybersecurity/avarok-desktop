// SPDX-License-Identifier: MIT OR Apache-2.0
//! ML-DSA-65 (FIPS 204) publisher signatures over a signed JSON document, and the pinned list of
//! publishers the host trusts. Tab manifests and update manifests share this one scheme; each
//! uses its own FIPS 204 context string, so a signature for one can never pass as the other.

use crate::canonical::{self, CanonicalError};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use serde_json::Value;
use std::fmt;

pub const TAB_MANIFEST_CONTEXT: &str = "avarok-tab-manifest-v1";
pub const UPDATE_MANIFEST_CONTEXT: &str = "avarok-update-manifest-v1";
pub const PUBLIC_KEY_LEN: usize = 1952;
pub const SIGNATURE_LEN: usize = 3309;

/// Avarok's tab and update publisher keys (hex, 1952 bytes each), shipped with the host. Only
/// these may register tabs (owner decision D-C). Each key lives in `keys/` as the one copy; its
/// private seed never enters this repository.
pub const AVAROK_PUBLISHER_KEYS: &[&str] = &[include_str!("../keys/avarok-tab-publisher.pub")];
pub const AVAROK_PUBLISHER_NAME: &str = "Avarok Cybersecurity";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedRefusal {
    Unsigned,
    /// The key is not one the host pins.
    ForeignPublisher,
    /// The key is pinned, under a different name than the document claims.
    PublisherNameMismatch,
    MalformedKey(String),
    MalformedSignature(String),
    /// Well formed, and does not verify.
    BadSignature,
    NotCanonical(CanonicalError),
    NoPinnedPublishers,
}

impl fmt::Display for SignedRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned => f.write_str("it is not signed"),
            Self::ForeignPublisher => f.write_str("its publisher is not one this host trusts"),
            Self::PublisherNameMismatch => f.write_str("its publisher name does not match the key"),
            Self::MalformedKey(why) => write!(f, "the publisher key is malformed: {why}"),
            Self::MalformedSignature(why) => write!(f, "the signature is malformed: {why}"),
            Self::BadSignature => f.write_str("the signature does not verify"),
            Self::NotCanonical(why) => write!(f, "it cannot be signed: {why}"),
            Self::NoPinnedPublishers => f.write_str("this host pins no publisher keys"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PinnedPublisher {
    pub name: String,
    key_hex: String,
    key: VerifyingKey<MlDsa65>,
}

#[derive(Debug, Clone)]
pub struct TrustedPublishers(Vec<PinnedPublisher>);

impl TrustedPublishers {
    /// `(name, key hex)` pairs. At least one, each a valid ML-DSA-65 key in lowercase hex, the
    /// one spelling a manifest may use (contract: 3904 lowercase hex characters).
    pub fn new(pinned: &[(&str, &str)]) -> Result<Self, SignedRefusal> {
        if pinned.is_empty() {
            return Err(SignedRefusal::NoPinnedPublishers);
        }
        let parse = |(name, hex): &(&str, &str)| {
            if hex.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(SignedRefusal::MalformedKey(
                    "it is not lowercase hex".to_owned(),
                ));
            }
            Ok(PinnedPublisher {
                name: (*name).to_owned(),
                key_hex: (*hex).to_owned(),
                key: parse_key(hex)?,
            })
        };
        Ok(Self(pinned.iter().map(parse).collect::<Result<_, _>>()?))
    }

    /// The list a shipped host uses.
    pub fn avarok() -> Result<Self, SignedRefusal> {
        let pinned: Vec<(&str, &str)> = AVAROK_PUBLISHER_KEYS
            .iter()
            .map(|key| (AVAROK_PUBLISHER_NAME, *key))
            .collect();
        Self::new(&pinned)
    }

    /// An exact match: a key spelled any other way than the pinned lowercase hex is foreign.
    fn find(&self, key_hex: &str) -> Option<&PinnedPublisher> {
        self.0.iter().find(|p| p.key_hex == key_hex)
    }
}

/// Accepts `document` only when its `sig` is a valid ML-DSA-65 signature, under `context`, by a
/// pinned key over [`canonical::signed_bytes`]; returns the publisher that signed it.
pub fn verify_signed<'t>(
    document: &Value,
    context: &str,
    trusted: &'t TrustedPublishers,
) -> Result<&'t PinnedPublisher, SignedRefusal> {
    let sig = match document.get("sig") {
        Some(Value::String(s)) if !s.is_empty() => s,
        _ => return Err(SignedRefusal::Unsigned),
    };
    let publisher = document.get("publisher");
    let field = |name: &str| publisher.and_then(|p| p.get(name)).and_then(Value::as_str);
    let key_hex = field("mldsa65_public_key").ok_or(SignedRefusal::ForeignPublisher)?;
    let pinned = trusted
        .find(key_hex)
        .ok_or(SignedRefusal::ForeignPublisher)?;
    if field("name") != Some(pinned.name.as_str()) {
        return Err(SignedRefusal::PublisherNameMismatch);
    }
    let message = canonical::signed_bytes(document, "sig").map_err(SignedRefusal::NotCanonical)?;
    let signature = parse_signature(sig)?;
    if pinned
        .key
        .verify_with_context(&message, context.as_bytes(), &signature)
    {
        Ok(pinned)
    } else {
        Err(SignedRefusal::BadSignature)
    }
}

fn parse_key(hex_text: &str) -> Result<VerifyingKey<MlDsa65>, SignedRefusal> {
    let bytes = hex::decode(hex_text).map_err(|e| SignedRefusal::MalformedKey(e.to_string()))?;
    let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(&bytes[..]).map_err(|_| {
        SignedRefusal::MalformedKey(format!("{} bytes, not {PUBLIC_KEY_LEN}", bytes.len()))
    })?;
    Ok(VerifyingKey::<MlDsa65>::decode(&encoded))
}

fn parse_signature(text: &str) -> Result<Signature<MlDsa65>, SignedRefusal> {
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|e| SignedRefusal::MalformedSignature(e.to_string()))?;
    let encoded = EncodedSignature::<MlDsa65>::try_from(&bytes[..]).map_err(|_| {
        SignedRefusal::MalformedSignature(format!("{} bytes, not {SIGNATURE_LEN}", bytes.len()))
    })?;
    Signature::<MlDsa65>::decode(&encoded)
        .ok_or_else(|| SignedRefusal::MalformedSignature("it does not decode".to_owned()))
}
