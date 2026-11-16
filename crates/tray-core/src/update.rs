// SPDX-License-Identifier: MIT OR Apache-2.0
//! Update checks. The feed is a JSON manifest signed like a tab manifest (ML-DSA-65 by a pinned
//! publisher, its own context string); a download must then match the manifest's size and
//! SHA3-256, and the staged app must pass the OS code-signature port before it replaces anything.
//! Only strictly newer versions are offered: a validly signed old manifest cannot downgrade.

use crate::manifest::{AppSection, Publisher};
use crate::ports::{CodeSignature, PortError};
use crate::signature::{self, SignedRefusal, TrustedPublishers};
use serde::Deserialize;
use sha3::{Digest, Sha3_256};
use std::fmt;

pub const FORMAT: u64 = 1;
pub const MAX_UPDATE_MANIFEST_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u32, pub u32, pub u32);

impl Version {
    /// `major.minor.patch`, digits only: there are no pre-release builds on the feed.
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split('.').map(|p| {
            (!p.is_empty() && p.len() <= 9 && p.bytes().all(|b| b.is_ascii_digit()))
                .then(|| p.parse().ok())
                .flatten()
        });
        let v = Self(parts.next()??, parts.next()??, parts.next()??);
        parts.next().is_none().then_some(v)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    /// A Rust target triple, such as `aarch64-apple-darwin`.
    pub target: String,
    pub url: String,
    pub sha3_256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateManifest {
    format: u64,
    product: String,
    version: String,
    notes_url: String,
    assets: Vec<Asset>,
    #[allow(dead_code, reason = "verified through the raw document before parsing")]
    publisher: Publisher,
    #[allow(dead_code, reason = "verified through the raw document before parsing")]
    sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateDecision {
    UpToDate,
    Available {
        version: Version,
        notes_url: String,
        asset: Asset,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateRefusal {
    Oversize(u64),
    NotJson(String),
    Signature(SignedRefusal),
    Malformed(String),
    WrongProduct(String),
    BadVersion(String),
    NotHttps(String),
    NoAssetForTarget,
    SizeMismatch { expected: u64, actual: u64 },
    DigestMismatch,
    CodeSignature(String),
}

/// Whether the signed feed offers something newer than `current` for `target`.
pub fn check(
    bytes: &[u8],
    trusted: &TrustedPublishers,
    product: &str,
    current: Version,
    target: &str,
) -> Result<UpdateDecision, UpdateRefusal> {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if len > MAX_UPDATE_MANIFEST_BYTES {
        return Err(UpdateRefusal::Oversize(len));
    }
    let document: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| UpdateRefusal::NotJson(e.to_string()))?;
    signature::verify_signed(&document, signature::UPDATE_MANIFEST_CONTEXT, trusted)
        .map_err(UpdateRefusal::Signature)?;
    let m: UpdateManifest =
        serde_json::from_value(document).map_err(|e| UpdateRefusal::Malformed(e.to_string()))?;
    if m.format != FORMAT {
        return Err(UpdateRefusal::Malformed(format!("format {}", m.format)));
    }
    if m.product != product {
        return Err(UpdateRefusal::WrongProduct(m.product));
    }
    let version = Version::parse(&m.version).ok_or(UpdateRefusal::BadVersion(m.version))?;
    if version <= current {
        return Ok(UpdateDecision::UpToDate);
    }
    https(&m.notes_url)?;
    let asset = m
        .assets
        .into_iter()
        .find(|a| a.target == target)
        .ok_or(UpdateRefusal::NoAssetForTarget)?;
    https(&asset.url)?;
    Ok(UpdateDecision::Available {
        version,
        notes_url: m.notes_url,
        asset,
    })
}

fn https(url: &str) -> Result<(), UpdateRefusal> {
    let ok = url.len() > "https://".len()
        && url.starts_with("https://")
        && url.bytes().all(|b| b.is_ascii_graphic());
    ok.then_some(())
        .ok_or_else(|| UpdateRefusal::NotHttps(url.to_owned()))
}

/// The downloaded bytes are the ones the publisher signed for.
pub fn verify_download(asset: &Asset, bytes: &[u8]) -> Result<(), UpdateRefusal> {
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual != asset.size {
        return Err(UpdateRefusal::SizeMismatch {
            expected: asset.size,
            actual,
        });
    }
    let digest = hex::encode(Sha3_256::digest(bytes));
    if digest != asset.sha3_256.to_ascii_lowercase() {
        return Err(UpdateRefusal::DigestMismatch);
    }
    Ok(())
}

/// The unpacked, staged app is signed by the expected team or publisher.
pub fn verify_staged(os: &dyn CodeSignature, app: &AppSection) -> Result<(), UpdateRefusal> {
    os.verify(app)
        .map_err(|e: PortError| UpdateRefusal::CodeSignature(e.to_string()))
}
