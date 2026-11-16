// SPDX-License-Identifier: MIT OR Apache-2.0
//! Turning a manifest file into a [`Tab`], or saying exactly why not (master plan §5.4).
//!
//! The order is cheapest-and-most-hostile first: size, then JSON, then the signature by a pinned
//! publisher, and only then the typed fields, so an unsigned or foreign file is never parsed
//! further than it takes to find its key. The OS code-signature check of the app it points at
//! comes last, because it is the only step that touches the system.

use crate::manifest::{self, TabManifest};
use crate::model::Tab;
use crate::ports::CodeSignature;
use crate::signature::{self, SignedRefusal, TrustedPublishers};
use crate::verify_rules as rules;
use std::fmt;

/// The platform the host runs on, with what its rules need to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Windows,
    /// `home` is the user's absolute home directory, for the `~/.local` install root.
    Linux {
        home: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Oversize {
        what: &'static str,
        len: u64,
        max: u64,
    },
    Unreadable(String),
    NotJson(String),
    Signature(SignedRefusal),
    Malformed(String),
    UnsupportedFormat(u64),
    BadId(String),
    FileNameMismatch {
        file: String,
        expected: String,
    },
    PathEscape(String),
    BadBundleId(String),
    BadField(String),
    NotLoopback(String),
    NoAppForPlatform,
    /// The manifest names no complete platform, or only half of one.
    IncompleteApp(String),
    CodeSignature(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oversize { what, len, max } => {
                write!(f, "the {what} is {len} bytes, more than the {max} allowed")
            }
            Self::Unreadable(why) => write!(f, "it could not be read: {why}"),
            Self::NotJson(why) => write!(f, "it is not JSON: {why}"),
            Self::Signature(why) => write!(f, "{why}"),
            Self::Malformed(why) => write!(f, "it is not a tab manifest: {why}"),
            Self::UnsupportedFormat(n) => write!(f, "format {n} is not one this host reads"),
            Self::BadId(id) => write!(f, "{id:?} is not a reverse-DNS tab id"),
            Self::FileNameMismatch { file, expected } => {
                write!(
                    f,
                    "the file is {file:?}; a manifest for this tab must be {expected:?}"
                )
            }
            Self::PathEscape(path) => write!(f, "{path:?} is outside the allowed install roots"),
            Self::BadBundleId(id) => write!(f, "{id:?} is not a bundle id"),
            Self::BadField(why) => f.write_str(why),
            Self::NotLoopback(url) => {
                write!(f, "the panel {url:?} is not this tab's loopback port")
            }
            Self::NoAppForPlatform => f.write_str("it names no app for this platform"),
            Self::IncompleteApp(why) => write!(f, "its app section is incomplete: {why}"),
            Self::CodeSignature(why) => write!(f, "the app it names failed the OS check: {why}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Verifier {
    pub platform: Platform,
    pub trusted: TrustedPublishers,
}

impl Verifier {
    pub fn verify(
        &self,
        file_name: &str,
        bytes: &[u8],
        os: &dyn CodeSignature,
    ) -> Result<Tab, Refusal> {
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if len > manifest::MAX_MANIFEST_BYTES {
            return Err(Refusal::Oversize {
                what: "manifest",
                len,
                max: manifest::MAX_MANIFEST_BYTES,
            });
        }
        let document: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| Refusal::NotJson(e.to_string()))?;
        signature::verify_signed(&document, signature::TAB_MANIFEST_CONTEXT, &self.trusted)
            .map_err(Refusal::Signature)?;
        let parsed: TabManifest =
            serde_json::from_value(document).map_err(|e| Refusal::Malformed(e.to_string()))?;
        if parsed.format != manifest::FORMAT {
            return Err(Refusal::UnsupportedFormat(parsed.format));
        }
        let tab = rules::tab(&parsed, file_name, &self.platform)?;
        os.verify(&parsed.app)
            .map_err(|e| Refusal::CodeSignature(e.to_string()))?;
        Ok(tab)
    }
}
