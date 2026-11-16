// SPDX-License-Identifier: MIT OR Apache-2.0
//! Finding the tabs installed for this user: every `<id>.json` in the tab directory, each
//! verified on its own, so one bad file costs only its own tab. The host runs this at start and
//! again after every [`crate::ports::DirectoryWatch`] change.

use crate::manifest::MAX_MANIFEST_BYTES;
use crate::model::Tab;
use crate::ports::{CodeSignature, PortError, TabDirectory};
use crate::verify::{Refusal, Verifier};

/// More files than this are refused, not read: the directory is writable by anything the user
/// runs, and discovery must stay bounded.
pub const MAX_MANIFEST_FILES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    /// Sorted by id, which is the file name: the order the tab strip shows.
    pub tabs: Vec<Tab>,
    /// Each file that was not accepted, and why: for the log, never shown as a tab.
    pub refused: Vec<(String, Refusal)>,
}

pub fn discover(
    dir: &dyn TabDirectory,
    verifier: &Verifier,
    os: &dyn CodeSignature,
) -> Result<Discovered, PortError> {
    let mut entries: Vec<_> = dir
        .list()?
        .into_iter()
        .filter(|e| e.file_name.ends_with(".json"))
        .collect();
    entries.sort_by(|a, b| a.file_name.cmp(&b.file_name));
    let mut found = Discovered {
        tabs: Vec::new(),
        refused: Vec::new(),
    };
    for (index, entry) in entries.into_iter().enumerate() {
        let outcome = if index >= MAX_MANIFEST_FILES {
            Err(Refusal::BadField(format!(
                "more than {MAX_MANIFEST_FILES} manifests are installed"
            )))
        } else if entry.len > MAX_MANIFEST_BYTES {
            Err(Refusal::Oversize {
                what: "manifest",
                len: entry.len,
                max: MAX_MANIFEST_BYTES,
            })
        } else {
            dir.read(&entry.file_name, MAX_MANIFEST_BYTES)
                .map_err(|e| Refusal::Unreadable(e.to_string()))
                .and_then(|bytes| verifier.verify(&entry.file_name, &bytes, os))
        };
        match outcome {
            Ok(tab) => found.tabs.push(tab),
            Err(why) => found.refused.push((entry.file_name, why)),
        }
    }
    Ok(found)
}
