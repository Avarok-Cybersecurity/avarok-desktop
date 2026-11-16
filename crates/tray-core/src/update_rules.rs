// SPDX-License-Identifier: MIT OR Apache-2.0
//! The field rules of a signed update manifest (contract `update-manifest.schema.json`). As with
//! tab manifests, a valid signature proves who wrote the feed, not that every field is sane.

use crate::update::{Asset, UpdateRefusal};

const MAX_ASSETS: usize = 16;
const MAX_URL_CHARS: usize = 1024;
const MAX_TARGET_CHARS: usize = 64;
const SHA3_256_HEX_LEN: usize = 64;

pub(crate) fn https(url: &str) -> Result<(), UpdateRefusal> {
    let ok = url.len() > "https://".len()
        && url.len() <= MAX_URL_CHARS
        && url.starts_with("https://")
        && url.bytes().all(|b| b.is_ascii_graphic());
    ok.then_some(())
        .ok_or_else(|| UpdateRefusal::NotHttps(url.to_owned()))
}

pub(crate) fn assets(list: &[Asset]) -> Result<(), UpdateRefusal> {
    if list.is_empty() || list.len() > MAX_ASSETS {
        return Err(malformed(format!(
            "{} assets; a release has 1 to {MAX_ASSETS}",
            list.len()
        )));
    }
    for asset in list {
        if !is_target(&asset.target) {
            return Err(malformed(format!("{:?} is not a target", asset.target)));
        }
        https(&asset.url)?;
        let digest_ok = asset.sha3_256.len() == SHA3_256_HEX_LEN
            && asset
                .sha3_256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !digest_ok {
            return Err(malformed(format!(
                "{:?} is not a lowercase SHA3-256 digest",
                asset.sha3_256
            )));
        }
        if asset.size == 0 {
            return Err(malformed("an asset is empty".to_owned()));
        }
    }
    Ok(())
}

/// `<os>-<arch>`: a `[a-z0-9]` word, then one or more `-[a-z0-9_]` words.
fn is_target(text: &str) -> bool {
    let mut words = text.split('-');
    let first_ok = words.next().is_some_and(|w| {
        !w.is_empty()
            && w.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    });
    let rest: Vec<&str> = words.collect();
    text.len() <= MAX_TARGET_CHARS
        && first_ok
        && !rest.is_empty()
        && rest.iter().all(|w| {
            !w.is_empty()
                && w.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}

fn malformed(why: String) -> UpdateRefusal {
    UpdateRefusal::Malformed(why)
}
