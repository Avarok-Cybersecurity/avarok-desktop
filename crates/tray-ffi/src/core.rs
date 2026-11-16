// SPDX-License-Identifier: MIT OR Apache-2.0
//! What each C entry point does, as safe functions over slices.

use crate::encode;
use std::collections::BTreeMap;
use std::path::PathBuf;
use tray_core::discover::discover;
use tray_core::handshake::{HandshakeToken, panel_url as build_url};
use tray_core::model::{PanelSpec, PanelToken};
use tray_core::ports::CodeSignature;
use tray_core::signature::{AVAROK_PUBLISHER_KEYS, AVAROK_PUBLISHER_NAME, TrustedPublishers};
use tray_core::tabs::{MenuState, entries};
use tray_core::verify::{Platform, Verifier};
use tray_std::tab_dir::FsTabDirectory;

/// The shipped pinned list (owner decision D-C), from tray-core's `keys/`, its one copy.
pub fn avarok_publishers() -> Vec<u8> {
    let list: Vec<(String, String)> = AVAROK_PUBLISHER_KEYS
        .iter()
        .map(|key| (AVAROK_PUBLISHER_NAME.to_owned(), (*key).to_owned()))
        .collect();
    encode::to_bytes(&encode::publishers(&list))
}

/// What the host knows that the menu shows.
#[derive(Debug, Clone, Copy)]
pub struct HostState<'a> {
    pub start_at_login: bool,
    pub host_name: &'a [u8],
}

/// Discovery of `dir` for macOS, trusting exactly `pinned`, with `os` as the code-signature
/// port, and the menu for the tabs found.
pub fn tabs(dir: &[u8], pinned: &[u8], host: HostState<'_>, os: &dyn CodeSignature) -> Vec<u8> {
    encode::to_bytes(&match tabs_value(dir, pinned, host, os) {
        Ok(value) => value,
        Err(why) => encode::error(&why),
    })
}

fn tabs_value(
    dir: &[u8],
    pinned: &[u8],
    host: HostState<'_>,
    os: &dyn CodeSignature,
) -> Result<ciborium::Value, String> {
    let dir = std::str::from_utf8(dir).map_err(|_| "the tab directory is not UTF-8".to_owned())?;
    let host_name =
        std::str::from_utf8(host.host_name).map_err(|_| "the host name is not UTF-8".to_owned())?;
    let list = encode::parse_publishers(pinned)?;
    let borrowed: Vec<(&str, &str)> = list.iter().map(|(n, k)| (n.as_str(), k.as_str())).collect();
    let trusted = TrustedPublishers::new(&borrowed).map_err(|e| e.to_string())?;
    let verifier = Verifier {
        platform: Platform::MacOs,
        trusted,
    };
    let found = discover(&FsTabDirectory::new(PathBuf::from(dir)), &verifier, os)
        .map_err(|e| e.to_string())?;
    // The macOS host does not supervise through this ABI yet, so no agent has a state to show.
    let agents = BTreeMap::new();
    let state = MenuState {
        agents: &agents,
        start_at_login: host.start_at_login,
        host_name,
    };
    Ok(encode::discovered(&found, &entries(&found.tabs, &state)))
}

/// The web panel URL for a tab served on `port` at `path`, from one stdout `line`; empty when
/// the line carries no token.
pub fn panel_url(port: u16, path: &[u8], line: &[u8]) -> Vec<u8> {
    let (Ok(path), Ok(line)) = (std::str::from_utf8(path), std::str::from_utf8(line)) else {
        return Vec::new();
    };
    let panel = PanelSpec::Web {
        port,
        path: path.to_owned(),
        token: PanelToken::StdoutHandshake,
    };
    HandshakeToken::from_line(line)
        .and_then(|token| build_url(&panel, &token))
        .map(String::into_bytes)
        .unwrap_or_default()
}
