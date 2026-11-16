// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `stdout-handshake` panel token (contract §3): the host reads one line from the stdout of
//! the agent process it launched and, only from that line, learns the token its web panel loads
//! with. The panel URL is then built here, so every host spells it the same way.
//!
//! The line format is not yet frozen by the batch-1116 contracts; this is the proposal every host
//! shares until it is: `AVAROK_PANEL_TOKEN=<token>`, the token 32 to 128 base64url characters.

use crate::model::{PanelSpec, PanelToken};

pub const TOKEN_PREFIX: &str = "AVAROK_PANEL_TOKEN=";
pub const MIN_TOKEN_CHARS: usize = 32;
pub const MAX_TOKEN_CHARS: usize = 128;

/// A token read from the launched agent's own stdout, and from nowhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeToken(String);

impl HandshakeToken {
    /// The token on `line` (one stdout line, its newline already removed), or `None`.
    pub fn from_line(line: &str) -> Option<Self> {
        let token = line.strip_prefix(TOKEN_PREFIX)?;
        let ok = (MIN_TOKEN_CHARS..=MAX_TOKEN_CHARS).contains(&token.len())
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        ok.then(|| Self(token.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `http://127.0.0.1:<port><path>?token=<token>` for a web panel; `None` for a native one.
pub fn panel_url(panel: &PanelSpec, token: &HandshakeToken) -> Option<String> {
    match panel {
        PanelSpec::Web {
            port,
            path,
            token: PanelToken::StdoutHandshake,
        } => Some(format!(
            "http://127.0.0.1:{port}{path}?token={}",
            token.as_str()
        )),
        PanelSpec::Native { .. } => None,
    }
}
