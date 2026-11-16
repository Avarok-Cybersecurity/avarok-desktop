// SPDX-License-Identifier: MIT OR Apache-2.0
//! A tab as the host uses it: built only by [`crate::verify`] from a manifest that passed every
//! check, so holding a [`Tab`] means holding something verified.

use std::fmt;

/// Milliseconds on a monotonic clock ([`crate::ports::Clock`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Millis(pub u64);

impl Millis {
    pub fn plus(self, ms: u64) -> Self {
        Self(self.0.saturating_add(ms))
    }

    pub fn since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// A reverse-DNS tab id, such as `net.avarok.certifiedcopy`. Only [`TabId::parse`] makes one,
/// so every id is lowercase `[a-z0-9-]` labels joined by dots and is safe as a file name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TabId(String);

pub const TAB_ID_MAX_LEN: usize = 128;

impl TabId {
    pub fn parse(text: &str) -> Option<Self> {
        let labels: Vec<&str> = text.split('.').collect();
        let label_ok = |l: &&str| {
            !l.is_empty()
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        (text.len() <= TAB_ID_MAX_LEN && labels.len() >= 2 && labels.iter().all(label_ok))
            .then(|| Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The only file name a manifest for this tab may have.
    pub fn manifest_file_name(&self) -> String {
        format!("{}.json", self.0)
    }
}

impl fmt::Display for TabId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How the host knows a tab's agent is up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadyProbe {
    /// Something accepts a TCP connection on `127.0.0.1:port`.
    Tcp { port: u16 },
}

/// The installed app a tab's agent is, on the platform the host runs on. Its code signature has
/// been checked by [`crate::ports::CodeSignature`] before a [`Tab`] holding it exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Program {
    MacBundle { bundle_id: String, team_id: String },
    WindowsExe { path: String, thumbprint: String },
    LinuxExec { path: String },
}

/// What the host runs for a tab, and how hard it tries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSpec {
    pub program: Program,
    pub argv: Vec<String>,
    pub ready: ReadyProbe,
    /// Back-off restarts after failing starts before the tab is `failed`.
    pub crash_cap: u8,
}

/// Where the panel's per-launch token comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelToken {
    /// The agent prints it on stdout when it starts; the host reads it from the process it
    /// launched, so no other process can supply it.
    StdoutHandshake,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanelSpec {
    /// A web panel served by the tab's agent on loopback, at the port the manifest names.
    Web {
        port: u16,
        path: String,
        token: PanelToken,
    },
    /// A panel compiled into the host (SwiftUI module on macOS).
    Native { macos_module: String },
}

/// What choosing an action does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    /// macOS: `open -b <bundle id>` the tab's app.
    pub macos_open_bundle: bool,
    /// Opened in the app's main window, such as `#/`.
    pub url_fragment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    /// `[a-z0-9-]`, unique within its tab.
    pub id: String,
    pub title: String,
    pub launch: Launch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tab {
    pub id: TabId,
    pub title: String,
    /// A template PNG (monochrome, drawn to match the menu bar), at most 16 KiB.
    pub icon: Vec<u8>,
    pub agent: AgentSpec,
    pub panel: PanelSpec,
    pub actions: Vec<Action>,
}
