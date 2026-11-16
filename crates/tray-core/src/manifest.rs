// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tab manifest as it is written on disk (master plan §5.4), field for field. These types
//! are only ever filled from a document whose signature already verified ([`crate::verify`]);
//! an unknown field is refused rather than ignored, so nothing signed is silently dropped.

use serde::Deserialize;

pub const FORMAT: u64 = 1;
/// Larger files are refused before they are read in full.
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
pub const MAX_ICON_BYTES: usize = 16 * 1024;
pub const MAX_TITLE_CHARS: usize = 64;
pub const MAX_ACTIONS: usize = 16;
pub const MAX_ARGS: usize = 32;
pub const MAX_CRASH_CAP: u8 = 10;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TabManifest {
    pub format: u64,
    pub id: String,
    pub title: String,
    pub icon_template_png: String,
    pub publisher: Publisher,
    pub app: AppSection,
    pub agent: AgentSection,
    pub panel: PanelSection,
    pub actions: Vec<ActionSection>,
    pub sig: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publisher {
    pub name: String,
    pub mldsa65_public_key: String,
}

/// Where the tab's app is installed on each platform, and who must have signed it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppSection {
    pub macos_bundle_id: Option<String>,
    pub macos_team_id: Option<String>,
    pub windows_exe: Option<String>,
    pub windows_publisher_thumbprint: Option<String>,
    pub linux_exec: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSection {
    pub argv: Vec<String>,
    pub ready: ReadySection,
    pub crash_cap: u8,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ReadySection {
    Tcp { port: u16 },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum PanelSection {
    Web { url: String, token: String },
    Native { macos_module: String },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSection {
    pub id: String,
    pub title: String,
    pub launch: LaunchSection,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSection {
    pub macos_open_bundle: bool,
    pub url_fragment: Option<String>,
}
