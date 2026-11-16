// SPDX-License-Identifier: MIT OR Apache-2.0
//! The host's log: where it lives, when it starts over, and what a line may contain.
//!
//! Rotation is Citadel's (`starts_over` in `shell_menu.rs`, `LogFile` in the Mac launcher): past
//! the limit the log starts over at launch, because a crash loop left alone must not fill a disk.

use crate::model::TabId;
use crate::ports::{LogStore, PortError};

/// Citadel's limit, kept so both hosts behave alike.
pub const LOG_LIMIT_BYTES: u64 = 10 * 1024 * 1024;

/// Whether an existing log of this size is replaced rather than appended to.
pub fn starts_over(existing_len: Option<u64>, limit: u64) -> bool {
    existing_len.is_some_and(|len| len > limit)
}

/// Opens the log for this launch: truncated when [`starts_over`], appended to otherwise.
/// Returns whether it started over, for the first line to say so.
pub fn open(store: &mut dyn LogStore, limit: u64) -> Result<bool, PortError> {
    let over = starts_over(store.existing_len()?, limit);
    if over {
        store.truncate()?;
    }
    Ok(over)
}

/// One log line. Control characters (a newline above all) are replaced, so text from an agent
/// or a manifest can never forge a line of its own (CWE-117).
pub fn line(stamp: &str, source: &str, text: &str) -> String {
    let clean = |s: &str| -> String {
        s.chars()
            .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
            .collect()
    };
    format!("[{} {}] {}\n", clean(source), clean(stamp), clean(text))
}

/// The file names under the platform's log directory (the port supplies the directory: macOS
/// `~/Library/Logs/Avarok`, Windows `%LOCALAPPDATA%\Avarok\logs`, Linux
/// `$XDG_STATE_HOME/avarok`). Tab ids are already file-name safe.
pub fn host_log_name() -> &'static str {
    "avarok.log"
}

pub fn agent_log_name(tab: &TabId) -> String {
    format!("{tab}.log")
}
