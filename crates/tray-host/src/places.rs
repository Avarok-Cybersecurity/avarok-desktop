// SPDX-License-Identifier: MIT OR Apache-2.0
//! Where the host finds its tabs (contract §1), from the environment it is given. A variable the
//! platform must provide and does not is an error, never a guessed path.

use std::path::PathBuf;
use tray_core::verify::Platform;

/// `os` is `std::env::consts::OS`; `env` reads one variable.
pub fn platform(os: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Platform, String> {
    match os {
        "windows" => Ok(Platform::Windows),
        "linux" => {
            let home = env("HOME").ok_or("HOME is not set")?;
            Ok(Platform::Linux { home })
        }
        "macos" => Err("on macOS the host is Avarok.app (apps/macos)".to_owned()),
        other => Err(format!("{other} has no Avarok host")),
    }
}

/// Windows `%LOCALAPPDATA%\Avarok\tabs`; Linux `$XDG_DATA_HOME/avarok/tabs`, where an unset
/// `XDG_DATA_HOME` means `$HOME/.local/share` as the XDG Base Directory specification defines it.
pub fn tab_directory(
    platform: &Platform,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<PathBuf, String> {
    match platform {
        Platform::Windows => {
            let local = env("LOCALAPPDATA").ok_or("LOCALAPPDATA is not set")?;
            Ok(PathBuf::from(local).join("Avarok").join("tabs"))
        }
        Platform::Linux { home } => {
            let data = env("XDG_DATA_HOME")
                .filter(|d| d.starts_with('/'))
                .map_or_else(|| PathBuf::from(home).join(".local/share"), PathBuf::from);
            Ok(data.join("avarok").join("tabs"))
        }
        Platform::MacOs => Err("on macOS the host is Avarok.app (apps/macos)".to_owned()),
    }
}
