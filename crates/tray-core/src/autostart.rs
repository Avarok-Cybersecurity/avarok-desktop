// SPDX-License-Identifier: MIT OR Apache-2.0
//! Start at login, one trait ([`crate::ports::Autostart`]) over three mechanisms. This module
//! only decides what the entry says; writing it is the port's job.
//!
//! The text that ends up in the registry or a `.desktop` file is built here, so it is checked
//! here: a path or argument that could break out of its quoting is refused, never escaped.

use crate::verify::Platform;
use std::fmt;

/// `HKEY_CURRENT_USER\` + this: per user, no elevation.
pub const WINDOWS_RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutostartEntry {
    /// `SMAppService.mainApp`, registered through TrayKit: the bundle is the entry.
    MacLoginItem,
    /// A string value under [`WINDOWS_RUN_KEY`].
    WindowsRun { value_name: String, command: String },
    /// `$XDG_CONFIG_HOME/autostart/<file_name>`.
    XdgDesktop { file_name: String, contents: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutostartError(pub String);

impl fmt::Display for AutostartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What starts the host at login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLaunch<'a> {
    /// Reverse-DNS, such as `net.avarok.desktop`: the value or file name.
    pub app_id: &'a str,
    pub display_name: &'a str,
    pub executable: &'a str,
    pub args: &'a [&'a str],
}

pub fn entry(platform: &Platform, host: &HostLaunch<'_>) -> Result<AutostartEntry, AutostartError> {
    if !crate::verify_paths::is_bundle_id(host.app_id) {
        return Err(AutostartError(format!(
            "{:?} is not a reverse-DNS id",
            host.app_id
        )));
    }
    if host.display_name.is_empty() || host.display_name.chars().any(char::is_control) {
        return Err(AutostartError(
            "the display name must be printable".to_owned(),
        ));
    }
    if let Some(bad) = host.args.iter().find(|a| !is_plain_arg(a)) {
        return Err(AutostartError(format!(
            "the argument {bad:?} needs quoting; refused"
        )));
    }
    let args: String = host.args.iter().map(|a| format!(" {a}")).collect();
    match platform {
        Platform::MacOs => Ok(AutostartEntry::MacLoginItem),
        Platform::Windows => {
            quotable(host.executable, &['"'])?;
            Ok(AutostartEntry::WindowsRun {
                value_name: host.app_id.to_owned(),
                command: format!("\"{}\"{args}", host.executable),
            })
        }
        Platform::Linux { .. } => {
            // The desktop-entry spec gives these meaning inside a quoted Exec argument.
            quotable(host.executable, &['"', '`', '$', '\\', '%'])?;
            if !host.executable.starts_with('/') {
                return Err(AutostartError(
                    "the executable path is not absolute".to_owned(),
                ));
            }
            let contents = format!(
                "[Desktop Entry]\nType=Application\nName={}\nExec=\"{}\"{args}\n\
                 X-GNOME-Autostart-enabled=true\nNoDisplay=true\n",
                host.display_name, host.executable
            );
            Ok(AutostartEntry::XdgDesktop {
                file_name: format!("{}.desktop", host.app_id),
                contents,
            })
        }
    }
}

fn is_plain_arg(arg: &str) -> bool {
    !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_=.:/".contains(&b))
}

fn quotable(path: &str, forbidden: &[char]) -> Result<(), AutostartError> {
    if path.is_empty()
        || path
            .chars()
            .any(|c| c.is_control() || forbidden.contains(&c))
    {
        return Err(AutostartError(format!(
            "the executable path {path:?} cannot be quoted safely"
        )));
    }
    Ok(())
}
