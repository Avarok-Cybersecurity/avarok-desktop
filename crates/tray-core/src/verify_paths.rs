// SPDX-License-Identifier: MIT OR Apache-2.0
//! Where a tab's app may be installed. A manifest anyone can write must only ever point the
//! host at an installed, signed app, so every path is rooted in an install location, spelled
//! with no `.`/`..` or empty components, and checked again by the OS signature port.

use crate::manifest::AppSection;
use crate::model::Program;
use crate::verify::{Platform, Refusal};

/// The prefixes a Windows `windows_exe` may start with; the host expands the variable.
const WINDOWS_ROOTS: &[&str] = &[
    "%ProgramFiles%\\",
    "%ProgramFiles(x86)%\\",
    "%LOCALAPPDATA%\\Programs\\",
];
/// Linux has no OS code signature, so the root is half the gate (§5.4).
const LINUX_ROOTS: &[&str] = &["/usr/", "/opt/"];
const TEAM_ID_LEN: usize = 10;
const THUMBPRINT_HEX_LEN: usize = 64;
const MAX_PATH_CHARS: usize = 1024;

pub(crate) fn program(app: &AppSection, platform: &Platform) -> Result<Program, Refusal> {
    match platform {
        Platform::MacOs => {
            let (Some(bundle_id), Some(team_id)) = (&app.macos_bundle_id, &app.macos_team_id)
            else {
                return Err(Refusal::NoAppForPlatform);
            };
            if !is_bundle_id(bundle_id) {
                return Err(Refusal::BadBundleId(bundle_id.clone()));
            }
            let team_ok = team_id.len() == TEAM_ID_LEN
                && team_id
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
            if !team_ok {
                return Err(Refusal::BadField(format!("{team_id:?} is not a team id")));
            }
            Ok(Program::MacBundle {
                bundle_id: bundle_id.clone(),
                team_id: team_id.clone(),
            })
        }
        Platform::Windows => {
            let (Some(path), Some(thumbprint)) =
                (&app.windows_exe, &app.windows_publisher_thumbprint)
            else {
                return Err(Refusal::NoAppForPlatform);
            };
            windows_exe(path)?;
            let thumb_ok = thumbprint.len() == THUMBPRINT_HEX_LEN
                && thumbprint.bytes().all(|b| b.is_ascii_hexdigit());
            if !thumb_ok {
                return Err(Refusal::BadField(format!(
                    "{thumbprint:?} is not a SHA-256 thumbprint"
                )));
            }
            Ok(Program::WindowsExe {
                path: path.clone(),
                thumbprint: thumbprint.to_ascii_lowercase(),
            })
        }
        Platform::Linux { home } => {
            let path = app.linux_exec.as_ref().ok_or(Refusal::NoAppForPlatform)?;
            linux_exec(path, home)?;
            Ok(Program::LinuxExec { path: path.clone() })
        }
    }
}

/// Reverse-DNS: two or more labels of ASCII letters, digits and `-`.
pub(crate) fn is_bundle_id(id: &str) -> bool {
    let labels: Vec<&str> = id.split('.').collect();
    id.len() <= 255
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn clean_components<'a>(mut parts: impl Iterator<Item = &'a str>) -> bool {
    parts.all(|part| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && !part.contains('\0')
            && !part.chars().any(char::is_control)
    })
}

fn windows_exe(path: &str) -> Result<(), Refusal> {
    let escape = || Refusal::PathEscape(path.to_owned());
    let rest = WINDOWS_ROOTS
        .iter()
        .find_map(|root| path.strip_prefix(root))
        .ok_or_else(escape)?;
    let ok = path.len() <= MAX_PATH_CHARS
        && !rest.contains(['/', ':', '%', '"'])
        && clean_components(rest.split('\\'))
        && rest.to_ascii_lowercase().ends_with(".exe");
    ok.then_some(()).ok_or_else(escape)
}

fn linux_exec(path: &str, home: &str) -> Result<(), Refusal> {
    let escape = || Refusal::PathEscape(path.to_owned());
    if !home.starts_with('/') || !clean_components(home.trim_start_matches('/').split('/')) {
        return Err(Refusal::BadField(format!(
            "the home directory {home:?} is not absolute"
        )));
    }
    let local = format!("{}/.local/", home.trim_end_matches('/'));
    let rest = LINUX_ROOTS
        .iter()
        .copied()
        .chain(std::iter::once(local.as_str()))
        .find_map(|root| path.strip_prefix(root))
        .ok_or_else(escape)?;
    let ok = path.len() <= MAX_PATH_CHARS && clean_components(rest.split('/'));
    ok.then_some(()).ok_or_else(escape)
}
