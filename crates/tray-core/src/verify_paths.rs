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
/// Linux has no OS code signature, so the root is half the gate (§5.4). `~/.local/` is written
/// literally, so the check never depends on whose machine reads the manifest; the Linux host
/// expands it to the user's home.
const LINUX_ROOTS: &[&str] = &["/usr/", "/opt/", "~/.local/"];
const HOME_PREFIX: &str = "~/";
const TEAM_ID_LEN: usize = 10;
const THUMBPRINT_HEX_LEN: usize = 64;
const MAX_PATH_CHARS: usize = 1024;
const MAX_BUNDLE_ID_CHARS: usize = 128;

/// Every platform the manifest names is checked, whichever one the host runs on: a field's
/// shape is a property of the signed document, not of the machine reading it. Then the program
/// for `platform` is picked.
pub(crate) fn program(app: &AppSection, platform: &Platform) -> Result<Program, Refusal> {
    let mac = pair(&app.macos_bundle_id, &app.macos_team_id, "macos")?;
    let windows = pair(
        &app.windows_exe,
        &app.windows_publisher_thumbprint,
        "windows",
    )?;
    let linux = app.linux_exec.as_ref();
    if mac.is_none() && windows.is_none() && linux.is_none() {
        return Err(Refusal::IncompleteApp("it names no platform".to_owned()));
    }
    if let Some((bundle_id, team_id)) = mac {
        mac_fields(bundle_id, team_id)?;
    }
    if let Some((path, thumbprint)) = windows {
        windows_fields(path, thumbprint)?;
    }
    if let Some(path) = linux {
        linux_exec(path)?;
    }
    match platform {
        Platform::MacOs => mac
            .map(|(bundle_id, team_id)| Program::MacBundle {
                bundle_id: bundle_id.clone(),
                team_id: team_id.clone(),
            })
            .ok_or(Refusal::NoAppForPlatform),
        Platform::Windows => windows
            .map(|(path, thumbprint)| Program::WindowsExe {
                path: path.clone(),
                thumbprint: thumbprint.to_ascii_lowercase(),
            })
            .ok_or(Refusal::NoAppForPlatform),
        Platform::Linux { home } => {
            let path = linux.ok_or(Refusal::NoAppForPlatform)?;
            Ok(Program::LinuxExec {
                path: expand_home(path, home)?,
            })
        }
    }
}

/// Both halves of a platform, or neither.
fn pair<'a>(
    a: &'a Option<String>,
    b: &'a Option<String>,
    platform: &str,
) -> Result<Option<(&'a String, &'a String)>, Refusal> {
    match (a, b) {
        (Some(a), Some(b)) => Ok(Some((a, b))),
        (None, None) => Ok(None),
        _ => Err(Refusal::IncompleteApp(format!(
            "it names only half of its {platform} app"
        ))),
    }
}

fn mac_fields(bundle_id: &str, team_id: &str) -> Result<(), Refusal> {
    if !is_bundle_id(bundle_id) {
        return Err(Refusal::BadBundleId(bundle_id.to_owned()));
    }
    let team_ok = team_id.len() == TEAM_ID_LEN
        && team_id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    if !team_ok {
        return Err(Refusal::BadField(format!("{team_id:?} is not a team id")));
    }
    Ok(())
}

fn windows_fields(path: &str, thumbprint: &str) -> Result<(), Refusal> {
    windows_exe(path)?;
    let thumb_ok =
        thumbprint.len() == THUMBPRINT_HEX_LEN && thumbprint.bytes().all(|b| b.is_ascii_hexdigit());
    if !thumb_ok {
        return Err(Refusal::BadField(format!(
            "{thumbprint:?} is not a SHA-256 thumbprint"
        )));
    }
    Ok(())
}

/// Reverse-DNS: two or more labels of ASCII letters, digits and `-`, at most 128 bytes.
pub(crate) fn is_bundle_id(id: &str) -> bool {
    let labels: Vec<&str> = id.split('.').collect();
    id.len() <= MAX_BUNDLE_ID_CHARS
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

fn linux_exec(path: &str) -> Result<(), Refusal> {
    let rest = LINUX_ROOTS
        .iter()
        .find_map(|root| path.strip_prefix(root))
        .ok_or_else(|| Refusal::PathEscape(path.to_owned()))?;
    let ok = path.len() <= MAX_PATH_CHARS && clean_components(rest.split('/'));
    ok.then_some(())
        .ok_or_else(|| Refusal::PathEscape(path.to_owned()))
}

/// The absolute path of an already-checked `linux_exec` for the user whose home is `home`.
pub(crate) fn expand_home(path: &str, home: &str) -> Result<String, Refusal> {
    let Some(rest) = path.strip_prefix(HOME_PREFIX) else {
        return Ok(path.to_owned());
    };
    if !home.starts_with('/') || !clean_components(home.trim_start_matches('/').split('/')) {
        return Err(Refusal::BadField(format!(
            "the home directory {home:?} is not absolute"
        )));
    }
    Ok(format!("{}/{rest}", home.trim_end_matches('/')))
}
