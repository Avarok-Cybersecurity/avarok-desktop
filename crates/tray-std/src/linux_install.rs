// SPDX-License-Identifier: MIT OR Apache-2.0
//! Linux has no OS code signature, so its [`CodeSignature`] port checks what the contract asks
//! instead: the executable is a regular, executable file that neither it nor any directory above
//! it is writable by group or others, so nobody but its owner can have replaced it.

use std::path::{Path, PathBuf};
use tray_core::manifest::AppSection;
use tray_core::ports::{CodeSignature, PortError};
use tray_core::verify::linux_exec_path;

#[derive(Debug, Clone)]
pub struct LinuxInstallCheck {
    /// The user's home, for `~/.local/`.
    pub home: String,
}

impl CodeSignature for LinuxInstallCheck {
    fn verify(&self, app: &AppSection) -> Result<(), PortError> {
        let raw = app
            .linux_exec
            .as_deref()
            .ok_or_else(|| PortError("the manifest names no Linux executable".to_owned()))?;
        let path = linux_exec_path(raw, &self.home).map_err(|e| PortError(e.to_string()))?;
        check(Path::new(&path))
    }
}

#[cfg(unix)]
fn check(path: &Path) -> Result<(), PortError> {
    use std::os::unix::fs::PermissionsExt;
    const GROUP_OR_OTHER_WRITE: u32 = 0o022;
    const ANY_EXECUTE: u32 = 0o111;
    let meta = std::fs::symlink_metadata(path).map_err(|e| err(path, &e.to_string()))?;
    if !meta.file_type().is_file() {
        return Err(err(path, "is not a regular file"));
    }
    if meta.permissions().mode() & ANY_EXECUTE == 0 {
        return Err(err(path, "is not executable"));
    }
    let mut at: Option<PathBuf> = Some(path.to_path_buf());
    while let Some(current) = at {
        let mode = std::fs::metadata(&current)
            .map_err(|e| err(&current, &e.to_string()))?
            .permissions()
            .mode();
        if mode & GROUP_OR_OTHER_WRITE != 0 {
            return Err(err(&current, "is writable by others"));
        }
        at = current.parent().map(Path::to_path_buf);
    }
    Ok(())
}

#[cfg(not(unix))]
fn check(path: &Path) -> Result<(), PortError> {
    Err(err(path, "the Linux install check runs only on Unix"))
}

fn err(path: &Path, why: &str) -> PortError {
    PortError(format!("{} {why}", path.display()))
}
