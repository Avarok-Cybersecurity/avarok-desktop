// SPDX-License-Identifier: MIT OR Apache-2.0
//! The per-user tab-manifest directory on disk ([`TabDirectory`]).

use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use tray_core::ports::{DirEntry, PortError, TabDirectory};

#[derive(Debug, Clone)]
pub struct FsTabDirectory {
    dir: PathBuf,
}

impl FsTabDirectory {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }
}

impl TabDirectory for FsTabDirectory {
    /// Regular files only (a symlink or a directory is never a manifest). A directory that does
    /// not exist yet holds no tabs: no app has registered one.
    fn list(&self) -> Result<Vec<DirEntry>, PortError> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(port_error(&self.dir, &e)),
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| port_error(&self.dir, &e))?;
            let meta = entry
                .metadata()
                .map_err(|e| port_error(&entry.path(), &e))?;
            if !meta.file_type().is_file() {
                continue;
            }
            // A name that is not UTF-8 cannot be `<id>.json`; listing it lossily lets discovery
            // refuse it by name rather than hide it.
            out.push(DirEntry {
                file_name: entry.file_name().to_string_lossy().into_owned(),
                len: meta.len(),
            });
        }
        Ok(out)
    }

    fn read(&self, file_name: &str, max_bytes: u64) -> Result<Vec<u8>, PortError> {
        if file_name.contains(['/', '\\']) || file_name == ".." {
            return Err(PortError(format!("{file_name:?} is not a file name")));
        }
        let path = self.dir.join(file_name);
        let file = fs::File::open(&path).map_err(|e| port_error(&path, &e))?;
        let mut bytes = Vec::new();
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| port_error(&path, &e))?;
        Ok(bytes)
    }
}

fn port_error(path: &Path, e: &std::io::Error) -> PortError {
    PortError(format!("{}: {e}", path.display()))
}
