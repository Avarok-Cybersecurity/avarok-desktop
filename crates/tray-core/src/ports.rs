// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every operating-system and I/O call the core needs, as a trait. The core never implements
//! these; each platform host does (SBIO). Tests implement them in memory.

use crate::autostart::AutostartEntry;
use crate::manifest::AppSection;
use crate::model::{AgentSpec, Millis, ReadyProbe};
use crate::single_instance::LockName;
use std::fmt;

/// Why a port could not do what it was asked. The text is for the log and the person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortError(pub String);

impl fmt::Display for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PortError {}

/// A monotonic clock. Supervision takes `now` from here and from nowhere else.
pub trait Clock {
    fn now(&self) -> Millis;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockOutcome {
    /// This process now holds the lock and is the one host.
    Acquired,
    /// Another host holds it; this process should wake that one and exit.
    HeldElsewhere,
}

/// A named, per-user lock: a named mutex on Windows, an `flock`ed file on macOS and Linux.
pub trait InstanceLock {
    fn try_acquire(&mut self, name: &LockName) -> Result<LockOutcome, PortError>;
}

/// The channel the running host listens on for a second launch's wake message: a named pipe on
/// Windows, a Unix socket in the per-user runtime directory elsewhere.
pub trait WakeChannel {
    fn send(&self, name: &LockName, message: &[u8]) -> Result<(), PortError>;
}

/// The platform's start-at-login mechanism: `SMAppService` (through TrayKit), the HKCU `Run`
/// key, or an XDG autostart `.desktop` file.
pub trait Autostart {
    fn is_enabled(&self) -> Result<bool, PortError>;
    fn enable(&self, entry: &AutostartEntry) -> Result<(), PortError>;
    fn disable(&self) -> Result<(), PortError>;
}

/// The operating system's verdict on an installed or staged app: on macOS the designated
/// requirement for the team, on Windows `WinVerifyTrust` with the pinned thumbprint, on Linux the
/// ownership and mode of the executable (there is no OS signature there).
pub trait CodeSignature {
    fn verify(&self, app: &AppSection) -> Result<(), PortError>;
}

/// One file in the tab-manifest directory, as listed (before it is read).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub file_name: String,
    pub len: u64,
}

/// The tab-manifest directory for this user.
pub trait TabDirectory {
    fn list(&self) -> Result<Vec<DirEntry>, PortError>;
    /// Reads at most `max_bytes + 1` bytes, so an oversize file is seen without reading it all.
    fn read(&self, file_name: &str, max_bytes: u64) -> Result<Vec<u8>, PortError>;
}

/// FSEvents, `ReadDirectoryChangesW` or inotify on the tab directory: blocks until something in
/// it changed, after which the host re-runs discovery.
pub trait DirectoryWatch {
    fn next_change(&mut self) -> Result<(), PortError>;
}

/// A handle on an agent process the host started. Only processes it started are trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pid(pub u32);

/// Starts, probes and stops tab agents; the supervision state machine says when.
pub trait AgentLauncher {
    fn spawn(&mut self, agent: &AgentSpec) -> Result<Pid, PortError>;
    fn terminate(&mut self, pid: Pid) -> Result<(), PortError>;
    /// Whether the agent answers its readiness probe right now.
    fn is_ready(&self, probe: &ReadyProbe) -> bool;
}

/// Fetches a signed update manifest over HTTPS.
pub trait UpdateFeed {
    fn fetch(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>, PortError>;
}

/// The host's own log file.
pub trait LogStore {
    /// The existing log's size, or `None` when there is none yet.
    fn existing_len(&self) -> Result<Option<u64>, PortError>;
    fn truncate(&mut self) -> Result<(), PortError>;
    fn append(&mut self, line: &str) -> Result<(), PortError>;
}
