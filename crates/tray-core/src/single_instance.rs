// SPDX-License-Identifier: MIT OR Apache-2.0
//! One host per user. The first launch takes a named lock; a second launch (the login item and
//! a double-click, say) sends the first a wake message and exits, so the person sees the panel
//! they asked for rather than a second icon.

use crate::model::TabId;
use crate::ports::{InstanceLock, LockOutcome, PortError, WakeChannel};

const WAKE_PREFIX: &str = "avarok-wake-v1 ";
pub const MAX_WAKE_BYTES: usize = 256;
const MAX_USER_SCOPE: usize = 64;

/// `<app id>.<user scope>`: the mutex, socket or pipe name the ports derive their object from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockName(String);

impl LockName {
    /// `user_scope` is the uid (Unix) or the session's SID (Windows), as the port reads it.
    pub fn new(app_id: &str, user_scope: &str) -> Result<Self, PortError> {
        let scope_ok = !user_scope.is_empty()
            && user_scope.len() <= MAX_USER_SCOPE
            && user_scope
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !crate::verify_paths::is_bundle_id(app_id) || !scope_ok {
            return Err(PortError(format!(
                "{app_id:?}/{user_scope:?} cannot name a per-user lock"
            )));
        }
        Ok(Self(format!("{app_id}.{user_scope}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a second launch asks the running host to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wake {
    Show,
    ShowTab(TabId),
}

impl Wake {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Show => format!("{WAKE_PREFIX}show"),
            Self::ShowTab(id) => format!("{WAKE_PREFIX}show-tab {id}"),
        }
        .into_bytes()
    }

    /// Anything can write to the channel; only exact, bounded messages are understood.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_WAKE_BYTES {
            return None;
        }
        let text = std::str::from_utf8(bytes).ok()?.strip_prefix(WAKE_PREFIX)?;
        match text.split_once(' ') {
            None if text == "show" => Some(Self::Show),
            Some(("show-tab", id)) => TabId::parse(id).map(Self::ShowTab),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// This process holds the lock: build the tray.
    Primary,
    /// The running host was woken: exit.
    Forwarded,
}

pub fn claim(
    lock: &mut dyn InstanceLock,
    channel: &dyn WakeChannel,
    name: &LockName,
    request: &Wake,
) -> Result<Role, PortError> {
    match lock.try_acquire(name)? {
        LockOutcome::Acquired => Ok(Role::Primary),
        LockOutcome::HeldElsewhere => {
            channel.send(name, &request.encode())?;
            Ok(Role::Forwarded)
        }
    }
}
