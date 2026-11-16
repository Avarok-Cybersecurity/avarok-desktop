// SPDX-License-Identifier: MIT OR Apache-2.0
//! The I/O half of the tray host (SBIO): each type here implements one of
//! [`tray_core::ports`] with the standard library and nothing else, so the macOS C ABI
//! (`tray-ffi`) and the Windows/Linux host (`tray-host`) read the same directory the same way.

pub mod clock;
pub mod launcher;
pub mod linux_install;
pub mod tab_dir;
