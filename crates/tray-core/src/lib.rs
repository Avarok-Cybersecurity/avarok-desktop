// SPDX-License-Identifier: MIT OR Apache-2.0
//! The portable core of the Avarok tray host.
//!
//! Everything here is a pure decision over plain data. Whatever touches the operating system
//! (locks, processes, files, the login-item registry, code signatures, the network) is a trait in
//! [`ports`], implemented by the platform hosts (TrayKit on macOS, `tray-host` on Windows and
//! Linux). That is what lets the whole model run under `cargo test` on any machine.

pub mod autostart;
pub mod canonical;
pub mod discover;
pub mod logs;
pub mod manifest;
pub mod model;
pub mod ports;
pub mod signature;
pub mod single_instance;
pub mod supervise;
pub mod tabs;
pub mod update;
mod update_rules;
pub mod verify;
mod verify_paths;
mod verify_rules;
