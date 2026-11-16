// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Windows and Linux host over tray-core's ports: where things live ([`places`]), the OS
//! code-signature port ([`signature`]), the menu as muda items ([`menu`]) and the event loop with
//! its web panels ([`gui`]).

pub mod gui;
pub mod menu;
pub mod places;
pub mod signature;

/// Runs the host until Quit.
pub fn run() -> Result<(), String> {
    let env = |name: &str| std::env::var(name).ok();
    let platform = places::platform(std::env::consts::OS, &env)?;
    let tab_dir = places::tab_directory(&platform, &env)?;
    gui::run(platform, tab_dir)
}
