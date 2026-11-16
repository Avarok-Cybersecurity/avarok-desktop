// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Avarok tray host for Windows and Linux. On macOS the host is `apps/macos/Avarok.app`.

use std::process::ExitCode;

fn main() -> ExitCode {
    match tray_host::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("avarok: {why}");
            ExitCode::FAILURE
        }
    }
}
