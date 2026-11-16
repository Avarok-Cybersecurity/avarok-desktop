// SPDX-License-Identifier: MIT OR Apache-2.0
//! The C ABI over tray-core for the macOS host (master plan T2). Everything that decides
//! anything is safe Rust in [`core`] and tested natively; [`abi`] only turns pointers into
//! slices and back. The wire between the two languages is CBOR ([`encode`]).
//!
//! Functions (see `TrayKit/Sources/CTrayCore/include/tray_core.h`):
//! - `tray_core_avarok_publishers()`: the pinned publisher list the shipped host passes back in.
//! - `tray_core_tabs(dir, pinned, check, ctx)`: discovery + verification of the tab directory;
//!   `check` is the host's OS code-signature port (`SecStaticCodeCheckValidity` on macOS).
//! - `tray_core_panel_url(port, path, line)`: a web panel's URL from the agent's handshake line.
//! - `tray_core_buffer_free(buffer)`: every returned buffer goes back through this.

pub mod abi;
pub mod core;
pub mod encode;
