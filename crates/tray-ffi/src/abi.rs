// SPDX-License-Identifier: MIT OR Apache-2.0
//! The C entry points. This is the only module that may use `unsafe`, and only for what a C ABI
//! cannot do without it:
//!
//! 1. reading a `(pointer, length)` the caller lends us as a slice (`slice::from_raw_parts`), and
//! 2. handing a buffer to the caller and taking it back to free (`Box::from_raw`).
//!
//! Each block states the invariant it relies on; the header documents the caller's side.
#![allow(
    unsafe_code,
    reason = "a C ABI; each unsafe block below states why it is sound"
)]

use crate::core;
use std::ffi::c_void;
use tray_core::manifest::AppSection;
use tray_core::ports::{CodeSignature, PortError};

/// Bytes owned by Rust, lent to the caller until it passes them to `tray_core_buffer_free`.
#[repr(C)]
#[derive(Debug)]
pub struct TrayBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

/// The host's OS code-signature check for a macOS app: `true` only when the bundle installed for
/// `bundle_id` satisfies `anchor apple generic and certificate leaf[subject.OU] = <team_id>`.
/// Both strings are UTF-8, not NUL-terminated, valid only for the call.
pub type TrayCodeSignatureFn = extern "C" fn(
    ctx: *mut c_void,
    bundle_id: *const u8,
    bundle_id_len: usize,
    team_id: *const u8,
    team_id_len: usize,
) -> bool;

fn give(bytes: Vec<u8>) -> TrayBuffer {
    let boxed = bytes.into_boxed_slice();
    let len = boxed.len();
    TrayBuffer {
        ptr: Box::into_raw(boxed).cast::<u8>(),
        len,
    }
}

/// # Safety
/// `ptr` is null with `len == 0`, or points at `len` readable bytes that stay valid and
/// unmodified for the duration of the call (the header's contract for every input).
unsafe fn borrow<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: the caller's contract above; u8 has no alignment or validity requirement.
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

struct Callback {
    check: TrayCodeSignatureFn,
    ctx: *mut c_void,
}

impl CodeSignature for Callback {
    fn verify(&self, app: &AppSection) -> Result<(), PortError> {
        let (Some(bundle), Some(team)) = (&app.macos_bundle_id, &app.macos_team_id) else {
            return Err(PortError("the manifest names no macOS app".to_owned()));
        };
        let ok = (self.check)(
            self.ctx,
            bundle.as_ptr(),
            bundle.len(),
            team.as_ptr(),
            team.len(),
        );
        ok.then_some(())
            .ok_or_else(|| PortError(format!("{bundle} is not installed signed by team {team}")))
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tray_core_avarok_publishers() -> TrayBuffer {
    give(core::avarok_publishers())
}

/// # Safety
/// `dir`, `pinned` and `host_name` follow [`borrow`]'s contract; `check` is called synchronously, only during
/// this call, with `ctx` passed through untouched.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tray_core_tabs(
    dir: *const u8,
    dir_len: usize,
    pinned: *const u8,
    pinned_len: usize,
    start_at_login: bool,
    host_name: *const u8,
    host_name_len: usize,
    check: TrayCodeSignatureFn,
    ctx: *mut c_void,
) -> TrayBuffer {
    // SAFETY: forwarded from this function's own contract.
    let (dir, pinned, host_name) = unsafe {
        (
            borrow(dir, dir_len),
            borrow(pinned, pinned_len),
            borrow(host_name, host_name_len),
        )
    };
    let host = core::HostState {
        start_at_login,
        host_name,
    };
    give(core::tabs(dir, pinned, host, &Callback { check, ctx }))
}

/// # Safety
/// `path` and `line` follow [`borrow`]'s contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tray_core_panel_url(
    port: u16,
    path: *const u8,
    path_len: usize,
    line: *const u8,
    line_len: usize,
) -> TrayBuffer {
    // SAFETY: forwarded from this function's own contract.
    let (path, line) = unsafe { (borrow(path, path_len), borrow(line, line_len)) };
    give(core::panel_url(port, path, line))
}

/// # Safety
/// `buffer` came from one of the functions above and has not been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tray_core_buffer_free(buffer: TrayBuffer) {
    if buffer.ptr.is_null() {
        return;
    }
    let slice = std::ptr::slice_from_raw_parts_mut(buffer.ptr, buffer.len);
    // SAFETY: `ptr`/`len` are exactly what `give` produced from a `Box<[u8]>`, returned once.
    drop(unsafe { Box::from_raw(slice) });
}
