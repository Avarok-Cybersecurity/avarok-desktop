// SPDX-License-Identifier: MIT OR Apache-2.0
// The C ABI of crates/tray-ffi (Rust). Every input is a (pointer, length) of UTF-8 or CBOR that
// must stay valid for the duration of the call; every returned TrayBuffer is owned by Rust and
// must be passed to tray_core_buffer_free exactly once.
#ifndef TRAY_CORE_H
#define TRAY_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *ptr;
    size_t len;
} TrayBuffer;

// The host's macOS code-signature check: true only when the bundle installed for bundle_id
// satisfies `anchor apple generic and certificate leaf[subject.OU] = <team_id>`. Called
// synchronously during tray_core_tabs only; strings are UTF-8, not NUL-terminated.
typedef bool (*TrayCodeSignatureFn)(void *ctx, const uint8_t *bundle_id, size_t bundle_id_len,
                                    const uint8_t *team_id, size_t team_id_len);

// CBOR [[name, key hex]]: the publishers a shipped host pins (tray-core keys/).
TrayBuffer tray_core_avarok_publishers(void);

// CBOR {"tabs": [...], "refused": [...], "menu": [...]} or {"error": text}; see
// crates/tray-ffi/src/encode.rs. host_name is the name in "Quit <host>".
TrayBuffer tray_core_tabs(const uint8_t *dir, size_t dir_len, const uint8_t *pinned,
                          size_t pinned_len, bool start_at_login, const uint8_t *host_name,
                          size_t host_name_len, TrayCodeSignatureFn check, void *ctx);

// UTF-8 panel URL from one stdout line of the launched agent; empty when it carries no token.
TrayBuffer tray_core_panel_url(uint16_t port, const uint8_t *path, size_t path_len,
                               const uint8_t *line, size_t line_len);

void tray_core_buffer_free(TrayBuffer buffer);

#endif
