# avarok-desktop

The Avarok menu-bar and tray host: one icon, with a tab for each Avarok app installed on the
machine (Citadel Workspaces, CertifiedCopy, synchronized.work). Each app installs on its own and
drops a signed tab manifest; the host finds it, verifies it, runs the app's agent and shows its
panel.

## Layout

| Path | What |
|------|------|
| `crates/tray-core` | The portable model, in Rust: tabs and the menu, agent supervision, single instance, autostart, update and tab-manifest verification, log rotation. Pure decisions; every OS call is a trait in `ports.rs`. |
| `crates/tray-host` | Windows and Linux host over `tray-core` (`tray-icon`, `muda`, `wry`). Not yet written. |
| `TrayKit/` | The macOS host's Swift package. Not yet written. |

## Trust

A tab manifest is accepted only when all of these hold:

1. Its ML-DSA-65 signature (FIPS 204, context `avarok-tab-manifest-v1`, over the deterministic
   CBOR of every field but `sig`) verifies with a publisher key the host pins. Only Avarok's
   keys are pinned.
2. Every field passes its rule: a reverse-DNS id matching the file name, an install path under
   the platform's install roots with no `..`, a panel on the agent's own loopback port, an icon
   of at most 16 KiB, a manifest of at most 64 KiB, no unknown fields.
3. The app it names passes the operating system's code-signature check (macOS designated
   requirement for the team, Windows `WinVerifyTrust` with the pinned thumbprint, Linux file
   ownership and mode).

Update manifests use the same scheme with their own context, `avarok-update-manifest-v1`.

## Building

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
```

The toolchain is pinned in `rust-toolchain.toml`.

## Licence

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. See [LICENSE-NOTES.md](LICENSE-NOTES.md) for how the
host stays separate from AGPL apps it launches.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
