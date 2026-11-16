# Licence notes

This repository is MIT OR Apache-2.0, and every crate and file in it must stay so.

Some of the apps the host shows as tabs are licensed differently: CertifiedCopy is AGPL. The
boundary is the process. The host reads a JSON manifest the app installs, launches the app's
own signed executable, and loads its panel over loopback HTTP. It never links, embeds or copies
the app's code.

Two gates in CI hold the line:

- `cargo deny check licenses` (`deny.toml`) allows only permissive licences, for dependencies
  and for this workspace's own crates, so an AGPL, GPL or LGPL crate fails the build.
- `scripts/check-spdx.sh` refuses any file whose SPDX header names a GPL-family licence, and any
  Rust source without the MIT OR Apache-2.0 header.

Behaviour may be learned from an AGPL implementation; its text may not be copied here.

## Grant: the Citadel macOS agent sources (2026-11-16)

The copyright holder (Avarok Cybersecurity, Thomas Braun) licenses the Swift sources of the Citadel
macOS agent, `apps/macos-agent/*.swift` in `Avarok-Cybersecurity/citadel-workspace`, under
**MIT OR Apache-2.0** for use in this repository. In that repository they remain under AGPL-3.0 as
well. Code ported from them may be copied here literally. Each ported file carries this
repository's SPDX header and names its source file in a comment.

This grant does not cover CertifiedCopy (`rMazing`) or any other AGPL project.

## MPL-2.0 dependencies (2026-11-16)

MPL-2.0 is allowed for third-party dependencies only, and only because the Windows/Linux host needs
it through wry and tray-icon. MPL is file-level copyleft: changes to those files stay MPL, and no
MPL source is copied into this repository. The owner approved it on 2026-11-16.
