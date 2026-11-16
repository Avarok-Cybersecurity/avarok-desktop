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
