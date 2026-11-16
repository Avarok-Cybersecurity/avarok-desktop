// SPDX-License-Identifier: MIT OR Apache-2.0
//! The OS code-signature port for this host's platform.

use tray_core::manifest::AppSection;
use tray_core::ports::{CodeSignature, PortError};
use tray_core::verify::Platform;
use tray_std::linux_install::LinuxInstallCheck;

/// Linux: the install check (there is no OS signature). Windows: `WinVerifyTrust` with the
/// pinned thumbprint is not wired yet, so every Windows app is refused rather than trusted.
#[derive(Debug, Clone)]
pub enum HostSignature {
    Linux(LinuxInstallCheck),
    WindowsNotWired,
}

impl HostSignature {
    pub fn for_platform(platform: &Platform) -> Result<Self, String> {
        match platform {
            Platform::Linux { home } => Ok(Self::Linux(LinuxInstallCheck { home: home.clone() })),
            Platform::Windows => Ok(Self::WindowsNotWired),
            Platform::MacOs => Err("on macOS the host is Avarok.app (apps/macos)".to_owned()),
        }
    }
}

impl CodeSignature for HostSignature {
    fn verify(&self, app: &AppSection) -> Result<(), PortError> {
        match self {
            Self::Linux(check) => check.verify(app),
            Self::WindowsNotWired => Err(PortError(
                "Authenticode verification (WinVerifyTrust) is not in this build".to_owned(),
            )),
        }
    }
}
