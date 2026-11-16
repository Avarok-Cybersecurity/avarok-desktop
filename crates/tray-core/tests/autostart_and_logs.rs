// SPDX-License-Identifier: MIT OR Apache-2.0
//! What the autostart entry says on each platform, and when the log starts over.
use tray_core::autostart::{AutostartEntry, HostLaunch, entry};
use tray_core::logs::{LOG_LIMIT_BYTES, line, open, starts_over};
use tray_core::ports::{LogStore, PortError};
use tray_core::verify::Platform;

fn host<'a>(exe: &'a str, args: &'a [&'a str]) -> HostLaunch<'a> {
    HostLaunch {
        app_id: "net.avarok.desktop",
        display_name: "Avarok",
        executable: exe,
        args,
    }
}

#[test]
fn each_platform_gets_its_own_entry() {
    assert_eq!(
        entry(&Platform::MacOs, &host("/Applications/Avarok.app", &[])),
        Ok(AutostartEntry::MacLoginItem)
    );
    let exe = r"C:\Program Files\Avarok\avarok.exe";
    assert_eq!(
        entry(&Platform::Windows, &host(exe, &["--background"])),
        Ok(AutostartEntry::WindowsRun {
            value_name: "net.avarok.desktop".to_owned(),
            command: format!("\"{exe}\" --background"),
        })
    );
    let linux = Platform::Linux {
        home: "/home/ada".to_owned(),
    };
    let Ok(AutostartEntry::XdgDesktop {
        file_name,
        contents,
    }) = entry(
        &linux,
        &host(
            "/home/ada/Applications/My Apps/Avarok.AppImage",
            &["--background"],
        ),
    )
    else {
        panic!("not an XDG entry");
    };
    assert_eq!(file_name, "net.avarok.desktop.desktop");
    assert!(
        contents
            .contains("\nExec=\"/home/ada/Applications/My Apps/Avarok.AppImage\" --background\n")
    );
}

#[test]
fn text_that_could_break_its_quoting_is_refused() {
    let linux = Platform::Linux {
        home: "/home/ada".to_owned(),
    };
    for exe in [
        "/opt/a\"b",
        "/opt/$(id)",
        "/opt/a`id`",
        "/opt/a\nExec=evil",
        "/opt/a%f",
        "relative/avarok",
    ] {
        assert!(entry(&linux, &host(exe, &[])).is_err(), "{exe:?}");
    }
    assert!(entry(&Platform::Windows, &host("C:\\a\" & calc", &[])).is_err());
    assert!(entry(&Platform::Windows, &host("C:\\a.exe", &["--x \"y\""])).is_err());
    let bad_id = HostLaunch {
        app_id: "../evil",
        ..host("/opt/a", &[])
    };
    assert!(entry(&linux, &bad_id).is_err());
}

#[test]
fn the_log_starts_over_only_past_its_limit() {
    assert!(!starts_over(None, LOG_LIMIT_BYTES));
    assert!(!starts_over(Some(LOG_LIMIT_BYTES), LOG_LIMIT_BYTES));
    assert!(starts_over(Some(LOG_LIMIT_BYTES + 1), LOG_LIMIT_BYTES));
}

struct Store {
    len: Option<u64>,
    truncated: bool,
}
impl LogStore for Store {
    fn existing_len(&self) -> Result<Option<u64>, PortError> {
        Ok(self.len)
    }
    fn truncate(&mut self) -> Result<(), PortError> {
        self.truncated = true;
        Ok(())
    }
    fn append(&mut self, _: &str) -> Result<(), PortError> {
        Ok(())
    }
}

#[test]
fn opening_truncates_an_oversize_log_and_keeps_a_small_one() {
    let mut big = Store {
        len: Some(LOG_LIMIT_BYTES + 1),
        truncated: false,
    };
    assert_eq!(open(&mut big, LOG_LIMIT_BYTES), Ok(true));
    assert!(big.truncated);
    let mut small = Store {
        len: Some(10),
        truncated: false,
    };
    assert_eq!(open(&mut small, LOG_LIMIT_BYTES), Ok(false));
    assert!(!small.truncated);
}

#[test]
fn a_log_line_cannot_forge_another() {
    let l = line(
        "2026-11-16T00:00:00Z",
        "net.avarok.x",
        "ok\n[host 2026] forged",
    );
    assert_eq!(l.matches('\n').count(), 1);
    assert!(l.ends_with("ok\u{FFFD}[host 2026] forged\n"));
}
