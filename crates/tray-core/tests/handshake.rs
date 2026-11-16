// SPDX-License-Identifier: MIT OR Apache-2.0
//! The stdout-handshake token and the web panel URL built from it.

use tray_core::handshake::{HandshakeToken, panel_url};
use tray_core::model::{PanelSpec, PanelToken};

const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz012345-_AB";

fn web() -> PanelSpec {
    PanelSpec::Web {
        port: 4823,
        path: "/panel/".to_owned(),
        token: PanelToken::StdoutHandshake,
    }
}

#[test]
fn the_token_line_becomes_the_loopback_panel_url() {
    let token = HandshakeToken::from_line(&format!("AVAROK_PANEL_TOKEN={TOKEN}")).unwrap();
    assert_eq!(
        panel_url(&web(), &token).as_deref(),
        Some(format!("http://127.0.0.1:4823/panel/?token={TOKEN}").as_str())
    );
    let native = PanelSpec::Native {
        macos_module: "CitadelPanel".to_owned(),
    };
    assert_eq!(panel_url(&native, &token), None);
}

#[test]
fn any_other_line_carries_no_token() {
    let short = "a".repeat(31);
    let long = "a".repeat(129);
    for line in [
        format!(" AVAROK_PANEL_TOKEN={TOKEN}"),
        format!("AVAROK_PANEL_TOKEN={TOKEN} "),
        format!("AVAROK_PANEL_TOKEN={TOKEN}&x=1"),
        format!("AVAROK_PANEL_TOKEN={short}"),
        format!("AVAROK_PANEL_TOKEN={long}"),
        format!("avarok_panel_token={TOKEN}"),
        "listening on 127.0.0.1:4823".to_owned(),
    ] {
        assert_eq!(HandshakeToken::from_line(&line), None, "{line}");
    }
    assert!(HandshakeToken::from_line(&format!("AVAROK_PANEL_TOKEN={}", "a".repeat(32))).is_some());
    assert!(
        HandshakeToken::from_line(&format!("AVAROK_PANEL_TOKEN={}", "a".repeat(128))).is_some()
    );
}
