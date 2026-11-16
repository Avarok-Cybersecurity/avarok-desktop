// SPDX-License-Identifier: MIT OR Apache-2.0
//! The event loop: a tray icon whose menu is tray-core's, an agent per verified tab, and a wry
//! window for a tab's web panel, loaded only from the URL tray-core built from that agent's
//! handshake line.
//!
//! Not yet here: supervision (tray-core's state machine is not driven; an agent that exits
//! stays exited), re-discovery on directory change, start at login, update checks.

use crate::menu;
use crate::signature::HostSignature;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::{Window, WindowBuilder, WindowId};
use tray_core::discover::discover;
use tray_core::handshake::panel_url;
use tray_core::model::{PanelSpec, Tab, TabId};
use tray_core::ports::{AgentLauncher, Pid};
use tray_core::signature::TrustedPublishers;
use tray_core::tabs::{MenuAction, MenuState, entries};
use tray_core::verify::{Platform, Verifier};
use tray_icon::TrayIconBuilder;
use tray_icon::menu::MenuEvent;
use tray_std::launcher::StdAgentLauncher;
use tray_std::tab_dir::FsTabDirectory;
use wry::{WebView, WebViewBuilder};

const HOST_NAME: &str = "Avarok";
const PROBE_TIMEOUT: Duration = Duration::from_millis(250);
const TICK: Duration = Duration::from_millis(100);
const GLYPH_SIDE: u32 = 16;

pub fn run(platform: Platform, tab_dir: PathBuf) -> Result<(), String> {
    let os = HostSignature::for_platform(&platform)?;
    let trusted = TrustedPublishers::avarok().map_err(|e| e.to_string())?;
    let verifier = Verifier { platform, trusted };
    let found =
        discover(&FsTabDirectory::new(tab_dir), &verifier, &os).map_err(|e| e.to_string())?;
    for (file, why) in &found.refused {
        eprintln!("avarok: refused {file}: {why}");
    }
    let tabs = found.tabs;
    let mut launcher = StdAgentLauncher::new(
        PROBE_TIMEOUT,
        Arc::new(|pid: Pid, line: &str| eprintln!("agent {}: {line}", pid.0)),
    );
    let mut pids: BTreeMap<TabId, Pid> = BTreeMap::new();
    for tab in &tabs {
        match launcher.spawn(&tab.agent) {
            Ok(pid) => drop(pids.insert(tab.id.clone(), pid)),
            Err(why) => eprintln!("avarok: {} did not start: {why}", tab.id),
        }
    }
    let agents = BTreeMap::new();
    let state = MenuState {
        agents: &agents,
        start_at_login: false,
        host_name: HOST_NAME,
    };
    let event_loop = EventLoopBuilder::new().build();
    let icon =
        tray_icon::Icon::from_rgba(glyph(), GLYPH_SIDE, GLYPH_SIDE).map_err(|e| e.to_string())?;
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu::build(&entries(&tabs, &state))?))
        .with_tooltip(HOST_NAME)
        .with_icon(icon)
        .build()
        .map_err(|e| e.to_string())?;
    let mut panels: BTreeMap<WindowId, (Window, WebView)> = BTreeMap::new();
    event_loop.run(move |event, target, flow| {
        let _keep_tray = &tray;
        *flow = ControlFlow::WaitUntil(Instant::now() + TICK);
        if let Event::WindowEvent {
            window_id,
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            panels.remove(&window_id);
        }
        while let Ok(chosen) = MenuEvent::receiver().try_recv() {
            match MenuAction::from_id(chosen.id.as_ref(), &tabs) {
                Some(MenuAction::Quit) => {
                    for (tab, pid) in &pids {
                        if let Err(why) = launcher.terminate(*pid) {
                            eprintln!("avarok: {tab} did not stop: {why}");
                        }
                    }
                    *flow = ControlFlow::Exit;
                }
                Some(MenuAction::Tab { tab, .. }) => {
                    let Some(tab) = tabs.iter().find(|t| t.id == tab) else {
                        continue;
                    };
                    match open_panel(
                        tab,
                        pids.get(&tab.id).and_then(|p| launcher.token(*p)),
                        target,
                    ) {
                        Ok(window) => drop(panels.insert(window.0.id(), window)),
                        Err(why) => eprintln!("avarok: {}: {why}", tab.id),
                    }
                }
                Some(other) => eprintln!("avarok: {} is not in this build yet", other.id()),
                None => eprintln!("avarok: no such menu item {:?}", chosen.id.as_ref()),
            }
        }
    })
}

fn open_panel(
    tab: &Tab,
    token: Option<tray_core::handshake::HandshakeToken>,
    target: &tao::event_loop::EventLoopWindowTarget<()>,
) -> Result<(Window, WebView), String> {
    let PanelSpec::Web { port, .. } = &tab.panel else {
        return Err("its panel is native, and this host shows web panels only".to_owned());
    };
    let token = token.ok_or("its agent has not handed over a panel token")?;
    let url = panel_url(&tab.panel, &token).ok_or("it has no web panel")?;
    let origin = format!("http://127.0.0.1:{port}/");
    let window = WindowBuilder::new()
        .with_title(&tab.title)
        .build(target)
        .map_err(|e| e.to_string())?;
    let builder = WebViewBuilder::new()
        .with_url(&url)
        // The panel stays on its agent's loopback origin; anything else is refused.
        .with_navigation_handler(move |to| to.starts_with(&origin));
    #[cfg(target_os = "linux")]
    let webview = {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        let vbox = window.default_vbox().ok_or("the window has no GTK box")?;
        builder.build_gtk(vbox)
    };
    #[cfg(not(target_os = "linux"))]
    let webview = builder.build(&window);
    Ok((window, webview.map_err(|e| e.to_string())?))
}

/// The host's tray glyph: a white rounded square, drawn rather than shipped as a file.
fn glyph() -> Vec<u8> {
    let side = GLYPH_SIDE;
    (0..side * side)
        .flat_map(|i| {
            let (x, y) = (i % side, i / side);
            let corner = (x < 2 || x >= side - 2) && (y < 2 || y >= side - 2);
            let inside = (1..side - 1).contains(&x) && (1..side - 1).contains(&y) && !corner;
            [255, 255, 255, if inside { 255 } else { 0 }]
        })
        .collect()
}
