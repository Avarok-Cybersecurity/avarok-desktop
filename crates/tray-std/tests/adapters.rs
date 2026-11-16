// SPDX-License-Identifier: MIT OR Apache-2.0
//! The std adapters against a real temporary directory and real processes.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tray_core::model::{AgentSpec, Program, ReadyProbe};
use tray_core::ports::{AgentLauncher, Pid, TabDirectory};
use tray_std::launcher::StdAgentLauncher;
use tray_std::tab_dir::FsTabDirectory;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tray-std-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_directory_lists_regular_files_and_reads_at_most_one_byte_past_the_limit() {
    let dir = scratch("dir");
    std::fs::write(dir.join("net.avarok.a.json"), b"0123456789").unwrap();
    std::fs::create_dir(dir.join("net.avarok.b.json")).unwrap();
    let tabs = FsTabDirectory::new(dir.clone());
    let listed = tabs.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (listed[0].file_name.as_str(), listed[0].len),
        ("net.avarok.a.json", 10)
    );
    assert_eq!(tabs.read("net.avarok.a.json", 4).unwrap(), b"01234");
    assert!(tabs.read("../net.avarok.a.json", 4).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(FsTabDirectory::new(dir).list().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn an_agent_hands_over_its_token_on_stdout_and_never_logs_it() {
    let token = "t".repeat(40);
    let logged = Arc::new(Mutex::new(Vec::new()));
    let sink_log = Arc::clone(&logged);
    let mut launcher = StdAgentLauncher::new(
        Duration::from_millis(200),
        Arc::new(move |_pid: Pid, line: &str| sink_log.lock().unwrap().push(line.to_owned())),
    );
    let agent = AgentSpec {
        program: Program::LinuxExec {
            path: "/bin/sh".to_owned(),
        },
        argv: vec![
            "-c".to_owned(),
            format!(
                "echo hello; echo AVAROK_PANEL_TOKEN={token}; echo AVAROK_PANEL_TOKEN={}",
                "u".repeat(40)
            ),
        ],
        ready: ReadyProbe::Tcp { port: 1 },
        crash_cap: 1,
    };
    let pid = launcher.spawn(&agent).unwrap();
    let mut seen = None;
    for _ in 0..200 {
        seen = launcher.token(pid);
        if seen.is_some() && logged.lock().unwrap().len() == 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(seen.map(|t| t.as_str().to_owned()), Some(token.clone()));
    let lines = logged.lock().unwrap().clone();
    assert_eq!(lines[0], "hello");
    assert!(lines.iter().all(|l| !l.contains(&token)), "{lines:?}");
    assert!(!launcher.is_ready(&ReadyProbe::Tcp { port: 1 }));
}
