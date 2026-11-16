// SPDX-License-Identifier: MIT OR Apache-2.0
//! Agent processes for the Windows and Linux host ([`AgentLauncher`]). Each agent's stdout is
//! read on its own thread: lines go to the agent's log, and the first handshake line becomes its
//! panel token. Only a process this launcher started can supply one.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tray_core::handshake::HandshakeToken;
use tray_core::model::{AgentSpec, Program, ReadyProbe};
use tray_core::ports::{AgentLauncher, Pid, PortError};

/// Where an agent's stdout lines go (the host's log store).
pub type LineSink = Arc<dyn Fn(Pid, &str) + Send + Sync>;

struct Running {
    child: Child,
    token: Arc<Mutex<Option<HandshakeToken>>>,
}

pub struct StdAgentLauncher {
    probe_timeout: Duration,
    sink: LineSink,
    running: BTreeMap<Pid, Running>,
}

impl std::fmt::Debug for StdAgentLauncher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdAgentLauncher")
            .field("running", &self.running.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl StdAgentLauncher {
    /// `probe_timeout` bounds each readiness connect; `sink` receives every stdout line.
    pub fn new(probe_timeout: Duration, sink: LineSink) -> Self {
        Self {
            probe_timeout,
            sink,
            running: BTreeMap::new(),
        }
    }

    /// The token the agent printed, once it has.
    pub fn token(&self, pid: Pid) -> Option<HandshakeToken> {
        let running = self.running.get(&pid)?;
        running
            .token
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether the agent has exited; it is forgotten once it has.
    pub fn has_exited(&mut self, pid: Pid) -> Result<bool, PortError> {
        let Some(running) = self.running.get_mut(&pid) else {
            return Ok(true);
        };
        let exited = running
            .child
            .try_wait()
            .map_err(|e| PortError(e.to_string()))?
            .is_some();
        if exited {
            self.running.remove(&pid);
        }
        Ok(exited)
    }
}

impl AgentLauncher for StdAgentLauncher {
    fn spawn(&mut self, agent: &AgentSpec) -> Result<Pid, PortError> {
        let program = executable(&agent.program)?;
        let mut child = Command::new(&program)
            .args(&agent.argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| PortError(format!("{program}: {e}")))?;
        let pid = Pid(child.id());
        let token = Arc::new(Mutex::new(None));
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| PortError("the agent has no stdout".to_owned()))?;
        let (sink, slot) = (Arc::clone(&self.sink), Arc::clone(&token));
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let mut held = slot.lock().unwrap_or_else(PoisonError::into_inner);
                match HandshakeToken::from_line(&line) {
                    // Never logged: the token is the panel's credential.
                    Some(found) if held.is_none() => *held = Some(found),
                    _ => sink(pid, &line),
                }
            }
        });
        self.running.insert(pid, Running { child, token });
        Ok(pid)
    }

    fn terminate(&mut self, pid: Pid) -> Result<(), PortError> {
        let mut running = self
            .running
            .remove(&pid)
            .ok_or_else(|| PortError(format!("pid {} is not an agent this host started", pid.0)))?;
        running.child.kill().map_err(|e| PortError(e.to_string()))?;
        running.child.wait().map_err(|e| PortError(e.to_string()))?;
        Ok(())
    }

    fn is_ready(&self, probe: &ReadyProbe) -> bool {
        let ReadyProbe::Tcp { port } = probe;
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, *port));
        TcpStream::connect_timeout(&addr, self.probe_timeout).is_ok()
    }
}

/// The file to run. Windows paths are written with `%ProgramFiles%`-style roots, expanded here
/// from this user's environment; a root the environment lacks is an error, never a guess.
fn executable(program: &Program) -> Result<String, PortError> {
    match program {
        Program::LinuxExec { path } => Ok(path.clone()),
        Program::WindowsExe { path, .. } => {
            let (var, rest) = path
                .strip_prefix('%')
                .and_then(|p| p.split_once('%'))
                .ok_or_else(|| PortError(format!("{path:?} has no install root")))?;
            let root = std::env::var(var).map_err(|_| PortError(format!("%{var}% is not set")))?;
            Ok(format!("{root}{rest}"))
        }
        Program::MacBundle { .. } => Err(PortError(
            "a macOS bundle is launched by the Avarok app, not this host".to_owned(),
        )),
    }
}
