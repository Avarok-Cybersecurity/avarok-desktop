// SPDX-License-Identifier: MIT OR Apache-2.0
//! Keeping one tab's agent running, as a pure state machine.
//!
//! The behaviour is Citadel's Mac launcher's (`AgentProcess.swift`): an agent that stops after
//! doing real work is started again at once; one that keeps stopping as soon as it starts backs
//! off 1, 2, 4, 8, 16 s; after `crash_cap` such restarts the tab is `failed`, because restarting
//! a crash loop forever only fills the log; a person choosing "Restart" starts the count over.
//! If something else already answers on the agent's port the tab is `external` and the port is
//! checked again later, so this host takes over when that agent stops.
//!
//! One deliberate difference: the Swift launcher also forgets its count when the agent becomes
//! ready. Here only a run of at least `quick_exit_ms` does, so an agent that answers and then
//! dies at once still reaches the cap instead of looping at a 1 s back-off forever.
//!
//! The machine never reads a clock or sleeps: every event carries `now`, and a wanted wake-up is
//! returned as [`Command::WakeAt`] for the host's timer, which then delivers [`Event::Due`].

use crate::model::Millis;

/// The timings, all explicit: there are no defaults in production code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisionPolicy {
    /// A run shorter than this is a failing start, not a crash after work.
    pub quick_exit_ms: u64,
    /// The first back-off; each further failing start doubles it.
    pub backoff_base_ms: u64,
    /// How long to wait before checking a port another agent held.
    pub external_recheck_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentState {
    Idle,
    /// Checking whether the agent's port is free before starting it.
    Probing,
    Starting {
        since: Millis,
    },
    Running {
        since: Millis,
    },
    /// Another process answers on the agent's port; this host is not running one.
    External,
    BackingOff {
        until: Millis,
    },
    /// Gave up; only [`Event::UserRestart`] leaves this state.
    Failed {
        reason: String,
    },
    Stopping,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Start,
    PortFree,
    PortBusy,
    SpawnFailed(String),
    Ready,
    Exited,
    /// A [`Command::WakeAt`] time has come.
    Due,
    UserRestart,
    Stop,
}

/// What the host must do next for this tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    ProbePort,
    Spawn,
    WakeAt(Millis),
    Terminate,
}

pub const KEEPS_STOPPING: &str = "The agent keeps stopping as soon as it starts. The log says why.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Supervisor {
    policy: SupervisionPolicy,
    crash_cap: u8,
    quick_exits: u8,
    state: AgentState,
}

impl Supervisor {
    pub fn new(policy: SupervisionPolicy, crash_cap: u8) -> Self {
        Self {
            policy,
            crash_cap,
            quick_exits: 0,
            state: AgentState::Idle,
        }
    }

    pub fn state(&self) -> &AgentState {
        &self.state
    }

    /// Consecutive failing starts so far.
    pub fn quick_exits(&self) -> u8 {
        self.quick_exits
    }

    pub fn handle(&mut self, event: Event, now: Millis) -> Option<Command> {
        use AgentState as S;
        match (&self.state, event) {
            (S::Idle | S::Stopped, Event::Start) => self.probe(),
            (S::Idle | S::Stopped | S::Failed { .. }, Event::UserRestart) => {
                self.quick_exits = 0;
                self.probe()
            }
            (S::Probing, Event::PortBusy) => {
                self.state = S::External;
                Some(Command::WakeAt(now.plus(self.policy.external_recheck_ms)))
            }
            (S::Probing, Event::PortFree) => {
                self.state = S::Starting { since: now };
                Some(Command::Spawn)
            }
            (S::Starting { .. }, Event::SpawnFailed(why)) => {
                self.state = S::Failed {
                    reason: format!("The agent could not be started: {why}"),
                };
                None
            }
            (S::Starting { since }, Event::Ready) => {
                self.state = S::Running { since: *since };
                None
            }
            (S::Starting { since } | S::Running { since }, Event::Exited) => {
                let ran = now.since(*since);
                self.exited(ran, now)
            }
            (S::External, Event::Due) => self.probe(),
            (S::BackingOff { until }, Event::Due) if now >= *until => self.probe(),
            (S::Starting { .. } | S::Running { .. }, Event::Stop) => {
                self.state = S::Stopping;
                Some(Command::Terminate)
            }
            (S::Stopping, Event::Exited) => {
                self.state = S::Stopped;
                None
            }
            (S::Stopping | S::Stopped, Event::Stop) => None,
            (_, Event::Stop) => {
                self.state = S::Stopped;
                None
            }
            _ => None,
        }
    }

    fn probe(&mut self) -> Option<Command> {
        self.state = AgentState::Probing;
        Some(Command::ProbePort)
    }

    fn exited(&mut self, ran_ms: u64, now: Millis) -> Option<Command> {
        if ran_ms >= self.policy.quick_exit_ms {
            self.quick_exits = 0;
            return self.probe();
        }
        self.quick_exits = self.quick_exits.saturating_add(1);
        if self.quick_exits > self.crash_cap {
            self.state = AgentState::Failed {
                reason: KEEPS_STOPPING.to_owned(),
            };
            return None;
        }
        let until = now.plus(backoff_ms(self.policy.backoff_base_ms, self.quick_exits));
        self.state = AgentState::BackingOff { until };
        Some(Command::WakeAt(until))
    }
}

/// `base * 2^(n-1)` for the n-th consecutive failing start, saturating rather than wrapping.
pub fn backoff_ms(base_ms: u64, failing_starts: u8) -> u64 {
    let doublings = u32::from(failing_starts.saturating_sub(1));
    base_ms.saturating_mul(1u64.checked_shl(doublings).unwrap_or(u64::MAX))
}
