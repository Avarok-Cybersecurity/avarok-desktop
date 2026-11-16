// SPDX-License-Identifier: MIT OR Apache-2.0
//! The supervision table: each row is (state, event, time) -> (state, command).
use tray_core::model::Millis;
use tray_core::supervise::{
    AgentState, Command, Event, KEEPS_STOPPING, SupervisionPolicy, Supervisor,
};

/// The Mac launcher's timings: under 5 s is a failing start, back-off starts at 1 s.
const POLICY: SupervisionPolicy = SupervisionPolicy {
    quick_exit_ms: 5_000,
    backoff_base_ms: 1_000,
    external_recheck_ms: 10_000,
};
const CAP: u8 = 5;

/// A supervisor whose agent is up, started at `t`.
fn started(t: u64) -> Supervisor {
    let mut s = Supervisor::new(POLICY, CAP);
    assert_eq!(s.handle(Event::Start, Millis(t)), Some(Command::ProbePort));
    assert_eq!(s.handle(Event::PortFree, Millis(t)), Some(Command::Spawn));
    s
}

/// Exits after `ran` ms, then (if backing off) lets the back-off elapse and starts again.
/// Returns the back-off waited, or `None` when the machine did not back off.
fn fail_after(s: &mut Supervisor, now: &mut u64, ran: u64) -> Option<u64> {
    *now += ran;
    match s.handle(Event::Exited, Millis(*now)) {
        Some(Command::WakeAt(Millis(at))) => {
            let waited = at - *now;
            *now = at;
            assert_eq!(s.handle(Event::Due, Millis(*now)), Some(Command::ProbePort));
            assert_eq!(
                s.handle(Event::PortFree, Millis(*now)),
                Some(Command::Spawn)
            );
            Some(waited)
        }
        _ => None,
    }
}

#[test]
fn a_crash_after_work_restarts_at_once() {
    let mut s = started(0);
    assert_eq!(s.handle(Event::Ready, Millis(400)), None);
    assert_eq!(s.state(), &AgentState::Running { since: Millis(0) });
    assert_eq!(
        s.handle(Event::Exited, Millis(60_000)),
        Some(Command::ProbePort)
    );
    assert_eq!(s.state(), &AgentState::Probing);
    assert_eq!(s.quick_exits(), 0);
}

#[test]
fn a_failing_start_backs_off_1_2_4_8_16_seconds_then_fails() {
    let (mut s, mut now) = (started(0), 0);
    let waits: Vec<_> = (0..CAP)
        .map(|_| fail_after(&mut s, &mut now, 100).unwrap())
        .collect();
    assert_eq!(waits, [1_000, 2_000, 4_000, 8_000, 16_000]);
    assert_eq!(fail_after(&mut s, &mut now, 100), None);
    assert_eq!(
        s.state(),
        &AgentState::Failed {
            reason: KEEPS_STOPPING.to_owned()
        }
    );
}

#[test]
fn a_crash_loop_always_ends_in_failed() {
    // Without the cap this runs every iteration and never fails: the loop bound is the proof.
    let (mut s, mut now) = (started(0), 0);
    let mut exits = 0u32;
    while !matches!(s.state(), AgentState::Failed { .. }) && exits < 10_000 {
        fail_after(&mut s, &mut now, 1);
        exits += 1;
    }
    assert_eq!(
        exits,
        u32::from(CAP) + 1,
        "the agent was restarted {exits} times"
    );
}

#[test]
fn a_long_run_between_failing_starts_forgets_the_count() {
    let (mut s, mut now) = (started(0), 0);
    fail_after(&mut s, &mut now, 100);
    fail_after(&mut s, &mut now, 100);
    assert_eq!(s.quick_exits(), 2);
    now += 5_000;
    assert_eq!(
        s.handle(Event::Exited, Millis(now)),
        Some(Command::ProbePort)
    );
    assert_eq!(s.quick_exits(), 0);
}

#[test]
fn ready_alone_does_not_forget_the_count() {
    let (mut s, mut now) = (started(0), 0);
    for _ in 0..=CAP {
        assert_eq!(s.handle(Event::Ready, Millis(now + 1)), None);
        fail_after(&mut s, &mut now, 2_000);
    }
    assert!(matches!(s.state(), AgentState::Failed { .. }));
}

#[test]
fn a_user_restart_resets_a_failed_tab() {
    let (mut s, mut now) = (started(0), 0);
    while !matches!(s.state(), AgentState::Failed { .. }) {
        fail_after(&mut s, &mut now, 1);
    }
    assert_eq!(
        s.handle(Event::Due, Millis(now + 100_000)),
        None,
        "failed stays failed"
    );
    assert_eq!(
        s.handle(Event::Start, Millis(now)),
        None,
        "only the person restarts it"
    );
    assert_eq!(
        s.handle(Event::UserRestart, Millis(now)),
        Some(Command::ProbePort)
    );
    assert_eq!(s.quick_exits(), 0);
    assert_eq!(s.handle(Event::PortFree, Millis(now)), Some(Command::Spawn));
    assert_eq!(fail_after(&mut s, &mut now, 1), Some(1_000));
}

#[test]
fn an_early_wake_does_not_cut_the_back_off_short() {
    let mut s = started(0);
    assert_eq!(
        s.handle(Event::Exited, Millis(10)),
        Some(Command::WakeAt(Millis(1_010)))
    );
    assert_eq!(s.handle(Event::Due, Millis(1_009)), None);
    assert_eq!(
        s.handle(Event::Due, Millis(1_010)),
        Some(Command::ProbePort)
    );
}

#[test]
fn a_port_held_by_another_agent_is_watched_not_fought() {
    let mut s = Supervisor::new(POLICY, CAP);
    s.handle(Event::Start, Millis(0));
    assert_eq!(
        s.handle(Event::PortBusy, Millis(0)),
        Some(Command::WakeAt(Millis(10_000)))
    );
    assert_eq!(s.state(), &AgentState::External);
    assert_eq!(
        s.handle(Event::Due, Millis(10_000)),
        Some(Command::ProbePort)
    );
    assert_eq!(
        s.handle(Event::PortFree, Millis(10_000)),
        Some(Command::Spawn)
    );
}

#[test]
fn a_spawn_the_os_refuses_fails_at_once() {
    let mut s = started(0);
    assert_eq!(
        s.handle(Event::SpawnFailed("no such file".to_owned()), Millis(0)),
        None
    );
    assert!(matches!(s.state(), AgentState::Failed { reason } if reason.contains("no such file")));
}

#[test]
fn stopping_terminates_and_an_exit_then_is_not_a_crash() {
    let mut s = started(0);
    s.handle(Event::Ready, Millis(1));
    assert_eq!(s.handle(Event::Stop, Millis(2)), Some(Command::Terminate));
    assert_eq!(s.handle(Event::Exited, Millis(3)), None);
    assert_eq!(s.state(), &AgentState::Stopped);
    assert_eq!(s.quick_exits(), 0);
    let mut backing = started(0);
    backing.handle(Event::Exited, Millis(1));
    assert_eq!(backing.handle(Event::Stop, Millis(2)), None);
    assert_eq!(
        backing.handle(Event::Due, Millis(5_000)),
        None,
        "a stopped tab never restarts"
    );
}

#[test]
fn the_back_off_saturates_instead_of_overflowing() {
    assert_eq!(tray_core::supervise::backoff_ms(1_000, 1), 1_000);
    assert_eq!(tray_core::supervise::backoff_ms(1_000, 200), u64::MAX);
}
