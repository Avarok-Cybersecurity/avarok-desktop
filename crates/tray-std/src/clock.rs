// SPDX-License-Identifier: MIT OR Apache-2.0
//! The monotonic clock supervision reads ([`Clock`]).

use std::time::Instant;
use tray_core::model::Millis;
use tray_core::ports::Clock;

#[derive(Debug, Clone, Copy)]
pub struct MonotonicClock {
    origin: Instant,
}

impl MonotonicClock {
    pub fn starting_now() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Clock for MonotonicClock {
    fn now(&self) -> Millis {
        Millis(u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}
