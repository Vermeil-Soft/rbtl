use std::time::{Instant, Duration};
use std::collections::VecDeque;

use crate::net::common::SeqId;

#[derive(Debug)]
pub (crate) struct PingTracker {
    pub (crate) waiting_ping: Option<(u32, Instant)>,
    // in ms
    pub (crate) recorded_pings: VecDeque<(u32, Instant)>,
}

impl PingTracker {
    const PINGS_LEN: usize = 16;

    pub fn new() -> PingTracker {
        PingTracker {
            waiting_ping: None,
            recorded_pings: VecDeque::with_capacity(Self::PINGS_LEN),
        }
    }

    /// Should be called when we send the packet that will act as a ping
    ///
    /// Does nothing if there is already another last_ping_sent recorded unanswered
    pub (crate) fn ping(&mut self, seq_id: SeqId) {
        let now = Instant::now();
        let delta_sec = self.waiting_ping.map(|(_, time)| {
            (now - time).as_secs()
        });
        if let Some(delta_sec) = delta_sec {
            if delta_sec <= 3 {
                // current ping is valid, we will skip storing given seq_id
                return;
            }
        }
        self.waiting_ping = Some((seq_id, now));
    }

    fn register_ping(&mut self, ping_ms: u32, now: Instant) {
        if self.recorded_pings.len() == Self::PINGS_LEN {
            self.recorded_pings.pop_back();
        }
        self.recorded_pings.push_front((ping_ms, now));
    }

    /// Should be called when we receive the ping back
    ///
    /// Does nothing if the seq_id has not been recorded
    pub (crate) fn pong(&mut self, seq_id: SeqId) {
        let clear_waiting_ping: bool = match self.waiting_ping {
            Some((stored_seq_id, time)) if stored_seq_id == seq_id => {
                let now = Instant::now();
                let d = now - time;
                let ms = d.subsec_millis();
                let secs = d.as_secs();
                let ping_ms = if secs >= 5 {
                    4999u32
                } else {
                    ms + (secs as u32) * 1000
                };
                self.register_ping(ping_ms, now);
                true
            },
            _ => false
        };
        if clear_waiting_ping {
            self.waiting_ping = None;
        }
    }

    /// Returns the average ping over the given past duration
    pub (crate) fn avg_ping(&self, seconds: f32) -> Option<f32> {
        let mut tot = 0.0;
        let mut n: u64 = 0;
        let Some(old_date) = Instant::now().checked_sub(Duration::from_secs_f32(seconds)) else {
            return None;
        };
        if seconds <= 0.0 {
            return self.recorded_pings.get(0).map(|(p, _)| *p as f32);
        }
        for (ping, _) in self.recorded_pings.iter().take_while(|(_, instant)| *instant >= old_date) {
            tot += *ping as f32;
            n += 1;
        }
        if n == 0 {
            None
        } else {
            Some(tot / n as f32)
        }
    }

    /// Returns the lastest ping in ms, and when it arrived.
    pub (crate) fn last_ping_info(&self) -> Option<(u32, Instant)> {
        self.recorded_pings.get(0).copied()
    }
}