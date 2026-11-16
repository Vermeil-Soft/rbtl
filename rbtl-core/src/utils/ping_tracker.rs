use std::time::{Instant, Duration};
use std::collections::VecDeque;

/// Helper for implementors: measures the ping from a message we sent and its answer.
///
/// Only one message is timed at a time.
#[derive(Debug)]
pub struct PingTracker {
    waiting_ping: Option<(u32, Instant)>,
    // in ms
    recorded_pings: VecDeque<(u32, Instant)>,
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
    pub fn ping(&mut self, msg_id: u32) {
        let now = Instant::now();
        let delta_sec = self.waiting_ping.map(|(_, time)| {
            (now - time).as_secs()
        });
        if let Some(delta_sec) = delta_sec {
            if delta_sec <= 3 {
                // current ping is valid, we will skip storing given msg_id
                return;
            }
        }
        self.waiting_ping = Some((msg_id, now));
    }

    fn register_ping(&mut self, ping_ms: u32, now: Instant) {
        if self.recorded_pings.len() == Self::PINGS_LEN {
            self.recorded_pings.pop_back();
        }
        self.recorded_pings.push_front((ping_ms, now));
    }

    /// Should be called when we receive the ping back
    ///
    /// Does nothing if the msg_id has not been recorded
    pub fn pong(&mut self, msg_id: u32) {
        self.pong_with_delay(msg_id, Duration::ZERO)
    }

    /// Same as `pong`, but `remote_delay` is how long the remote waited before answering:
    /// it is not part of the network time, so it is removed from the ping.
    pub fn pong_with_delay(&mut self, msg_id: u32, remote_delay: Duration) {
        match self.waiting_ping {
            Some((stored_msg_id, time)) if stored_msg_id == msg_id => {
                let now = Instant::now();
                let round_trip = now.saturating_duration_since(time).saturating_sub(remote_delay);
                let ping_ms = round_trip.as_millis().min(4999) as u32;
                self.register_ping(ping_ms, now);
                self.waiting_ping = None;
            },
            _ => {}
        }
    }

    /// Forget the ping of `msg_id` without recording anything, because its answer can't be timed correctly.
    ///
    /// Allows timing the next message right away.
    pub fn cancel(&mut self, msg_id: u32) {
        if matches!(self.waiting_ping, Some((stored_msg_id, _)) if stored_msg_id == msg_id) {
            self.waiting_ping = None;
        }
    }

    /// Returns the average ping over the given past duration
    pub fn avg_ping(&self, seconds: f32) -> Option<f32> {
        // also catches NaN, which `Duration::from_secs_f32` would panic on, as would negatives
        if !(seconds > 0.0) {
            return self.recorded_pings.get(0).map(|(p, _)| *p as f32);
        }
        let Some(old_date) = Duration::try_from_secs_f32(seconds).ok().and_then(|d| Instant::now().checked_sub(d)) else {
            // too far in the past to represent: every record qualifies
            return self.avg_of(self.recorded_pings.iter());
        };
        self.avg_of(self.recorded_pings.iter().take_while(|(_, instant)| *instant >= old_date))
    }

    /// Average of the given records, or the latest ping if there are none
    fn avg_of<'a>(&self, records: impl Iterator<Item=&'a (u32, Instant)>) -> Option<f32> {
        let mut tot = 0.0;
        let mut n: u64 = 0;
        for (ping, _) in records {
            tot += *ping as f32;
            n += 1;
        }
        if n == 0 {
            self.recorded_pings.get(0).map(|(p, _)| *p as f32)
        } else {
            Some(tot / n as f32)
        }
    }

    /// Returns the lastest ping in ms, and when it arrived.
    pub fn last_ping_info(&self) -> Option<(u32, Instant)> {
        self.recorded_pings.get(0).copied()
    }
}

impl Default for PingTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[test]
fn avg_ping_any_seconds() {
    let mut p = PingTracker::new();
    assert_eq!(p.avg_ping(1.0), None);
    p.register_ping(42, Instant::now());
    for seconds in [-1.0, 0.0, f32::NAN, f32::INFINITY, 1e30, 1.0] {
        assert_eq!(p.avg_ping(seconds), Some(42.0), "seconds={}", seconds);
    }
}

#[test]
fn pong_removes_remote_delay() {
    let mut p = PingTracker::new();
    p.ping(1);
    std::thread::sleep(Duration::from_millis(30));
    // the remote says it waited longer than the whole round trip: never underflows
    p.pong_with_delay(1, Duration::from_secs(10));
    assert_eq!(p.last_ping_info().map(|(ms, _)| ms), Some(0));

    p.ping(2);
    std::thread::sleep(Duration::from_millis(30));
    p.pong_with_delay(2, Duration::from_millis(20));
    let ms = p.last_ping_info().unwrap().0;
    assert!(ms >= 10 && ms < 30, "ping was {}ms", ms);
}

#[test]
fn cancel_skips_sample() {
    let mut p = PingTracker::new();
    p.ping(1);
    p.cancel(1);
    p.pong(1);
    assert_eq!(p.last_ping_info(), None);
    // the next message can be timed right away
    p.ping(2);
    p.pong(2);
    assert!(p.last_ping_info().is_some());
}
