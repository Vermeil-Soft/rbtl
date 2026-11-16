use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hashbrown::{HashMap, HashSet};
use x25519_dalek::SharedSecret;
use std::collections::VecDeque;
use crate::consts::{MAX_INCOMPLETE_FRAGMENT_SETS, MAX_FRAGMENT_SETS};
use crate::net::common::{nonce_from_seq_id, SeqId};

use super::ack::{Acks, Ack, AckTiming};
use super::{Fragment, build_data_from_fragments};
use super::FragmentSetFlags;
use std::time::{Instant, Duration};

pub (crate) trait FragmentDataRef: std::fmt::Debug + AsRef<[u8]> + 'static {}

impl<D> FragmentDataRef for D where D: std::fmt::Debug + AsRef<[u8]> + 'static {
}

#[derive(Debug)]
pub (crate) enum FragmentAssemblyState<B: FragmentDataRef> {
    Incomplete {
        fragments: HashMap<u8, Fragment<B>>,
    },
    /// (iteration_n of completion, n of fragments)
    Complete(Instant, u8)
}

/// Represents fragments for a given seq_id
#[derive(Debug)]
pub (crate) struct FragmentAssemblySet<B: FragmentDataRef> {
    pub (crate) seq_id: SeqId,

    pub (crate) state: FragmentAssemblyState<B>,

    /// Flags of the set, taken from the first fragment received. Every other fragment must have the same.
    ///
    /// Never contains per-transmission flags (see `FragmentSetFlags::set_flags`)
    pub (crate) frag_set_flags: FragmentSetFlags,

    /// frag_total of the set, taken from the first fragment received. Every other fragment must have the same.
    pub (crate) frag_total: u8,

    /// Id of the last iteration we sent an ack for this FragmentSet
    pub (crate) last_sent_ack: Option<Instant>,

    pub (crate) last_received: Instant,

    /// Whether the last fragment received was a resend: then the remote can't use our ack to compute the ping
    pub (crate) last_received_resend: bool,

    /// When the set was created, to tell it apart from an older set with the same seq_id
    pub (crate) created: Instant,

    /// Acks sent since last update. Resets whenver new fragments are received.
    pub (crate) acks_sent_count: u32,
}

impl<B: FragmentDataRef> FragmentAssemblySet<B> {
    /// Panic is the state is ALREADY complete
    pub (crate) fn complete(&mut self, now: Instant) -> HashMap<u8, Fragment<B>> {
        // frag_total is set to 0 at first, but is modified right after. It could e any number for all we care.
        let old_state = std::mem::replace(&mut self.state, FragmentAssemblyState::Complete(now, 0));
        if let FragmentAssemblyState::Incomplete { fragments } = old_state {
            self.reset_ack_sent_count();
            if let FragmentAssemblyState::Complete(_, frag_total) = &mut self.state {
                *frag_total = (fragments.len() - 1) as u8
            } else {
                unreachable!()
            };
            fragments
        } else {
            panic!("seq_id {} has already been completed", self.seq_id)
        }
    }

    pub (crate) fn with_capacity(seq_id: SeqId, now: Instant, frag_total: u8, frag_meta: FragmentSetFlags) -> FragmentAssemblySet<B> {
        FragmentAssemblySet {
            seq_id,
            frag_set_flags: frag_meta.set_flags(),
            frag_total,
            state: FragmentAssemblyState::Incomplete { fragments: HashMap::with_capacity_and_hasher(frag_total as usize + 1, Default::default()) },
            last_sent_ack: None,
            last_received: now,
            last_received_resend: frag_meta.is_resend(),
            created: now,
            acks_sent_count: 0,
        }
    }

    pub (crate) fn generate_ack(&self) -> Ack<Box<[u8]>> {
        match &self.state {
            FragmentAssemblyState::Complete(_, frag_total) => {
                // println!("Generating complete ack seq_id={:?}", self.seq_id);
                Ack::create_complete(*frag_total)
            },
            FragmentAssemblyState::Incomplete { fragments } => {
                let frag_ids_iter = fragments.keys().cloned();
                // println!("Generating incomplete ack seq_id={:?} ({:?}/{:?})", self.seq_id, frag_ids_iter.size_hint().0, frag_total as usize + 1);
                Ack::create_from_frag_ids(frag_ids_iter, self.frag_total)
            },
        }
    }

    pub (crate) fn send_ack(&mut self, now: Instant) {
        self.last_sent_ack = Some(now);
        self.acks_sent_count += 1;
    }

    pub (crate) fn reset_ack_sent_count(&mut self) {
        self.last_sent_ack = None;
        self.acks_sent_count = 0;
    }

    #[inline]
    pub (crate) fn can_send_ack(&self) -> bool {
        self.frag_set_flags.is_key()
    }

    #[inline]
    pub (crate) fn is_complete(&self) -> bool {
        matches!(self.state, FragmentAssemblyState::Complete(..))
    }

    /// Should the set be removed because no more data will arrive and we can't send ack
    /// for it anymore
    #[inline]
    pub (crate) fn is_stale(&self, now: Instant) -> bool {
        match &self.state {
            FragmentAssemblyState::Complete(complete_time, _) => {
                now >= *complete_time + Duration::from_secs(20)
            },
            FragmentAssemblyState::Incomplete { .. } => {
                if !self.frag_set_flags.is_key() {
                    // a second expiry
                    now >= self.last_received + Duration::from_secs(1)
                } else if !self.frag_set_flags.is_expire() {
                    now >= self.last_received + Duration::from_secs(5)
                } else {
                    // 50 seconds expiry for key messages
                    now >= self.last_received + Duration::from_secs(50)
                }
            }
        }
    }
}

#[derive(Debug)]
pub (crate) struct FragmentAssembler<B: FragmentDataRef> {
    pub (crate) pending_fragments: HashMap<u32, FragmentAssemblySet<B>>,

    /// seq_ids of the incomplete sets in `pending_fragments`, there are at most `MAX_INCOMPLETE_FRAGMENT_SETS`
    pub (crate) incomplete_sets: HashSet<u32>,

    /// (seq_id, created) of the sets in `pending_fragments`, oldest first. When there are too many sets,
    /// the oldest one is removed.
    ///
    /// It can contain sets already removed from `pending_fragments`, but never more than `MAX_FRAGMENT_SETS` entries.
    pub (crate) creation_order: VecDeque<(u32, Instant)>,

    // (seq_id, data)
    pub (crate) out_messages: VecDeque<(u32, Box<[u8]>)>,
}

impl<B: FragmentDataRef> FragmentAssembler<B> {
    pub (crate) fn new() -> Self {
        FragmentAssembler {
            pending_fragments: HashMap::default(),
            incomplete_sets: HashSet::default(),
            creation_order: VecDeque::new(),
            out_messages: VecDeque::new(),
        }
    }

    fn remove_set(&mut self, seq_id: SeqId) {
        self.pending_fragments.remove(&seq_id);
        self.incomplete_sets.remove(&seq_id);
    }

    /// Removes sets until a new one with `frag_total` can be added without going over the limits.
    ///
    /// A remote sending too many messages at once (or garbage) can only use a bounded amount of memory this way.
    fn make_room_for_new_set(&mut self, frag_total: u8) {
        while self.creation_order.len() >= MAX_FRAGMENT_SETS {
            let Some((seq_id, created)) = self.creation_order.pop_front() else { break };
            // the set may have already been removed, or replaced by a newer one with the same seq_id
            if self.pending_fragments.get(&seq_id).is_some_and(|set| set.created == created) {
                log::debug!("too many fragment sets, dropping the oldest seq_id={}", seq_id);
                self.remove_set(seq_id);
            }
        }
        // single fragment sets are complete right away, so they don't count
        if frag_total > 0 && self.incomplete_sets.len() >= MAX_INCOMPLETE_FRAGMENT_SETS {
            let oldest = self.incomplete_sets.iter()
                .filter_map(|seq_id| self.pending_fragments.get(seq_id))
                .min_by_key(|set| set.last_received)
                .map(|set| set.seq_id);
            if let Some(seq_id) = oldest {
                log::debug!("too many incomplete messages, dropping the oldest seq_id={}", seq_id);
                self.remove_set(seq_id);
            }
        }
    }

    /// Removes the HashMap for key `seq_id`, an tries to create a message out of that.
    ///
    /// Panics if there is no HashMap at `seq_id`, or if the message is already complete
    ///
    /// Returns an Error if all the fragments do not have the same frag_total,
    /// or if "build_message_from_fragments" encountered an error
    fn transform_message(&mut self, seq_id: SeqId, shared_secret: Option<&SharedSecret>, sender_pub_key: &[u8; 32], now: Instant) -> Result<(), ()> {
        let Some(fragment_set) = self.pending_fragments.get_mut(&seq_id) else {
            panic!("seq_id {} does not exist in fragment_combiner.fragments", seq_id);
        };
        self.incomplete_sets.remove(&seq_id);

        // every fragment was checked against the set's flags and frag_total when it was pushed
        let is_encrypted_chacha20 = fragment_set.frag_set_flags.is_encrypted_cha_cha_20();
        let fragments = fragment_set.complete(now);
        let message = match (shared_secret, is_encrypted_chacha20) {
            (Some(shared_secret), true) => {
                let encrypted = build_data_from_fragments(fragments.into_iter().map(|(_k, v)| v))?;
                let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes()).unwrap();
                let nonce = nonce_from_seq_id(seq_id, sender_pub_key);
                cipher.decrypt(&nonce.into(), &*encrypted)
                    .map_err(|_| ())?
                    .into_boxed_slice()
            },
            (_, false) => {
                build_data_from_fragments(fragments.into_iter().map(|(_k, v)| v))?
            },
            _ => return Err(()),
        };

        self.out_messages.push_back((seq_id, message));
        Ok(())
    }

    pub fn next_out_message(&mut self) -> Option<(u32, Box<[u8]>)> {
        self.out_messages.pop_front()
    }

    /// Push a fragment into the internal queue.
    ///
    /// If the fragment is the last to arrive
    /// `sender_pub_key` is the public key of the remote that sent the fragment, used to decrypt it
    pub fn push(&mut self, fragment: Fragment<B>, now: Instant, shared_secret: Option<&SharedSecret>, sender_pub_key: &[u8; 32]) {
        let seq_id = fragment.seq_id;
        let frag_total = fragment.frag_total;
        let frag_meta = fragment.frag_set_flags;

        match self.pending_fragments.get(&seq_id) {
            None => {
                self.make_room_for_new_set(frag_total);
                self.pending_fragments.insert(seq_id, FragmentAssemblySet::with_capacity(seq_id, now, frag_total, frag_meta));
                self.creation_order.push_back((seq_id, now));
                self.incomplete_sets.insert(seq_id);
            },
            Some(set) if set.frag_set_flags != frag_meta.set_flags() || set.frag_total != frag_total => {
                if set.is_complete() {
                    // can't be a legitimate resend, but the message was already delivered: ignore this fragment
                    log::warn!("seq_id={} received fragment with different flags or frag_total after completion", seq_id);
                } else {
                    // a fragment "lied" about the set: we can't know which ones are right, drop everything.
                    log::warn!("seq_id={} received fragments with different flags or frag_total, dropping the set", seq_id);
                    self.remove_set(seq_id);
                }
                return;
            },
            Some(_) => {},
        }

        let try_transform = {
            let fragment_set = self.pending_fragments.get_mut(&seq_id)
                .expect("fragment set was just checked or created");

            fragment_set.last_received = now;
            fragment_set.last_received_resend = frag_meta.is_resend();

            // if the seq_id/frag_id combo already existed, override it. It can happen when the sender re-sends a packet we've already received
            // because it didn't receive the ack on time.
            if let FragmentAssemblyState::Incomplete { ref mut fragments } = fragment_set.state {
                fragment_set.acks_sent_count = 0;
                fragments.insert(fragment.frag_id, fragment);
                // try to transform fragments into a message, because we have enough of them here
                // (frag_id <= frag_total is checked when parsing, so there can't be too many)
                fragments.len() > frag_total as usize
            } else {
                // We are trying to push a fragment to something that is already complete: the remote
                // is resending because it hasn't received our complete ack yet. Allow acks to be
                // sent again, otherwise if our acks were lost the remote would resend forever.
                fragment_set.acks_sent_count = 0;
                false
            }
        };

        if try_transform {
            if let Err(()) = self.transform_message(seq_id, shared_secret, sender_pub_key, now) {
                // If we fail to transform a message (set is corrupted), we want to remove it.
                log::warn!("set seq_id={} is corrupted", seq_id);
                self.remove_set(seq_id);
            }
        }
    }

    /// Must be called after we have received bytes from the socket, but before we send messages back
    pub (crate) fn tick(&mut self, now: Instant) -> Acks<Box<[u8]>> {
        let mut acks_to_send = Acks::new();
        let mut acks_to_remove: Vec<u32> = Vec::new();
        for (seq_id, fragment_set) in &mut self.pending_fragments {
            if fragment_set.is_stale(now) {
                acks_to_remove.push(*seq_id);
                continue;
            }
            let should_send_ack: bool = if fragment_set.can_send_ack() && fragment_set.acks_sent_count < 2 {
                match fragment_set.last_sent_ack {
                    Some(last_iter) => {
                        now.saturating_duration_since(last_iter) >= crate::consts::ACK_SEND_INTERVAL
                    },
                    // if there are no previous recordings of an ack being sent, send it right away
                    None => true,
                }
            } else {
                false
            };
            if should_send_ack {
                let timing = AckTiming {
                    delay: Some(now.saturating_duration_since(fragment_set.last_received)),
                    after_resend: fragment_set.last_received_resend,
                };
                acks_to_send.push((*seq_id, timing, fragment_set.generate_ack()));
                fragment_set.send_ack(now);
            }
        }
        for seq_id in acks_to_remove {
            self.remove_set(seq_id);
        }
        acks_to_send
    }
}

#[test]
#[cfg(test)]
fn fragment_combiner_success_clear() {
    let flags = FragmentSetFlags::new().encrypted_cha_cha_20(false).key(true).expire(true);
    let fragments: Vec<Fragment<Box<[u8]>>> = vec![
        Fragment { seq_id: 3, frag_id: 1, frag_total: 2, frag_set_flags: flags, data: Box::new([0, 5]) },
        Fragment { seq_id: 4, frag_id: 1, frag_total: 2, frag_set_flags: flags, data: Box::new([4, 0]) },
        Fragment { seq_id: 7, frag_id: 0, frag_total: 0, frag_set_flags: flags, data: Box::new([64, 64]) },
        Fragment { seq_id: 5, frag_id: 1, frag_total: 2, frag_set_flags: flags, data: Box::new([4, 5]) },
        Fragment { seq_id: 5, frag_id: 0, frag_total: 2, frag_set_flags: flags, data: Box::new([1, 2, 3]) },
        Fragment { seq_id: 5, frag_id: 2, frag_total: 2, frag_set_flags: flags, data: Box::new([6, 7, 8, 9]) },
        Fragment { seq_id: 6, frag_id: 1, frag_total: 2, frag_set_flags: flags, data: Box::new([14, 5]) },
    ];
    let mut fragment_combiner = FragmentAssembler::new();
    for fragment in fragments {
        fragment_combiner.push(fragment, Instant::now(), None, &[0xBB; 32]);
    }

    let out_message = fragment_combiner.next_out_message().expect("out msg");
    assert_eq!(out_message.1.as_ref(), &[64, 64]);
    let out_message = fragment_combiner.next_out_message().expect("out msg2");
    assert_eq!(out_message.1.as_ref(), &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert!(fragment_combiner.next_out_message().is_none());
}

#[test]
#[cfg(test)]
fn fragment_combiner_success_encrypted() {
    let flags = FragmentSetFlags::new().encrypted_cha_cha_20(true).key(true).expire(false);
    let shared_secret: SharedSecret = unsafe { std::mem::transmute([0xAAu8; 32]) };
    let cypher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
    let plaintext = vec![0, 1, 2, 3];
    let bytes = cypher.encrypt(
        &nonce_from_seq_id(7, &[0xBB; 32]).into(),
        plaintext.as_ref()
    ).unwrap();
    let fragments: Vec<Fragment<Box<[u8]>>> = vec![
        Fragment { seq_id: 7, frag_id: 0, frag_total: 0, frag_set_flags: flags, data: bytes.into_boxed_slice() },
    ];
    let mut fragment_combiner = FragmentAssembler::new();
    for fragment in fragments {
        fragment_combiner.push(fragment, Instant::now(), Some(&shared_secret), &[0xBB; 32]);
    }

    let out_message = fragment_combiner.next_out_message().expect("out msg");
    assert_eq!(out_message.1.as_ref(), &[0, 1, 2, 3]);
}

#[test]
#[cfg(test)]
fn fragment_flags_mismatch_drops_set() {
    let plain = FragmentSetFlags::new().key(true);
    let encrypted = FragmentSetFlags::new().key(true).encrypted_cha_cha_20(true);
    let mut assembler = FragmentAssembler::new();
    let now = Instant::now();
    assembler.push(Fragment { seq_id: 1, frag_id: 0, frag_total: 1, frag_set_flags: encrypted, data: Box::from([1u8]) as Box<[u8]> }, now, None, &[0; 32]);
    // claims the set is not encrypted: the whole set is dropped, nothing is delivered
    assembler.push(Fragment { seq_id: 1, frag_id: 1, frag_total: 1, frag_set_flags: plain, data: Box::from([2u8]) }, now, None, &[0; 32]);
    assert!(assembler.next_out_message().is_none());
    assert!(assembler.pending_fragments.is_empty());
    assert!(assembler.incomplete_sets.is_empty());
}

#[test]
#[cfg(test)]
fn fragment_resend_flag_is_not_a_mismatch() {
    let flags = FragmentSetFlags::new().key(true);
    let mut resent = flags;
    resent.set_resend(true);
    let mut assembler = FragmentAssembler::new();
    let now = Instant::now();
    assembler.push(Fragment { seq_id: 1, frag_id: 0, frag_total: 1, frag_set_flags: flags, data: Box::from([1u8]) as Box<[u8]> }, now, None, &[0; 32]);
    assembler.push(Fragment { seq_id: 1, frag_id: 1, frag_total: 1, frag_set_flags: resent, data: Box::from([2u8]) }, now, None, &[0; 32]);
    assert_eq!(assembler.next_out_message().map(|m| m.1), Some(Box::from([1u8, 2])));
    // the ack says the last fragment was a resend, so the remote won't use it to compute the ping
    let acks = assembler.tick(now);
    assert_eq!(acks.len(), 1);
    assert!(acks[0].1.after_resend);
}

#[test]
#[cfg(test)]
fn fragment_sets_are_bounded() {
    let flags = FragmentSetFlags::new().key(true);
    let mut assembler: FragmentAssembler<Box<[u8]>> = FragmentAssembler::new();
    let now = Instant::now();
    // incomplete sets: only the newest ones are kept
    for seq_id in 0..(MAX_INCOMPLETE_FRAGMENT_SETS as u32 * 3) {
        assembler.push(Fragment { seq_id, frag_id: 0, frag_total: 1, frag_set_flags: flags, data: Box::from([0u8]) }, now + Duration::from_millis(seq_id as u64), None, &[0; 32]);
    }
    assert_eq!(assembler.incomplete_sets.len(), MAX_INCOMPLETE_FRAGMENT_SETS);
    let newest = MAX_INCOMPLETE_FRAGMENT_SETS as u32 * 3 - 1;
    assert!(assembler.incomplete_sets.contains(&newest));
    assert!(!assembler.incomplete_sets.contains(&0));
    // complete sets: bounded as well
    for seq_id in 1000..(1000 + MAX_FRAGMENT_SETS as u32 * 2) {
        assembler.push(Fragment { seq_id, frag_id: 0, frag_total: 0, frag_set_flags: flags, data: Box::from([0u8]) }, now, None, &[0; 32]);
    }
    assert!(assembler.pending_fragments.len() <= MAX_FRAGMENT_SETS);
    assert!(assembler.creation_order.len() <= MAX_FRAGMENT_SETS);
}
