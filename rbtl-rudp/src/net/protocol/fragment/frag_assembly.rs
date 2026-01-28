use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hashbrown::HashMap;
use x25519_dalek::SharedSecret;
use std::collections::VecDeque;
use crate::net::common::{nonce_from_seq_id, SeqId};

use super::ack::{Acks, Ack};
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

    /// Whether or not we want to send Acks for this set.
    pub (crate) frag_set_flags: FragmentSetFlags,

    /// Id of the last iteration we sent an ack for this FragmentSet
    pub (crate) last_sent_ack: Option<Instant>,

    pub (crate) last_received: Instant,

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
    
    pub (crate) fn with_capacity(seq_id: SeqId, now: Instant, frag_total: usize, frag_meta: FragmentSetFlags) -> FragmentAssemblySet<B> {
        FragmentAssemblySet {
            seq_id,
            frag_set_flags: frag_meta, 
            state: FragmentAssemblyState::Incomplete { fragments: HashMap::with_capacity_and_hasher(frag_total, Default::default()) },
            last_sent_ack: None,
            last_received: now,
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
                let frag_total = fragments.values().next().unwrap().frag_total;
                let frag_ids_iter = fragments.keys().cloned();
                // println!("Generating incomplete ack seq_id={:?} ({:?}/{:?})", self.seq_id, frag_ids_iter.size_hint().0, frag_total as usize + 1);
                Ack::create_from_frag_ids(frag_ids_iter, frag_total)
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
    // TODO: Against DOS attacks, we should make this a VecDeque of small size and get rid
    // of the old stuff automatically.
    pub (crate) pending_fragments: HashMap<u32, FragmentAssemblySet<B>>,

    // (seq_id, data)
    pub (crate) out_messages: VecDeque<(u32, Box<[u8]>)>,
}

impl<B: FragmentDataRef> FragmentAssembler<B> {
    pub (crate) fn new() -> Self {
        FragmentAssembler {
            pending_fragments: HashMap::default(),
            out_messages: VecDeque::new(),
        }
    }

    /// Removes the HashMap for key `seq_id`, an tries to create a message out of that.
    ///
    /// Panics if there is no HashMap at `seq_id`, or if the message is already complete
    ///
    /// Returns an Error if all the fragments do not have the same frag_total,
    /// or if "build_message_from_fragments" encountered an error
    fn transform_message(&mut self, seq_id: SeqId, shared_secret: Option<&SharedSecret>, now: Instant) -> Result<(), ()> {
        let Some(fragment_set) = self.pending_fragments.get_mut(&seq_id) else {
            panic!("seq_id {} does not exist in fragment_combiner.fragments", seq_id);
        };

        let fragments = fragment_set.complete(now);
        let Some(first_total) = fragments.values().map(|f| f.frag_total).next() else {
            return Err(())
        };
        let is_encrypted_chacha20 = fragments.values()
            .map(|f| f.frag_set_flags.is_encrypted_cha_cha_20())
            .next()
            .unwrap();
        if fragments.values().any(|f| f.frag_total != first_total) {
            return Err(())
        };
        let message = match (shared_secret, is_encrypted_chacha20) {
            (Some(shared_secret), true) => {
                let encrypted = build_data_from_fragments(fragments.into_iter().map(|(_k, v)| v))?;
                let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes()).unwrap();
                let nonce = nonce_from_seq_id(seq_id);
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
    pub fn push(&mut self, fragment: Fragment<B>, now: Instant, shared_secret: Option<&SharedSecret>) {
        let seq_id = fragment.seq_id;
        let frag_total = fragment.frag_total;
        let frag_meta = fragment.frag_set_flags;

        let try_transform = {
            let entry = self.pending_fragments.entry(seq_id);

            // if the hashmap doesn't exist, create an empty one
            let fragment_set = entry.or_insert_with(|| {
                FragmentAssemblySet::with_capacity(seq_id, now, frag_total as usize, frag_meta)
            });

            fragment_set.last_received = now;

            // if the seq_id/frag_id combo already existed, override it. It can happen when the sender re-sends a packet we've already received
            // because it didn't receive the ack on time.
            if let FragmentAssemblyState::Incomplete { ref mut fragments } = fragment_set.state {
                fragment_set.acks_sent_count = 0;
                fragments.insert(fragment.frag_id, fragment);
                // try to transform fragments into a message, because we have enough of them here
                // if len() > frag_total + 1, that means that there are too many messages!
                // This can only happen when a packet "lied" about its frag_total.
                // If we try to re-build the message here, we will get an error because all of the fragments
                // don't have the same frag_total, but we still return true to "clear" the queue.
                fragments.len() > frag_total as usize
            } else {
                // We are trying to push a fragment to something that is already complete.
                // So let's do nothing instead.
                false
            }
        };

        if try_transform {
            if let Err(()) = self.transform_message(seq_id, shared_secret, now) {
                // If we fail to transform a message (set is corrupted), we want to remove it.
                log::warn!("set seq_id={} is corrupted", seq_id);
                self.pending_fragments.remove(&seq_id)
                    .expect("transform message failed because seq_id is corrupted, but seq_id is already removed. This is a bug.");
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
                        debug_assert!(now > last_iter);
                        now - last_iter >= crate::consts::ACK_SEND_INTERVAL
                    },
                    // if there are no previous recordings of an ack being sent, send it right away
                    None => true,
                }
            } else {
                false
            };
            if should_send_ack {
                acks_to_send.push((*seq_id, fragment_set.generate_ack()));
                fragment_set.send_ack(now);
            }
        }
        for seq_id in acks_to_remove {
            self.pending_fragments.remove(&seq_id);
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
        fragment_combiner.push(fragment, Instant::now(), None);
    }

    let out_message = fragment_combiner.next_out_message().unwrap();
    assert_eq!(out_message.1.as_ref(), &[64, 64]);
    let out_message = fragment_combiner.next_out_message().unwrap();
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
        &[0x07, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00].into(),
        plaintext.as_ref()
    ).unwrap();
    let fragments: Vec<Fragment<Box<[u8]>>> = vec![
        Fragment { seq_id: 7, frag_id: 0, frag_total: 0, frag_set_flags: flags, data: bytes.into_boxed_slice() },
    ];
    let mut fragment_combiner = FragmentAssembler::new();
    for fragment in fragments {
        fragment_combiner.push(fragment, Instant::now(), Some(&shared_secret));
    }

    let out_message = fragment_combiner.next_out_message().unwrap();
    assert_eq!(out_message.1.as_ref(), &[0, 1, 2, 3]);
}