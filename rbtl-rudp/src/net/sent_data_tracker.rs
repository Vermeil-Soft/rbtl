use std::time::{Duration, Instant};

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use hashbrown::HashMap;

use crate::{
    PacketSendOptions,
    net::{
        common::{PacketSendError, nonce_from_seq_id, SeqId},
        inner::SocketInner,
        protocol::{fragment::{Fragment, FragmentSetFlags, ack::Ack, build_fragments_from_bytes}, packet::Packet},
    }, utils::BoxedSlice
};

pub (self) struct SentDataSet<D: AsRef<[u8]> + 'static + Clone> {
    pub (self) data: D,
    pub (self) frag_total: u8,
    pub (self) expiration: Option<Instant>,
    /// (iteration_n, ack_data)
    pub (self) last_received_ack: Option<(Instant, Ack<BoxedSlice<u8>>)>,
    pub (self) last_sent_packet: Instant,

    pub (self) complete_since: Option<Instant>,
    /// (Oldest unanswered ack, Newest unanswered ack)
    pub (self) unanswered_ack: Option<(Instant, Instant)>,
    pub (self) resend_delay: Duration,
}

impl<D: AsRef<[u8]> + 'static + Clone> std::fmt::Debug for SentDataSet<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        let len = self.data.as_ref().len();
        write!(f, "SentDataSet {{ frag_total: {}, last_received_ack: {:?}, last_sent_packet: {:?}, data: {} bytes }}",
            self.frag_total,
            self.last_received_ack,
            self.last_sent_packet,
            len
        )
    }
}

impl<D: AsRef<[u8]> + 'static + Clone> SentDataSet<D> {
    pub fn new(data: D, frag_total: u8, now: Instant, options: &PacketSendOptions) -> SentDataSet<D> {
        SentDataSet {
            data,
            frag_total,
            expiration: options.expiration.map(|d| now + d),
            last_received_ack: None,
            last_sent_packet: now,
            unanswered_ack: None,
            complete_since: None,
            resend_delay: options.resend_delay,
        }
    }

    /// Returns since when the remote party has received all acks.
    ///
    /// None means the remote has not received the message yet (as of what we know)
    /// Some(instant) is the time when the first complete ack has been received
    pub (self) fn attempt_resend_packets(&mut self, seq_id: SeqId, now: Instant, socket: &mut SocketInner) -> Option<Instant> {
        if now >= self.last_sent_packet + self.resend_delay {
            self.resend_packets(seq_id, now, socket)
        } else {
            if let Some((old, new)) = self.unanswered_ack {
                // if we have received an unanswered ack 80% of resend_delay ago,
                // OR if we have NOT received an ack for 60% of resend_delay, resend the packets
                if now >= old + self.resend_delay * 4 / 5 || now - new >= self.resend_delay * 3 / 5 {
                    self.resend_packets(seq_id, now, socket)
                } else {
                    None
                }
            } else {
                None
            }
        }
    }

    #[inline]
    pub fn is_expired(&self, now: Instant) -> bool {
        match self.expiration {
            Some(expiration) => now > expiration,
            _ => false,
        }
    }

    /// Returns whether or not all acks have been received by the other party
    pub (self) fn resend_packets(&mut self, seq_id: SeqId, now: Instant, socket: &mut SocketInner) -> Option<Instant> {
        let mut frag_flags = FragmentSetFlags::new();
        frag_flags.set_expire(self.expiration.is_some());
        let (fragments, frag_total) = build_fragments_from_bytes(self.data.as_ref(), seq_id, frag_flags)
            .expect("Unreachable: message has been sent once but couldn't be resent because too big");
        
        let mut last_complete_ack: Option<Instant> = None;
        match &self.last_received_ack {
            Some((ack_received_instant, ack)) => {
                let all_fragments: Vec<_> = fragments.collect();
                debug_assert!(! all_fragments.is_empty());
                debug_assert_eq!((all_fragments.len() - 1) as u8, self.frag_total);
                debug_assert_eq!(frag_total, self.frag_total);
                let ack_missing_frags = ack.missing_iter(frag_total);

                // variable storing whether or not every ack is "ok"
                let mut complete = true;
                for frag_id in ack_missing_frags {
                    complete = false;
                    let _r = socket.send_fragment_ref(&all_fragments[frag_id as usize], now);
                    log::trace!("resending seq_id={} frag_id={} because we received incomplete ack", seq_id, frag_id);
                }
                if complete {
                    last_complete_ack = Some(*ack_received_instant);
                }
            },
            None => {
                // no ack has been received, resend everything we have
                for fragment in fragments {
                    log::trace!("resending seq_id={} frag_id={} because we received no ack", seq_id, fragment.frag_id);
                    let _r = socket.send_fragment(fragment, now);
                }

                // obviously no acks have been received, so this set can't be complete, so don't set "last_received_ack"
            },
        };
        self.unanswered_ack = None;
        self.last_sent_packet = now;
        last_complete_ack
    } 
}

#[derive(Debug)]
pub (crate) struct SentDataTracker<D: AsRef<[u8]> + 'static + Clone> {
    pub (self) sets: HashMap<u32, SentDataSet<D>>,
}

impl<D: AsRef<[u8]> + 'static + Clone> SentDataTracker<D> {
    pub fn new() -> SentDataTracker<D> {
        SentDataTracker {
            sets: Default::default(),
        }
    }

    pub fn send_data<I: Into<D> + AsRef<[u8]>>(&mut self, seq_id: SeqId, data: I, now: Instant,
        send_options: PacketSendOptions, socket: &mut SocketInner) -> Result<(), PacketSendError> {
        let mut flags = FragmentSetFlags::new();
        flags.set_expire(send_options.expiration.is_some());
        if send_options.encryption {
            flags.set_encrypted_cha_cha_20(true);
        }
        flags.set_key(send_options.key);

        #[allow(unused)]
        // a Vec with no capacity does not allocate and can be optimized away
        // this is just to please the borrow checker
        let mut encrypted: Vec<u8> = Vec::with_capacity(0); 
        let bytes_to_send = if send_options.encryption {
            let Some(secret) = socket.secret.shared() else {
                return Err(PacketSendError::NoEncryptionKey)
            };
            let cipher = ChaCha20Poly1305::new_from_slice(secret.as_bytes()).unwrap();
            let nonce = nonce_from_seq_id(seq_id);
            encrypted = cipher.encrypt(&nonce.into(), data.as_ref())
                .map_err(|_| PacketSendError::EncryptionError)?;
            encrypted.as_ref()
        } else {
            data.as_ref()
        };
        let (fragments, frag_total) = build_fragments_from_bytes(bytes_to_send, seq_id, flags)?;
        for fragment in fragments {
            let _r = socket.send_fragment(fragment, now);
        }

        if send_options.key {
            self.insert(seq_id, data.into(), frag_total, now, &send_options);
        }
        Ok(())
    }

    pub fn insert(&mut self, seq_id: SeqId, data: D, frag_total: u8, now: Instant, options: &PacketSendOptions) {
        let sent_data_set = SentDataSet::new(data, frag_total, now, options);

        if self.sets.insert(seq_id, sent_data_set).is_some() {
            panic!("seq_id {:?} is already registered in sent_data_tracker", seq_id);
        }
    }

    fn remove_seq_id(&mut self, seq_id: SeqId) {
        self.sets.remove(&seq_id);
    }

    pub fn is_seq_id_received(&self, seq_id: SeqId) -> Result<bool, ()> {
        match self.sets.get(&seq_id) {
            None => Err(()),
            Some(set) => Ok(set.complete_since.is_some())
        }
    }

    pub fn receive_ack(&mut self, seq_id: SeqId, data: BoxedSlice<u8>, now: Instant) {
        if let Some(set) = self.sets.get_mut(&seq_id) {
            let ack = Ack::new(data);
            set.last_received_ack = Some((now, ack));
            match set.unanswered_ack {
                Some((old, _)) => {
                    set.unanswered_ack = Some((old, now))
                },
                None => {
                    set.unanswered_ack = Some((now, now))
                }
            };
        } else {
            // couldn't find the matching fragment set... 2 possibilities:
            // * The remote lied, we never had such a seq_id
            // * We dropped the message on our end, so we can't even try to recover it 
            // in either case, the only thing we can do is to drop the ack and give up on life.
        };
        // if remove_ack {
        //     self.remove_seq_id(seq_id);
        // }
    }

    /// Clears data that is too old to be stored here (acks missing a part that are too old, ...)
    pub fn next_tick(&mut self, now: Instant, socket: &mut SocketInner) {
        let mut entries_to_remove: Vec<_> = vec!();
        for (seq_id, ref mut set) in &mut self.sets {
            if set.is_expired(now) {
                entries_to_remove.push(*seq_id);
                continue;
            }
            if let Some(complete_time) = set.complete_since {
                let delta = now - complete_time;
                if delta >= crate::consts::SEQ_DATA_CLEANUP_DELAY {
                    entries_to_remove.push(*seq_id);
                }
            } else {
                let ack_received = set.attempt_resend_packets(*seq_id, now, socket);
                if let Some(ack_received) = ack_received {
                    set.complete_since = Some(ack_received);
                }
            }
        }
        for seq_id in entries_to_remove {
            self.remove_seq_id(seq_id);
        }
    }
}