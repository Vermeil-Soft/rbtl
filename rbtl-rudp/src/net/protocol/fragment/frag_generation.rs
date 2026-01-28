use crate::consts::{MAX_FRAGMENT_INNER_SIZE, MAX_FRAGMENTS_IN_MESSAGE};
use crate::net::common::SeqId;

use super::{Fragment, FragmentSetFlags};
use std::slice::Chunks;

#[derive(Clone)]
pub struct FragmentGenerator<'a> {
    seq_id: SeqId,
    frag_total: u8,
    next_frag: u8,
    frag_meta: FragmentSetFlags,
    iterator: Chunks<'a, u8>
}

impl<'a> FragmentGenerator<'a> {
    /// Attempts to create a FragmentGenerator from a slice
    /// 
    /// 
    pub fn new(bytes: &'a [u8], seq_id: SeqId, frag_meta: FragmentSetFlags) -> Result<Self, ()> {
        if bytes.is_empty() {
            return Err(());
        }

        let mut fragments_count = bytes.len() / MAX_FRAGMENT_INNER_SIZE;
        if bytes.len() % MAX_FRAGMENT_INNER_SIZE != 0 {
            // if we can fix message into boxes exactly that's great! otherwise it means that there is a left-over,
            // and we should build the left over accordingly as well.
            fragments_count += 1;
        }
        debug_assert!(fragments_count > 0, "number of fragments to build cannot be 0");
        if fragments_count > MAX_FRAGMENTS_IN_MESSAGE {
            return Err(());
        }
        let frag_total = (fragments_count - 1) as u8;

        Ok(FragmentGenerator {
            seq_id,
            frag_total,
            iterator: bytes.chunks(MAX_FRAGMENT_INNER_SIZE),
            frag_meta,
            next_frag: 0,
        })
    }

    pub fn frag_total(&self) -> u8 {
        self.frag_total
    }
}

impl<'a> Iterator for FragmentGenerator<'a> {
    type Item = Fragment<&'a [u8]>;
    fn next(&mut self) -> Option<Self::Item> {
        let data = self.iterator.next();
        data.map(|data| {
            let current_frag = self.next_frag;
            self.next_frag += 1;
            Fragment {
                seq_id: self.seq_id,
                frag_total: self.frag_total,
                frag_id: current_frag,
                frag_set_flags: self.frag_meta,
                data,
            }
        })
    }
}