use crate::{consts::*, net::{common::{PacketSendError, SeqId}, inner::SocketSecret}};
use frag_generation::FragmentGenerator;

pub (crate) mod frag_generation;
pub (crate) mod frag_assembly;
pub (crate) mod ack;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub (crate) struct FragmentSetFlags(pub u16);

impl FragmentSetFlags {
    pub (self) const IS_KEY_MASK: u16 = 0b001;
    pub (self) const IS_EXPIRE_MASK: u16 = 0b010;
    pub (self) const IS_ENCRYPTED_CHACHA20_MASK: u16 = 0b100;

    pub fn set_encrypted_cha_cha_20(&mut self, b: bool) {
        self.0 = self.0 & !Self::IS_ENCRYPTED_CHACHA20_MASK;
        if b { self.0 |= Self::IS_ENCRYPTED_CHACHA20_MASK };
    }

    pub fn set_key(&mut self, b: bool) {
        self.0 = self.0 & !Self::IS_KEY_MASK;
        if b { self.0 |= Self::IS_KEY_MASK };
    }

    pub fn set_expire(&mut self, b: bool) {
        self.0 = self.0 & !Self::IS_EXPIRE_MASK;
        if b { self.0 |= Self::IS_EXPIRE_MASK };
    }

    pub fn is_encrypted_cha_cha_20(&self) -> bool {
        self.0 & Self::IS_ENCRYPTED_CHACHA20_MASK > 0
    }

    pub fn is_key(&self) -> bool {
        self.0 & Self::IS_KEY_MASK > 0
    }

    pub fn is_expire(&self) -> bool {
        self.0 & Self::IS_EXPIRE_MASK > 0
    }

    pub fn new() -> Self {
        Self(0)
    }

    #[cfg(test)]
    pub fn encrypted_cha_cha_20(mut self, b: bool) -> Self {
        self.set_encrypted_cha_cha_20(b);
        self
    }

    #[cfg(test)]
    pub fn key(mut self, b: bool) -> Self {
        self.set_key(b);
        self
    }

    #[cfg(test)]
    pub fn expire(mut self, b: bool) -> Self {
        self.set_expire(b);
        self
    }
}

/// A fragment is a part of a destructured UdpPacket.
/// 
/// If all the fragments are brought together, the UdpPacket can be restored
#[derive(Debug, PartialEq, Eq)]
pub struct Fragment<T: AsRef<[u8]>> {
    pub seq_id: SeqId,
    pub frag_id: u8,
    // real frag total is +1, meaning that 0 => 1 and 63 => 64
    // so if frag_id = 0 and frag_total = 0, there is only one message and nothing else
    pub frag_total: u8,
    pub frag_set_flags: FragmentSetFlags,
    pub data: T
}

impl<T: Clone + AsRef<[u8]>> Clone for Fragment<T> {
    fn clone(&self) -> Self {
        Self {
            seq_id: self.seq_id,
            frag_id: self.frag_id,
            data: self.data.clone(),
            frag_total: self.frag_total,
            frag_set_flags: self.frag_set_flags.clone()
        }
    }
}

impl<T: AsRef<[u8]>> Fragment<T> {
    pub fn as_borrowed_frag<'a>(&'a self) -> Fragment<&'a T> {
        Fragment {
            seq_id: self.seq_id,
            frag_id: self.frag_id,
            frag_total: self.frag_total,
            frag_set_flags: self.frag_set_flags,
            data: &self.data,
        }
    }
}

impl<'a> Fragment<&'a [u8]> {
    #[cfg(test)]
    pub fn into_boxed(self) -> Fragment<Box<[u8]>> {
        Fragment {
            seq_id: self.seq_id,
            frag_id: self.frag_id,
            frag_total: self.frag_total,
            frag_set_flags: self.frag_set_flags,
            data: Box::from(self.data)
        }
    }
}

/// Restore the data from multiple fragments
///
/// This method accepts an iterator, but the iterator doesn't have to be sorted,
/// sorting is done by this function itself.
///
/// Panics if the number of fragment is not equal to the length of the given Vec
///
/// returns an error if the message couldn't be restored properly: a frag_id is higher than frag_total,
/// 2 frag_id are the same, ...
pub (crate) fn build_data_from_fragments<I, B>(fragments: I) -> Result<Box<[u8]>, ()> 
    where B: AsRef<[u8]> + 'static, I: Iterator<Item = Fragment<B>> + ExactSizeIterator {
    // start with vec!(None; n) and for every fragment, replace None by Some(...)
    // it does not matter if the original slice is out of order, this vec will be in order
    // Note that we can't do `= vec!(None; fragments.len())` because Option<Fragment<_>> is not `Clone`
    let mut fragments_vec: Vec<Option<Fragment<B>>> = (0..fragments.len()).map(|_| None).collect();
    // track the size of all data chunks summed
    let mut total_data_size: usize = 0;
    for fragment in fragments {
        let frag_id = fragment.frag_id as usize;
        if frag_id >= fragments_vec.len() || fragments_vec[frag_id].is_some() {
            return Err(())
        };
        total_data_size += fragment.data.as_ref().len();
        fragments_vec[frag_id] = Some(fragment);
    }
    // security check: no None are left, otherwise that means the message is incomplete
    assert!(fragments_vec.iter().all(Option::is_some));
    assert_eq!(usize::from(fragments_vec[0].as_ref().unwrap().frag_total) + 1, fragments_vec.len());

    let mut reassembled_data: Vec<u8> = Vec::with_capacity(total_data_size);

    for o in fragments_vec.iter() {
        // unwrapping is 0 cost here since we assert-ed earlier that all the elements are "is_some"
        let fragment = o.as_ref().unwrap();
        reassembled_data.extend(fragment.data.as_ref());
    };
    Ok(reassembled_data.into_boxed_slice())
}

#[test]
fn build_data_from_fragments_success() {
    let frag_set_flags = FragmentSetFlags(1);
    let fragments: Vec<Fragment<Box<[u8]>>> = vec![
        Fragment { seq_id: 5, frag_id: 1, frag_total: 2, frag_set_flags, data: Box::new([4, 5]) },
        Fragment { seq_id: 5, frag_id: 0, frag_total: 2, frag_set_flags, data: Box::new([1, 2, 3]) },
        Fragment { seq_id: 5, frag_id: 2, frag_total: 2, frag_set_flags, data: Box::new([6, 7, 8, 9]) },
    ];

    let message: Box<[u8]> = build_data_from_fragments(fragments.into_iter()).expect("built message");
    assert_eq!(message.as_ref(), &[1u8, 2, 3, 4, 5, 6, 7, 8, 9]);
}

#[test]
#[should_panic]
fn build_data_from_fragments_fail_wrong_frag_total() {
    let frag_set_flags = FragmentSetFlags(2);
    let fragments: Vec<Fragment<Box<[u8]>>> = vec![
        Fragment { seq_id: 5, frag_id: 1, frag_total: 3, frag_set_flags, data: Box::new([4, 5]) },
        Fragment { seq_id: 5, frag_id: 0, frag_total: 3, frag_set_flags, data: Box::new([1, 2, 3]) },
        Fragment { seq_id: 5, frag_id: 2, frag_total: 3, frag_set_flags, data: Box::new([6, 7, 8, 9]) },
    ];

    build_data_from_fragments(fragments.into_iter()).expect("built msg error");
}

#[test]
fn build_data_from_fragments_fail_wrong_frag_id() {
    let frag_set_flags = FragmentSetFlags(3);
    let fragments: Vec<Fragment<Box<[u8]>>> = vec![
        Fragment { seq_id: 5, frag_id: 0, frag_total: 1, frag_set_flags, data: Box::new([1, 2, 3]) },
        Fragment { seq_id: 5, frag_id: 5, frag_total: 1, frag_set_flags, data: Box::new([6, 7, 8, 9]) },
    ];

    let e = build_data_from_fragments(fragments.into_iter()).expect_err("built msg error");
    assert_eq!(e, ());
}

#[test]
fn build_data_from_fragments_fail_duplicate_frag_id() {
    let frag_set_flags = FragmentSetFlags(0);
    let fragments: Vec<Fragment<Box<[u8]>>> = vec![
        Fragment { seq_id: 5, frag_id: 0, frag_total: 1, frag_set_flags, data: Box::new([1, 2, 3]) },
        Fragment { seq_id: 5, frag_id: 0, frag_total: 1, frag_set_flags, data: Box::new([6, 7, 8, 9]) },
    ];

    let e = build_data_from_fragments(fragments.into_iter()).expect_err("build fragment error");
    assert_eq!(e, ());
}

pub (crate) fn build_fragments_from_bytes<'a>(data: &'a [u8], seq_id: SeqId, set_flags: FragmentSetFlags) -> Result<(FragmentGenerator<'a>, u8), PacketSendError> {
    match FragmentGenerator::new(data, seq_id, set_flags) {
        Err(()) => {
            let len = data.len();
            if len == 0 {
                Err(PacketSendError::SentMsgEmpty)
            } else {
                Err(PacketSendError::SentMsgTooBig { attempt_size: len })
            }
        },
        Ok(generator) => {
            let frag_tot = generator.frag_total();
            Ok((generator, frag_tot))
        }
    }
}

#[test]
fn build_rebuild_data() {
    let seq_id: SeqId = 1;
    let data = vec!(0; 1024);
    let flags = FragmentSetFlags::new().encrypted_cha_cha_20(true).expire(true).key(true);
    let (frags_iter_boxed, _frag_total) = build_fragments_from_bytes(data.as_ref(), seq_id, flags).expect("built fragments");
    let frags: Vec<Fragment<Box<[u8]>>> = frags_iter_boxed.map(|f| f.into_boxed()).collect();
    let new_data = build_data_from_fragments(frags.into_iter()).expect("built fragments");
    assert_eq!(new_data.len(), data.len());
}

#[test]
fn build_one_frag_from_data() {
    let seq_id: SeqId = 1;
    let data = vec!(0; 1024);
    let flags = FragmentSetFlags::new();
    let (mut frags_iter, frag_total) = build_fragments_from_bytes(data.as_ref(), seq_id, flags).expect("built fragments");
    let frag = frags_iter.next().expect("frag");
    assert!(frags_iter.next().is_none()); 
    assert_eq!(frag.data.len(), 1024);
    assert_eq!(frag.seq_id, seq_id);
    assert_eq!(frag.frag_id, 0);
    assert_eq!(frag.frag_set_flags, flags);
    assert_eq!(frag.frag_total, 0);
    assert_eq!(frag_total, 0);
}

#[test]
fn build_multiple_frags_from_data() {
    let seq_id: SeqId = 1;
    let data = vec!(0; 2048);
    let flags = FragmentSetFlags::new();
    let (mut frags_iter, frag_total) = build_fragments_from_bytes(data.as_ref(), seq_id, flags).expect("built fragments");
    let frag_1 = frags_iter.next().expect("frag1");
    let frag_2 = frags_iter.next().expect("frag2");
    assert!(frags_iter.next().is_none()); 
    assert_eq!(frag_1.data.len(), MAX_FRAGMENT_INNER_SIZE);
    assert_eq!(frag_2.data.len(), 2048 - MAX_FRAGMENT_INNER_SIZE);
    assert_eq!(frag_1.seq_id, seq_id);
    assert_eq!(frag_2.seq_id, seq_id);
    assert_eq!(frag_1.frag_id, 0);
    assert_eq!(frag_2.frag_id, 1);
    assert_eq!(frag_1.frag_total, 1);
    assert_eq!(frag_2.frag_total, 1);
    assert_eq!(frag_total, 1);
}

#[test]
fn build_frags_from_data_fail() {
    let seq_id: SeqId = 1;
    let data = vec!(0; MAX_FRAGMENTS_IN_MESSAGE * MAX_FRAGMENT_INNER_SIZE + 1);
    assert!(build_fragments_from_bytes(data.as_ref(), seq_id, FragmentSetFlags(1)).is_err());
}