

use std::time::Duration;

/// (seq_id, timing, Ack)
pub type Acks<D> = Vec<(u32, AckTiming, Ack<D>)>;

/// Sent with every ack, so the remote can compute an accurate ping from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub (crate) struct AckTiming {
    /// How long we waited between receiving the last fragment of the set and sending this ack.
    ///
    /// None if it is too long to be encoded.
    pub (crate) delay: Option<Duration>,
    /// Whether the last fragment received was a resend. The remote can't know when that resend was sent,
    /// so it must not use this ack to compute the ping.
    pub (crate) after_resend: bool,
}

impl AckTiming {
    const AFTER_RESEND_BIT: u16 = 0x8000;
    const DELAY_MASK: u16 = 0x7FFF;
    const DELAY_UNIT_MICROS: u64 = 200;

    /// Encoded as a u16: the highest bit is `after_resend`, the 15 others are the delay in units of 200µs,
    /// so at most ~6.5s. The highest value means the delay was longer than that (or unknown).
    pub (crate) fn to_u16(self) -> u16 {
        let units = match self.delay {
            Some(delay) => (delay.as_micros() / Self::DELAY_UNIT_MICROS as u128).min(Self::DELAY_MASK as u128) as u16,
            None => Self::DELAY_MASK,
        };
        units | if self.after_resend { Self::AFTER_RESEND_BIT } else { 0 }
    }

    pub (crate) fn from_u16(v: u16) -> Self {
        let units = v & Self::DELAY_MASK;
        Self {
            delay: (units != Self::DELAY_MASK).then(|| Duration::from_micros(units as u64 * Self::DELAY_UNIT_MICROS)),
            after_resend: v & Self::AFTER_RESEND_BIT != 0,
        }
    }
}

#[test]
fn ack_timing_ser_de() {
    let t = AckTiming { delay: Some(Duration::from_micros(1234)), after_resend: false };
    assert_eq!(AckTiming::from_u16(t.to_u16()), AckTiming { delay: Some(Duration::from_micros(1200)), after_resend: false });
    let t = AckTiming { delay: Some(Duration::ZERO), after_resend: true };
    assert_eq!(AckTiming::from_u16(t.to_u16()), t);
    // too long to be encoded
    let t = AckTiming { delay: Some(Duration::from_secs(60)), after_resend: false };
    assert_eq!(AckTiming::from_u16(t.to_u16()).delay, None);
}

#[derive(Debug, Clone)]
/// Represents a series of a bits that each represent whether or not the frag has arrived
/// 
/// e.g. 0b0100: frag 2 has arrived, frag 0+1+3 haven't arrived.
pub struct Ack<D: AsRef<[u8]> + 'static>(D);

/// Number of bytes needed to hold one bit per fragment. There are frag_total + 1 fragments.
fn ack_size_from_frag_total(frag_total: u8) -> usize {
    (frag_total as usize + 1).div_ceil(8)
}

#[cfg(test)]
pub (self) fn frag_ids_received_from_ack<I: Iterator<Item=u8>>(ack_bytes: I, frag_total: u8) -> impl Iterator<Item=u8> {
    ack_bytes.take(32).enumerate().flat_map(move |(index, bits): (usize, u8)| {
        (0..8).filter_map(move |bit_index| {
            debug_assert!(index < 32); // 31 * 8 + 7 is max value at most in u8
            let bit = 1 << bit_index;
            if bits & bit > 0 {
                let v: u8 = (index * 8) as u8 + bit_index;
                if v <= frag_total {
                    Some(v)
                } else {
                    None
                }
            } else {
                None
            }
        })
    })
}

pub (self) fn frag_ids_missing_from_ack<'a, I: Iterator<Item=u8> + 'a>(ack_bytes: I, frag_total: u8) -> impl Iterator<Item=u8> + 'a {
    // the ack comes from the remote and may be longer than the 32 bytes needed for 256 frags
    ack_bytes.take(32).enumerate().flat_map(move |(index, bits): (usize, u8)| {
        (0..8).filter_map(move |bit_index| {
            debug_assert!(index < 32); // 31 * 8 + 7 is max value at most in u8
            let bit = 1 << bit_index;
            if bits & bit == 0 {
                let v: u8 = (index * 8) as u8 + bit_index;
                if v <= frag_total {
                    Some(v)
                } else {
                    None
                }
            } else {
                None
            }
        })
    })
}

impl Ack<Box<[u8]>> {
    pub (crate) fn create_complete(frag_total: u8) -> Ack<Box<[u8]>> {
        Ack(vec!(0xFFu8; ack_size_from_frag_total(frag_total)).into_boxed_slice())
    }

    pub (crate) fn create_from_frag_ids<I: Iterator<Item=u8>>(iter: I, frag_total: u8) -> Ack<Box<[u8]>> {
        let mut ack = vec!(0x0u8; ack_size_from_frag_total(frag_total));

        // this loop may be totally unoptimized!! If encountering performance issues,
        // please test whether or not this is a good solution!
        for frag_id in iter {
            let byte_index = (frag_id / 8) as usize;
            let bit_index: u8 = frag_id % 8;
            ack[byte_index] |= 1 << bit_index;
        }

        Ack(ack.into_boxed_slice())
    }
}

impl<D: AsRef<[u8]> + 'static> Ack<D> {
    pub (crate) fn new(data: D) -> Ack<D> {
        Ack(data)
    }

    #[cfg(test)]
    pub (crate) fn into_iter(self, frag_total: u8) -> impl Iterator<Item=u8> {
        let v = Vec::from(self.0.as_ref());
        frag_ids_received_from_ack(v.into_iter(), frag_total)
    }

    #[cfg(test)]
    pub (crate) fn into_missing_iter(self, frag_total: u8) -> impl Iterator<Item=u8> {
        let v = Vec::from(self.0.as_ref());
        frag_ids_missing_from_ack(v.into_iter(), frag_total)
    }
    
    pub (crate) fn missing_iter<'a>(&'a self, frag_total: u8) -> impl Iterator<Item=u8> + 'a {
        frag_ids_missing_from_ack(self.0.as_ref().iter().cloned(), frag_total)
    }

    pub fn into_inner(self) -> D {
        self.0
    }
}

#[test]
fn ack_ser() {
    let frag_ids = vec!(1u8, 2u8, 8u8, 9u8);
    let frag_total: u8 = 15;
    let ack = Ack::create_from_frag_ids(frag_ids.iter().cloned(), frag_total);

    assert_eq!(ack.0.as_ref(), &[0b00000110, 0b00000011]);
}

#[test]
fn ack_missing() {
    let frag_ids = vec!(1u8, 2u8, 8u8, 9u8);
    let frag_total: u8 = 15;
    let ack = Ack::create_from_frag_ids(frag_ids.iter().cloned(), frag_total);
    let missing: Vec<u8> = ack.into_missing_iter(frag_total).collect();

    assert_eq!(missing.as_slice(), &[0, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15]);
}

#[test]
fn ack_deser() {
    let ack = Ack(vec!(0b00000110u8, 0b00000011).into_boxed_slice());
    let frag_total: u8 = 15;

    let expected_frag_ids = &[1u8, 2u8, 8u8, 9u8];

    let ack_frag_ids: Vec<_> = ack.into_iter(frag_total).collect();

    assert_eq!(ack_frag_ids, expected_frag_ids);
}

#[test]
fn ack_ser_deser() {
    let vec1: Vec<u8> = (0..255u8).into_iter().collect();
    let frag_total: u8 = 254;
    let vec2: Vec<u8> = (0..255u8).into_iter().step_by(2).collect();
    let vec3: Vec<u8> = (0..255u8).into_iter().step_by(3).collect();
    
    let ack1 = Ack::create_from_frag_ids(vec1.iter().cloned(), frag_total);
    let ack2 = Ack::create_from_frag_ids(vec2.iter().cloned(), frag_total);
    let ack3 = Ack::create_from_frag_ids(vec3.iter().cloned(), frag_total);

    let ack_vec1: Vec<u8> = ack1.into_iter(frag_total).collect();
    let ack_vec2: Vec<u8> = ack2.into_iter(frag_total).collect();
    let ack_vec3: Vec<u8> = ack3.into_iter(frag_total).collect();

    assert_eq!(ack_vec1, vec1);
    assert_eq!(ack_vec2, vec2);
    assert_eq!(ack_vec3, vec3);
}
#[test]
fn ack_size_frag_total_multiple_of_8() {
    // 1 fragment and 9 fragments are the edge cases: 1 and 2 bytes
    assert_eq!(ack_size_from_frag_total(0), 1);
    assert_eq!(ack_size_from_frag_total(7), 1);
    assert_eq!(ack_size_from_frag_total(8), 2);
    assert_eq!(ack_size_from_frag_total(255), 32);
    // receiving the last frag of 9 first must not panic, and the others are reported missing
    let ack = Ack::create_from_frag_ids([8u8].into_iter(), 8);
    let missing: Vec<u8> = ack.into_missing_iter(8).collect();
    assert_eq!(missing, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    // the reverse: frag 8 is the missing one
    let ack = Ack::create_from_frag_ids(0..8u8, 8);
    let missing: Vec<u8> = ack.into_missing_iter(8).collect();
    assert_eq!(missing, vec![8]);
}

#[test]
fn ack_oversized_from_remote() {
    // a remote may send more bytes than needed, it must not panic
    let ack = Ack(vec![0u8; 100].into_boxed_slice());
    assert_eq!(ack.into_missing_iter(255).count(), 256);
}
