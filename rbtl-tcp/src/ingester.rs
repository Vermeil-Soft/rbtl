use byteorder::{BigEndian, ByteOrder};

use crate::{
    SeqId, 
    socket::{
        MSG_TYPE_DATA_HEAD_LEN, MSG_TYPE_DATA_ID, MSG_TYPE_HEARTBEAT_ID, MSG_TYPE_STATUS_HEAD_LEN, MSG_TYPE_STATUS_ID
    }
};

pub (crate) struct Ingester {
    incomplete: Option<IncomingIncomplete>,
    pub (crate) results: Vec<IngesterResult>,
}

impl Ingester {
    pub fn new() -> Self {
        Self {
            incomplete: None,
            results: Vec::new(),
        }
    }

    pub (crate) fn take_bytes(&mut self, bytes: &[u8], max_len: u32) {
        if bytes.len() == 0 {
            return;
        }
        // that's not very DRY..., but I don't know how to simplify it better than that.
        match &mut self.incomplete {
            None => {
                let id = bytes[0];
                let headless_bytes = &bytes[1..];
                if id == MSG_TYPE_DATA_ID {
                    match headless_bytes.split_at_checked(MSG_TYPE_DATA_HEAD_LEN) {
                        None => {
                            self.incomplete = Some(IncomingIncomplete::Bytes(Vec::from(bytes)));
                        },
                        Some((head, tail)) => {
                            let d = IncompleteData::new(head, max_len);
                            match d {
                                Ok(d) => {
                                    self.incomplete = Some(IncomingIncomplete::Data(d));
                                    self.take_bytes(tail, max_len);
                                },
                                Err(expected_len) => {
                                    let msg = format!("sent message from remote was too big: {} bytes", expected_len);
                                    self.results.push(IngesterResult::Error(msg));
                                }
                            }
                        },
                    };
                } else if id == MSG_TYPE_STATUS_ID {
                    match headless_bytes.split_at_checked(MSG_TYPE_STATUS_HEAD_LEN) {
                        None => {
                            self.incomplete = Some(IncomingIncomplete::Bytes(Vec::from(bytes)));
                        },
                        Some((head, tail)) => {
                            let seq_id = BigEndian::read_u32(head);
                            self.results.push(IngesterResult::SeqIdOk(seq_id));
                            self.take_bytes(tail, max_len);
                        },
                    };
                } else if id == MSG_TYPE_HEARTBEAT_ID {
                    self.results.push(IngesterResult::Heartbeat);
                    self.take_bytes(headless_bytes, max_len);
                } else {
                    let msg = format!("wrong rbtl-tcp msg id {}", id);
                    self.results.push(IngesterResult::Error(msg));
                }
            }
            Some(IncomingIncomplete::Bytes(incomplete_bytes)) => {
                let id = incomplete_bytes[0];
                let tail_bytes = &incomplete_bytes[1..];
                if id == MSG_TYPE_DATA_ID {
                    match bytes.split_at_checked(MSG_TYPE_DATA_HEAD_LEN - tail_bytes.len()) {
                        None => {
                            let mut v = std::mem::take(incomplete_bytes);
                            v.extend_from_slice(bytes);
                            self.incomplete = Some(IncomingIncomplete::Bytes(Vec::from(v)));
                        },
                        Some((head, tail)) => {
                            incomplete_bytes.extend_from_slice(head);
                            match IncompleteData::new(&incomplete_bytes[1..], max_len) {
                                Ok(d) => {
                                    self.incomplete = Some(IncomingIncomplete::Data(d));
                                    self.take_bytes(tail, max_len);
                                },
                                Err(expected_len) => {
                                    let msg = format!("sent message from remote was too big: {} bytes", expected_len);
                                    self.results.push(IngesterResult::Error(msg));
                                }
                            }
                        },
                    };
                } else if id == MSG_TYPE_STATUS_ID {
                    match bytes.split_at_checked(MSG_TYPE_STATUS_HEAD_LEN - tail_bytes.len()) {
                        None => {
                            let mut v = std::mem::take(incomplete_bytes);
                            v.extend_from_slice(bytes);
                            self.incomplete = Some(IncomingIncomplete::Bytes(v));
                        },
                        Some((head, tail)) => {
                            incomplete_bytes.extend_from_slice(head);
                            let seq_id = BigEndian::read_u32(&incomplete_bytes[1..]);
                            self.results.push(IngesterResult::SeqIdOk(seq_id));
                            self.incomplete = None;
                            self.take_bytes(tail, max_len);
                        },
                    };
                } else {
                    let msg = format!("wrong rbtl-tcp (incomplete) msg id {}", id);
                    self.results.push(IngesterResult::Error(msg));
                }
            },
            Some(IncomingIncomplete::Data(d)) => {
                let taken = std::cmp::min(d.expected_len as usize - d.waiting_bytes.len(), bytes.len());
                d.waiting_bytes.extend_from_slice(&bytes[0..taken]);
                if d.expected_len as usize == d.waiting_bytes.len() {
                    // the message is complete, transform it
                    self.results.push(IngesterResult::Data(d.seq_id, std::mem::take(&mut d.waiting_bytes)));
                    self.incomplete = None;
                    if taken < bytes.len() {
                        self.take_bytes(&bytes[taken..], max_len);
                    }
                } else {
                    // the message is still incomplete, but there are no more bytes to take
                }
            },
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub (crate) enum IngesterResult {
    Data(SeqId, Vec<u8>),
    Heartbeat,
    SeqIdOk(SeqId),
    Error(String),
}

#[derive(Debug)]
struct IncompleteData {
    waiting_bytes: Vec<u8>,
    expected_len: u32,
    seq_id: u32,
}

impl IncompleteData {
    /// bytes MUST have a length of 8
    ///
    /// Returns an error if the expected len is higher than max length
    pub fn new(bytes: &[u8], max_len: u32) -> Result<Self, u32> {
        assert_eq!(bytes.len(), 8);
        let seq_id = BigEndian::read_u32(&bytes[0..4]);
        let expected_len = BigEndian::read_u32(&bytes[4..8]);
        if expected_len > max_len {
            return Err(expected_len);
        }
        Ok(Self {
            waiting_bytes: Vec::with_capacity(expected_len as usize),
            seq_id,
            expected_len
        })
    }
}

#[derive(Debug)]
enum IncomingIncomplete {
    Bytes(Vec<u8>),
    Data(IncompleteData),
}

#[cfg(test)]
fn base_ingester_test(cut_len: usize) {
    let mut ingester = Ingester::new();

    let bytes = &[
        0, // msg type 0: data
        0, 0, 0, 99, // seq id
        0, 0, 0, 8, // length
        0, 1, 2, 3, 4, 5, 6, 7, // bytes,
        1, // msg type 1: status
        0, 0, 0, 0,
        0, // msg type 0: data
        0, 0, 0, 100, // seq id
        0, 0, 0, 4, // length
        0, 1, 2, 3, // bytes
        1,
        0, 0, 0, 1
    ];

    for chunk in bytes.chunks(cut_len) {
        ingester.take_bytes(chunk, 1_000_000);
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    assert_eq!(ingester.results[0], IngesterResult::Data(99, vec![0, 1, 2, 3, 4, 5, 6, 7]));
    assert_eq!(ingester.results[1], IngesterResult::SeqIdOk(0));
    assert_eq!(ingester.results[2], IngesterResult::Data(100, vec![0, 1, 2, 3]));
    assert_eq!(ingester.results[3], IngesterResult::SeqIdOk(1));
}

#[cfg(test)]
#[test]
fn ingester_test_nocut() {
    base_ingester_test(1_000_000);
}

#[cfg(test)]
#[test]
fn ingester_test_cut1() {
    base_ingester_test(1);
}

#[cfg(test)]
#[test]
fn ingester_test_cut5() {
    base_ingester_test(5);
}