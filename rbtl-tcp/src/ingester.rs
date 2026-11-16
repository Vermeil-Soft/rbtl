use byteorder::{BigEndian, ByteOrder};

use crate::{
    SeqId,
    socket::{
        MSG_TYPE_DATA_HEAD_LEN, MSG_TYPE_DATA_ID, MSG_TYPE_HEARTBEAT_ID, MSG_TYPE_STATUS_HEAD_LEN, MSG_TYPE_STATUS_ID
    }
};

#[derive(Debug)]
pub (crate) struct Ingester {
    incomplete: Option<IncomingIncomplete>,
    pub (crate) results: Vec<IngesterResult>,
    /// Set after the first error: the stream is out of sync, so nothing after it can be parsed reliably
    failed: bool,
}

impl Ingester {
    pub fn new() -> Self {
        Self {
            incomplete: None,
            results: Vec::new(),
            failed: false,
        }
    }

    pub (crate) fn take_bytes(&mut self, mut bytes: &[u8], max_len: u32) {
        while !bytes.is_empty() && !self.failed {
            bytes = self.take_some_bytes(bytes, max_len);
        }
    }

    fn fail(&mut self, msg: String) {
        self.results.push(IngesterResult::Error(msg));
        self.incomplete = None;
        self.failed = true;
    }

    /// Starts receiving the body of a data message, or finishes it right away if it is empty
    fn start_data(&mut self, data: IncompleteData) {
        if data.expected_len == 0 {
            self.results.push(IngesterResult::Data(data.seq_id, Vec::new()));
            self.incomplete = None;
        } else {
            self.incomplete = Some(IncomingIncomplete::Data(data));
        }
    }

    /// Parses the start of `bytes` (which must not be empty), and returns what is left to parse
    fn take_some_bytes<'a>(&mut self, bytes: &'a [u8], max_len: u32) -> &'a [u8] {
        // that's not very DRY..., but I don't know how to simplify it better than that.
        match &mut self.incomplete {
            None => {
                let id = bytes[0];
                let headless_bytes = &bytes[1..];
                if id == MSG_TYPE_DATA_ID {
                    match headless_bytes.split_at_checked(MSG_TYPE_DATA_HEAD_LEN) {
                        None => {
                            self.incomplete = Some(IncomingIncomplete::Bytes(Vec::from(bytes)));
                            &[]
                        },
                        Some((head, tail)) => {
                            match IncompleteData::new(head, max_len) {
                                Ok(d) => {
                                    self.start_data(d);
                                    tail
                                },
                                Err(expected_len) => {
                                    self.fail(format!("sent message from remote was too big: {} bytes", expected_len));
                                    &[]
                                }
                            }
                        },
                    }
                } else if id == MSG_TYPE_STATUS_ID {
                    match headless_bytes.split_at_checked(MSG_TYPE_STATUS_HEAD_LEN) {
                        None => {
                            self.incomplete = Some(IncomingIncomplete::Bytes(Vec::from(bytes)));
                            &[]
                        },
                        Some((head, tail)) => {
                            let seq_id = BigEndian::read_u32(head);
                            self.results.push(IngesterResult::SeqIdOk(seq_id));
                            tail
                        },
                    }
                } else if id == MSG_TYPE_HEARTBEAT_ID {
                    self.results.push(IngesterResult::Heartbeat);
                    headless_bytes
                } else {
                    self.fail(format!("wrong rbtl-tcp msg id {}", id));
                    &[]
                }
            }
            Some(IncomingIncomplete::Bytes(incomplete_bytes)) => {
                let id = incomplete_bytes[0];
                let tail_bytes = &incomplete_bytes[1..];
                if id == MSG_TYPE_DATA_ID {
                    match bytes.split_at_checked(MSG_TYPE_DATA_HEAD_LEN - tail_bytes.len()) {
                        None => {
                            incomplete_bytes.extend_from_slice(bytes);
                            &[]
                        },
                        Some((head, tail)) => {
                            incomplete_bytes.extend_from_slice(head);
                            match IncompleteData::new(&incomplete_bytes[1..], max_len) {
                                Ok(d) => {
                                    self.start_data(d);
                                    tail
                                },
                                Err(expected_len) => {
                                    self.fail(format!("sent message from remote was too big: {} bytes", expected_len));
                                    &[]
                                }
                            }
                        },
                    }
                } else if id == MSG_TYPE_STATUS_ID {
                    match bytes.split_at_checked(MSG_TYPE_STATUS_HEAD_LEN - tail_bytes.len()) {
                        None => {
                            incomplete_bytes.extend_from_slice(bytes);
                            &[]
                        },
                        Some((head, tail)) => {
                            incomplete_bytes.extend_from_slice(head);
                            let seq_id = BigEndian::read_u32(&incomplete_bytes[1..]);
                            self.results.push(IngesterResult::SeqIdOk(seq_id));
                            self.incomplete = None;
                            tail
                        },
                    }
                } else {
                    self.fail(format!("wrong rbtl-tcp (incomplete) msg id {}", id));
                    &[]
                }
            },
            Some(IncomingIncomplete::Data(d)) => {
                let taken = std::cmp::min(d.expected_len as usize - d.waiting_bytes.len(), bytes.len());
                d.waiting_bytes.extend_from_slice(&bytes[0..taken]);
                if d.expected_len as usize == d.waiting_bytes.len() {
                    // the message is complete, transform it
                    self.results.push(IngesterResult::Data(d.seq_id, std::mem::take(&mut d.waiting_bytes)));
                    self.incomplete = None;
                }
                &bytes[taken..]
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

#[cfg(test)]
#[test]
fn ingester_stops_at_first_error() {
    let mut ingester = Ingester::new();
    // an unknown message id, followed by what would be a valid status message
    ingester.take_bytes(&[42, 1, 0, 0, 0, 7], 1_000_000);
    ingester.take_bytes(&[1, 0, 0, 0, 8], 1_000_000);
    assert_eq!(ingester.results.len(), 1);
    assert!(matches!(ingester.results[0], IngesterResult::Error(_)));
}

#[cfg(test)]
#[test]
fn ingester_many_heartbeats_no_recursion() {
    // used to recurse once per message: a long burst of small messages could overflow the stack
    let mut ingester = Ingester::new();
    let bytes = vec![MSG_TYPE_HEARTBEAT_ID; 1_000_000];
    ingester.take_bytes(&bytes, 1_000_000);
    assert_eq!(ingester.results.len(), 1_000_000);
}

#[cfg(test)]
#[test]
fn ingester_empty_data_message() {
    let mut ingester = Ingester::new();
    ingester.take_bytes(&[0, 0, 0, 0, 5, 0, 0, 0, 0], 1_000_000);
    assert_eq!(ingester.results, vec![IngesterResult::Data(5, vec![])]);
}
