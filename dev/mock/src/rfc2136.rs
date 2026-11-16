//! Mock of an authoritative name server that accepts DNS UPDATE (RFC 2136) signed with TSIG
//! (RFC 8945), over TCP (RFC 1035 section 4.2.2, RFC 7766) and over UDP on the same port number
//! (RFC 1035 section 4.2.1). The client under test speaks TCP only; UDP serves the tests that
//! cross-check the mock with independent tools, which use UDP by default.
//!
//! The mock answers queries for its zones itself, with the AA flag, so an ACME server such as
//! Pebble can be pointed at it as its DNS server directly; no [`link`](crate::link::link) to a
//! [`DnsMock`](crate::dns::DnsMock) is needed.
//!
//! The parser, the signer and the verifier here are written for the mock and share nothing with
//! the client under test; the HMAC comes from `aws-lc-rs` directly. The behavior follows these
//! sources:
//!
//! - RFC 1035 section 4.1: header (ID, QR, opcode, AA, TC, RD, RCODE), question and resource
//!   record layout, name compression (section 4.1.4); section 4.2.2: the two-octet length prefix
//!   on TCP.
//! - RFC 2136 section 2: opcode UPDATE (5); the zone section holds exactly one `zone SOA` entry
//!   (2.3); prerequisites (2.4): "name is in use" (`ANY ANY`), "name is not in use"
//!   (`NONE ANY`), "RRset exists (value independent)" (`ANY type`), "RRset exists (value
//!   dependent)" (`IN type` with the RRs), "RRset does not exist" (`NONE type`); updates (2.5):
//!   add (`zone class`), delete an RRset (`ANY type`), delete all RRsets of a name (`ANY ANY`),
//!   delete one RR (`NONE type` with the RDATA). RCODEs of section 2.2: NOTAUTH for a zone the
//!   server does not serve, NOTZONE for a name outside the zone section's zone, NXDOMAIN,
//!   YXDOMAIN, NXRRSET, YXRRSET for failed prerequisites, FORMERR for what cannot be read. The
//!   response copies the ID and the opcode and sets QR (3.8).
//! - RFC 2136 section 3, for every update: prerequisites in order, the first that fails decides
//!   the RCODE, value-dependent RRsets compared as sets after the loop (3.2, pseudocode 3.2.5);
//!   the prescan of the update section (3.4.1); then the updates in order, all or nothing
//!   (3.4.2.1): a duplicate add replaces the zone RR, a CNAME add next to other data and a
//!   non-CNAME add next to a CNAME are ignored, an SOA add without a higher serial is ignored
//!   (3.4.2.2, serials compared by RFC 1982); the deletion of every RRset of the apex keeps SOA
//!   and NS, the deletion of the apex SOA or NS RRset is ignored (3.4.2.3); the deletion of an
//!   SOA RR, and of the last NS RR of the apex, is ignored (3.4.2.4); a duplicate add and the
//!   delete of an RR or RRset that does not exist are silently ignored (2.5.1, 2.5.2, 2.5.4).
//! - Queries (RFC 1034 section 4.3.2): an NS RRset at a name below the apex is a zone cut; a
//!   query at or below it is answered with a referral (step 3b: no AA, an empty answer section,
//!   the NS RRset of the cut in the authority section). A CNAME at the name answers a query of
//!   any type (step 3a), without following the chain. Names inside the RDATA of the RFC 1035
//!   types NS, CNAME, PTR, MX and SOA are compressed against the question name where a suffix
//!   matches (RFC 1035 section 4.1.4; RFC 3597 section 4 allows it for these types only).
//! - Names inside the RDATA of NS, CNAME, PTR, MX and SOA in a request may be compressed (RFC
//!   1035 section 4.1.4; RFC 3597 section 4 requires a receiver to decompress them for these
//!   types); the mock stores them uncompressed. `nsupdate` compresses the MX exchange against the
//!   zone section, so a mock that kept the raw octets answered with a corrupted name.
//! - Queries, negative answers: NXDOMAIN, or no data of the type, carries the zone's SOA in the
//!   authority section with the lower of its TTL and MINIMUM as the TTL (RFC 2308 section 3),
//!   when the seed holds an apex SOA.
//! - RFC 8945: TSIG is the last record of the additional section (5.1); the request MAC covers
//!   the message without the TSIG record (ARCOUNT less one, the original ID) and the TSIG
//!   variables (4.3.3); the response MAC covers the request MAC with its length, the response,
//!   and the response's variables (5.3). An unknown key is NOTAUTH with error BADKEY and no MAC
//!   (5.2.1, 5.3.2), a MAC that does not verify NOTAUTH with BADSIG and no MAC (5.2.2), a time
//!   outside the fudge NOTAUTH with BADTIME, signed, with the client's time in Time Signed and
//!   the server's time in the other data (5.2.3). Fudge 300 s (section 10).
//! - UDP: the mock does not implement EDNS (RFC 6891), so it never echoes an OPT record and an
//!   answer over UDP holds at most 512 octets (RFC 1035 sections 2.3.4 and 4.2.1; RFC 6891
//!   section 7). A longer answer is sent with TC set and without its answer and authority
//!   records (RFC 2181 section 9), signed like any other answer, so that the requester retries
//!   over TCP. [`Fault::truncate`] and [`Fault::short_length`] send the same cut octets in one
//!   datagram.
//!
//! Answers this mock invents because the sources are silent, each chosen so that a client cannot
//! rely on a lenient reading. A test that depends on one of them proves only how the client
//! handles that answer, not that a server gives it:
//!
//! - a request without TSIG is answered REFUSED, unsigned;
//! - a query for a name outside every zone, or any query while [`Control::refuse_queries`] is on,
//!   is answered REFUSED (signed: the request was authenticated);
//! - a query answer copies the question, sets AA, and names its answers with a compression
//!   pointer to the question;
//! - an add whose RDATA is already present replaces that record's TTL, and an add to an existing
//!   RRset gives every record of the RRset the added record's TTL (RFC 2136 section 3.4.2.2 says a
//!   duplicate replaces the zone RR; one TTL per RRset is RFC 2181 section 5.2);
//! - RDATA, names inside it included, is compared octet by octet (RFC 2136 sections 3.2.3 and
//!   3.4.2.4 speak of equal RDATA without saying how names compare); the seeds hold lowercase
//!   names, so the comparison is exact for what a client reads back;
//! - the zone apex counts as a name in use even without records, since a real zone always has
//!   its SOA there and the seeds usually leave it out;
//! - an update answer copies the zone section (RFC 2136 section 3.8 also allows zero counts;
//!   [`Fault::omit_question`] produces that form).
//! - a UDP answer cut for length (see above) drops every answer and authority record rather than
//!   as many as needed, and is signed over the cut message like any other answer.
//!
//! A test holds an [`Rfc2136Mock`] and changes its state and its behavior through
//! [`Rfc2136Mock::control`]:
//!
//! ```text
//! let mock = Rfc2136Mock::start(Seed::standard()).await;
//! mock.control().push(Fault::on(Op::Update).rcode(SERVFAIL));
//! // ... drive the client against mock.server() ...
//! assert_eq!(mock.control().txt("_acme-challenge.example.org."), ["v1"]);
//! ```

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::hmac;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Type code of TXT (RFC 1035 section 3.2.2).
pub const TYPE_TXT: u16 = 16;
/// Type code of A (RFC 1035 section 3.2.2).
pub const TYPE_A: u16 = 1;
/// Type code of CNAME (RFC 1035 section 3.2.2).
pub const TYPE_CNAME: u16 = 5;
/// Type code of NS (RFC 1035 section 3.2.2).
pub const TYPE_NS: u16 = 2;
/// Type code of SOA (RFC 1035 section 3.2.2).
pub const TYPE_SOA: u16 = 6;
/// Type code of MX (RFC 1035 section 3.2.2).
pub const TYPE_MX: u16 = 15;
/// Type code of PTR (RFC 1035 section 3.2.2).
const TYPE_PTR: u16 = 12;
const TYPE_TSIG: u16 = 250;
/// Type code ANY (RFC 1035 section 3.2.3).
pub const TYPE_ANY: u16 = 255;
/// Class IN (RFC 1035 section 3.2.4).
pub const CLASS_IN: u16 = 1;
/// Class NONE (RFC 2136 section 1.3).
pub const CLASS_NONE: u16 = 254;
/// Class ANY (RFC 1035 section 3.2.5).
pub const CLASS_ANY: u16 = 255;

/// RCODE NOERROR.
pub const NOERROR: u8 = 0;
/// RCODE FORMERR.
pub const FORMERR: u8 = 1;
/// RCODE SERVFAIL.
pub const SERVFAIL: u8 = 2;
/// RCODE NXDOMAIN.
pub const NXDOMAIN: u8 = 3;
/// RCODE NOTIMP.
pub const NOTIMP: u8 = 4;
/// RCODE REFUSED.
pub const REFUSED: u8 = 5;
/// RCODE YXDOMAIN (RFC 2136 section 2.2).
pub const YXDOMAIN: u8 = 6;
/// RCODE YXRRSET (RFC 2136 section 2.2).
pub const YXRRSET: u8 = 7;
/// RCODE NXRRSET (RFC 2136 section 2.2).
pub const NXRRSET: u8 = 8;
/// RCODE NOTAUTH (RFC 2136 section 2.2).
pub const NOTAUTH: u8 = 9;
/// RCODE NOTZONE (RFC 2136 section 2.2).
pub const NOTZONE: u8 = 10;

/// TSIG error BADSIG (RFC 8945 section 3).
pub const BADSIG: u16 = 16;
/// TSIG error BADKEY (RFC 8945 section 3).
pub const BADKEY: u16 = 17;
/// TSIG error BADTIME (RFC 8945 section 3).
pub const BADTIME: u16 = 18;

/// Fudge the mock signs with (RFC 8945 section 10 recommends 300 s).
const FUDGE: u16 = 300;

/// The largest answer sent over UDP without EDNS (RFC 1035 section 2.3.4).
const UDP_LIMIT: usize = 512;

/// The secret of the standard SHA-256 key, 32 octets. Synthetic.
pub const STANDARD_SECRET: &[u8; 32] = b"zonewright-rfc2136-mock-secret!!";
/// The secret of the standard SHA-512 key, 64 octets. Synthetic.
pub const STANDARD_SECRET_512: &[u8; 64] =
    b"zonewright-rfc2136-mock-secret-for-the-hmac-sha512-key-64-octets";
/// The name of the standard SHA-256 key.
pub const KEY_NAME: &str = "zw-test-key.";
/// The name of the standard SHA-512 key.
pub const KEY_NAME_512: &str = "zw-test-key-512.";
/// The zone of the standard seed.
pub const ZONE: &str = "example.org.";

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A TSIG key the server knows.
#[derive(Clone, Debug)]
pub struct MockKey {
    /// Lowercase, with the trailing dot.
    pub name: String,
    /// `hmac-sha256.` or `hmac-sha512.`.
    pub algorithm: String,
    /// The shared secret.
    pub secret: Vec<u8>,
}

/// One resource record held by the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockRecord {
    /// Owner name, lowercase, with the trailing dot.
    pub name: String,
    /// Type code.
    pub rtype: u16,
    /// TTL in seconds.
    pub ttl: u32,
    /// RDATA in wire form.
    pub rdata: Vec<u8>,
}

/// The initial state of the server.
#[derive(Clone, Debug)]
pub struct Seed {
    /// Zones served, lowercase, with the trailing dot.
    pub zones: Vec<String>,
    /// Keys accepted.
    pub keys: Vec<MockKey>,
    /// Records present at start.
    pub records: Vec<MockRecord>,
}

impl Seed {
    /// One zone, `example.org.`, and two keys: [`KEY_NAME`] (`hmac-sha256`,
    /// [`STANDARD_SECRET`]) and [`KEY_NAME_512`] (`hmac-sha512`, [`STANDARD_SECRET_512`]).
    pub fn standard() -> Seed {
        Seed {
            zones: vec![ZONE.to_owned()],
            keys: vec![
                MockKey {
                    name: KEY_NAME.to_owned(),
                    algorithm: "hmac-sha256.".to_owned(),
                    secret: STANDARD_SECRET.to_vec(),
                },
                MockKey {
                    name: KEY_NAME_512.to_owned(),
                    algorithm: "hmac-sha512.".to_owned(),
                    secret: STANDARD_SECRET_512.to_vec(),
                },
            ],
            records: Vec::new(),
        }
    }
}

/// The kind of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Opcode QUERY.
    Query,
    /// Opcode UPDATE.
    Update,
}

/// One record of the prerequisite or update section of a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateRr {
    /// Owner name, lowercase, with the trailing dot.
    pub name: String,
    /// Type code.
    pub rtype: u16,
    /// Class code.
    pub class: u16,
    /// TTL.
    pub ttl: u32,
    /// RDATA in wire form.
    pub rdata: Vec<u8>,
}

/// One request the server received.
#[derive(Clone, Debug)]
pub struct Call {
    /// Query or update.
    pub op: Op,
    /// The message ID.
    pub id: u16,
    /// The question name (the zone of an update).
    pub qname: String,
    /// The question type.
    pub qtype: u16,
    /// The prerequisite section of an update.
    pub prereqs: Vec<UpdateRr>,
    /// The update section of an update.
    pub updates: Vec<UpdateRr>,
    /// The MAC of the request's TSIG record (empty when there was none).
    pub request_mac: Vec<u8>,
    /// The RCODE answered; `None` when no answer was sent.
    pub rcode: Option<u8>,
    /// The TSIG error answered.
    pub tsig_error: u16,
}

/// A behavior injected into the next matching requests. Built with [`Fault::on`] and the
/// methods below; the first fault in the queue whose operation matches takes the request.
///
/// Order of effects: the delay, the foreign deletion and record, then either no answer ([`Fault::close`]), a
/// fixed RCODE without applying the request ([`Fault::rcode`]), or normal processing; then the
/// changes to the answer; then how it is written ([`Fault::truncate`], [`Fault::short_length`],
/// [`Fault::drop_reply`]).
#[derive(Clone, Debug, Default)]
pub struct Fault {
    op: Option<Op>,
    times: usize,
    delay: Duration,
    foreign: Option<MockRecord>,
    foreign_delete: Option<(String, u16)>,
    close: bool,
    rcode: Option<u8>,
    unsigned: bool,
    corrupt_mac: bool,
    wrong_id: bool,
    wrong_question: bool,
    omit_question: bool,
    clear_qr: bool,
    set_tc: bool,
    clear_aa: bool,
    time_offset: i64,
    other_key: bool,
    truncate: bool,
    short_length: bool,
    drop_reply: bool,
    extra_answer: Option<(String, u16, u16, Vec<u8>)>,
    tsig_error: u16,
}

impl Fault {
    /// A fault for the next request of `op`, once.
    pub fn on(op: Op) -> Fault {
        Fault {
            op: Some(op),
            times: 1,
            ..Fault::default()
        }
    }

    /// A fault for the next request of any kind, once.
    pub fn any() -> Fault {
        Fault {
            times: 1,
            ..Fault::default()
        }
    }

    /// Applies to this many requests.
    pub fn times(mut self, times: usize) -> Fault {
        self.times = times;
        self
    }

    /// Waits this long before reading on.
    pub fn delay(mut self, delay: Duration) -> Fault {
        self.delay = delay;
        self
    }

    /// Adds a TXT record with `value` (one character-string) at `name` before the request is
    /// processed: a change by another writer.
    pub fn foreign_txt(mut self, name: &str, value: &str) -> Fault {
        self.foreign = Some(MockRecord {
            name: name.to_ascii_lowercase(),
            rtype: TYPE_TXT,
            ttl: 600,
            rdata: txt_rdata(value.as_bytes()),
        });
        self
    }

    /// Adds `record` before the request is processed: a change by another writer, of any type.
    pub fn foreign_record(mut self, record: MockRecord) -> Fault {
        self.foreign = Some(record);
        self
    }

    /// Deletes every record of `name` and `rtype` before the request is processed: a change by
    /// another writer.
    pub fn foreign_delete(mut self, name: &str, rtype: u16) -> Fault {
        self.foreign_delete = Some((name.to_ascii_lowercase(), rtype));
        self
    }

    /// Closes the connection without answering and without applying the request.
    pub fn close(mut self) -> Fault {
        self.close = true;
        self
    }

    /// Answers with this RCODE, signed, without applying the request.
    pub fn rcode(mut self, rcode: u8) -> Fault {
        self.rcode = Some(rcode);
        self
    }

    /// Sends the answer without a TSIG record.
    pub fn unsigned(mut self) -> Fault {
        self.unsigned = true;
        self
    }

    /// Flips a bit of the answer's MAC.
    pub fn corrupt_mac(mut self) -> Fault {
        self.corrupt_mac = true;
        self
    }

    /// Answers with another message ID (and signs that answer correctly).
    pub fn wrong_id(mut self) -> Fault {
        self.wrong_id = true;
        self
    }

    /// Answers with another question type in the question or zone section.
    pub fn wrong_question(mut self) -> Fault {
        self.wrong_question = true;
        self
    }

    /// Answers with an empty question or zone section (count zero).
    pub fn omit_question(mut self) -> Fault {
        self.omit_question = true;
        self
    }

    /// Clears the QR bit of the answer.
    pub fn clear_qr(mut self) -> Fault {
        self.clear_qr = true;
        self
    }

    /// Sets the TC bit of the answer.
    pub fn set_tc(mut self) -> Fault {
        self.set_tc = true;
        self
    }

    /// Clears the AA bit of the answer.
    pub fn clear_aa(mut self) -> Fault {
        self.clear_aa = true;
        self
    }

    /// Signs the answer with a time this many seconds off the server's clock.
    pub fn time_offset(mut self, seconds: i64) -> Fault {
        self.time_offset = seconds;
        self
    }

    /// Signs the answer with another key name (same secret and algorithm).
    pub fn other_key(mut self) -> Fault {
        self.other_key = true;
        self
    }

    /// Writes the length prefix of the full answer, then half of it, then closes.
    pub fn truncate(mut self) -> Fault {
        self.truncate = true;
        self
    }

    /// Writes a length prefix of 4 and 4 octets, shorter than any DNS header.
    pub fn short_length(mut self) -> Fault {
        self.short_length = true;
        self
    }

    /// Appends an answer record owned by `name` (written uncompressed) with this type, class
    /// and RDATA, as a server that follows a CNAME or answers for another name would.
    pub fn extra_answer(mut self, name: &str, rtype: u16, class: u16, rdata: &[u8]) -> Fault {
        self.extra_answer = Some((name.to_owned(), rtype, class, rdata.to_vec()));
        self
    }

    /// Processes the request, then closes the connection without answering.
    pub fn drop_reply(mut self) -> Fault {
        self.drop_reply = true;
        self
    }

    /// Puts this TSIG error code into the answer's TSIG record, with a valid MAC over it,
    /// whatever the RCODE. Combined with [`Fault::rcode`], it produces an answer that reports a
    /// TSIG error under an RCODE other than NOTAUTH, which RFC 8945 section 5.2 does not allow.
    pub fn tsig_error(mut self, error: u16) -> Fault {
        self.tsig_error = error;
        self
    }

    fn matches(&self, op: Op) -> bool {
        self.op.is_none_or(|o| o == op)
    }
}

/// The mutable state of the server.
#[derive(Debug, Default)]
struct State {
    records: Vec<MockRecord>,
    calls: Vec<Call>,
    faults: VecDeque<Fault>,
    refuse_queries: bool,
    skew: i64,
}

/// The handle through which a test reads and changes the server's state.
#[derive(Clone, Debug)]
pub struct Control {
    seed: Arc<Seed>,
    state: Arc<Mutex<State>>,
}

impl Control {
    /// The decoded TXT values at `name` (character-strings concatenated, lossy UTF-8), sorted.
    pub fn txt(&self, name: &str) -> Vec<String> {
        let mut values: Vec<String> = self
            .records(name)
            .into_iter()
            .filter(|r| r.rtype == TYPE_TXT)
            .map(|r| String::from_utf8_lossy(&txt_data(&r.rdata).unwrap_or_default()).into_owned())
            .collect();
        values.sort();
        values
    }

    /// Every record at `name`, in insertion order.
    pub fn records(&self, name: &str) -> Vec<MockRecord> {
        let name = name.to_ascii_lowercase();
        lock(&self.state)
            .records
            .iter()
            .filter(|r| r.name == name)
            .cloned()
            .collect()
    }

    /// The records of `name` and `rtype`, in insertion order.
    pub fn records_of(&self, name: &str, rtype: u16) -> Vec<MockRecord> {
        self.records(name)
            .into_iter()
            .filter(|r| r.rtype == rtype)
            .collect()
    }

    /// Every record held, in insertion order.
    pub fn all_records(&self) -> Vec<MockRecord> {
        lock(&self.state).records.clone()
    }

    /// How many update records deleted every RRset of a name (class ANY, type ANY, RFC 2136
    /// section 2.5.3).
    pub fn name_deletes(&self) -> usize {
        lock(&self.state)
            .calls
            .iter()
            .flat_map(|c| c.updates.iter())
            .filter(|u| u.class == CLASS_ANY && u.rtype == TYPE_ANY)
            .count()
    }

    /// Adds a TXT record with `value` as one character-string.
    pub fn add_txt(&self, name: &str, value: &str, ttl: u32) {
        self.add_record(MockRecord {
            name: name.to_ascii_lowercase(),
            rtype: TYPE_TXT,
            ttl,
            rdata: txt_rdata(value.as_bytes()),
        });
    }

    /// Adds a record as given.
    pub fn add_record(&self, record: MockRecord) {
        lock(&self.state).records.push(record);
    }

    /// Every request received so far.
    pub fn calls(&self) -> Vec<Call> {
        lock(&self.state).calls.clone()
    }

    /// How many requests of `op` were received.
    pub fn count(&self, op: Op) -> usize {
        lock(&self.state)
            .calls
            .iter()
            .filter(|c| c.op == op)
            .count()
    }

    /// Forgets the requests received so far.
    pub fn clear_calls(&self) {
        lock(&self.state).calls.clear();
    }

    /// How many update records deleted a whole RRset or every RRset of a name (class ANY).
    pub fn rrset_deletes(&self) -> usize {
        lock(&self.state)
            .calls
            .iter()
            .flat_map(|c| c.updates.iter())
            .filter(|u| u.class == CLASS_ANY)
            .count()
    }

    /// Queues a fault.
    pub fn push(&self, fault: Fault) {
        lock(&self.state).faults.push_back(fault);
    }

    /// Refuses every query (REFUSED, signed), as a server that allows the key to update but not
    /// to query.
    pub fn refuse_queries(&self, on: bool) {
        lock(&self.state).refuse_queries = on;
    }

    /// Moves the server's clock by `seconds`.
    pub fn clock_skew(&self, seconds: i64) {
        lock(&self.state).skew = seconds;
    }

    /// The seed the server started from.
    pub fn seed(&self) -> &Seed {
        &self.seed
    }

    fn next_fault(&self, op: Op) -> Option<Fault> {
        let mut state = lock(&self.state);
        let index = state.faults.iter().position(|f| f.matches(op))?;
        let fault = state.faults.get_mut(index)?;
        let taken = fault.clone();
        fault.times = fault.times.saturating_sub(1);
        if fault.times == 0 {
            state.faults.remove(index);
        }
        Some(taken)
    }
}

/// A running mock server. Dropping it stops accepting connections.
#[derive(Debug)]
pub struct Rfc2136Mock {
    addr: SocketAddr,
    control: Control,
    _shutdown: tokio::sync::watch::Sender<()>,
}

impl Rfc2136Mock {
    /// Starts the server on `127.0.0.1` with an ephemeral port, the same number for TCP and UDP.
    pub async fn start(seed: Seed) -> Rfc2136Mock {
        let state = State {
            records: seed.records.clone(),
            ..State::default()
        };
        let control = Control {
            seed: Arc::new(seed),
            state: Arc::new(Mutex::new(state)),
        };
        // The ephemeral TCP port may be taken for UDP by another process: try another one.
        let mut bound = None;
        for _ in 0..32 {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind 127.0.0.1:0");
            let addr = listener.local_addr().expect("local address");
            if let Ok(socket) = UdpSocket::bind(addr).await {
                bound = Some((listener, socket, addr));
                break;
            }
        }
        let (listener, socket, addr) = bound.expect("bind TCP and UDP on one port of 127.0.0.1");
        let (tx, mut rx) = tokio::sync::watch::channel(());
        let mut udp_rx = rx.clone();
        let accept_control = control.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    accepted = listener.accept() => {
                        if let Ok((stream, _)) = accepted {
                            tokio::spawn(serve(stream, accept_control.clone()));
                        }
                    }
                }
            }
        });
        let udp_control = control.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = udp_rx.changed() => {}
                () = serve_udp(socket, udp_control) => {}
            }
        });
        Rfc2136Mock {
            addr,
            control,
            _shutdown: tx,
        }
    }

    /// The address the server listens on (TCP and UDP).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The address as the client's `server` setting: `127.0.0.1:<port>`.
    pub fn server(&self) -> String {
        self.addr.to_string()
    }

    /// The control handle.
    pub fn control(&self) -> &Control {
        &self.control
    }
}

async fn serve_udp(socket: UdpSocket, control: Control) {
    let mut buf = vec![0u8; 65_535];
    loop {
        let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
            return;
        };
        let request = buf.get(..len).unwrap_or_default().to_vec();
        let Reply::Send(bytes, how) = handle_on(&request, &control, Transport::Udp).await else {
            continue;
        };
        let out = match how {
            Write::Full => &bytes[..],
            Write::Truncated => &bytes[..bytes.len() / 2],
            Write::ShortLength => &bytes[..4.min(bytes.len())],
        };
        let _ = socket.send_to(out, peer).await;
    }
}

async fn serve(mut stream: TcpStream, control: Control) {
    loop {
        let Ok(len) = stream.read_u16().await else {
            return;
        };
        let mut buf = vec![0u8; usize::from(len)];
        if stream.read_exact(&mut buf).await.is_err() {
            return;
        }
        match handle(&buf, &control).await {
            Reply::Close => return,
            Reply::Send(bytes, how) => {
                let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
                let mut out = len.to_be_bytes().to_vec();
                match how {
                    Write::Full => out.extend_from_slice(&bytes),
                    Write::Truncated => out.extend_from_slice(&bytes[..bytes.len() / 2]),
                    Write::ShortLength => {
                        out = vec![0, 4];
                        out.extend_from_slice(&bytes[..4.min(bytes.len())]);
                    }
                }
                if stream.write_all(&out).await.is_err() || how != Write::Full {
                    let _ = stream.shutdown().await;
                    return;
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Write {
    Full,
    Truncated,
    ShortLength,
}

enum Reply {
    Close,
    Send(Vec<u8>, Write),
}

// ---- Parsing -----------------------------------------------------------------------------------

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn be32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(i)?,
        *b.get(i + 1)?,
        *b.get(i + 2)?,
        *b.get(i + 3)?,
    ]))
}

/// A name with compression, lowercase with the trailing dot, and the position after it.
fn read_name(b: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut end = None;
    for _ in 0..128 {
        let len = *b.get(i)?;
        if len & 0xc0 == 0xc0 {
            end.get_or_insert(i + 2);
            i = (usize::from(len & 0x3f) << 8) | usize::from(*b.get(i + 1)?);
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        if len == 0 {
            if out.is_empty() {
                out.push('.');
            }
            return Some((out, end.unwrap_or(i + 1)));
        }
        let label = b.get(i + 1..i + 1 + usize::from(len))?;
        out.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        out.push('.');
        i += 1 + usize::from(len);
    }
    None
}

/// A name with compression as uncompressed wire octets, the case of its labels kept, and the
/// position after it.
fn read_wire_name(b: &[u8], mut i: usize) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut end = None;
    for _ in 0..128 {
        let len = *b.get(i)?;
        if len & 0xc0 == 0xc0 {
            end.get_or_insert(i + 2);
            i = (usize::from(len & 0x3f) << 8) | usize::from(*b.get(i + 1)?);
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        out.push(len);
        if len == 0 {
            return (out.len() <= 255).then_some((out, end.unwrap_or(i + 1)));
        }
        out.extend_from_slice(b.get(i + 1..i + 1 + usize::from(len))?);
        i += 1 + usize::from(len);
    }
    None
}

/// The RDATA of a request record at `start`, `len` octets long. The names inside the RDATA of
/// NS, CNAME, PTR, MX and SOA may be compressed against the rest of the message (RFC 1035
/// section 4.1.4; RFC 3597 section 4: a receiver decompresses them for these types); they are
/// stored uncompressed, since a pointer means nothing outside the message it came in. `None`
/// when a name runs outside the RDATA or the RDATA has octets left over.
fn request_rdata(b: &[u8], rtype: u16, start: usize, len: usize) -> Option<Vec<u8>> {
    let raw = b.get(start..start + len)?;
    let end = start + len;
    if raw.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    let name = |at: usize, out: &mut Vec<u8>| -> Option<usize> {
        let (wire, next) = read_wire_name(b, at)?;
        out.extend_from_slice(&wire);
        (next <= end).then_some(next)
    };
    let next = match rtype {
        TYPE_NS | TYPE_CNAME | TYPE_PTR => name(start, &mut out)?,
        TYPE_MX => {
            out.extend_from_slice(b.get(start..start + 2)?);
            name(start + 2, &mut out)?
        }
        TYPE_SOA => {
            let second = name(start, &mut out)?;
            let fixed = name(second, &mut out)?;
            out.extend_from_slice(b.get(fixed..fixed + 20)?);
            fixed + 20
        }
        _ => return Some(raw.to_vec()),
    };
    (next == end).then_some(out)
}

/// The uncompressed wire form of a name given as text with a trailing dot.
fn wire_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(u8::try_from(label.len()).unwrap_or(63));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// TXT RDATA from data, in character-strings of at most 255 octets.
pub fn txt_rdata(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if data.is_empty() {
        out.push(0);
    }
    for chunk in data.chunks(255) {
        out.push(u8::try_from(chunk.len()).unwrap_or(255));
        out.extend_from_slice(chunk);
    }
    out
}

/// The concatenated character-strings of TXT RDATA; `None` when malformed.
pub fn txt_data(rdata: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < rdata.len() {
        let n = usize::from(rdata[i]);
        out.extend_from_slice(rdata.get(i + 1..i + 1 + n)?);
        i += 1 + n;
    }
    Some(out)
}

struct Rr {
    name: String,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
    start: usize,
}

struct Request {
    id: u16,
    opcode: u8,
    /// Raw octets of the question or zone section, copied into the answer.
    question: Vec<u8>,
    qname: String,
    qtype: u16,
    prereqs: Vec<Rr>,
    updates: Vec<Rr>,
    additional: Vec<Rr>,
}

fn parse(b: &[u8]) -> Option<Request> {
    let id = be16(b, 0)?;
    let flags = be16(b, 2)?;
    let counts = [be16(b, 4)?, be16(b, 6)?, be16(b, 8)?, be16(b, 10)?];
    if counts[0] != 1 {
        return None;
    }
    let (qname, i) = read_name(b, 12)?;
    let qtype = be16(b, i)?;
    let mut i = i + 4;
    let question = b.get(12..i)?.to_vec();
    let mut sections: [Vec<Rr>; 3] = Default::default();
    for (s, section) in sections.iter_mut().enumerate() {
        for _ in 0..counts[s + 1] {
            let start = i;
            let (name, j) = read_name(b, i)?;
            let rtype = be16(b, j)?;
            let class = be16(b, j + 2)?;
            let ttl = be32(b, j + 4)?;
            let len = usize::from(be16(b, j + 8)?);
            let rdata = request_rdata(b, rtype, j + 10, len)?;
            i = j + 10 + len;
            section.push(Rr {
                name,
                rtype,
                class,
                ttl,
                rdata,
                start,
            });
        }
    }
    if i != b.len() {
        return None;
    }
    let [prereqs, updates, additional] = sections;
    Some(Request {
        id,
        opcode: ((flags >> 11) & 0xf) as u8,
        question,
        qname,
        qtype,
        prereqs,
        updates,
        additional,
    })
}

struct Tsig {
    key_name: String,
    algorithm: String,
    time: u64,
    fudge: u16,
    mac: Vec<u8>,
    original_id: u16,
    error: u16,
    other: Vec<u8>,
    start: usize,
}

fn parse_tsig(rr: &Rr) -> Option<Tsig> {
    let d = &rr.rdata;
    let (algorithm, i) = read_name(d, 0)?;
    let time = d
        .get(i..i + 6)?
        .iter()
        .fold(0u64, |a, x| (a << 8) | u64::from(*x));
    let fudge = be16(d, i + 6)?;
    let mac_len = usize::from(be16(d, i + 8)?);
    let mac = d.get(i + 10..i + 10 + mac_len)?.to_vec();
    let j = i + 10 + mac_len;
    let original_id = be16(d, j)?;
    let error = be16(d, j + 2)?;
    let other_len = usize::from(be16(d, j + 4)?);
    let other = d.get(j + 6..j + 6 + other_len)?.to_vec();
    if j + 6 + other_len != d.len() || rr.class != CLASS_ANY || rr.ttl != 0 {
        return None;
    }
    Some(Tsig {
        key_name: rr.name.clone(),
        algorithm,
        time,
        fudge,
        mac,
        original_id,
        error,
        other,
        start: rr.start,
    })
}

fn algorithm(name: &str) -> Option<hmac::Algorithm> {
    match name {
        "hmac-sha256." => Some(hmac::HMAC_SHA256),
        "hmac-sha512." => Some(hmac::HMAC_SHA512),
        _ => None,
    }
}

/// The TSIG variables (RFC 8945 section 4.3.3).
fn variables(key: &str, alg: &str, time: u64, fudge: u16, error: u16, other: &[u8]) -> Vec<u8> {
    let mut v = wire_name(key);
    v.extend_from_slice(&CLASS_ANY.to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 0]);
    v.extend_from_slice(&wire_name(alg));
    v.extend_from_slice(&time.to_be_bytes()[2..]);
    v.extend_from_slice(&fudge.to_be_bytes());
    v.extend_from_slice(&error.to_be_bytes());
    v.extend_from_slice(&u16::try_from(other.len()).unwrap_or(0).to_be_bytes());
    v.extend_from_slice(other);
    v
}

fn now(skew: i64) -> u64 {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    (t + skew).max(0) as u64
}

// ---- Processing --------------------------------------------------------------------------------

/// How the answer is signed.
#[derive(Clone)]
struct Signing<'a> {
    key_name: String,
    algorithm: &'a str,
    /// `None`: a TSIG record with an empty MAC (BADKEY, BADSIG).
    secret: Option<&'a [u8]>,
    request_mac: &'a [u8],
    time: u64,
    error: u16,
    other: Vec<u8>,
}

/// The transport a request came over.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Transport {
    Tcp,
    Udp,
}

async fn handle(b: &[u8], control: &Control) -> Reply {
    handle_on(b, control, Transport::Tcp).await
}

async fn handle_on(b: &[u8], control: &Control, transport: Transport) -> Reply {
    let Some(req) = parse(b) else {
        return Reply::Close;
    };
    let op = if req.opcode == 5 {
        Op::Update
    } else {
        Op::Query
    };
    let fault = control.next_fault(op).unwrap_or_default();
    if !fault.delay.is_zero() {
        tokio::time::sleep(fault.delay).await;
    }
    if let Some((name, rtype)) = &fault.foreign_delete {
        lock(&control.state)
            .records
            .retain(|r| !(&r.name == name && r.rtype == *rtype));
    }
    if let Some(record) = &fault.foreign {
        control.add_record(record.clone());
    }
    let (skew, refuse_queries) = {
        let state = lock(&control.state);
        (state.skew, state.refuse_queries)
    };
    let server_now = now(skew);
    let mut call = Call {
        op,
        id: req.id,
        qname: req.qname.clone(),
        qtype: req.qtype,
        prereqs: req.prereqs.iter().map(update_rr).collect(),
        updates: req.updates.iter().map(update_rr).collect(),
        request_mac: Vec::new(),
        rcode: None,
        tsig_error: 0,
    };
    let tsig_count = req
        .additional
        .iter()
        .filter(|r| r.rtype == TYPE_TSIG)
        .count();
    let last = req.additional.last().filter(|r| r.rtype == TYPE_TSIG);
    let Some(tsig) = last.filter(|_| tsig_count == 1).and_then(parse_tsig) else {
        let rcode = if tsig_count == 0 { REFUSED } else { FORMERR };
        call.rcode = Some(rcode);
        lock(&control.state).calls.push(call);
        return Reply::Send(
            answer(&req, &Outcome::rcode(rcode), None, &fault),
            Write::Full,
        );
    };
    call.request_mac = tsig.mac.clone();
    if fault.close {
        lock(&control.state).calls.push(call);
        return Reply::Close;
    }
    let key = control
        .seed
        .keys
        .iter()
        .find(|k| k.name == tsig.key_name && k.algorithm == tsig.algorithm);
    let tsig_failure = |call: &mut Call, error: u16, secret: Option<&[u8]>| {
        call.rcode = Some(NOTAUTH);
        call.tsig_error = error;
        let other = if error == BADTIME {
            server_now.to_be_bytes()[2..].to_vec()
        } else {
            Vec::new()
        };
        // RFC 8945 section 5.2.3: a BADTIME answer "MUST include the client's current time in
        // the Time Signed field", so that the client can verify it despite the clock difference.
        let time = if error == BADTIME {
            tsig.time
        } else {
            server_now
        };
        let signing = Signing {
            key_name: tsig.key_name.clone(),
            algorithm: &tsig.algorithm,
            secret,
            request_mac: &tsig.mac,
            time,
            error,
            other,
        };
        answer(
            &req,
            &Outcome::rcode(NOTAUTH),
            Some(signing),
            &Fault::default(),
        )
    };
    let Some(key) = key else {
        let reply = tsig_failure(&mut call, BADKEY, None);
        lock(&control.state).calls.push(call);
        return Reply::Send(reply, Write::Full);
    };
    let Some(alg) = algorithm(&key.algorithm) else {
        return Reply::Close;
    };
    // The request MAC: the message without the TSIG record, ARCOUNT less one, the original ID,
    // then the variables (RFC 8945 sections 4.3.2 and 4.3.3).
    let mut data = b[..tsig.start].to_vec();
    let arcount = be16(&data, 10).unwrap_or(1).saturating_sub(1);
    data[10..12].copy_from_slice(&arcount.to_be_bytes());
    data[..2].copy_from_slice(&tsig.original_id.to_be_bytes());
    data.extend_from_slice(&variables(
        &tsig.key_name,
        &tsig.algorithm,
        tsig.time,
        tsig.fudge,
        tsig.error,
        &tsig.other,
    ));
    if hmac::verify(&hmac::Key::new(alg, &key.secret), &data, &tsig.mac).is_err() {
        let reply = tsig_failure(&mut call, BADSIG, None);
        lock(&control.state).calls.push(call);
        return Reply::Send(reply, Write::Full);
    }
    if server_now.abs_diff(tsig.time) > u64::from(tsig.fudge) {
        let reply = tsig_failure(&mut call, BADTIME, Some(&key.secret));
        lock(&control.state).calls.push(call);
        return Reply::Send(reply, Write::Full);
    }
    let outcome = match fault.rcode {
        Some(rcode) => Outcome::rcode(rcode),
        None => process(&req, control, refuse_queries),
    };
    call.rcode = Some(outcome.rcode);
    lock(&control.state).calls.push(call);
    if fault.drop_reply {
        return Reply::Close;
    }
    let signing = (!fault.unsigned).then(|| Signing {
        key_name: if fault.other_key {
            "other-key.".to_owned()
        } else {
            tsig.key_name.clone()
        },
        algorithm: &tsig.algorithm,
        secret: Some(&key.secret),
        request_mac: &tsig.mac,
        time: now(skew + fault.time_offset),
        error: fault.tsig_error,
        other: Vec::new(),
    });
    let mut reply = answer(&req, &outcome, signing.clone(), &fault);
    if transport == Transport::Udp && reply.len() > UDP_LIMIT {
        let cut = Outcome {
            answers: Vec::new(),
            authority: Vec::new(),
            ..outcome
        };
        let tc = Fault {
            set_tc: true,
            extra_answer: None,
            ..fault.clone()
        };
        reply = answer(&req, &cut, signing, &tc);
    }
    let how = if fault.truncate {
        Write::Truncated
    } else if fault.short_length {
        Write::ShortLength
    } else {
        Write::Full
    };
    Reply::Send(reply, how)
}

fn update_rr(rr: &Rr) -> UpdateRr {
    UpdateRr {
        name: rr.name.clone(),
        rtype: rr.rtype,
        class: rr.class,
        ttl: rr.ttl,
        rdata: rr.rdata.clone(),
    }
}

fn in_zone(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{zone}"))
}

/// Query and meta types: the reserved 0, OPT and 128 ..= 255 (RFC 6895 section 3.1), which RFC
/// 2136 section 3.4.1.2 calls "ANY, AXFR, MAILA, MAILB, or any other QUERY metatype".
fn is_meta(rtype: u16) -> bool {
    rtype == 0 || rtype == 41 || (128..=255).contains(&rtype)
}

/// One record of an answer.
#[derive(Clone, Debug)]
struct AnswerRr {
    owner: String,
    rtype: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

/// What processing a request produced.
#[derive(Debug)]
struct Outcome {
    rcode: u8,
    /// AA: the answer comes from an authority for the name (false for a referral).
    authoritative: bool,
    answers: Vec<AnswerRr>,
    authority: Vec<AnswerRr>,
}

impl Outcome {
    fn rcode(rcode: u8) -> Outcome {
        Outcome {
            rcode,
            authoritative: true,
            answers: Vec::new(),
            authority: Vec::new(),
        }
    }
}

fn process(req: &Request, control: &Control, refuse_queries: bool) -> Outcome {
    let zones = &control.seed.zones;
    let mut state = lock(&control.state);
    match req.opcode {
        0 => {
            let Some(zone) = zones.iter().find(|z| in_zone(&req.qname, z)) else {
                return Outcome::rcode(REFUSED);
            };
            if refuse_queries {
                return Outcome::rcode(REFUSED);
            }
            let to_answer = |r: &MockRecord| AnswerRr {
                owner: r.name.clone(),
                rtype: r.rtype,
                ttl: r.ttl,
                rdata: r.rdata.clone(),
            };
            // A zone cut: NS records at a name below the apex (RFC 1034 section 4.3.2, step 3b).
            let cut = state
                .records
                .iter()
                .filter(|r| r.rtype == TYPE_NS && &r.name != zone && in_zone(&req.qname, &r.name))
                .map(|r| r.name.clone())
                .next();
            if let Some(cut) = cut {
                return Outcome {
                    rcode: NOERROR,
                    authoritative: false,
                    answers: Vec::new(),
                    authority: state
                        .records
                        .iter()
                        .filter(|r| r.name == cut && r.rtype == TYPE_NS)
                        .map(to_answer)
                        .collect(),
                };
            }
            // A CNAME at the name answers a query of any type (RFC 1034 section 4.3.2, step
            // 3a). The mock does not follow the chain to the target.
            let answers: Vec<AnswerRr> = state
                .records
                .iter()
                .filter(|r| {
                    r.name == req.qname
                        && (req.qtype == r.rtype || req.qtype == TYPE_ANY || r.rtype == TYPE_CNAME)
                })
                .map(to_answer)
                .collect();
            let exists =
                state.records.iter().any(|r| r.name == req.qname) || zones.contains(&req.qname);
            // A negative answer (NXDOMAIN, or no data of the type) carries the zone's SOA in the
            // authority section, with the lower of its TTL and its MINIMUM field as the TTL (RFC
            // 2308 section 3). A seed without an apex SOA gets an empty authority section.
            let authority = if answers.is_empty() {
                state
                    .records
                    .iter()
                    .filter(|r| &r.name == zone && r.rtype == TYPE_SOA)
                    .map(|r| AnswerRr {
                        ttl: soa_minimum(&r.rdata).map_or(r.ttl, |m| m.min(r.ttl)),
                        ..to_answer(r)
                    })
                    .collect()
            } else {
                Vec::new()
            };
            Outcome {
                rcode: if exists { NOERROR } else { NXDOMAIN },
                authoritative: true,
                answers,
                authority,
            }
        }
        5 => Outcome::rcode(update(req, zones, &mut state.records)),
        _ => Outcome::rcode(NOTIMP),
    }
}

/// The serial of SOA RDATA: the third 32-bit field after the two names.
fn soa_serial(rdata: &[u8]) -> Option<u32> {
    let (_, i) = read_name(rdata, 0)?;
    let (_, j) = read_name(rdata, i)?;
    be32(rdata, j)
}

/// The MINIMUM field of SOA RDATA: the last 32-bit field.
fn soa_minimum(rdata: &[u8]) -> Option<u32> {
    let (_, i) = read_name(rdata, 0)?;
    let (_, j) = read_name(rdata, i)?;
    be32(rdata, j + 16).filter(|_| rdata.len() == j + 20)
}

/// `a` is lower than or equal to `b` in serial number arithmetic (RFC 1982 section 3.2).
fn serial_not_greater(a: u32, b: u32) -> bool {
    a == b || (a < b && b - a < (1 << 31)) || (a > b && a - b > (1 << 31))
}

/// RFC 2136 section 3: zone section, prerequisites, prescan, then the updates, all or nothing.
fn update(req: &Request, zones: &[String], records: &mut Vec<MockRecord>) -> u8 {
    if req.qtype != TYPE_SOA {
        return FORMERR;
    }
    let zone = &req.qname;
    if !zones.contains(zone) {
        return NOTAUTH;
    }
    // Section 3.2 (pseudocode 3.2.5): in order, the first failure decides.
    let mut temp: Vec<(String, u16, Vec<Vec<u8>>)> = Vec::new();
    for p in &req.prereqs {
        if p.ttl != 0 {
            return FORMERR;
        }
        if !in_zone(&p.name, zone) {
            return NOTZONE;
        }
        let name_in_use = &p.name == zone || records.iter().any(|r| r.name == p.name);
        let rrset_exists = records
            .iter()
            .any(|r| r.name == p.name && r.rtype == p.rtype);
        match p.class {
            CLASS_ANY | CLASS_NONE if !p.rdata.is_empty() => return FORMERR,
            CLASS_ANY if p.rtype == TYPE_ANY && !name_in_use => return NXDOMAIN,
            CLASS_ANY if p.rtype != TYPE_ANY && !rrset_exists => return NXRRSET,
            CLASS_NONE if p.rtype == TYPE_ANY && name_in_use => return YXDOMAIN,
            CLASS_NONE if p.rtype != TYPE_ANY && rrset_exists => return YXRRSET,
            CLASS_ANY | CLASS_NONE => {}
            CLASS_IN => match temp
                .iter_mut()
                .find(|(n, t, _)| n == &p.name && *t == p.rtype)
            {
                Some((_, _, set)) => set.push(p.rdata.clone()),
                None => temp.push((p.name.clone(), p.rtype, vec![p.rdata.clone()])),
            },
            _ => return FORMERR,
        }
    }
    // Section 3.2.3: each value-dependent RRset must equal the zone RRset, as a set.
    for (name, rtype, set) in &temp {
        let zone_set: Vec<&Vec<u8>> = records
            .iter()
            .filter(|r| &r.name == name && r.rtype == *rtype)
            .map(|r| &r.rdata)
            .collect();
        let equal =
            zone_set.iter().all(|z| set.contains(z)) && set.iter().all(|s| zone_set.contains(&s));
        if !equal {
            return NXRRSET;
        }
    }
    // Section 3.4.1: the prescan.
    for u in &req.updates {
        if !in_zone(&u.name, zone) {
            return NOTZONE;
        }
        let valid = match u.class {
            CLASS_IN => !is_meta(u.rtype),
            CLASS_ANY => {
                u.ttl == 0 && u.rdata.is_empty() && (u.rtype == TYPE_ANY || !is_meta(u.rtype))
            }
            CLASS_NONE => u.ttl == 0 && !is_meta(u.rtype),
            _ => false,
        };
        if !valid {
            return FORMERR;
        }
    }
    // Section 3.4.2 (pseudocode 3.4.2.7), on a copy committed at the end (3.4.2.1).
    let mut work = records.clone();
    for u in &req.updates {
        match u.class {
            CLASS_IN => {
                // "In the case of a CNAME Update RR and a non-CNAME Zone RRset or vice versa,
                // ignore the CNAME Update RR." The add is ignored silently: NOERROR all the
                // same.
                let conflicting = work.iter().any(|r| {
                    r.name == u.name && ((r.rtype == TYPE_CNAME) != (u.rtype == TYPE_CNAME))
                });
                if conflicting {
                    continue;
                }
                if u.rtype == TYPE_SOA {
                    let current = work
                        .iter()
                        .find(|r| r.name == u.name && r.rtype == TYPE_SOA)
                        .and_then(|r| soa_serial(&r.rdata));
                    let ignored = match (current, soa_serial(&u.rdata)) {
                        (Some(current), Some(new)) => serial_not_greater(new, current),
                        _ => true,
                    };
                    if ignored {
                        continue;
                    }
                }
                let replaces = |r: &MockRecord| {
                    r.name == u.name
                        && r.rtype == u.rtype
                        && (u.rtype == TYPE_CNAME || u.rtype == TYPE_SOA || r.rdata == u.rdata)
                };
                if let Some(existing) = work.iter_mut().find(|r| replaces(r)) {
                    existing.rdata = u.rdata.clone();
                    existing.ttl = u.ttl;
                } else {
                    work.push(MockRecord {
                        name: u.name.clone(),
                        rtype: u.rtype,
                        ttl: u.ttl,
                        rdata: u.rdata.clone(),
                    });
                }
                // Invented (see the module documentation): one TTL per RRset, the added one.
                for r in work
                    .iter_mut()
                    .filter(|r| r.name == u.name && r.rtype == u.rtype)
                {
                    r.ttl = u.ttl;
                }
            }
            CLASS_ANY => {
                let apex = &u.name == zone;
                if u.rtype == TYPE_ANY {
                    work.retain(|r| {
                        !(r.name == u.name && !(apex && matches!(r.rtype, TYPE_SOA | TYPE_NS)))
                    });
                } else if !(apex && matches!(u.rtype, TYPE_SOA | TYPE_NS)) {
                    work.retain(|r| !(r.name == u.name && r.rtype == u.rtype));
                }
            }
            _ => {
                if u.rtype == TYPE_SOA {
                    continue;
                }
                let ns: Vec<&MockRecord> = work
                    .iter()
                    .filter(|r| r.name == u.name && r.rtype == TYPE_NS)
                    .collect();
                let last_apex_ns = u.rtype == TYPE_NS
                    && &u.name == zone
                    && matches!(ns.as_slice(), [only] if only.rdata == u.rdata);
                if last_apex_ns {
                    continue;
                }
                work.retain(|r| !(r.name == u.name && r.rtype == u.rtype && r.rdata == u.rdata));
            }
        }
    }
    *records = work;
    NOERROR
}

/// The labels of an uncompressed wire name, `None` when malformed.
fn labels(wire: &[u8]) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let len = usize::from(*wire.get(i)?);
        if len == 0 {
            return Some(out);
        }
        out.push(wire.get(i + 1..i + 1 + len)?);
        i += 1 + len;
    }
}

/// The suffixes of the question name with their offsets in the message (the question starts at
/// offset 12).
fn question_suffixes(question: &[u8]) -> Vec<(Vec<&[u8]>, usize)> {
    let Some(all) = labels(question) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut offset = 12;
    for i in 0..all.len() {
        out.push((all[i..].to_vec(), offset));
        offset += 1 + all[i].len();
    }
    out
}

/// Appends the uncompressed wire name `name`, compressed against the question where a suffix of
/// labels matches octet for octet (RFC 1035 section 4.1.4).
fn put_compressed(m: &mut Vec<u8>, name: &[u8], suffixes: &[(Vec<&[u8]>, usize)]) {
    let Some(name_labels) = labels(name) else {
        m.extend_from_slice(name);
        return;
    };
    for start in 0..name_labels.len() {
        let rest = &name_labels[start..];
        if let Some((_, offset)) = suffixes.iter().find(|(s, _)| s.as_slice() == rest) {
            for label in &name_labels[..start] {
                m.push(u8::try_from(label.len()).unwrap_or(63));
                m.extend_from_slice(label);
            }
            let pointer = 0xc000 | u16::try_from(*offset).unwrap_or(0);
            m.extend_from_slice(&pointer.to_be_bytes());
            return;
        }
    }
    m.extend_from_slice(name);
}

/// The RDATA of an answer record, with the names of NS, CNAME, PTR, MX and SOA compressed.
fn answer_rdata(rtype: u16, rdata: &[u8], suffixes: &[(Vec<&[u8]>, usize)]) -> Vec<u8> {
    let name_end = |at: usize| -> Option<usize> {
        let mut i = at;
        loop {
            let len = usize::from(*rdata.get(i)?);
            i += 1 + len;
            if len == 0 {
                return Some(i);
            }
        }
    };
    let compressed = (|| -> Option<Vec<u8>> {
        let mut out = Vec::new();
        match rtype {
            TYPE_NS | TYPE_CNAME | TYPE_PTR => {
                let end = name_end(0).filter(|&e| e == rdata.len())?;
                put_compressed(&mut out, rdata.get(..end)?, suffixes);
            }
            TYPE_MX => {
                let end = name_end(2).filter(|&e| e == rdata.len())?;
                out.extend_from_slice(rdata.get(..2)?);
                put_compressed(&mut out, rdata.get(2..end)?, suffixes);
            }
            TYPE_SOA => {
                let first = name_end(0)?;
                let second = name_end(first)?;
                if second + 20 != rdata.len() {
                    return None;
                }
                put_compressed(&mut out, rdata.get(..first)?, suffixes);
                put_compressed(&mut out, rdata.get(first..second)?, suffixes);
                out.extend_from_slice(rdata.get(second..)?);
            }
            _ => return None,
        }
        Some(out)
    })();
    compressed.unwrap_or_else(|| rdata.to_vec())
}

/// Builds the answer: header, question or zone section, answers, authority, then the TSIG
/// record.
fn answer(
    req: &Request,
    outcome: &Outcome,
    signing: Option<Signing<'_>>,
    fault: &Fault,
) -> Vec<u8> {
    let id = if fault.wrong_id {
        req.id.wrapping_add(1)
    } else {
        req.id
    };
    let rcode = outcome.rcode;
    let mut flags: u16 = 0x8000 | (u16::from(req.opcode) << 11) | u16::from(rcode & 0x0f);
    if outcome.authoritative && !fault.clear_aa {
        flags |= 0x0400;
    }
    if fault.clear_qr {
        flags &= !0x8000;
    }
    if fault.set_tc {
        flags |= 0x0200;
    }
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&flags.to_be_bytes());
    let qdcount: u16 = if fault.omit_question { 0 } else { 1 };
    let extra = usize::from(fault.extra_answer.is_some());
    let ancount = u16::try_from(outcome.answers.len() + extra).unwrap_or(0);
    let nscount = u16::try_from(outcome.authority.len()).unwrap_or(0);
    for n in [qdcount, ancount, nscount, 0] {
        m.extend_from_slice(&n.to_be_bytes());
    }
    let suffixes = if fault.omit_question {
        Vec::new()
    } else {
        question_suffixes(&req.question)
    };
    if !fault.omit_question {
        let mut question = req.question.clone();
        if fault.wrong_question {
            let at = question.len() - 4;
            question[at..at + 2].copy_from_slice(&TYPE_A.to_be_bytes());
        }
        m.extend_from_slice(&question);
    }
    for rr in outcome.answers.iter().chain(&outcome.authority) {
        put_compressed(&mut m, &wire_name(&rr.owner), &suffixes);
        m.extend_from_slice(&rr.rtype.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        m.extend_from_slice(&rr.ttl.to_be_bytes());
        let rdata = answer_rdata(rr.rtype, &rr.rdata, &suffixes);
        m.extend_from_slice(&u16::try_from(rdata.len()).unwrap_or(0).to_be_bytes());
        m.extend_from_slice(&rdata);
    }
    if let Some((name, rtype, class, rdata)) = &fault.extra_answer {
        m.extend_from_slice(&wire_name(name));
        m.extend_from_slice(&rtype.to_be_bytes());
        m.extend_from_slice(&class.to_be_bytes());
        m.extend_from_slice(&60u32.to_be_bytes());
        m.extend_from_slice(&u16::try_from(rdata.len()).unwrap_or(0).to_be_bytes());
        m.extend_from_slice(rdata);
    }
    let Some(s) = signing else {
        return m;
    };
    let mac = match (s.secret, algorithm(s.algorithm)) {
        (Some(secret), Some(alg)) => {
            let mut data = u16::try_from(s.request_mac.len())
                .unwrap_or(0)
                .to_be_bytes()
                .to_vec();
            data.extend_from_slice(s.request_mac);
            data.extend_from_slice(&m);
            data.extend_from_slice(&variables(
                &s.key_name,
                s.algorithm,
                s.time,
                FUDGE,
                s.error,
                &s.other,
            ));
            let mut mac = hmac::sign(&hmac::Key::new(alg, secret), &data)
                .as_ref()
                .to_vec();
            if fault.corrupt_mac
                && let Some(first) = mac.first_mut()
            {
                *first ^= 0x01;
            }
            mac
        }
        _ => Vec::new(),
    };
    let mut rd = wire_name(s.algorithm);
    rd.extend_from_slice(&s.time.to_be_bytes()[2..]);
    rd.extend_from_slice(&FUDGE.to_be_bytes());
    rd.extend_from_slice(&u16::try_from(mac.len()).unwrap_or(0).to_be_bytes());
    rd.extend_from_slice(&mac);
    rd.extend_from_slice(&id.to_be_bytes());
    rd.extend_from_slice(&s.error.to_be_bytes());
    rd.extend_from_slice(&u16::try_from(s.other.len()).unwrap_or(0).to_be_bytes());
    rd.extend_from_slice(&s.other);
    m.extend_from_slice(&wire_name(&s.key_name));
    m.extend_from_slice(&TYPE_TSIG.to_be_bytes());
    m.extend_from_slice(&CLASS_ANY.to_be_bytes());
    m.extend_from_slice(&[0, 0, 0, 0]);
    m.extend_from_slice(&u16::try_from(rd.len()).unwrap_or(0).to_be_bytes());
    m.extend_from_slice(&rd);
    m[10..12].copy_from_slice(&1u16.to_be_bytes());
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a signed request the way RFC 8945 describes it, independently of the client.
    fn signed(unsigned: &[u8], key: &MockKey, time: u64) -> (Vec<u8>, Vec<u8>) {
        let alg = algorithm(&key.algorithm).unwrap();
        let mut data = unsigned.to_vec();
        data.extend_from_slice(&variables(&key.name, &key.algorithm, time, 300, 0, &[]));
        let mac = hmac::sign(&hmac::Key::new(alg, &key.secret), &data)
            .as_ref()
            .to_vec();
        let mut rd = wire_name(&key.algorithm);
        rd.extend_from_slice(&time.to_be_bytes()[2..]);
        rd.extend_from_slice(&300u16.to_be_bytes());
        rd.extend_from_slice(&(mac.len() as u16).to_be_bytes());
        rd.extend_from_slice(&mac);
        rd.extend_from_slice(&unsigned[..2]);
        rd.extend_from_slice(&[0, 0, 0, 0]);
        let mut msg = unsigned.to_vec();
        msg.extend_from_slice(&wire_name(&key.name));
        msg.extend_from_slice(&TYPE_TSIG.to_be_bytes());
        msg.extend_from_slice(&CLASS_ANY.to_be_bytes());
        msg.extend_from_slice(&[0, 0, 0, 0]);
        msg.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        msg.extend_from_slice(&rd);
        let ar = be16(&msg, 10).unwrap() + 1;
        msg[10..12].copy_from_slice(&ar.to_be_bytes());
        (msg, mac)
    }

    fn add_txt_update(id: u16, name: &str, value: &str) -> Vec<u8> {
        let mut m = id.to_be_bytes().to_vec();
        m.extend_from_slice(&[0x28, 0, 0, 1, 0, 0, 0, 1, 0, 0]);
        m.extend_from_slice(&wire_name(ZONE));
        m.extend_from_slice(&[0, 6, 0, 1]);
        m.extend_from_slice(&wire_name(name));
        m.extend_from_slice(&[0, 16, 0, 1, 0, 0, 0, 60]);
        let rd = txt_rdata(value.as_bytes());
        m.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        m.extend_from_slice(&rd);
        m
    }

    #[tokio::test]
    async fn signed_update_is_applied_and_answer_is_signed() {
        let mock = Rfc2136Mock::start(Seed::standard()).await;
        let key = mock.control().seed().keys[0].clone();
        let unsigned = add_txt_update(7, "a.example.org.", "v1");
        let (msg, request_mac) = signed(&unsigned, &key, now(0));
        let Reply::Send(reply, Write::Full) = handle(&msg, mock.control()).await else {
            panic!("no reply");
        };
        assert_eq!(mock.control().txt("a.example.org."), ["v1"]);
        assert_eq!(reply[3] & 0x0f, NOERROR);
        // Verify the answer's MAC as a client would.
        let req = parse(&reply).unwrap();
        let tsig = parse_tsig(req.additional.last().unwrap()).unwrap();
        let mut data = (request_mac.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&request_mac);
        let mut body = reply[..tsig.start].to_vec();
        body[10..12].copy_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&body);
        data.extend_from_slice(&variables(
            &tsig.key_name,
            &tsig.algorithm,
            tsig.time,
            tsig.fudge,
            0,
            &[],
        ));
        let alg = algorithm(&key.algorithm).unwrap();
        assert!(hmac::verify(&hmac::Key::new(alg, &key.secret), &data, &tsig.mac).is_ok());
    }

    #[tokio::test]
    async fn wrong_secret_is_badsig_without_mac() {
        let mock = Rfc2136Mock::start(Seed::standard()).await;
        let mut key = mock.control().seed().keys[0].clone();
        key.secret = b"another-secret-another-secret-!!".to_vec();
        let (msg, _) = signed(&add_txt_update(9, "a.example.org.", "v1"), &key, now(0));
        let Reply::Send(reply, _) = handle(&msg, mock.control()).await else {
            panic!("no reply");
        };
        assert_eq!(reply[3] & 0x0f, NOTAUTH);
        assert!(mock.control().txt("a.example.org.").is_empty());
        let call = &mock.control().calls()[0];
        assert_eq!(call.tsig_error, BADSIG);
    }

    fn rr(name: &str, rtype: u16, class: u16, ttl: u32, rdata: &[u8]) -> Rr {
        Rr {
            name: name.to_owned(),
            rtype,
            class,
            ttl,
            rdata: rdata.to_vec(),
            start: 0,
        }
    }

    fn update_request(prereqs: Vec<Rr>, updates: Vec<Rr>) -> Request {
        Request {
            id: 1,
            opcode: 5,
            question: Vec::new(),
            qname: ZONE.to_owned(),
            qtype: TYPE_SOA,
            prereqs,
            updates,
            additional: Vec::new(),
        }
    }

    fn record(name: &str, rtype: u16, rdata: &[u8]) -> MockRecord {
        MockRecord {
            name: name.to_owned(),
            rtype,
            ttl: 300,
            rdata: rdata.to_vec(),
        }
    }

    fn soa(serial: u32) -> Vec<u8> {
        let mut rd = wire_name("ns1.example.org.");
        rd.extend_from_slice(&wire_name("admin.example.org."));
        rd.extend_from_slice(&serial.to_be_bytes());
        rd.extend_from_slice(&[0; 16]);
        rd
    }

    const A: &str = "a.example.org.";

    /// The five prerequisite forms of RFC 2136 section 2.4 and their RCODEs (section 3.2).
    #[test]
    fn prerequisites_follow_section_3_2() {
        let zones = vec![ZONE.to_owned()];
        let base = vec![
            record(A, TYPE_TXT, &txt_rdata(b"x")),
            record(A, TYPE_TXT, &txt_rdata(b"y")),
        ];
        let run = |prereqs: Vec<Rr>| {
            let mut records = base.clone();
            let add = rr(A, TYPE_A, CLASS_IN, 60, &[192, 0, 2, 1]);
            let rcode = update(&update_request(prereqs, vec![add]), &zones, &mut records);
            (rcode, records.len())
        };
        let x = txt_rdata(b"x");
        let y = txt_rdata(b"y");
        let cases: Vec<(Vec<Rr>, u8)> = vec![
            (vec![rr(A, TYPE_ANY, CLASS_ANY, 0, &[])], NOERROR),
            (
                vec![rr("b.example.org.", TYPE_ANY, CLASS_ANY, 0, &[])],
                NXDOMAIN,
            ),
            (vec![rr(A, TYPE_ANY, CLASS_NONE, 0, &[])], YXDOMAIN),
            (
                vec![rr("b.example.org.", TYPE_ANY, CLASS_NONE, 0, &[])],
                NOERROR,
            ),
            (vec![rr(A, TYPE_TXT, CLASS_ANY, 0, &[])], NOERROR),
            (vec![rr(A, TYPE_MX, CLASS_ANY, 0, &[])], NXRRSET),
            (vec![rr(A, TYPE_TXT, CLASS_NONE, 0, &[])], YXRRSET),
            (vec![rr(A, TYPE_MX, CLASS_NONE, 0, &[])], NOERROR),
            // Value dependent: the same set in any order, nothing more, nothing less.
            (
                vec![
                    rr(A, TYPE_TXT, CLASS_IN, 0, &y),
                    rr(A, TYPE_TXT, CLASS_IN, 0, &x),
                ],
                NOERROR,
            ),
            (vec![rr(A, TYPE_TXT, CLASS_IN, 0, &x)], NXRRSET),
            (
                vec![
                    rr(A, TYPE_TXT, CLASS_IN, 0, &x),
                    rr(A, TYPE_TXT, CLASS_IN, 0, &y),
                    rr(A, TYPE_TXT, CLASS_IN, 0, &txt_rdata(b"z")),
                ],
                NXRRSET,
            ),
            (vec![rr(A, TYPE_MX, CLASS_IN, 0, &[0, 10, 0])], NXRRSET),
            // Malformed prerequisites.
            (vec![rr(A, TYPE_TXT, CLASS_IN, 60, &x)], FORMERR),
            (vec![rr(A, TYPE_TXT, CLASS_ANY, 0, &x)], FORMERR),
            (vec![rr(A, TYPE_TXT, CLASS_NONE, 0, &x)], FORMERR),
            (vec![rr(A, TYPE_TXT, 3, 0, &[])], FORMERR),
            (
                vec![rr("a.example.net.", TYPE_TXT, CLASS_ANY, 0, &[])],
                NOTZONE,
            ),
            // In order: the first failing prerequisite decides.
            (
                vec![
                    rr(A, TYPE_TXT, CLASS_NONE, 0, &[]),
                    rr(A, TYPE_ANY, CLASS_NONE, 0, &[]),
                ],
                YXRRSET,
            ),
            (
                vec![
                    rr(A, TYPE_MX, CLASS_NONE, 0, &[]),
                    rr(A, TYPE_ANY, CLASS_NONE, 0, &[]),
                ],
                YXDOMAIN,
            ),
        ];
        for (prereqs, expected) in cases {
            let (rcode, len) = run(prereqs);
            assert_eq!(rcode, expected);
            // Applied only when every prerequisite holds.
            assert_eq!(len, if expected == NOERROR { 3 } else { 2 });
        }
    }

    /// Deletion of an RRset and of every RRset of a name; replacement in one message is atomic.
    #[test]
    fn updates_follow_section_3_4() {
        let zones = vec![ZONE.to_owned()];
        let mut records = vec![
            record(A, TYPE_TXT, &txt_rdata(b"x")),
            record(A, TYPE_A, &[192, 0, 2, 1]),
            record("b.example.org.", TYPE_TXT, &txt_rdata(b"b")),
        ];
        // Delete an RRset, then add its new member, in one message.
        let req = update_request(
            vec![rr(A, TYPE_TXT, CLASS_IN, 0, &txt_rdata(b"x"))],
            vec![
                rr(A, TYPE_TXT, CLASS_ANY, 0, &[]),
                rr(A, TYPE_TXT, CLASS_IN, 120, &txt_rdata(b"new")),
            ],
        );
        assert_eq!(update(&req, &zones, &mut records), NOERROR);
        let txt: Vec<_> = records
            .iter()
            .filter(|r| r.name == A && r.rtype == TYPE_TXT)
            .collect();
        assert_eq!(txt.len(), 1);
        assert_eq!((txt[0].rdata.clone(), txt[0].ttl), (txt_rdata(b"new"), 120));
        // A failing update later in the message leaves nothing applied (prescan).
        let before = records.clone();
        let req = update_request(
            Vec::new(),
            vec![
                rr(A, TYPE_TXT, CLASS_ANY, 0, &[]),
                rr(A, TYPE_TXT, CLASS_ANY, 60, &[]),
            ],
        );
        assert_eq!(update(&req, &zones, &mut records), FORMERR);
        assert_eq!(records, before);
        for bad in [
            rr(A, TYPE_ANY, CLASS_IN, 60, &[]),
            rr(A, 252, CLASS_ANY, 0, &[]),
            rr(A, TYPE_TXT, CLASS_ANY, 0, &[1]),
            rr(A, TYPE_TXT, CLASS_NONE, 60, &txt_rdata(b"x")),
            rr(A, TYPE_ANY, CLASS_NONE, 0, &[]),
            rr(A, TYPE_TXT, 3, 0, &[]),
        ] {
            assert_eq!(
                update(&update_request(Vec::new(), vec![bad]), &zones, &mut records),
                FORMERR
            );
        }
        // Delete all RRsets from a name.
        let req = update_request(Vec::new(), vec![rr(A, TYPE_ANY, CLASS_ANY, 0, &[])]);
        assert_eq!(update(&req, &zones, &mut records), NOERROR);
        assert!(records.iter().all(|r| r.name != A));
        assert_eq!(records.len(), 1);
    }

    /// The special rules for SOA and NS at the apex (sections 3.4.2.2 to 3.4.2.4) and for CNAME.
    #[test]
    fn apex_soa_ns_and_cname_rules() {
        let zones = vec![ZONE.to_owned()];
        let ns1 = wire_name("ns1.example.org.");
        let ns2 = wire_name("ns2.example.org.");
        let mut records = vec![
            record(ZONE, TYPE_SOA, &soa(10)),
            record(ZONE, TYPE_NS, &ns1),
            record(ZONE, TYPE_NS, &ns2),
            record(ZONE, TYPE_TXT, &txt_rdata(b"apex")),
        ];
        let apply = |records: &mut Vec<MockRecord>, updates: Vec<Rr>| {
            assert_eq!(
                update(&update_request(Vec::new(), updates), &zones, records),
                NOERROR
            );
        };
        // An SOA without a higher serial is ignored; a higher one replaces it.
        apply(
            &mut records,
            vec![rr(ZONE, TYPE_SOA, CLASS_IN, 60, &soa(10))],
        );
        apply(
            &mut records,
            vec![rr(ZONE, TYPE_SOA, CLASS_IN, 60, &soa(9))],
        );
        assert_eq!(soa_serial(&records[0].rdata), Some(10));
        apply(
            &mut records,
            vec![rr(ZONE, TYPE_SOA, CLASS_IN, 60, &soa(11))],
        );
        let soas: Vec<_> = records.iter().filter(|r| r.rtype == TYPE_SOA).collect();
        assert_eq!((soas.len(), soa_serial(&soas[0].rdata)), (1, Some(11)));
        // The apex SOA and NS RRsets survive their deletion and the deletion of the apex.
        apply(
            &mut records,
            vec![
                rr(ZONE, TYPE_SOA, CLASS_ANY, 0, &[]),
                rr(ZONE, TYPE_NS, CLASS_ANY, 0, &[]),
                rr(ZONE, TYPE_SOA, CLASS_NONE, 0, &soa(11)),
                rr(ZONE, TYPE_ANY, CLASS_ANY, 0, &[]),
            ],
        );
        let types: Vec<u16> = records.iter().map(|r| r.rtype).collect();
        assert_eq!(types, [TYPE_SOA, TYPE_NS, TYPE_NS]);
        // One NS RR can go; the last one stays.
        apply(
            &mut records,
            vec![
                rr(ZONE, TYPE_NS, CLASS_NONE, 0, &ns1),
                rr(ZONE, TYPE_NS, CLASS_NONE, 0, &ns2),
            ],
        );
        let ns: Vec<_> = records.iter().filter(|r| r.rtype == TYPE_NS).collect();
        assert_eq!(ns.len(), 1);
        assert_eq!(ns[0].rdata, ns2);
        // CNAME: ignored next to other data, replaces a CNAME, blocks other data.
        let c = "c.example.org.";
        records.push(record(c, TYPE_TXT, &txt_rdata(b"t")));
        apply(&mut records, vec![rr(c, TYPE_CNAME, CLASS_IN, 60, &ns1)]);
        assert!(records.iter().all(|r| r.rtype != TYPE_CNAME));
        apply(
            &mut records,
            vec![
                rr(c, TYPE_TXT, CLASS_ANY, 0, &[]),
                rr(c, TYPE_CNAME, CLASS_IN, 60, &ns1),
                rr(c, TYPE_CNAME, CLASS_IN, 60, &ns2),
                rr(c, TYPE_TXT, CLASS_IN, 60, &txt_rdata(b"t")),
            ],
        );
        let at_c: Vec<_> = records.iter().filter(|r| r.name == c).collect();
        assert_eq!(at_c.len(), 1);
        assert_eq!((at_c[0].rtype, at_c[0].rdata.clone()), (TYPE_CNAME, ns2));
    }

    /// Queries below a zone cut get a referral; RDATA names of RFC 1035 types are compressed.
    #[tokio::test]
    async fn referrals_and_compressed_rdata() {
        let mock = Rfc2136Mock::start(Seed::standard()).await;
        let control = mock.control();
        control.add_record(record(
            "child.example.org.",
            TYPE_NS,
            &wire_name("ns.child.example.org."),
        ));
        control.add_record(record(
            "www.example.org.",
            TYPE_CNAME,
            &wire_name("host.example.org."),
        ));
        let query = |name: &str| Request {
            id: 1,
            opcode: 0,
            question: {
                let mut q = wire_name(name);
                q.extend_from_slice(&[0, 1, 0, 1]);
                q
            },
            qname: name.to_owned(),
            qtype: TYPE_A,
            prereqs: Vec::new(),
            updates: Vec::new(),
            additional: Vec::new(),
        };
        let req = query("x.child.example.org.");
        let outcome = process(&req, control, false);
        assert!(!outcome.authoritative && outcome.answers.is_empty());
        assert_eq!(outcome.authority.len(), 1);
        let req = query("www.example.org.");
        let outcome = process(&req, control, false);
        let reply = answer(&req, &outcome, None, &Fault::default());
        // The answer's owner points to the question, its target's suffix too.
        let at = 12 + req.question.len();
        assert_eq!(&reply[at..at + 2], &[0xc0, 12]);
        assert_eq!(&reply[at + 10..at + 12], &[0, 7]);
        assert_eq!(&reply[at + 12..at + 19], b"\x04host\xc0\x10");
    }

    /// Names in the RDATA of an MX record are decompressed against the request, case kept
    /// (RFC 1035 section 4.1.4, RFC 3597 section 4); other types are kept as they came.
    #[test]
    fn request_rdata_is_decompressed_for_rfc_1035_types() {
        let mut m = vec![0u8; 12];
        m.extend_from_slice(b"\x07Example\x03org\x00");
        let start = m.len();
        m.extend_from_slice(&[0, 10]);
        m.extend_from_slice(b"\x04mail\xc0\x0c");
        let len = m.len() - start;
        let mut want = vec![0, 10];
        want.extend_from_slice(b"\x04mail\x07Example\x03org\x00");
        assert_eq!(request_rdata(&m, TYPE_MX, start, len).unwrap(), want);
        assert_eq!(
            request_rdata(&m, TYPE_TXT, start, len).unwrap(),
            m[start..].to_vec()
        );
        assert_eq!(
            request_rdata(&m, TYPE_MX, start, 0).unwrap(),
            Vec::<u8>::new()
        );
        // A name that ends before the RDATA does, or runs past it.
        assert!(request_rdata(&m, TYPE_MX, start, len - 1).is_none());
        m.push(0);
        assert!(request_rdata(&m, TYPE_MX, start, len + 1).is_none());
    }

    /// Over UDP an answer longer than 512 octets is cut to the header and the question with TC
    /// set, and still signed; over TCP it is whole.
    #[tokio::test]
    async fn long_udp_answer_is_truncated_and_signed() {
        let mock = Rfc2136Mock::start(Seed::standard()).await;
        let key = mock.control().seed().keys[0].clone();
        for c in *b"abc" {
            mock.control()
                .add_txt(A, &String::from_utf8(vec![c; 200]).unwrap(), 60);
        }
        let mut query = 5u16.to_be_bytes().to_vec();
        query.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        query.extend_from_slice(&wire_name(A));
        query.extend_from_slice(&[0, 16, 0, 1]);
        let (msg, _) = signed(&query, &key, now(0));
        let Reply::Send(udp, Write::Full) = handle_on(&msg, mock.control(), Transport::Udp).await
        else {
            panic!("no reply");
        };
        assert!(udp.len() <= UDP_LIMIT);
        assert_eq!(udp[2] & 0x02, 0x02, "TC");
        assert_eq!(&udp[6..10], &[0, 0, 0, 0], "no answer or authority records");
        let reply = parse(&udp).unwrap();
        let tsig = parse_tsig(reply.additional.last().unwrap()).unwrap();
        assert_eq!(tsig.mac.len(), 32);
        let Reply::Send(tcp, Write::Full) = handle(&msg, mock.control()).await else {
            panic!("no reply");
        };
        assert_eq!(tcp[2] & 0x02, 0);
        assert_eq!(&tcp[6..8], &[0, 3]);
    }

    #[test]
    fn txt_helpers_round_trip() {
        assert_eq!(txt_data(&txt_rdata(b"abc")).unwrap(), b"abc");
        assert_eq!(txt_rdata(b""), [0]);
        let long = vec![b'x'; 300];
        let rd = txt_rdata(&long);
        assert_eq!(rd[0], 255);
        assert_eq!(txt_data(&rd).unwrap(), long);
        assert!(txt_data(&[5, b'a']).is_none());
        let looped = [0xc0u8, 0];
        assert!(read_name(&looped, 0).is_none());
    }
}
