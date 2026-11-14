//! Mock of an authoritative name server that accepts DNS UPDATE (RFC 2136) signed with TSIG
//! (RFC 8945), over TCP (RFC 1035 section 4.2.2, RFC 7766).
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
//!   (`NONE ANY`), "RRset exists" (`ANY type`), "RRset does not exist" (`NONE type`); updates
//!   (2.5): add (`zone class`), delete an RRset (`ANY type`), delete all RRsets of a name
//!   (`ANY ANY`), delete one RR (`NONE type` with the RDATA). A duplicate add and the delete of an
//!   RR that does not exist are silently ignored (2.5.1, 2.5.4). RCODEs of section 2.2: NOTAUTH
//!   for a zone the server does not serve, NOTZONE for a name outside the zone section's zone,
//!   NXDOMAIN, YXDOMAIN, NXRRSET, YXRRSET for failed prerequisites, FORMERR for what cannot be
//!   read. The response copies the ID and the opcode and sets QR (3.8).
//! - RFC 8945: TSIG is the last record of the additional section (5.1); the request MAC covers
//!   the message without the TSIG record (ARCOUNT less one, the original ID) and the TSIG
//!   variables (4.3.3); the response MAC covers the request MAC with its length, the response,
//!   and the response's variables (5.3). An unknown key is NOTAUTH with error BADKEY and no MAC
//!   (5.2.1, 5.3.2), a MAC that does not verify NOTAUTH with BADSIG and no MAC (5.2.2), a time
//!   outside the fudge NOTAUTH with BADTIME, signed, with the server's time in the other data
//!   (5.2.3). Fudge 300 s (section 10).
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
//! - an update answer copies the zone section (RFC 2136 section 3.8 also allows zero counts;
//!   [`Fault::omit_question`] produces that form).
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
use tokio::net::{TcpListener, TcpStream};

/// Type code of TXT (RFC 1035 section 3.2.2).
pub const TYPE_TXT: u16 = 16;
/// Type code of A (RFC 1035 section 3.2.2).
pub const TYPE_A: u16 = 1;
/// Type code of CNAME (RFC 1035 section 3.2.2).
pub const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_TSIG: u16 = 250;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;
const CLASS_NONE: u16 = 254;
const CLASS_ANY: u16 = 255;

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
/// Order of effects: the delay, the foreign record, then either no answer ([`Fault::close`]), a
/// fixed RCODE without applying the request ([`Fault::rcode`]), or normal processing; then the
/// changes to the answer; then how it is written ([`Fault::truncate`], [`Fault::short_length`],
/// [`Fault::drop_reply`]).
#[derive(Clone, Debug, Default)]
pub struct Fault {
    op: Option<Op>,
    times: usize,
    delay: Duration,
    foreign: Option<MockRecord>,
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
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl Rfc2136Mock {
    /// Starts the server on `127.0.0.1` with an ephemeral port.
    pub async fn start(seed: Seed) -> Rfc2136Mock {
        let state = State {
            records: seed.records.clone(),
            ..State::default()
        };
        let control = Control {
            seed: Arc::new(seed),
            state: Arc::new(Mutex::new(state)),
        };
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind 127.0.0.1:0");
        let addr = listener.local_addr().expect("local address");
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let accept_control = control.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accepted = listener.accept() => {
                        if let Ok((stream, _)) = accepted {
                            tokio::spawn(serve(stream, accept_control.clone()));
                        }
                    }
                }
            }
        });
        Rfc2136Mock {
            addr,
            control,
            _shutdown: tx,
        }
    }

    /// The address the server listens on.
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
            let rdata = b.get(j + 10..j + 10 + len)?.to_vec();
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

async fn handle(b: &[u8], control: &Control) -> Reply {
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
        return Reply::Send(answer(&req, rcode, &[], None, &fault), Write::Full);
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
        let signing = Signing {
            key_name: tsig.key_name.clone(),
            algorithm: &tsig.algorithm,
            secret,
            request_mac: &tsig.mac,
            time: server_now,
            error,
            other,
        };
        answer(&req, NOTAUTH, &[], Some(signing), &Fault::default())
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
    let (rcode, answers) = match fault.rcode {
        Some(rcode) => (rcode, Vec::new()),
        None => process(&req, control, refuse_queries),
    };
    call.rcode = Some(rcode);
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
    let reply = answer(&req, rcode, &answers, signing, &fault);
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

/// Answer records as (type, TTL, RDATA).
type Answers = Vec<(u16, u32, Vec<u8>)>;

fn process(req: &Request, control: &Control, refuse_queries: bool) -> (u8, Answers) {
    let zones = &control.seed.zones;
    let mut state = lock(&control.state);
    match req.opcode {
        0 => {
            if refuse_queries || !zones.iter().any(|z| in_zone(&req.qname, z)) {
                return (REFUSED, Vec::new());
            }
            // A CNAME at the name answers a query of any type (RFC 1034 section 4.3.2, step
            // 3a). The mock does not follow the chain to the target.
            let answers: Answers = state
                .records
                .iter()
                .filter(|r| {
                    r.name == req.qname
                        && (req.qtype == r.rtype || req.qtype == TYPE_ANY || r.rtype == TYPE_CNAME)
                })
                .map(|r| (r.rtype, r.ttl, r.rdata.clone()))
                .collect();
            let exists =
                state.records.iter().any(|r| r.name == req.qname) || zones.contains(&req.qname);
            (if exists { NOERROR } else { NXDOMAIN }, answers)
        }
        5 => (update(req, zones, &mut state.records), Vec::new()),
        _ => (NOTIMP, Vec::new()),
    }
}

/// RFC 2136 section 3: zone section, prerequisites, then updates, all or nothing.
fn update(req: &Request, zones: &[String], records: &mut Vec<MockRecord>) -> u8 {
    if req.qtype != TYPE_SOA {
        return FORMERR;
    }
    let zone = &req.qname;
    if !zones.contains(zone) {
        return NOTAUTH;
    }
    for p in &req.prereqs {
        if !in_zone(&p.name, zone) {
            return NOTZONE;
        }
        let name_in_use = &p.name == zone || records.iter().any(|r| r.name == p.name);
        let rrset_exists = records
            .iter()
            .any(|r| r.name == p.name && r.rtype == p.rtype);
        match (p.class, p.rtype) {
            (CLASS_ANY, TYPE_ANY) if !name_in_use => return NXDOMAIN,
            (CLASS_NONE, TYPE_ANY) if name_in_use => return YXDOMAIN,
            (CLASS_ANY, TYPE_ANY) | (CLASS_NONE, TYPE_ANY) => {}
            (CLASS_ANY, _) if !rrset_exists => return NXRRSET,
            (CLASS_NONE, _) if rrset_exists => return YXRRSET,
            (CLASS_ANY, _) | (CLASS_NONE, _) => {}
            _ => return FORMERR,
        }
    }
    for u in &req.updates {
        if !in_zone(&u.name, zone) {
            return NOTZONE;
        }
        if !matches!(u.class, CLASS_IN | CLASS_NONE | CLASS_ANY) || u.rtype == TYPE_TSIG {
            return FORMERR;
        }
    }
    for u in &req.updates {
        match u.class {
            // RFC 2136 section 3.4.2.2: "In the case of a CNAME Update RR and a non-CNAME Zone
            // RRset or vice versa, ignore the CNAME Update RR, otherwise replace the CNAME Zone
            // RR with the CNAME Update RR." The add is ignored silently: NOERROR all the same.
            CLASS_IN
                if records.iter().any(|r| {
                    r.name == u.name && ((r.rtype == TYPE_CNAME) != (u.rtype == TYPE_CNAME))
                }) => {}
            CLASS_IN if u.rtype == TYPE_CNAME => {
                records.retain(|r| !(r.name == u.name && r.rtype == TYPE_CNAME));
                records.push(MockRecord {
                    name: u.name.clone(),
                    rtype: u.rtype,
                    ttl: u.ttl,
                    rdata: u.rdata.clone(),
                });
            }
            CLASS_IN => {
                for r in records
                    .iter_mut()
                    .filter(|r| r.name == u.name && r.rtype == u.rtype)
                {
                    r.ttl = u.ttl;
                }
                let present = records
                    .iter()
                    .any(|r| r.name == u.name && r.rtype == u.rtype && r.rdata == u.rdata);
                if !present {
                    records.push(MockRecord {
                        name: u.name.clone(),
                        rtype: u.rtype,
                        ttl: u.ttl,
                        rdata: u.rdata.clone(),
                    });
                }
            }
            CLASS_NONE => {
                records.retain(|r| !(r.name == u.name && r.rtype == u.rtype && r.rdata == u.rdata));
            }
            _ => {
                records
                    .retain(|r| !(r.name == u.name && (u.rtype == TYPE_ANY || r.rtype == u.rtype)));
            }
        }
    }
    NOERROR
}

/// Builds the answer: header, question or zone section, answers, then the TSIG record.
fn answer(
    req: &Request,
    rcode: u8,
    answers: &[(u16, u32, Vec<u8>)],
    signing: Option<Signing<'_>>,
    fault: &Fault,
) -> Vec<u8> {
    let id = if fault.wrong_id {
        req.id.wrapping_add(1)
    } else {
        req.id
    };
    let mut flags: u16 = 0x8000 | (u16::from(req.opcode) << 11) | 0x0400 | u16::from(rcode & 0x0f);
    if fault.clear_qr {
        flags &= !0x8000;
    }
    if fault.clear_aa {
        flags &= !0x0400;
    }
    if fault.set_tc {
        flags |= 0x0200;
    }
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&flags.to_be_bytes());
    let qdcount: u16 = if fault.omit_question { 0 } else { 1 };
    let extra = usize::from(fault.extra_answer.is_some());
    let ancount = u16::try_from(answers.len() + extra).unwrap_or(0);
    for n in [qdcount, ancount, 0, 0] {
        m.extend_from_slice(&n.to_be_bytes());
    }
    if !fault.omit_question {
        let mut question = req.question.clone();
        if fault.wrong_question {
            let at = question.len() - 4;
            question[at..at + 2].copy_from_slice(&TYPE_A.to_be_bytes());
        }
        m.extend_from_slice(&question);
    }
    for (rtype, ttl, rdata) in answers {
        // The owner is a compression pointer to the question name at offset 12.
        m.extend_from_slice(&[0xc0, 12]);
        m.extend_from_slice(&rtype.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        m.extend_from_slice(&ttl.to_be_bytes());
        m.extend_from_slice(&u16::try_from(rdata.len()).unwrap_or(0).to_be_bytes());
        m.extend_from_slice(rdata);
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
