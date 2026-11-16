//! A DNS server (UDP and TCP) for the inspector tests and for the tests of an application.
//!
//! One [`DnsMock`] listens on `127.0.0.1` with an ephemeral port ([`DnsMock::start`]) or on an
//! address the test gives ([`DnsMock::start_on`]), the same port for UDP and TCP, and stops when
//! dropped. It plays one of two roles:
//!
//! - [`Role::Authoritative`]: answers with the AA flag for the zones it serves
//!   ([`DnsMock::serve_zone`]), refuses names outside them, answers a referral (no AA, NS in the
//!   authority section, glue in the additional section) for names below a delegation, follows a
//!   CNAME chain inside its own zone, and answers NXDOMAIN or NODATA (with the zone's SOA, when
//!   it has one) otherwise.
//! - [`Role::Recursive`]: a resolver over the same data, without zones: no AA, RA set, CNAME
//!   chains followed across all of its data.
//!
//! Requests are decoded with `hickory-proto`; answers are written by this module's own encoder,
//! so that names can be compressed (also inside MX, SRV, NS, CNAME and SOA data), RDATA is sent
//! exactly as a test gives it, and malformed or oversized messages can be produced.
//!
//! Wire facts come from RFC 1035 (section 4.1 message layout, 4.1.4 compression, 4.2.1 the
//! 512-octet UDP limit and the TC bit, 4.2.2 the TCP length prefix), RFC 6891 (EDNS OPT record,
//! the requestor's payload size; a server without EDNS answers FORMERR), RFC 2308 (negative
//! answers carry the SOA in the authority section) and RFC 6604 (the response code of a CNAME
//! chain describes its last name).
//!
//! Behavior is changed through [`Fault`]s (consumed per matching query), through
//! [`DnsMock::set_delay`] and [`DnsMock::set_silent`] for every query, and through
//! [`DnsMock::set_authoritative_answers`] for every query into one zone. Every query received is
//! in [`DnsMock::log`].
//!
//! ```text
//! let mock = DnsMock::start(Role::Authoritative).await;
//! mock.serve_zone("example.test");
//! mock.add("www.example.test", TYPE_A, 300, Data::a([192, 0, 2, 1]));
//! mock.push(Fault::new(Action::Truncate).times(1));
//! // ... query mock.addr() ...
//! assert_eq!(mock.log().len(), 2); // UDP, then TCP
//! ```
//!
//! Common setups of a test of an application:
//!
//! ```text
//! // NS of the zone and the address of the name server (glue).
//! mock.add("example.test", TYPE_NS, 300, Data::name("ns1.example.test"));
//! mock.add("ns1.example.test", TYPE_A, 300, Data::a([192, 0, 2, 53]));
//! // A delegation: queries below it get a referral with this glue.
//! mock.add("sub.example.test", TYPE_NS, 300, Data::name("ns.sub.example.test"));
//! mock.add("ns.sub.example.test", TYPE_A, 300, Data::a([192, 0, 2, 54]));
//! // A CNAME into a zone that another DnsMock serves: this server answers the CNAME only.
//! mock.add("_acme-challenge.example.test", TYPE_CNAME, 300, Data::name("x.other.test"));
//! // CAA without hand-encoded RDATA.
//! mock.add("example.test", TYPE_CAA, 300, Data::caa(0, "issue", "ca.example.net"));
//! // SERVFAIL for one name, every time.
//! mock.push(Fault::new(Action::Rcode(SERVFAIL)).name("www.example.test").always());
//! // A lame server: answers for the zone without the AA flag.
//! mock.set_authoritative_answers("example.test", false);
//! ```
//!
//! What a provider mock holds can be served by a [`DnsMock`] through a
//! [`link`](crate::link::link).

use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

/// Type code of A.
pub const TYPE_A: u16 = 1;
/// Type code of NS.
pub const TYPE_NS: u16 = 2;
/// Type code of CNAME.
pub const TYPE_CNAME: u16 = 5;
/// Type code of SOA.
pub const TYPE_SOA: u16 = 6;
/// Type code of PTR.
pub const TYPE_PTR: u16 = 12;
/// Type code of MX.
pub const TYPE_MX: u16 = 15;
/// Type code of TXT.
pub const TYPE_TXT: u16 = 16;
/// Type code of AAAA.
pub const TYPE_AAAA: u16 = 28;
/// Type code of SRV.
pub const TYPE_SRV: u16 = 33;
/// Type code of TLSA.
pub const TYPE_TLSA: u16 = 52;
/// Type code of SVCB.
pub const TYPE_SVCB: u16 = 64;
/// Type code of HTTPS.
pub const TYPE_HTTPS: u16 = 65;
/// Type code of CAA.
pub const TYPE_CAA: u16 = 257;

/// Response code NOERROR.
pub const NOERROR: u16 = 0;
/// Response code FORMERR.
pub const FORMERR: u16 = 1;
/// Response code SERVFAIL.
pub const SERVFAIL: u16 = 2;
/// Response code NXDOMAIN.
pub const NXDOMAIN: u16 = 3;
/// Response code NOTIMP.
pub const NOTIMP: u16 = 4;
/// Response code REFUSED.
pub const REFUSED: u16 = 5;

const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;
/// The payload size this server advertises in its OPT record.
const SERVER_PAYLOAD: u16 = 1232;
/// Longest CNAME chain the server follows inside one answer.
const CHAIN_MAX: usize = 16;

/// What the server is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// An authoritative server for the zones given to [`DnsMock::serve_zone`].
    Authoritative,
    /// A recursive resolver over all of its data.
    Recursive,
}

/// The RDATA of one record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Data {
    /// RDATA octets, sent exactly as given.
    Raw(Vec<u8>),
    /// A single domain name (NS, CNAME, PTR, DNAME), written with compression.
    Name(String),
    /// MX: preference and exchange, the exchange compressed.
    Mx(u16, String),
    /// SRV: priority, weight, port and target, the target compressed (RFC 2782 forbids it;
    /// servers do it anyway, and a client must cope).
    Srv(u16, u16, u16, String),
    /// SOA, both names compressed.
    Soa {
        /// Primary server.
        mname: String,
        /// Responsible mailbox.
        rname: String,
        /// Serial.
        serial: u32,
        /// Refresh interval.
        refresh: u32,
        /// Retry interval.
        retry: u32,
        /// Expire limit.
        expire: u32,
        /// Negative-caching TTL.
        minimum: u32,
    },
}

impl Data {
    /// An A record.
    pub fn a(octets: [u8; 4]) -> Data {
        Data::Raw(octets.to_vec())
    }

    /// An AAAA record.
    pub fn aaaa(address: Ipv6Addr) -> Data {
        Data::Raw(address.octets().to_vec())
    }

    /// A TXT record of these character-strings, each at most 255 octets.
    pub fn txt(strings: &[&[u8]]) -> Data {
        let mut out = Vec::new();
        for string in strings {
            out.push(u8::try_from(string.len()).unwrap_or(u8::MAX));
            out.extend_from_slice(string);
        }
        Data::Raw(out)
    }

    /// A name record (NS, CNAME, PTR).
    pub fn name(target: &str) -> Data {
        Data::Name(target.to_owned())
    }

    /// A CAA record (RFC 8659 section 4.1): flags, the tag (at most 255 octets) and the value,
    /// which is written as its octets, without quotes.
    pub fn caa(flags: u8, tag: &str, value: &str) -> Data {
        let mut out = vec![flags, u8::try_from(tag.len()).unwrap_or(u8::MAX)];
        out.extend_from_slice(tag.as_bytes());
        out.extend_from_slice(value.as_bytes());
        Data::Raw(out)
    }
}

/// One record held by the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Owner name; compared case-insensitively, a trailing dot optional.
    pub owner: String,
    /// Type code.
    pub rtype: u16,
    /// TTL in seconds.
    pub ttl: u32,
    /// RDATA.
    pub data: Data,
}

impl Record {
    /// A record.
    pub fn new(owner: &str, rtype: u16, ttl: u32, data: Data) -> Record {
        Record {
            owner: canonical(owner),
            rtype,
            ttl,
            data,
        }
    }
}

/// The transport a query arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    /// UDP.
    Udp,
    /// TCP.
    Tcp,
}

/// One query the server received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoggedQuery {
    /// Transport.
    pub proto: Proto,
    /// Message ID.
    pub id: u16,
    /// Question name, lowercase with the trailing dot; empty when the request had none.
    pub name: String,
    /// Question type.
    pub rtype: u16,
    /// The RD flag.
    pub recursion_desired: bool,
    /// The request carried an OPT record.
    pub edns: bool,
    /// The payload size of the OPT record, when there was one.
    pub edns_payload: Option<u16>,
    /// The client's address and port.
    pub source: SocketAddr,
}

/// What a fault does to a matching query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// No answer; over TCP the connection is closed.
    Drop,
    /// Answer normally after this delay.
    Delay(Duration),
    /// Answer with this response code, the question copied and no records.
    Rcode(u16),
    /// Answer normally but without the AA flag (a lame server).
    NotAuthoritative,
    /// Over UDP: the TC flag and no records, whatever the size. Over TCP: a normal answer.
    Truncate,
    /// FORMERR without a question section if the request has EDNS; a normal answer otherwise.
    FormErrOnEdns,
    /// Over UDP: first a copy of the answer with another ID, then, with `then_answer`, the
    /// answer. Over TCP: only the copy with another ID.
    WrongId {
        /// Also send the real answer after the spoofed one.
        then_answer: bool,
    },
    /// Like [`Action::WrongId`], with the query's ID but another question name.
    WrongQuestion {
        /// Also send the real answer after the spoofed one.
        then_answer: bool,
    },
    /// Over UDP: the answer from another socket (another source port), then, with
    /// `then_answer`, from the server's own socket. Over TCP: a normal answer.
    OtherSource {
        /// Also send the real answer from the right address.
        then_answer: bool,
    },
    /// A message with the query's ID that cannot be decoded.
    Malformed,
    /// Over UDP: a well-formed header with the query's ID, padded to 4500 octets.
    Oversized,
    /// These octets, with the first two replaced by the query's ID.
    Raw(Vec<u8>),
    /// Answer normally and append these records to the answer section.
    Extra(Vec<Record>),
    /// Answer with the records the data gives, but with this response code (for example
    /// NXDOMAIN together with records of the asked type).
    AnswerWithRcode(u16),
    /// Never answer and, over TCP, keep the connection open.
    Stall,
    /// The normal answer with one header or question field changed. With `then_answer`, over
    /// UDP, the unchanged answer follows.
    Altered {
        /// The change.
        change: Change,
        /// Also send the unchanged answer after the altered one (UDP only).
        then_answer: bool,
    },
}

/// A change applied to an encoded answer by [`Action::Altered`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// The QR flag cleared: the message claims to be a query.
    NotResponse,
    /// This opcode (0 to 15) instead of QUERY.
    Opcode(u8),
    /// This question type instead of the asked one.
    QuestionType(u16),
    /// This question class instead of IN.
    QuestionClass(u16),
    /// The question name in upper case (records compressed against it follow).
    UpperCaseQuestion,
    /// The TC flag set, the content unchanged.
    Truncated,
}

impl Change {
    /// Applies the change to `octets`, an answer whose question name is `name_len` octets long
    /// and written uncompressed at offset 12.
    fn apply(&self, octets: &mut [u8], name_len: usize) {
        let question = 12 + name_len;
        match self {
            Change::NotResponse => {
                if let Some(flags) = octets.get_mut(2) {
                    *flags &= !0x80;
                }
            }
            Change::Opcode(opcode) => {
                if let Some(flags) = octets.get_mut(2) {
                    *flags = (*flags & !0x78) | ((opcode & 0x0f) << 3);
                }
            }
            Change::QuestionType(rtype) => put_u16(octets, question, *rtype),
            Change::QuestionClass(class) => put_u16(octets, question + 2, *class),
            Change::UpperCaseQuestion => {
                if let Some(name) = octets.get_mut(12..question) {
                    // Length octets are at most 63, below every ASCII letter.
                    name.make_ascii_uppercase();
                }
            }
            Change::Truncated => {
                if let Some(flags) = octets.get_mut(2) {
                    *flags |= 0x02;
                }
            }
        }
    }
}

fn put_u16(octets: &mut [u8], at: usize, value: u16) {
    if let Some(slot) = octets.get_mut(at..at + 2) {
        slot.copy_from_slice(&value.to_be_bytes());
    }
}

/// A behavior for the next matching queries.
#[derive(Clone, Debug)]
pub struct Fault {
    name: Option<String>,
    rtype: Option<u16>,
    proto: Option<Proto>,
    times: usize,
    action: Action,
}

impl Fault {
    /// A fault for the next query, whatever it asks.
    pub fn new(action: Action) -> Fault {
        Fault {
            name: None,
            rtype: None,
            proto: None,
            times: 1,
            action,
        }
    }

    /// Only for this question name.
    pub fn name(mut self, name: &str) -> Fault {
        self.name = Some(canonical(name));
        self
    }

    /// Only for this question type.
    pub fn rtype(mut self, rtype: u16) -> Fault {
        self.rtype = Some(rtype);
        self
    }

    /// Only for this transport.
    pub fn proto(mut self, proto: Proto) -> Fault {
        self.proto = Some(proto);
        self
    }

    /// For the next `times` matching queries.
    pub fn times(mut self, times: usize) -> Fault {
        self.times = times;
        self
    }

    /// For every matching query from now on.
    pub fn always(mut self) -> Fault {
        self.times = usize::MAX;
        self
    }

    fn matches(&self, query: &Request, proto: Proto) -> bool {
        self.times > 0
            && self.name.as_ref().is_none_or(|name| *name == query.name)
            && self.rtype.is_none_or(|rtype| rtype == query.rtype)
            && self.proto.is_none_or(|p| p == proto)
    }
}

#[derive(Debug)]
struct State {
    role: Role,
    zones: Vec<String>,
    records: Vec<Record>,
    faults: VecDeque<Fault>,
    log: Vec<LoggedQuery>,
    delay: Option<Duration>,
    silent: bool,
    udp_limit: Option<usize>,
    /// Served zones answered without the AA flag.
    lame: Vec<String>,
}

/// The handle of one running server. Dropping it stops the server.
#[derive(Debug)]
pub struct DnsMock {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for DnsMock {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl DnsMock {
    /// Starts a server on `127.0.0.1` with an ephemeral port, UDP and TCP on the same port.
    pub async fn start(role: Role) -> DnsMock {
        DnsMock::start_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), role).await
    }

    /// Starts a server on `addr`, UDP and TCP on the same port: for example `0.0.0.0:8053`, so
    /// that a server in another container (an ACME server such as Pebble) can query it. Port 0
    /// takes an ephemeral port; [`DnsMock::addr`] reports the one bound.
    ///
    /// A bind to an address other than loopback exposes the server to every host that can reach
    /// this one. It is meant for an isolated test network.
    ///
    /// # Panics
    ///
    /// If the address cannot be bound for UDP and TCP.
    pub async fn start_on(addr: SocketAddr, role: Role) -> DnsMock {
        // With port 0 the OS may hand out a UDP port whose TCP twin is taken; try a few times.
        let mut attempt = 0;
        let (udp, tcp) = loop {
            attempt += 1;
            let udp = UdpSocket::bind(addr)
                .await
                .unwrap_or_else(|err| panic!("mock DNS: UDP bind of {addr} failed: {err}"));
            let port = udp
                .local_addr()
                .unwrap_or_else(|err| panic!("mock DNS: local address: {err}"))
                .port();
            match TcpListener::bind((addr.ip(), port)).await {
                Ok(tcp) => break (udp, tcp),
                Err(err) if attempt >= 20 || addr.port() != 0 => {
                    panic!("mock DNS: TCP bind of {}:{port} failed: {err}", addr.ip())
                }
                Err(_) => continue,
            }
        };
        let addr = udp
            .local_addr()
            .unwrap_or_else(|err| panic!("mock DNS: local address: {err}"));
        let state = Arc::new(Mutex::new(State {
            role,
            zones: Vec::new(),
            records: Vec::new(),
            faults: VecDeque::new(),
            log: Vec::new(),
            delay: None,
            silent: false,
            udp_limit: None,
            lame: Vec::new(),
        }));
        let udp = Arc::new(udp);
        let udp_task = tokio::spawn(serve_udp(udp, state.clone()));
        let tcp_task = tokio::spawn(serve_tcp(tcp, state.clone()));
        DnsMock {
            addr,
            state,
            tasks: vec![udp_task, tcp_task],
        }
    }

    /// The address the server is bound to. After a bind to a wildcard address (`0.0.0.0`,
    /// `::`) this is the wildcard address with the bound port; a query is sent to an address of
    /// the host, such as `127.0.0.1` with that port.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Shared access to the server's data; a [`link`](crate::link::link) writes through it.
    pub(crate) fn handle(&self) -> Handle {
        Handle(self.state.clone())
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Serve `zone` authoritatively ([`Role::Authoritative`] only).
    pub fn serve_zone(&self, zone: &str) {
        self.state().zones.push(canonical(zone));
    }

    /// Adds one record.
    pub fn add(&self, owner: &str, rtype: u16, ttl: u32, data: Data) {
        self.state()
            .records
            .push(Record::new(owner, rtype, ttl, data));
    }

    /// Replaces the rrset of `owner` and `rtype` with these values; an empty list removes it.
    pub fn set(&self, owner: &str, rtype: u16, ttl: u32, values: Vec<Data>) {
        self.handle().set(owner, rtype, ttl, values);
    }

    /// Answers every query into served zone `zone` with the AA flag (`true`, the default) or
    /// without it (`false`, a lame server). The answers are otherwise unchanged. A zone that is
    /// not served is unaffected.
    pub fn set_authoritative_answers(&self, zone: &str, authoritative: bool) {
        let zone = canonical(zone);
        let mut state = self.state();
        state.lame.retain(|z| *z != zone);
        if !authoritative {
            state.lame.push(zone);
        }
    }

    /// Removes one value from the rrset of `owner` and `rtype`.
    pub fn remove(&self, owner: &str, rtype: u16, data: &Data) {
        let owner = canonical(owner);
        self.state().records.retain(|record| {
            !(record.owner == owner && record.rtype == rtype && record.data == *data)
        });
    }

    /// Delays every answer by this much (`None`: no delay).
    pub fn set_delay(&self, delay: Option<Duration>) {
        self.state().delay = delay;
    }

    /// Answers nothing at all while set.
    pub fn set_silent(&self, silent: bool) {
        self.state().silent = silent;
    }

    /// Truncates UDP answers larger than this (also below the requestor's payload size).
    pub fn set_udp_limit(&self, limit: Option<usize>) {
        self.state().udp_limit = limit;
    }

    /// Queues a fault.
    pub fn push(&self, fault: Fault) {
        self.state().faults.push_back(fault);
    }

    /// Every query received so far, in order.
    pub fn log(&self) -> Vec<LoggedQuery> {
        self.state().log.clone()
    }

    /// Forgets the queries received so far.
    pub fn clear_log(&self) {
        self.state().log.clear();
    }

    /// Queries received for this name and type.
    pub fn count(&self, name: &str, rtype: u16) -> usize {
        let name = canonical(name);
        self.state()
            .log
            .iter()
            .filter(|query| query.name == name && query.rtype == rtype)
            .count()
    }
}

/// Shared access to the data of a running [`DnsMock`], for the link.
#[derive(Clone, Debug)]
pub(crate) struct Handle(Arc<Mutex<State>>);

impl Handle {
    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Serves `zone`, unless it is served already.
    pub(crate) fn ensure_zone(&self, zone: &str) {
        let zone = canonical(zone);
        let mut state = self.state();
        if !state.zones.contains(&zone) {
            state.zones.push(zone);
        }
    }

    /// Replaces the rrset of `owner` and `rtype` with these values; an empty list removes it.
    pub(crate) fn set(&self, owner: &str, rtype: u16, ttl: u32, values: Vec<Data>) {
        let owner = canonical(owner);
        let mut state = self.state();
        state
            .records
            .retain(|record| !(record.owner == owner && record.rtype == rtype));
        for data in values {
            state.records.push(Record {
                owner: owner.clone(),
                rtype,
                ttl,
                data,
            });
        }
    }

    /// The records of `owner` and `rtype`.
    #[cfg(test)]
    pub(crate) fn rrset(&self, owner: &str, rtype: u16) -> Vec<Record> {
        self.state().rrset(&canonical(owner), rtype)
    }

    /// Whether `zone` is served.
    #[cfg(test)]
    pub(crate) fn serves(&self, zone: &str) -> bool {
        self.state().zones.contains(&canonical(zone))
    }
}

/// Lowercase with exactly one trailing dot.
fn canonical(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if lower == "." || lower.is_empty() {
        return ".".to_owned();
    }
    let trimmed = lower.trim_end_matches('.');
    format!("{trimmed}.")
}

/// `name` equals `zone` or lies below it (both canonical).
fn within(name: &str, zone: &str) -> bool {
    zone == "." || name == zone || name.ends_with(&format!(".{zone}"))
}

/// What the server took from a request.
#[derive(Clone, Debug)]
struct Request {
    id: u16,
    name: String,
    /// The question name as received, for copying into the answer.
    raw_name: Vec<u8>,
    rtype: u16,
    class: u16,
    recursion_desired: bool,
    edns_payload: Option<u16>,
    has_question: bool,
}

fn parse_request(octets: &[u8]) -> Option<Request> {
    let message = Message::from_vec(octets).ok()?;
    if message.metadata.message_type != MessageType::Query {
        return None;
    }
    let (name, raw_name, rtype, class, has_question) = match message.queries.first() {
        Some(query) => {
            let mut raw = Vec::new();
            for label in query.name.iter() {
                raw.push(u8::try_from(label.len()).unwrap_or(63));
                raw.extend_from_slice(label);
            }
            raw.push(0);
            (
                canonical(&query.name.to_ascii()),
                raw,
                u16::from(query.query_type),
                u16::from(query.query_class),
                true,
            )
        }
        None => (String::new(), vec![0], 0, CLASS_IN, false),
    };
    Some(Request {
        id: message.metadata.id,
        name,
        raw_name,
        rtype,
        class,
        recursion_desired: message.metadata.recursion_desired,
        edns_payload: message.edns.as_ref().map(|edns| edns.max_payload()),
        has_question,
    })
}

/// What one request resolves to.
#[derive(Debug, Default)]
struct Resolution {
    rcode: u16,
    authoritative: bool,
    answers: Vec<Record>,
    authority: Vec<Record>,
    additional: Vec<Record>,
}

impl State {
    fn rrset(&self, owner: &str, rtype: u16) -> Vec<Record> {
        self.records
            .iter()
            .filter(|record| record.owner == owner && record.rtype == rtype)
            .cloned()
            .collect()
    }

    /// The name has records, or names below it have (an empty non-terminal exists too).
    fn exists(&self, name: &str) -> bool {
        self.records
            .iter()
            .any(|record| record.owner == name || within(&record.owner, name))
    }

    fn zone_of(&self, name: &str) -> Option<String> {
        self.zones
            .iter()
            .filter(|zone| within(name, zone))
            .max_by_key(|zone| zone.len())
            .cloned()
    }

    fn resolve(&self, name: &str, rtype: u16) -> Resolution {
        let zone = match self.role {
            Role::Authoritative => match self.zone_of(name) {
                Some(zone) => Some(zone),
                None => {
                    return Resolution {
                        rcode: REFUSED,
                        ..Resolution::default()
                    };
                }
            },
            Role::Recursive => None,
        };
        if let Some(zone) = &zone
            && let Some(referral) = self.referral(name, zone)
        {
            return referral;
        }
        let authoritative = zone.is_some();
        let mut answers = Vec::new();
        let mut current = name.to_owned();
        for _ in 0..CHAIN_MAX {
            let exact = self.rrset(&current, rtype);
            if !exact.is_empty() {
                answers.extend(exact);
                return Resolution {
                    rcode: NOERROR,
                    authoritative,
                    answers,
                    ..Resolution::default()
                };
            }
            if rtype == TYPE_CNAME {
                break;
            }
            let Some(cname) = self.rrset(&current, TYPE_CNAME).into_iter().next() else {
                break;
            };
            let Data::Name(target) = &cname.data else {
                break;
            };
            let target = canonical(target);
            answers.push(cname);
            if let Some(zone) = &zone
                && !within(&target, zone)
            {
                // An authoritative server stops at the edge of its zone.
                return Resolution {
                    rcode: NOERROR,
                    authoritative,
                    answers,
                    ..Resolution::default()
                };
            }
            current = target;
        }
        let rcode = if self.exists(&current) {
            NOERROR
        } else {
            NXDOMAIN
        };
        let authority = zone
            .as_ref()
            .map(|zone| self.rrset(zone, TYPE_SOA))
            .unwrap_or_default();
        Resolution {
            rcode,
            authoritative,
            answers,
            authority,
            additional: Vec::new(),
        }
    }

    /// A referral when `name` is at or below a delegation inside `zone`.
    fn referral(&self, name: &str, zone: &str) -> Option<Resolution> {
        let cut = self
            .records
            .iter()
            .filter(|record| {
                record.rtype == TYPE_NS
                    && record.owner != zone
                    && within(&record.owner, zone)
                    && within(name, &record.owner)
            })
            .map(|record| record.owner.clone())
            .max_by_key(String::len)?;
        let authority = self.rrset(&cut, TYPE_NS);
        let mut additional = Vec::new();
        for ns in &authority {
            if let Data::Name(target) = &ns.data {
                let target = canonical(target);
                additional.extend(self.rrset(&target, TYPE_A));
                additional.extend(self.rrset(&target, TYPE_AAAA));
            }
        }
        Some(Resolution {
            rcode: NOERROR,
            authoritative: false,
            answers: Vec::new(),
            authority,
            additional,
        })
    }

    fn take_fault(&mut self, request: &Request, proto: Proto) -> Option<Action> {
        let index = self
            .faults
            .iter()
            .position(|fault| fault.matches(request, proto))?;
        let fault = self.faults.get_mut(index)?;
        fault.times = fault.times.saturating_sub(1);
        let action = fault.action.clone();
        if fault.times == 0 {
            self.faults.remove(index);
        }
        Some(action)
    }
}

/// One message to send.
#[derive(Debug)]
struct Outgoing {
    octets: Vec<u8>,
    /// Send from a socket other than the server's (UDP only).
    other_source: bool,
}

/// Everything decided about one request.
#[derive(Debug, Default)]
struct Plan {
    delay: Option<Duration>,
    send: Vec<Outgoing>,
    /// Over TCP: close the connection without an answer.
    close: bool,
    /// Send nothing and, over TCP, keep the connection open.
    stall: bool,
}

/// Decides how to answer one request.
fn plan(state: &Arc<Mutex<State>>, octets: &[u8], proto: Proto, source: SocketAddr) -> Plan {
    let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(request) = parse_request(octets) else {
        // Undecodable request: FORMERR with the ID, no question.
        let id = match octets {
            [a, b, ..] => u16::from_be_bytes([*a, *b]),
            _ => 0,
        };
        let mut out = header(id, FORMERR, false, false, false, false, [0, 0, 0, 0]);
        out.truncate(12);
        return Plan {
            send: vec![Outgoing {
                octets: out,
                other_source: false,
            }],
            ..Plan::default()
        };
    };
    state.log.push(LoggedQuery {
        proto,
        id: request.id,
        name: request.name.clone(),
        rtype: request.rtype,
        recursion_desired: request.recursion_desired,
        edns: request.edns_payload.is_some(),
        edns_payload: request.edns_payload,
        source,
    });
    if state.silent {
        return Plan {
            close: true,
            ..Plan::default()
        };
    }
    let delay = state.delay;
    let action = state.take_fault(&request, proto);
    let recursive = state.role == Role::Recursive;
    let mut resolution = if request.has_question && request.class == CLASS_IN {
        let mut resolution = state.resolve(&request.name, request.rtype);
        if state.role == Role::Authoritative
            && state
                .zone_of(&request.name)
                .is_some_and(|zone| state.lame.contains(&zone))
        {
            resolution.authoritative = false;
        }
        resolution
    } else {
        Resolution {
            rcode: FORMERR,
            ..Resolution::default()
        }
    };
    let limit = match (proto, request.edns_payload) {
        (Proto::Tcp, _) => usize::MAX,
        (Proto::Udp, Some(payload)) => usize::from(payload.max(512)),
        (Proto::Udp, None) => 512,
    };
    let limit = state.udp_limit.map_or(limit, |configured| {
        if proto == Proto::Udp {
            limit.min(configured)
        } else {
            limit
        }
    });
    drop(state);

    let one = |octets: Vec<u8>| Plan {
        delay,
        send: vec![Outgoing {
            octets,
            other_source: false,
        }],
        ..Plan::default()
    };
    let encode_full = |resolution: &Resolution, truncate: bool| {
        encode(&request, resolution, recursive, truncate, limit)
    };
    match action {
        None => one(encode_full(&resolution, false)),
        Some(Action::Drop) => Plan {
            close: true,
            ..Plan::default()
        },
        Some(Action::Delay(extra)) => {
            let mut plan = one(encode_full(&resolution, false));
            plan.delay = Some(delay.unwrap_or_default() + extra);
            plan
        }
        Some(Action::Rcode(rcode)) => {
            let resolution = Resolution {
                rcode,
                authoritative: !recursive,
                ..Resolution::default()
            };
            one(encode_full(&resolution, false))
        }
        Some(Action::NotAuthoritative) => {
            resolution.authoritative = false;
            one(encode_full(&resolution, false))
        }
        Some(Action::Truncate) => one(encode_full(&resolution, proto == Proto::Udp)),
        Some(Action::FormErrOnEdns) => {
            if request.edns_payload.is_some() {
                let mut out = header(
                    request.id,
                    FORMERR,
                    false,
                    false,
                    request.recursion_desired,
                    recursive,
                    [0, 0, 0, 0],
                );
                out.truncate(12);
                one(out)
            } else {
                one(encode_full(&resolution, false))
            }
        }
        Some(Action::WrongId { then_answer }) => {
            let real = encode_full(&resolution, false);
            let mut spoof = real.clone();
            let wrong = request.id.wrapping_add(1).to_be_bytes();
            spoof.splice(0..2, wrong);
            spoofed(delay, proto, spoof, real, then_answer, false)
        }
        Some(Action::WrongQuestion { then_answer }) => {
            let real = encode_full(&resolution, false);
            let mut other = request.clone();
            let mut raw = b"\x05other".to_vec();
            raw.extend_from_slice(&request.raw_name);
            other.raw_name = raw;
            other.name = format!("other.{}", request.name);
            let spoof = encode(&other, &resolution, recursive, false, limit);
            spoofed(delay, proto, spoof, real, then_answer, false)
        }
        Some(Action::OtherSource { then_answer }) => {
            let real = encode_full(&resolution, false);
            if proto == Proto::Tcp {
                return one(real);
            }
            spoofed(delay, proto, real.clone(), real, then_answer, true)
        }
        Some(Action::Malformed) => {
            let mut out = header(request.id, NOERROR, true, false, false, false, [1, 1, 0, 0]);
            out.extend_from_slice(&[0x07, b'b', b'r', b'o']);
            one(out)
        }
        Some(Action::Oversized) => {
            let mut out = header(request.id, NOERROR, true, false, false, false, [0, 0, 0, 0]);
            out.resize(4500, 0);
            one(out)
        }
        Some(Action::Raw(mut octets)) => {
            let id = request.id.to_be_bytes();
            for (slot, byte) in octets.iter_mut().zip(id) {
                *slot = byte;
            }
            one(octets)
        }
        Some(Action::Extra(extra)) => {
            resolution.answers.extend(extra);
            one(encode_full(&resolution, false))
        }
        Some(Action::AnswerWithRcode(rcode)) => {
            resolution.rcode = rcode;
            one(encode_full(&resolution, false))
        }
        Some(Action::Stall) => Plan {
            stall: true,
            ..Plan::default()
        },
        Some(Action::Altered {
            change,
            then_answer,
        }) => {
            let real = encode_full(&resolution, false);
            let mut altered = real.clone();
            if request.has_question {
                change.apply(&mut altered, request.raw_name.len());
            } else {
                change.apply(&mut altered, 0);
            }
            spoofed(delay, proto, altered, real, then_answer, false)
        }
    }
}

fn spoofed(
    delay: Option<Duration>,
    proto: Proto,
    spoof: Vec<u8>,
    real: Vec<u8>,
    then_answer: bool,
    from_other: bool,
) -> Plan {
    let mut send = vec![Outgoing {
        octets: spoof,
        other_source: from_other,
    }];
    if then_answer && proto == Proto::Udp {
        send.push(Outgoing {
            octets: real,
            other_source: false,
        });
    }
    Plan {
        delay,
        send,
        ..Plan::default()
    }
}

/// The 12-octet header. `counts` are QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT.
fn header(
    id: u16,
    rcode: u16,
    authoritative: bool,
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    counts: [u16; 4],
) -> Vec<u8> {
    let mut flags: u16 = 0x8000; // QR
    if authoritative {
        flags |= 0x0400;
    }
    if truncated {
        flags |= 0x0200;
    }
    if recursion_desired {
        flags |= 0x0100;
    }
    if recursion_available {
        flags |= 0x0080;
    }
    flags |= rcode & 0x000f;
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    for count in counts {
        out.extend_from_slice(&count.to_be_bytes());
    }
    out
}

/// A message writer with name compression (RFC 1035 section 4.1.4).
struct Writer {
    out: Vec<u8>,
    /// Lowercase wire form of each suffix written, with its offset.
    names: Vec<(Vec<u8>, usize)>,
}

impl Writer {
    /// Writes a name given in text (plain labels, no escapes), compressing against earlier
    /// names.
    fn name(&mut self, text: &str) {
        let canonical = canonical(text);
        let labels: Vec<&str> = canonical
            .trim_end_matches('.')
            .split('.')
            .filter(|label| !label.is_empty())
            .collect();
        let mut wire_labels: Vec<Vec<u8>> = Vec::new();
        for label in &labels {
            wire_labels.push(label.as_bytes().to_vec());
        }
        self.labels(&wire_labels);
    }

    /// Writes a name given as raw labels, compressing against earlier names.
    fn labels(&mut self, labels: &[Vec<u8>]) {
        for start in 0..labels.len() {
            let suffix = suffix_key(&labels[start..]);
            if let Some((_, offset)) = self.names.iter().find(|(key, _)| *key == suffix) {
                let pointer = 0xc000u16 | u16::try_from(*offset).unwrap_or(0);
                self.out.extend_from_slice(&pointer.to_be_bytes());
                return;
            }
            if self.out.len() < 0x3fff {
                self.names.push((suffix, self.out.len()));
            }
            let label = &labels[start];
            self.out.push(u8::try_from(label.len()).unwrap_or(63));
            self.out.extend_from_slice(label);
        }
        self.out.push(0);
    }

    fn u16(&mut self, value: u16) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn record(&mut self, record: &Record) {
        self.name(&record.owner);
        self.u16(record.rtype);
        self.u16(CLASS_IN);
        self.u32(record.ttl);
        let length_at = self.out.len();
        self.u16(0);
        let start = self.out.len();
        match &record.data {
            Data::Raw(octets) => self.out.extend_from_slice(octets),
            Data::Name(target) => self.name(target),
            Data::Mx(preference, exchange) => {
                self.u16(*preference);
                self.name(exchange);
            }
            Data::Srv(priority, weight, port, target) => {
                self.u16(*priority);
                self.u16(*weight);
                self.u16(*port);
                self.name(target);
            }
            Data::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                self.name(mname);
                self.name(rname);
                self.u32(*serial);
                self.u32(*refresh);
                self.u32(*retry);
                self.u32(*expire);
                self.u32(*minimum);
            }
        }
        let length = u16::try_from(self.out.len() - start).unwrap_or(u16::MAX);
        self.out
            .splice(length_at..length_at + 2, length.to_be_bytes());
    }
}

fn suffix_key(labels: &[Vec<u8>]) -> Vec<u8> {
    let mut key = Vec::new();
    for label in labels {
        key.push(u8::try_from(label.len()).unwrap_or(63));
        key.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    key
}

/// Encodes an answer. Over the size `limit`, or with `truncate`, the answer is the header with
/// TC, the question and the OPT record only.
fn encode(
    request: &Request,
    resolution: &Resolution,
    recursive: bool,
    truncate: bool,
    limit: usize,
) -> Vec<u8> {
    let full = encode_sections(request, resolution, recursive, false);
    if !truncate && full.len() <= limit {
        return full;
    }
    encode_sections(request, resolution, recursive, true)
}

fn encode_sections(
    request: &Request,
    resolution: &Resolution,
    recursive: bool,
    truncated: bool,
) -> Vec<u8> {
    let empty: &[Record] = &[];
    let (answers, authority, additional) = if truncated {
        (empty, empty, empty)
    } else {
        (
            resolution.answers.as_slice(),
            resolution.authority.as_slice(),
            resolution.additional.as_slice(),
        )
    };
    let edns = request.edns_payload.is_some();
    let count = |records: &[Record]| u16::try_from(records.len()).unwrap_or(u16::MAX);
    let mut writer = Writer {
        out: header(
            request.id,
            resolution.rcode,
            resolution.authoritative,
            truncated,
            request.recursion_desired,
            recursive,
            [
                u16::from(request.has_question),
                count(answers),
                count(authority),
                count(additional) + u16::from(edns),
            ],
        ),
        names: Vec::new(),
    };
    if request.has_question {
        let labels = raw_labels(&request.raw_name);
        writer.labels(&labels);
        writer.u16(request.rtype);
        writer.u16(request.class);
    }
    for record in answers.iter().chain(authority).chain(additional) {
        writer.record(record);
    }
    if edns {
        writer.out.push(0); // root owner
        writer.u16(TYPE_OPT);
        writer.u16(SERVER_PAYLOAD);
        writer.u32(u32::from(resolution.rcode >> 4) << 24);
        writer.u16(0);
    }
    writer.out
}

fn raw_labels(wire: &[u8]) -> Vec<Vec<u8>> {
    let mut labels = Vec::new();
    let mut pos = 0usize;
    while let Some(&len) = wire.get(pos) {
        if len == 0 {
            break;
        }
        let start = pos + 1;
        let end = start + usize::from(len);
        match wire.get(start..end) {
            Some(label) => labels.push(label.to_vec()),
            None => break,
        }
        pos = end;
    }
    labels
}

async fn serve_udp(socket: Arc<UdpSocket>, state: Arc<Mutex<State>>) {
    let mut buffer = vec![0u8; 65_535];
    loop {
        let Ok((len, source)) = socket.recv_from(&mut buffer).await else {
            continue;
        };
        let octets = buffer.get(..len).unwrap_or_default().to_vec();
        let socket = socket.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let plan = plan(&state, &octets, Proto::Udp, source);
            if let Some(delay) = plan.delay {
                tokio::time::sleep(delay).await;
            }
            for outgoing in plan.send {
                if outgoing.other_source {
                    if let Ok(other) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await {
                        let _ = other.send_to(&outgoing.octets, source).await;
                    }
                } else {
                    let _ = socket.send_to(&outgoing.octets, source).await;
                }
            }
        });
    }
}

async fn serve_tcp(listener: TcpListener, state: Arc<Mutex<State>>) {
    loop {
        let Ok((stream, source)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(serve_connection(stream, source, state.clone()));
    }
}

async fn serve_connection(mut stream: TcpStream, source: SocketAddr, state: Arc<Mutex<State>>) {
    loop {
        let mut prefix = [0u8; 2];
        if stream.read_exact(&mut prefix).await.is_err() {
            return;
        }
        let mut octets = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        if stream.read_exact(&mut octets).await.is_err() {
            return;
        }
        let plan = plan(&state, &octets, Proto::Tcp, source);
        if let Some(delay) = plan.delay {
            tokio::time::sleep(delay).await;
        }
        if plan.stall {
            // Hold the connection open without answering until the client gives up.
            let mut rest = [0u8; 512];
            while matches!(stream.read(&mut rest).await, Ok(n) if n > 0) {}
            return;
        }
        if plan.close {
            return;
        }
        for outgoing in plan.send {
            let len = u16::try_from(outgoing.octets.len()).unwrap_or(u16::MAX);
            let mut framed = len.to_be_bytes().to_vec();
            framed.extend_from_slice(&outgoing.octets);
            if stream.write_all(&framed).await.is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::{Edns, Query, ResponseCode};
    use hickory_proto::rr::{Name, RData, RecordType};

    use super::*;

    fn query(name: &str, rtype: RecordType, edns: bool) -> (Vec<u8>, u16) {
        let mut message = Message::query();
        message.metadata.recursion_desired = false;
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
        if edns {
            let mut opt = Edns::new();
            opt.set_max_payload(1232);
            message.set_edns(opt);
        }
        (message.to_vec().unwrap(), message.metadata.id)
    }

    async fn udp(server: SocketAddr, octets: &[u8]) -> Message {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        socket.connect(server).await.unwrap();
        socket.send(octets).await.unwrap();
        let mut buffer = vec![0u8; 65_535];
        let len = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        Message::from_vec(&buffer[..len]).unwrap()
    }

    async fn tcp(server: SocketAddr, octets: &[u8]) -> Message {
        let mut stream = TcpStream::connect(server).await.unwrap();
        let mut framed = u16::try_from(octets.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(octets);
        stream.write_all(&framed).await.unwrap();
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await.unwrap();
        let mut buffer = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut buffer).await.unwrap();
        Message::from_vec(&buffer).unwrap()
    }

    #[tokio::test]
    async fn authoritative_answers_compressed_records_and_negative_answers() {
        let mock = DnsMock::start(Role::Authoritative).await;
        mock.serve_zone("example.test");
        mock.add(
            "example.test",
            TYPE_MX,
            300,
            Data::Mx(10, "mail.example.test".into()),
        );
        mock.add("www.example.test", TYPE_A, 60, Data::a([192, 0, 2, 1]));

        let (octets, id) = query("example.test.", RecordType::MX, true);
        let answer = udp(mock.addr(), &octets).await;
        assert_eq!(answer.metadata.id, id);
        assert!(answer.metadata.authoritative);
        assert_eq!(answer.answers.len(), 1);
        match &answer.answers[0].data {
            RData::MX(mx) => {
                assert_eq!(mx.preference, 10);
                assert_eq!(mx.exchange.to_ascii(), "mail.example.test.");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(answer.edns.is_some());

        let (octets, _) = query("nope.example.test.", RecordType::A, false);
        let answer = udp(mock.addr(), &octets).await;
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);

        let (octets, _) = query("www.example.test.", RecordType::TXT, false);
        let answer = tcp(mock.addr(), &octets).await;
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        assert!(answer.answers.is_empty());

        let (octets, _) = query("other.test.", RecordType::A, false);
        let answer = udp(mock.addr(), &octets).await;
        assert_eq!(answer.metadata.response_code, ResponseCode::Refused);

        let log = mock.log();
        assert_eq!(log.len(), 4);
        assert_eq!(log[0].edns_payload, Some(1232));
        assert_eq!(log[2].proto, Proto::Tcp);
    }

    #[tokio::test]
    async fn large_answers_are_truncated_on_udp_and_complete_on_tcp() {
        let mock = DnsMock::start(Role::Authoritative).await;
        mock.serve_zone("example.test");
        let long = vec![b'x'; 255];
        for _ in 0..3 {
            mock.add(
                "big.example.test",
                TYPE_TXT,
                300,
                Data::txt(&[&long, &long]),
            );
        }
        let (octets, _) = query("big.example.test.", RecordType::TXT, true);
        let answer = udp(mock.addr(), &octets).await;
        assert!(answer.metadata.truncation);
        assert!(answer.answers.is_empty());
        let answer = tcp(mock.addr(), &octets).await;
        assert!(!answer.metadata.truncation);
        assert_eq!(answer.answers.len(), 3);
    }

    #[tokio::test]
    async fn faults_apply_to_matching_queries_only() {
        let mock = DnsMock::start(Role::Recursive).await;
        mock.add("a.test", TYPE_A, 60, Data::a([192, 0, 2, 7]));
        mock.push(Fault::new(Action::Rcode(SERVFAIL)).rtype(TYPE_AAAA));
        let (octets, _) = query("a.test.", RecordType::A, false);
        let answer = udp(mock.addr(), &octets).await;
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        assert!(!answer.metadata.authoritative);
        assert!(answer.metadata.recursion_available);
        let (octets, _) = query("a.test.", RecordType::AAAA, false);
        let answer = udp(mock.addr(), &octets).await;
        assert_eq!(answer.metadata.response_code, ResponseCode::ServFail);
        let answer = udp(mock.addr(), &octets).await;
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
    }

    #[tokio::test]
    async fn servfail_for_one_name() {
        let mock = DnsMock::start(Role::Authoritative).await;
        mock.serve_zone("example.test");
        mock.add("a.example.test", TYPE_A, 60, Data::a([192, 0, 2, 7]));
        mock.add("b.example.test", TYPE_A, 60, Data::a([192, 0, 2, 8]));
        mock.push(
            Fault::new(Action::Rcode(SERVFAIL))
                .name("a.example.test")
                .always(),
        );
        let (octets, _) = query("a.example.test.", RecordType::A, false);
        for _ in 0..2 {
            let answer = udp(mock.addr(), &octets).await;
            assert_eq!(answer.metadata.response_code, ResponseCode::ServFail);
        }
        let (octets, _) = query("b.example.test.", RecordType::A, false);
        let answer = udp(mock.addr(), &octets).await;
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
    }

    #[tokio::test]
    async fn a_wildcard_bind_answers_on_loopback() {
        let mock = DnsMock::start_on(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            Role::Authoritative,
        )
        .await;
        assert!(mock.addr().ip().is_unspecified());
        assert_ne!(mock.addr().port(), 0);
        mock.serve_zone("example.test");
        mock.add("a.example.test", TYPE_A, 60, Data::a([192, 0, 2, 7]));
        let server = SocketAddr::from((Ipv4Addr::LOCALHOST, mock.addr().port()));
        let (octets, _) = query("a.example.test.", RecordType::A, false);
        assert_eq!(udp(server, &octets).await.answers.len(), 1);
        assert_eq!(tcp(server, &octets).await.answers.len(), 1);
    }

    #[tokio::test]
    async fn caa_is_encoded_from_its_fields() {
        let mock = DnsMock::start(Role::Authoritative).await;
        mock.serve_zone("example.test");
        mock.add(
            "example.test",
            TYPE_CAA,
            60,
            Data::caa(128, "issue", "ca.example.net; account=1"),
        );
        let (octets, _) = query("example.test.", RecordType::CAA, false);
        let answer = udp(mock.addr(), &octets).await;
        match &answer.answers[0].data {
            RData::CAA(caa) => {
                assert!(caa.issuer_critical);
                assert_eq!(caa.tag, "issue");
                assert_eq!(caa.value, b"ca.example.net; account=1");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_zone_can_be_answered_without_aa() {
        let mock = DnsMock::start(Role::Authoritative).await;
        mock.serve_zone("example.test");
        mock.serve_zone("other.test");
        mock.add("a.example.test", TYPE_A, 60, Data::a([192, 0, 2, 7]));
        mock.add("a.other.test", TYPE_A, 60, Data::a([192, 0, 2, 8]));
        mock.set_authoritative_answers("example.test.", false);
        let (octets, _) = query("a.example.test.", RecordType::A, false);
        let answer = udp(mock.addr(), &octets).await;
        assert!(!answer.metadata.authoritative);
        assert_eq!(answer.answers.len(), 1);
        let (other, _) = query("a.other.test.", RecordType::A, false);
        assert!(udp(mock.addr(), &other).await.metadata.authoritative);
        mock.set_authoritative_answers("example.test", true);
        assert!(udp(mock.addr(), &octets).await.metadata.authoritative);
    }

    #[tokio::test]
    async fn ns_glue_and_delegations() {
        let mock = DnsMock::start(Role::Authoritative).await;
        mock.serve_zone("example.test");
        mock.add("example.test", TYPE_NS, 300, Data::name("ns1.example.test"));
        mock.add("ns1.example.test", TYPE_A, 300, Data::a([192, 0, 2, 53]));
        mock.add(
            "sub.example.test",
            TYPE_NS,
            300,
            Data::name("ns.sub.example.test"),
        );
        mock.add("ns.sub.example.test", TYPE_A, 300, Data::a([192, 0, 2, 54]));

        let (octets, _) = query("example.test.", RecordType::NS, false);
        let answer = udp(mock.addr(), &octets).await;
        assert!(answer.metadata.authoritative);
        match &answer.answers[0].data {
            RData::NS(ns) => assert_eq!(ns.0.to_ascii(), "ns1.example.test."),
            other => panic!("unexpected {other:?}"),
        }
        let (octets, _) = query("ns1.example.test.", RecordType::A, false);
        assert_eq!(udp(mock.addr(), &octets).await.answers.len(), 1);

        let (octets, _) = query("x.sub.example.test.", RecordType::TXT, false);
        let answer = udp(mock.addr(), &octets).await;
        assert!(!answer.metadata.authoritative);
        assert!(answer.answers.is_empty());
        assert_eq!(answer.authorities.len(), 1);
        match &answer.additionals[0].data {
            RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(192, 0, 2, 54)),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_cname_into_a_zone_of_another_server() {
        let first = DnsMock::start(Role::Authoritative).await;
        first.serve_zone("example.test");
        first.add(
            "_acme-challenge.example.test",
            TYPE_CNAME,
            300,
            Data::name("x.other.test"),
        );
        let second = DnsMock::start(Role::Authoritative).await;
        second.serve_zone("other.test");
        second.add("x.other.test", TYPE_TXT, 60, Data::txt(&[b"token"]));

        let (octets, _) = query("_acme-challenge.example.test.", RecordType::TXT, false);
        let answer = udp(first.addr(), &octets).await;
        assert!(answer.metadata.authoritative);
        assert_eq!(answer.answers.len(), 1);
        match &answer.answers[0].data {
            RData::CNAME(target) => assert_eq!(target.0.to_ascii(), "x.other.test."),
            other => panic!("unexpected {other:?}"),
        }
        let (octets, _) = query("x.other.test.", RecordType::TXT, false);
        let answer = udp(second.addr(), &octets).await;
        assert!(answer.metadata.authoritative);
        match &answer.answers[0].data {
            RData::TXT(txt) => assert_eq!(txt.txt_data[0].as_ref(), b"token"),
            other => panic!("unexpected {other:?}"),
        }
    }
}
