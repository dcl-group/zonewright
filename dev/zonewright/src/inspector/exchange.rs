//! The query transport (design section 8.4): one question to one server over UDP, with a TCP
//! retry on truncation and a retry without EDNS on `FORMERR`.
//!
//! `hickory-proto` is used only to encode the query and to decode the answer. Everything that
//! makes the observation exact is done here: a new socket per question, acceptance of a
//! datagram only from the queried address with the query's ID and question, the size limits,
//! and the conversion of the answer into a [`Reply`] that holds this crate's own values.
//!
//! The transport sits behind the private [`Transport`] trait, so that discovery,
//! classification, quorum and the wait loop can be unit-tested with a table-driven
//! implementation and tokio's paused clock.

use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType as WireType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use super::answer::convert_record;
use crate::record::RecordData;
use crate::redact::Detail;

/// The EDNS payload size advertised in queries (DNS flag day 2020).
pub(crate) const EDNS_PAYLOAD: u16 = 1232;

/// The largest UDP answer accepted, in octets.
pub(crate) const MAX_UDP_MESSAGE: usize = 4096;

/// One question as the transport sends it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Ask {
    /// The question name in uncompressed wire form, ASCII letters lowercased.
    pub(crate) name: Vec<u8>,
    /// The type code.
    pub(crate) rtype: u16,
    /// Recursion desired: true for a resolver, false for a name server.
    pub(crate) recursion: bool,
}

/// What a server answered, reduced to what classification needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reply {
    /// The response code, extended bits included.
    pub(crate) rcode: u16,
    /// The AA flag.
    pub(crate) authoritative: bool,
    /// The records of the answer section of class IN, in the order received.
    pub(crate) records: Vec<ReplyRecord>,
}

/// One record of the answer section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplyRecord {
    /// The owner in uncompressed wire form, ASCII letters lowercased.
    pub(crate) owner: Vec<u8>,
    /// The type code.
    pub(crate) rtype: u16,
    /// The TTL in seconds as received.
    pub(crate) ttl: u32,
    /// The value, or why the RDATA is malformed for its type. Conversion errors are kept per
    /// record so that a malformed record that classification does not look at fails nothing.
    pub(crate) data: Result<RecordData, String>,
}

/// Why no answer was obtained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    /// No acceptable answer arrived in time.
    Timeout,
    /// A socket operation failed: unreachable, refused, no route.
    Network(String),
    /// An answer arrived but cannot be used: undecodable, too large, off-topic over TCP.
    Malformed(String),
}

impl Failure {
    fn network(what: &str, err: &std::io::Error) -> Failure {
        Failure::Network(bounded(&format!("{what}: {}", err.kind())))
    }

    fn malformed(what: &str) -> Failure {
        Failure::Malformed(bounded(what))
    }
}

/// Text cut to 512 bytes without control characters.
pub(crate) fn bounded(text: &str) -> String {
    Detail::new(text).as_str().to_owned()
}

/// Sends one question to one server and returns its answer.
///
/// The caller bounds the call with the query timeout; dropping the future closes every socket
/// it opened.
pub(crate) trait Transport: Send + Sync {
    /// One question to `server`, retries on `FORMERR` and truncation included.
    fn exchange(
        &self,
        server: SocketAddr,
        ask: &Ask,
    ) -> impl Future<Output = Result<Reply, Failure>> + Send;
}

/// The transport over real UDP and TCP sockets.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NetTransport;

impl Transport for NetTransport {
    async fn exchange(&self, server: SocketAddr, ask: &Ask) -> Result<Reply, Failure> {
        let name = wire_to_name(&ask.name)?;
        let (mut query, mut id) = encode_query(&name, ask, true)?;
        let mut answer = udp(server, &query, id, ask).await?;
        if let Udp::Answer(received) = &answer
            && received.message.metadata.response_code == ResponseCode::FormErr
        {
            (query, id) = encode_query(&name, ask, false)?;
            answer = udp(server, &query, id, ask).await?;
        }
        let answer = match answer {
            Udp::Answer(received) if !received.message.metadata.truncation => received,
            Udp::Answer(_) | Udp::Truncated => tcp(server, &query, id, ask).await?,
        };
        reply_from(&answer)
    }
}

/// A decoded answer and the octets it was decoded from.
struct Received {
    message: Message,
    raw: Vec<u8>,
}

/// What one UDP exchange produced.
enum Udp {
    /// An answer to the question.
    Answer(Received),
    /// A response with the query's ID and the TC flag that could not be decoded: a server may
    /// cut a message anywhere when it truncates (RFC 2181 section 9). The question goes to TCP,
    /// where the answer is checked in full.
    Truncated,
}

/// The QR and TC flags in the third octet of a message header.
const FLAG_QR: u8 = 0x80;
const FLAG_TC: u8 = 0x02;

/// Builds the query message; returns its octets and its ID.
///
/// The ID is the one `Message::query` assigns: 16 bits from the `rand` crate's thread-local
/// generator, which is a cryptographically strong generator seeded from the operating system.
fn encode_query(name: &Name, ask: &Ask, edns: bool) -> Result<(Vec<u8>, u16), Failure> {
    let mut message = Message::query();
    message.metadata.recursion_desired = ask.recursion;
    message.add_query(Query::query(name.clone(), WireType::from(ask.rtype)));
    if edns {
        let mut opt = Edns::new();
        opt.set_max_payload(EDNS_PAYLOAD);
        message.set_edns(opt);
    }
    let id = message.metadata.id;
    let octets = message
        .to_vec()
        .map_err(|_| Failure::malformed("the query could not be encoded"))?;
    Ok((octets, id))
}

/// A `hickory` name from uncompressed wire form.
fn wire_to_name(wire: &[u8]) -> Result<Name, Failure> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut pos = 0usize;
    loop {
        let len = usize::from(
            *wire
                .get(pos)
                .ok_or_else(|| Failure::malformed("the question name is truncated"))?,
        );
        pos += 1;
        if len == 0 {
            break;
        }
        let label = wire
            .get(pos..pos + len)
            .ok_or_else(|| Failure::malformed("the question name is truncated"))?;
        labels.push(label);
        pos += len;
    }
    if labels.is_empty() {
        return Ok(Name::root());
    }
    Name::from_labels(labels).map_err(|_| Failure::malformed("the question name is invalid"))
}

/// The uncompressed wire form of a `hickory` name, ASCII letters lowercased.
pub(crate) fn name_to_wire(name: &Name) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.iter() {
        // A label from a decoded message is 1 to 63 octets; the cast cannot truncate.
        out.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
        out.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    out.push(0);
    out
}

/// The ID in the first two octets of a message, if it has them.
fn raw_id(octets: &[u8]) -> Option<u16> {
    match octets {
        [a, b, ..] => Some(u16::from_be_bytes([*a, *b])),
        _ => None,
    }
}

/// True when the message answers the query: a response to a standard query with the query's ID
/// and question (name compared case-insensitively, type, class IN). An error answer without a
/// question section is accepted too: some servers answer `FORMERR` and `REFUSED` that way, and
/// such an answer carries no data that could be mistaken for the zone's.
fn matches(message: &Message, id: u16, ask: &Ask) -> bool {
    let error = !matches!(
        message.metadata.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain
    );
    message.metadata.id == id
        && message.metadata.message_type == MessageType::Response
        && message.metadata.op_code == OpCode::Query
        && match message.queries.as_slice() {
            [query] => {
                u16::from(query.query_type) == ask.rtype
                    && query.query_class == DNSClass::IN
                    && name_to_wire(&query.name) == ask.name
            }
            [] => error,
            _ => false,
        }
}

/// One exchange over a new UDP socket bound to the wildcard address and connected to `server`.
/// Datagrams from another address, with another ID or another question are ignored; the
/// caller's timeout ends the wait.
async fn udp(server: SocketAddr, query: &[u8], id: u16, ask: &Ask) -> Result<Udp, Failure> {
    let bind: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|err| Failure::network("UDP bind failed", &err))?;
    socket
        .connect(server)
        .await
        .map_err(|err| Failure::network("UDP connect failed", &err))?;
    socket
        .send(query)
        .await
        .map_err(|err| Failure::network("UDP send failed", &err))?;
    // One octet more than accepted, so that an oversized datagram is recognized as such.
    let mut buffer = vec![0u8; MAX_UDP_MESSAGE + 1];
    loop {
        let (len, from) = socket
            .recv_from(&mut buffer)
            .await
            .map_err(|err| Failure::network("UDP receive failed", &err))?;
        if from != server {
            continue;
        }
        let octets = buffer.get(..len).unwrap_or_default();
        let ours = raw_id(octets) == Some(id);
        if len > MAX_UDP_MESSAGE {
            if ours {
                return Err(Failure::malformed(
                    "the UDP answer is larger than 4096 octets",
                ));
            }
            continue;
        }
        match Message::from_vec(octets) {
            Ok(message) if matches(&message, id, ask) => {
                return Ok(Udp::Answer(Received {
                    message,
                    raw: octets.to_vec(),
                }));
            }
            Ok(_) => continue,
            Err(_)
                if ours
                    && octets
                        .get(2)
                        .is_some_and(|f| f & (FLAG_QR | FLAG_TC) == FLAG_QR | FLAG_TC) =>
            {
                return Ok(Udp::Truncated);
            }
            Err(_) if ours => {
                return Err(Failure::malformed("the answer could not be decoded"));
            }
            Err(_) => continue,
        }
    }
}

/// One exchange over a new TCP connection (RFC 1035 section 4.2.2: two-octet length prefix).
async fn tcp(server: SocketAddr, query: &[u8], id: u16, ask: &Ask) -> Result<Received, Failure> {
    let len =
        u16::try_from(query.len()).map_err(|_| Failure::malformed("the query is too long"))?;
    let mut out = Vec::with_capacity(query.len() + 2);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(query);
    let mut stream = TcpStream::connect(server)
        .await
        .map_err(|err| Failure::network("TCP connect failed", &err))?;
    stream
        .write_all(&out)
        .await
        .map_err(|err| Failure::network("TCP send failed", &err))?;
    let mut prefix = [0u8; 2];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|err| Failure::network("TCP receive failed", &err))?;
    let mut raw = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream
        .read_exact(&mut raw)
        .await
        .map_err(|err| Failure::network("TCP receive failed", &err))?;
    let message = Message::from_vec(&raw)
        .map_err(|_| Failure::malformed("the answer could not be decoded"))?;
    if !matches(&message, id, ask) {
        return Err(Failure::malformed(
            "the TCP answer does not match the question",
        ));
    }
    // There is no larger transport to retry on: a truncated TCP answer is incomplete, and an
    // incomplete rrset must not be read as the whole one.
    if message.metadata.truncation {
        return Err(Failure::malformed("the TCP answer is truncated"));
    }
    Ok(Received { message, raw })
}

/// Converts a decoded answer into a [`Reply`].
fn reply_from(received: &Received) -> Result<Reply, Failure> {
    let rdata = answer_rdata(&received.raw)
        .ok_or_else(|| Failure::malformed("the answer section could not be read"))?;
    let answers = &received.message.answers;
    if rdata.len() != answers.len() {
        return Err(Failure::malformed("the answer section could not be read"));
    }
    let mut records = Vec::with_capacity(answers.len());
    for (record, (wire_type, raw)) in answers.iter().zip(rdata) {
        let rtype = u16::from(record.record_type());
        if rtype != wire_type {
            return Err(Failure::malformed("the answer section could not be read"));
        }
        if record.dns_class != DNSClass::IN {
            continue;
        }
        records.push(ReplyRecord {
            owner: name_to_wire(&record.name),
            rtype,
            ttl: record.ttl,
            data: convert_record(&record.data, rtype, raw),
        });
    }
    Ok(Reply {
        rcode: u16::from(received.message.metadata.response_code),
        authoritative: received.message.metadata.authoritative,
        records,
    })
}

/// The type and the raw RDATA of every record of the answer section, read from the message
/// octets. `None` when the message does not have the shape its header announces.
///
/// `hickory-proto` keeps no raw RDATA for the types it knows, and its own parsed forms are not
/// this crate's canonical forms; the raw octets go through `RecordData::from_wire` instead.
fn answer_rdata(message: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let count = |at: usize| -> Option<usize> {
        let octets = message.get(at..at + 2)?;
        Some(usize::from(u16::from_be_bytes([
            *octets.first()?,
            *octets.get(1)?,
        ])))
    };
    let questions = count(4)?;
    let answers = count(6)?;
    let mut pos = 12usize;
    for _ in 0..questions {
        pos = skip_name(message, pos)?;
        pos += 4;
    }
    let mut out = Vec::with_capacity(answers.min(64));
    for _ in 0..answers {
        pos = skip_name(message, pos)?;
        let rtype = count(pos)?;
        let rdlength = count(pos + 8)?;
        let start = pos + 10;
        let rdata = message.get(start..start + rdlength)?;
        let rtype = u16::try_from(rtype).ok()?;
        out.push((rtype, rdata));
        pos = start + rdlength;
    }
    Some(out)
}

/// The position after the name starting at `pos`; a compression pointer ends the name.
fn skip_name(message: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *message.get(pos)?;
        match len {
            0 => return Some(pos + 1),
            1..=63 => pos += 1 + usize::from(len),
            0xc0..=0xff => {
                message.get(pos + 1)?;
                return Some(pos + 2);
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_convert_both_ways_and_lowercase() {
        let name = Name::from_ascii("WWW.Example.ORG.").unwrap();
        let wire = name_to_wire(&name);
        assert_eq!(wire, b"\x03www\x07example\x03org\x00");
        let back = wire_to_name(&wire).unwrap();
        assert!(back.eq_case(&Name::from_ascii("www.example.org.").unwrap()));
        assert_eq!(name_to_wire(&Name::root()), vec![0]);
        assert!(wire_to_name(&[0]).unwrap().is_root());
        assert!(wire_to_name(b"\x03ww").is_err());
    }

    #[test]
    fn the_answer_walker_follows_the_header_and_stops_on_bad_shapes() {
        // Header: ID 1, QDCOUNT 1, ANCOUNT 1; question "a." A IN; answer with a pointer owner.
        let mut message = vec![0, 1, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        message.extend_from_slice(b"\x01a\x00\x00\x01\x00\x01");
        message.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        let rdata = answer_rdata(&message).unwrap();
        assert_eq!(rdata, vec![(1u16, &[192u8, 0, 2, 1][..])]);
        // RDLENGTH beyond the end.
        let mut short = message.clone();
        short.truncate(short.len() - 1);
        assert!(answer_rdata(&short).is_none());
        // A reserved label type.
        let mut bad = message.clone();
        bad[12] = 0x40;
        assert!(answer_rdata(&bad).is_none());
    }
}
