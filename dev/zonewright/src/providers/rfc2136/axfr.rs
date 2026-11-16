//! Zone transfer (AXFR, RFC 5936) over TCP with TSIG (RFC 8945 section 5.3.1): the records of a
//! whole zone, for `list_rrsets`.
//!
//! - Query (RFC 5936 section 2.1): one signed QUERY with the question `zone AXFR IN`, ID chosen
//!   per attempt, every flag zero, no answer or authority records, the TSIG record as the only
//!   additional record. One new connection per attempt, closed after the transfer.
//! - Response (section 2.2): one or more messages with the ID of the query, QR set and opcode
//!   QUERY. The first message copies the question; a later one copies it or leaves it empty; an
//!   error message copies it (section 2.2.2). The authority section is empty (section 2.2.4).
//!   AA, TC and RA are not read (sections 2.2 and 2.2.1, notes b and c). Records other than the
//!   TSIG record in the additional section are ignored (section 2.1.5).
//! - Records: the first record of the first message is the SOA of the zone; the transfer ends
//!   with the same SOA, as the last record of its message (section 2.2). The client stops
//!   reading there. Intermediate messages do not hold the zone's SOA, so an SOA at the apex is
//!   the end. A closing SOA that is not the opening one (another serial) means the zone changed
//!   during the transfer or the answer was cut: `Error::Transient`. The records come in any
//!   order and grouping; duplicates are ignored by the caller (section 2.2). Every record is of
//!   class IN, the class of the question; another class is `Error::Protocol`. RDATA is taken
//!   with compressed names expanded (`wire::rdata_uncompressed`, RFC 3597 section 4).
//! - Errors (section 2.2): a message with an RCODE other than NOERROR ends the transfer, in the
//!   first message or later. REFUSED is `Error::Forbidden` (the server's policy does not let the
//!   key transfer the zone, section 5), NOTAUTH `Error::ZoneNotFound` (section 2.2.1, note e),
//!   SERVFAIL `Error::Transient`, any other `Error::Rejected` with the RCODE. An error is honored
//!   only from a message whose TSIG verifies; a TSIG error of the first message is `Error::Auth`
//!   as for every other request (`transport.rs`).
//! - TSIG (RFC 8945 section 5.3.1): [`tsig::Stream`] verifies each message; the first and the
//!   last message must be signed, at most 99 in a row may be unsigned. A message that fails is
//!   the end of the transfer: the connection is closed and nothing of it is returned.
//! - Bounds: each read of a message has `ContextOptions::request_timeout` (the first one from
//!   sending the query); a length prefix below the size of a header is refused, and every prefix
//!   is checked against [`MAX_OCTETS`] before the message is allocated; at most
//!   [`MAX_MESSAGES`] messages. A connection that ends before the closing SOA is
//!   `Error::Transient`.
//! - Repeats: a transfer is a read. A transient failure (connection, timeout, a cut stream,
//!   SERVFAIL, a changed serial) is repeated as the transport repeats a query: up to 3 attempts
//!   with the back-off of design section 5.3, each with a new ID and signature (RFC 5936 section
//!   2.3: no endless cycle of retries).
//! - Tracing: one `DEBUG` event per attempt, target `zonewright::rfc2136`, with the operation
//!   `transfer`, the RCODE of the first message when one was read, and the duration.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::time::{Instant, timeout};

use crate::error::Error;
use crate::name::DomainName;
use crate::record::{RecordData, RecordType};
use crate::redact::Detail;

use super::transport::{
    MAX_ATTEMPTS, TARGET, Transport, backoff, framed, io_error, protocol, transient, unix_now,
    verdict_error,
};
use super::tsig::{self, Key, Link, Stream};
use super::txt::rcode_error;
use super::wire::{self, CLASS_IN, HEADER_LEN, OPCODE_QUERY, Request, TYPE_AXFR, TYPE_SOA, rcode};

/// The most octets a transfer may take, length prefixes included: 64 MiB. Design section 5.4
/// bounds an HTTP listing by pages of at most 4 MiB; a transfer has no pages, so the bound is on
/// the whole. 64 MiB is a thousand messages of the largest size the framing carries (65535
/// octets, RFC 1035 section 4.2.2), several hundred thousand records of a typical zone, far more
/// than the 10 000 entries section 5.4 guarantees for every listing, and it bounds the memory a
/// listing takes.
pub(super) const MAX_OCTETS: usize = 64 * 1024 * 1024;

/// The most messages a transfer may take: 100 000. A server may send one record per message
/// (RFC 5936 section 2.2), so this covers a zone of 100 000 records even then, ten times the
/// 10 000 entries of design section 5.4, and bounds the per-message work (parsing, HMAC) a
/// server can cause with small messages.
pub(super) const MAX_MESSAGES: usize = 100_000;

/// The limits of one transfer; [`MAX_OCTETS`] and [`MAX_MESSAGES`] except in unit tests.
#[derive(Clone, Copy, Debug)]
struct Limits {
    octets: usize,
    messages: usize,
}

const LIMITS: Limits = Limits {
    octets: MAX_OCTETS,
    messages: MAX_MESSAGES,
};

/// One record of a transfer: owner in the spelling of `wire::Reader::name`, type, TTL and the
/// uncompressed RDATA. The closing SOA is not among them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Transferred {
    pub(super) name: String,
    pub(super) rtype: u16,
    pub(super) ttl: u32,
    pub(super) rdata: Vec<u8>,
}

/// Transfers `zone` from the configured server, repeating transient failures (module
/// documentation).
pub(super) async fn transfer(
    transport: &Transport,
    zone: &DomainName,
) -> Result<Vec<Transferred>, Error> {
    let request = wire::Builder::query(zone, TYPE_AXFR).finish()?;
    let mut attempt = 1;
    loop {
        let started = Instant::now();
        let mut first_rcode = None;
        let result = transfer_once(transport, zone, &request, &mut first_rcode).await;
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match first_rcode {
            Some(rcode) => {
                tracing::debug!(target: TARGET, op = "transfer", rcode, elapsed_ms, "provider request");
            }
            None => {
                tracing::debug!(target: TARGET, op = "transfer", elapsed_ms, "provider request")
            }
        }
        if !matches!(result, Err(Error::Transient { .. })) || attempt >= MAX_ATTEMPTS {
            return result;
        }
        tokio::time::sleep(backoff(attempt)).await;
        attempt += 1;
    }
}

/// One attempt: connect, send the signed query, read and verify the answer.
async fn transfer_once(
    transport: &Transport,
    zone: &DomainName,
    request: &Request,
    first_rcode: &mut Option<u8>,
) -> Result<Vec<Transferred>, Error> {
    let id = fastrand::u16(..);
    let mut message = request.with_id(id);
    let request_mac = tsig::sign(&mut message, transport.key(), unix_now()?)?;
    let mut stream = transport.open().await?;
    let query = Query {
        zone,
        request,
        id,
        key: transport.key(),
        request_mac,
        timeout: transport.request_timeout(),
    };
    read_transfer(&mut stream, &message, query, LIMITS, first_rcode).await
}

/// What the answer is checked against.
struct Query<'a> {
    zone: &'a DomainName,
    request: &'a Request,
    id: u16,
    key: &'a Key,
    request_mac: Vec<u8>,
    timeout: Duration,
}

fn forbidden() -> Error {
    Error::Forbidden {
        detail: Detail::constant(
            "the server refused the zone transfer (REFUSED): its transfer policy does not let \
             this key transfer the zone",
        ),
    }
}

/// Writes the signed query `message` and reads the transfer from `stream`.
async fn read_transfer<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    message: &[u8],
    query: Query<'_>,
    limits: Limits,
    first_rcode: &mut Option<u8>,
) -> Result<Vec<Transferred>, Error> {
    let apex = query.zone.as_str();
    let framed = framed(message)?;
    let mut chain = Stream::new(query.key, query.request_mac.clone());
    let mut octets = 0usize;
    let mut messages = 0usize;
    let mut opening: Option<Vec<u8>> = None;
    let mut out: Vec<Transferred> = Vec::new();
    let mut write = Some(framed);
    loop {
        let read = async {
            if let Some(framed) = write.take() {
                stream.write_all(&framed).await.map_err(io_error)?;
            }
            let len = usize::from(stream.read_u16().await.map_err(io_error)?);
            if len < HEADER_LEN {
                return Err(protocol(
                    "a message of the zone transfer is shorter than a DNS header",
                ));
            }
            // Checked before the message is allocated.
            octets = octets.saturating_add(len).saturating_add(2);
            if octets > limits.octets {
                return Err(protocol(
                    "the zone transfer is longer than the client's limit of 64 MiB",
                ));
            }
            messages += 1;
            if messages > limits.messages {
                return Err(protocol(
                    "the zone transfer has more messages than the client's limit of 100000",
                ));
            }
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await.map_err(io_error)?;
            Ok(buf)
        };
        let buf = match timeout(query.timeout, read).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(transient(
                    "the DNS server did not send the zone transfer in time",
                ));
            }
        };
        let response = wire::parse(&buf).map_err(|_| {
            protocol("a message of the zone transfer is not a well-formed DNS message")
        })?;
        let first = opening.is_none();
        if first {
            *first_rcode = Some(response.rcode());
        }
        if response.id != query.id || !response.is_response() || response.opcode() != OPCODE_QUERY {
            return Err(protocol(
                "a message of the zone transfer does not match the request",
            ));
        }
        let link = chain
            .next(&buf, &response, unix_now()?)
            .map_err(|verdict| {
                verdict_error(verdict, response.rcode())
                    .unwrap_or_else(|| protocol("a message of the zone transfer does not verify"))
            })?;
        // RFC 5936 section 2.2.2: the first message and an error message copy the question, a
        // later one copies it or leaves it empty.
        let question_ok = match response.questions.as_slice() {
            [] => !first && response.rcode() == rcode::NOERROR,
            [question] => *question == query.request.question,
            _ => false,
        };
        if !question_ok {
            return Err(protocol(
                "a message of the zone transfer does not repeat the question of the request",
            ));
        }
        if response.rcode() != rcode::NOERROR {
            // An error ends the transfer (section 2.2). It is honored only when its TSIG
            // verifies; an unsigned one would be authenticated by a later message that does not
            // come.
            if link != Link::Signed {
                return Err(protocol(
                    "a message of the zone transfer reports an error but is not signed",
                ));
            }
            return Err(match response.rcode() {
                rcode::REFUSED => forbidden(),
                rcode::NOTAUTH => Error::zone_not_found(query.zone.clone()),
                other => rcode_error(other),
            });
        }
        if !response.authority.is_empty() {
            return Err(protocol(
                "a message of the zone transfer has records in its authority section (RFC 5936 \
                 section 2.2.4)",
            ));
        }
        let count = response.answers.len();
        for (index, record) in response.answers.iter().enumerate() {
            if record.class != CLASS_IN {
                return Err(protocol(
                    "a record of the zone transfer is not of class IN, the class of the zone",
                ));
            }
            let rdata = wire::rdata_uncompressed(&buf, record).map_err(|_| {
                protocol("a record of the zone transfer points outside its message")
            })?;
            let apex_soa = record.rtype == TYPE_SOA && record.name == apex;
            let Some(soa) = &opening else {
                if !apex_soa {
                    return Err(protocol(
                        "the zone transfer does not begin with the SOA of the zone (RFC 5936 \
                         section 2.2)",
                    ));
                }
                opening = Some(rdata.clone());
                out.push(Transferred {
                    name: record.name.clone(),
                    rtype: record.rtype,
                    ttl: record.ttl,
                    rdata,
                });
                continue;
            };
            if !apex_soa {
                out.push(Transferred {
                    name: record.name.clone(),
                    rtype: record.rtype,
                    ttl: record.ttl,
                    rdata,
                });
                continue;
            }
            // The closing SOA.
            if index + 1 != count {
                return Err(protocol(
                    "records follow the closing SOA of the zone transfer in its message",
                ));
            }
            if !same_soa(soa, &rdata) {
                return Err(transient(
                    "the SOA that ends the zone transfer is not the one that began it: the zone \
                     changed during the transfer",
                ));
            }
            if link != Link::Signed {
                return Err(protocol(
                    "the last message of the zone transfer is not signed (RFC 8945 section 5.3.1)",
                ));
            }
            return Ok(out);
        }
        if opening.is_none() {
            return Err(protocol(
                "the zone transfer does not begin with the SOA of the zone (RFC 5936 section 2.2)",
            ));
        }
    }
}

/// Two SOA RDATA are the same record: equal in canonical form (names compared without regard to
/// case), or equal octets where one does not read as SOA.
fn same_soa(a: &[u8], b: &[u8]) -> bool {
    match (
        RecordData::from_wire(RecordType::SOA, a),
        RecordData::from_wire(RecordType::SOA, b),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    //! The reading loop against an in-memory connection, with small limits; the mock covers the
    //! rest (`tests/rfc2136.rs`).

    use secrecy::SecretSlice;
    use tokio::io::duplex;

    use super::*;
    use crate::error::ErrorKind;
    use crate::providers::rfc2136::tsig::Algorithm;

    fn key() -> Key {
        Key::new(
            DomainName::parse("zw-key").unwrap(),
            Algorithm::HmacSha256,
            SecretSlice::from(b"0123456789abcdef0123456789abcdef".to_vec()),
        )
    }

    /// Runs the reader on a connection whose server side writes `server` and closes.
    async fn run(server: Vec<u8>, limits: Limits) -> Result<Vec<Transferred>, Error> {
        let zone = DomainName::parse("example.org").unwrap();
        let request = wire::Builder::query(&zone, TYPE_AXFR).finish().unwrap();
        let k = key();
        let (mut client, mut peer) = duplex(1 << 20);
        let writer = tokio::spawn(async move {
            let mut sink = vec![0u8; 512];
            let _ = peer.read(&mut sink).await;
            peer.write_all(&server).await.unwrap();
            peer.shutdown().await.unwrap();
            // Keep the peer open until the reader is done.
            let _ = peer.read(&mut sink).await;
        });
        let query = Query {
            zone: &zone,
            request: &request,
            id: 7,
            key: &k,
            request_mac: vec![1u8; 32],
            timeout: Duration::from_secs(5),
        };
        let mut rcode = None;
        let result = read_transfer(&mut client, b"\0\0", query, limits, &mut rcode).await;
        drop(client);
        writer.await.unwrap();
        result
    }

    /// A length prefix is checked against the octet limit before anything is allocated, and the
    /// message count against its limit; the error names the limit.
    #[tokio::test]
    async fn limits_are_checked_before_reading() {
        // One prefix announcing 65535 octets, nothing after it.
        let err = run(
            vec![0xff, 0xff],
            Limits {
                octets: 1000,
                messages: 10,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Protocol, "{err:?}");
        assert!(err.to_string().contains("64 MiB"), "{err}");
        // Two header-sized messages with a limit of one.
        let mut two = Vec::new();
        for _ in 0..2 {
            two.extend_from_slice(&[0, 12]);
            two.extend_from_slice(&[0, 7, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        }
        let err = run(
            two,
            Limits {
                octets: 1000,
                messages: 0,
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("100000"), "{err}");
        // A prefix below a header, and a stream that ends inside a message.
        let err = run(vec![0, 4, 1, 2, 3, 4], LIMITS).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Protocol);
        let err = run(vec![0, 40, 0, 7, 0x80], LIMITS).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Transient);
        let err = run(Vec::new(), LIMITS).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Transient);
    }

    #[test]
    fn soa_comparison_ignores_name_case() {
        let soa = |mname: &[u8], serial: u32| {
            let mut out = mname.to_vec();
            out.extend_from_slice(b"\x05admin\x07example\x03org\x00");
            out.extend_from_slice(&serial.to_be_bytes());
            out.extend_from_slice(&[0; 16]);
            out
        };
        let lower = soa(b"\x03ns1\x07example\x03org\x00", 1);
        let upper = soa(b"\x03NS1\x07Example\x03org\x00", 1);
        assert!(same_soa(&lower, &upper));
        assert!(!same_soa(&lower, &soa(b"\x03ns1\x07example\x03org\x00", 2)));
        assert!(same_soa(b"\x01", b"\x01"));
        assert!(!same_soa(b"\x01", b"\x02"));
    }
}
