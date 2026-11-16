//! Zone transfer (AXFR, RFC 5936) over TCP with TSIG (RFC 8945 section 5.3.1): the records of a
//! whole zone, for `list_rrsets`.
//!
//! - Query (RFC 5936 section 2.1): one signed QUERY with the question `zone AXFR IN`, ID chosen
//!   per attempt, every flag zero, no answer or authority records, the TSIG record as the only
//!   additional record. One new connection per attempt, closed after the transfer.
//! - Response (section 2.2): one or more messages with the ID of the query, QR set and opcode
//!   QUERY. The first message copies the question; a later one copies it or leaves it empty; an
//!   error message copies it (section 2.2.2), and a signed error message without the question is
//!   `Error::Protocol`, not the error it reports. The authority section is empty (section
//!   2.2.4). AA and RA are not read (section 2.2.1, notes b and c), and neither is TC: RFC 5936
//!   section 2 says an AXFR client does not consider it. Records other than the TSIG record in
//!   the additional section are ignored (section 2.1.5).
//! - Records: the first record of the first message is the SOA of the zone; the transfer ends
//!   with the same SOA, as the last record of its message (section 2.2). The client stops
//!   reading there. Intermediate messages do not hold the zone's SOA, so an SOA at the apex is
//!   the end. The message that holds it must be signed, which is checked before anything else
//!   about it; a closing SOA that is not the opening one (another serial) in a signed message
//!   means the zone changed during the transfer: `Error::Transient`. The records come in any
//!   order and grouping; duplicates are ignored by the caller (section 2.2). Every record is of
//!   class IN, the class of the question; another class is `Error::Protocol`. RDATA is taken
//!   with compressed names expanded (`wire::rdata_uncompressed`, RFC 3597 section 4).
//! - Unsigned messages: up to 99 in a row may come without TSIG (RFC 8945 section 5.3.1). Their
//!   header, question, RCODE, authority section and record classes are checked when they
//!   arrive, but their records are taken only after the next signed message has verified the
//!   run; until then the client holds the raw messages (at most 99 of at most 65535 octets, kept
//!   twice: once for the digest and once to be read). A transfer that fails holds nothing.
//! - Errors (section 2.2): a message with an RCODE other than NOERROR ends the transfer, in the
//!   first message or later. An error is honored only from a message whose TSIG verifies.
//!   REFUSED is `Error::Forbidden` (the server's policy does not let the key transfer the zone,
//!   section 5), NOTAUTH `Error::ZoneNotFound` (section 2.2.1, note e), SERVFAIL
//!   `Error::Transient`, any other `Error::Rejected` with the RCODE. A server that answers a
//!   denied transfer without a TSIG record (Knot DNS answers NOTAUTH and leaves the key out,
//!   `process_query_acl_check` in `src/knot/nameserver/process_query.c`,
//!   <https://gitlab.nic.cz/knot/knot-dns/-/blob/master/src/knot/nameserver/process_query.c>,
//!   read on 2026-11-16) gives `Error::Protocol`: an unsigned error is not believed. A TSIG error
//!   of the first message is `Error::Auth` as for every other request (`transport.rs`).
//! - TSIG (RFC 8945 section 5.3.1): [`tsig::Stream`] verifies each message; the first and the
//!   last message must be signed, at most 99 in a row may be unsigned. A message that fails is
//!   the end of the transfer: the connection is closed and nothing of it is returned. Such a
//!   failure is `Error::Protocol` and is not repeated, nor is a Time Signed that goes backwards.
//!   The section says a client should treat a failed verification like any other interrupted
//!   transfer; this client does not repeat it, because a forged or malformed answer is not a
//!   passing condition, and a repeat would give whoever forged it two more attempts.
//! - Bounds, per attempt:
//!   - time: each read of a message has `ContextOptions::request_timeout` (the first one from
//!     sending the query), and the attempt as a whole [`DEADLINE_FACTOR`] times that;
//!   - octets on the wire: a length prefix below the size of a header is refused, and every
//!     prefix is checked against [`MAX_OCTETS`] before the message is allocated;
//!   - messages: at most [`MAX_MESSAGES`];
//!   - records held: their decoded size, counted as [`decoded_size`] says, at most
//!     [`MAX_DECODED`]. The listing built from them afterwards takes memory of the same order.
//!
//!   Reaching a limit of octets, messages or records is `Error::Protocol` naming the limit; the
//!   deadline and a read timeout are `Error::Transient`. A connection that ends before the
//!   closing SOA is `Error::Transient`.
//! - Repeats: a transfer is a read. A transient failure (connection, timeout, a cut stream,
//!   SERVFAIL, a changed serial) is repeated as the transport repeats a query: up to 3 attempts
//!   with the back-off of design section 5.3, each with a new ID and signature (RFC 5936 section
//!   2.3: no endless cycle of retries).
//! - Tracing: one `DEBUG` event per attempt, target `zonewright::rfc2136`, with the operation
//!   `transfer`, the RCODE of the first message when its TSIG verified, and the duration.

use std::mem::size_of;
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
use super::wire::{
    self, CLASS_IN, HEADER_LEN, OPCODE_QUERY, Request, Response, TYPE_AXFR, TYPE_SOA, rcode,
};

/// The most octets a transfer may take on the wire, length prefixes included: 64 MiB. Design
/// section 5.4 bounds an HTTP listing by pages of at most 4 MiB; a transfer has no pages, so the
/// bound is on the whole. 64 MiB is a thousand messages of the largest size the framing carries
/// (65535 octets, RFC 1035 section 4.2.2), several hundred thousand records of a typical zone,
/// far more than the 10 000 entries section 5.4 guarantees for every listing. It bounds the
/// octets read, not the memory the records take once decoded: that is [`MAX_DECODED`].
pub(super) const MAX_OCTETS: usize = 64 * 1024 * 1024;

/// The most messages a transfer may take: 100 000. A server may send one record per message
/// (RFC 5936 section 2.2), so this covers a zone of 100 000 records even then, ten times the
/// 10 000 entries of design section 5.4, and bounds the per-message work (parsing, HMAC) a
/// server can cause with small messages.
pub(super) const MAX_MESSAGES: usize = 100_000;

/// The most the records of one transfer may take once decoded, counted by [`decoded_size`]:
/// 256 MiB, four times [`MAX_OCTETS`]. A record decodes to more than its wire form: the owner
/// name is expanded from a compression pointer into text, names inside RDATA are expanded, and
/// each record has a fixed part. A typical record (a compressed owner of a few octets on the
/// wire, a name of 20 to 40 characters held) takes about three times its wire size, so a zone
/// that fits [`MAX_OCTETS`] fits this too; a transfer shaped to expand (long names behind
/// two-octet pointers) ends here instead of taking memory.
pub(super) const MAX_DECODED: usize = 256 * 1024 * 1024;

/// One attempt may take at most this many times `ContextOptions::request_timeout`, from sending
/// the query to the closing SOA. Design section 3.7 sets no deadline over an operation because
/// each of its parts is bounded and there are few of them; a transfer has up to [`MAX_MESSAGES`]
/// parts, each allowed `request_timeout`, so without its own bound a server (or anyone on the
/// path, for the unsigned messages it may insert) could keep one call open for days. With the
/// default `request_timeout` of 30 s the factor gives 10 minutes, the time [`MAX_OCTETS`] takes
/// at about 1 Mbit/s.
pub(super) const DEADLINE_FACTOR: u32 = 20;

/// The limits of one transfer; the constants above except in unit tests.
#[derive(Clone, Copy, Debug)]
struct Limits {
    octets: usize,
    messages: usize,
    decoded: usize,
}

const LIMITS: Limits = Limits {
    octets: MAX_OCTETS,
    messages: MAX_MESSAGES,
    decoded: MAX_DECODED,
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

/// What a record held counts against [`MAX_DECODED`]: the size of [`Transferred`] plus the
/// octets of its owner name text and of its RDATA as held.
fn decoded_size(record: &Transferred) -> usize {
    size_of::<Transferred>()
        .saturating_add(record.name.len())
        .saturating_add(record.rdata.len())
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
    let per_message = transport.request_timeout();
    let query = Query {
        zone,
        request,
        id,
        key: transport.key(),
        request_mac,
        timeout: per_message,
        whole: per_message.saturating_mul(DEADLINE_FACTOR),
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
    /// For each read of a message.
    timeout: Duration,
    /// For the attempt as a whole, from sending the query.
    whole: Duration,
}

fn forbidden() -> Error {
    Error::Forbidden {
        detail: Detail::constant(
            "the server refused the zone transfer (REFUSED): its transfer policy does not let \
             this key transfer the zone",
        ),
    }
}

fn not_signed_at_end() -> Error {
    protocol("the last message of the zone transfer is not signed (RFC 8945 section 5.3.1)")
}

/// Writes the signed query `message` and reads the transfer from `stream`, within the deadline
/// of the attempt.
async fn read_transfer<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    message: &[u8],
    query: Query<'_>,
    limits: Limits,
    first_rcode: &mut Option<u8>,
) -> Result<Vec<Transferred>, Error> {
    let whole = query.whole;
    match timeout(
        whole,
        read_messages(stream, message, query, limits, first_rcode),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(transient(
            "the zone transfer did not complete within its time limit of 20 times the request \
             timeout",
        )),
    }
}

/// The records taken so far, and what is known about the transfer.
struct Collected<'a> {
    apex: &'a str,
    /// The RDATA of the opening SOA, once the first message is taken.
    opening: Option<Vec<u8>>,
    out: Vec<Transferred>,
    decoded: usize,
    limit: usize,
}

impl Collected<'_> {
    /// Takes the records of a verified message (signed, or unsigned and covered by a signed
    /// message after it). `Ok(true)` when it holds the closing SOA.
    fn take(&mut self, buf: &[u8], response: &Response, signed: bool) -> Result<bool, Error> {
        let count = response.answers.len();
        for (index, record) in response.answers.iter().enumerate() {
            let apex_soa = record.rtype == TYPE_SOA && record.name == self.apex;
            if self.opening.is_some() && apex_soa {
                // The closing SOA: only a signed message may end the transfer, and that is
                // checked before anything the message says is used.
                if !signed {
                    return Err(not_signed_at_end());
                }
                if index + 1 != count {
                    return Err(protocol(
                        "records follow the closing SOA of the zone transfer in its message",
                    ));
                }
                let rdata = wire::rdata_uncompressed(buf, record).map_err(|_| {
                    protocol("a record of the zone transfer points outside its message")
                })?;
                if self
                    .opening
                    .as_deref()
                    .is_some_and(|soa| !same_soa(soa, &rdata))
                {
                    return Err(transient(
                        "the SOA that ends the zone transfer is not the one that began it: the \
                         zone changed during the transfer",
                    ));
                }
                return Ok(true);
            }
            if self.opening.is_none() && !apex_soa {
                return Err(protocol(
                    "the zone transfer does not begin with the SOA of the zone (RFC 5936 section \
                     2.2)",
                ));
            }
            let rdata = wire::rdata_uncompressed(buf, record).map_err(|_| {
                protocol("a record of the zone transfer points outside its message")
            })?;
            if self.opening.is_none() {
                self.opening = Some(rdata.clone());
            }
            let kept = Transferred {
                name: record.name.clone(),
                rtype: record.rtype,
                ttl: record.ttl,
                rdata,
            };
            self.decoded = self.decoded.saturating_add(decoded_size(&kept));
            if self.decoded > self.limit {
                return Err(protocol(
                    "the records of the zone transfer take more than the client's limit of \
                     256 MiB once decoded",
                ));
            }
            self.out.push(kept);
        }
        if self.opening.is_none() {
            return Err(protocol(
                "the zone transfer does not begin with the SOA of the zone (RFC 5936 section 2.2)",
            ));
        }
        Ok(false)
    }
}

/// The loop of [`read_transfer`].
async fn read_messages<S: AsyncRead + AsyncWrite + Unpin>(
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
    let mut collected = Collected {
        apex,
        opening: None,
        out: Vec::new(),
        decoded: 0,
        limit: limits.decoded,
    };
    // Unsigned messages since the last signed one, as received, not yet read for records.
    let mut pending: Vec<Vec<u8>> = Vec::new();
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
                    "the DNS server did not send the next message of the zone transfer in time",
                ));
            }
        };
        let response = wire::parse(&buf).map_err(|_| {
            protocol("a message of the zone transfer is not a well-formed DNS message")
        })?;
        let first = collected.opening.is_none();
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
        if first {
            // Verified: the first message is always signed.
            *first_rcode = Some(response.rcode());
        }
        // RFC 5936 section 2.2.2: the first message and an error message copy the question, a
        // later one copies it or leaves it empty. A signed error without the question is
        // refused as malformed rather than taken for the error it reports.
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
        if response
            .answers
            .iter()
            .any(|record| record.class != CLASS_IN)
        {
            return Err(protocol(
                "a record of the zone transfer is not of class IN, the class of the zone",
            ));
        }
        if link == Link::Unsigned {
            // Not read for records until a signed message covers it; an unsigned message cannot
            // end the transfer.
            let closes = response
                .answers
                .iter()
                .any(|record| record.rtype == TYPE_SOA && record.name == apex);
            if closes {
                return Err(not_signed_at_end());
            }
            pending.push(buf);
            continue;
        }
        for earlier in pending.drain(..) {
            let parsed = wire::parse(&earlier).map_err(|_| {
                protocol("a message of the zone transfer is not a well-formed DNS message")
            })?;
            if collected.take(&earlier, &parsed, false)? {
                return Err(not_signed_at_end());
            }
        }
        if collected.take(&buf, &response, true)? {
            return Ok(collected.out);
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
    //! The reading loop against an in-memory connection, with answers signed here as a server
    //! signs them and with small limits; the mock covers the rest (`tests/rfc2136.rs`).

    use secrecy::SecretSlice;
    use tokio::io::duplex;

    use super::*;
    use crate::error::ErrorKind;
    use crate::providers::rfc2136::tsig::{Algorithm, sign_response};

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
    /// The request MAC the harness's client sends.
    const REQUEST_MAC: [u8; 32] = [1; 32];
    /// The query ID of the harness.
    const ID: u16 = 7;
    /// `example.org.` in wire form.
    const ZONE: &[u8] = b"\x07example\x03org\x00";
    /// QR and AA.
    const FLAGS: u16 = 0x8400;

    fn key_named(name: &str) -> Key {
        Key::new(
            DomainName::parse(name).unwrap(),
            Algorithm::HmacSha256,
            SecretSlice::from(SECRET.to_vec()),
        )
    }

    fn key() -> Key {
        key_named("zw-key")
    }

    const UNLIMITED: Limits = LIMITS;

    /// One resource record, TTL 300.
    fn rr(owner: &[u8], rtype: u16, rdata: &[u8]) -> Vec<u8> {
        rr_class(owner, rtype, CLASS_IN, rdata)
    }

    fn rr_class(owner: &[u8], rtype: u16, class: u16, rdata: &[u8]) -> Vec<u8> {
        let mut out = owner.to_vec();
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&class.to_be_bytes());
        out.extend_from_slice(&300u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }

    fn soa_rdata(serial: u32) -> Vec<u8> {
        let mut rd = b"\x03ns1\x07example\x03org\x00\x05admin\x07example\x03org\x00".to_vec();
        rd.extend_from_slice(&serial.to_be_bytes());
        rd.extend_from_slice(&[0; 16]);
        rd
    }

    fn soa(serial: u32) -> Vec<u8> {
        rr(ZONE, TYPE_SOA, &soa_rdata(serial))
    }

    fn a(last: u8) -> Vec<u8> {
        rr(b"\x01a\x07example\x03org\x00", 1, &[192, 0, 2, last])
    }

    /// A response message without TSIG: `id`, `flags`, the question when `qtype` is given, the
    /// answer and authority records.
    fn message(
        id: u16,
        flags: u16,
        qtype: Option<u16>,
        answers: &[Vec<u8>],
        authority: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut m = id.to_be_bytes().to_vec();
        m.extend_from_slice(&flags.to_be_bytes());
        m.extend_from_slice(&u16::from(qtype.is_some()).to_be_bytes());
        m.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        m.extend_from_slice(&(authority.len() as u16).to_be_bytes());
        m.extend_from_slice(&[0, 0]);
        if let Some(qtype) = qtype {
            m.extend_from_slice(ZONE);
            m.extend_from_slice(&qtype.to_be_bytes());
            m.extend_from_slice(&CLASS_IN.to_be_bytes());
        }
        for record in answers.iter().chain(authority) {
            m.extend_from_slice(record);
        }
        m
    }

    /// The first message of an answer: the question and `answers`.
    fn first(answers: &[Vec<u8>]) -> Vec<u8> {
        message(ID, FLAGS, Some(TYPE_AXFR), answers, &[])
    }

    /// A later message: no question.
    fn later(answers: &[Vec<u8>]) -> Vec<u8> {
        message(ID, FLAGS, None, answers, &[])
    }

    /// Signs the messages of one answer in order, as RFC 8945 section 5.3.1 describes.
    struct Signer {
        prior: Vec<u8>,
        pending: Vec<u8>,
        first: bool,
    }

    impl Signer {
        fn new() -> Signer {
            Signer {
                prior: REQUEST_MAC.to_vec(),
                pending: Vec::new(),
                first: true,
            }
        }

        fn signed(&mut self, mut m: Vec<u8>) -> Vec<u8> {
            self.signed_with(&key(), &mut m);
            m
        }

        fn signed_with(&mut self, key: &Key, m: &mut Vec<u8>) {
            let time = unix_now().unwrap();
            self.prior = sign_response(m, key, &self.prior, &self.pending, time, self.first);
            self.pending.clear();
            self.first = false;
        }

        fn unsigned(&mut self, m: Vec<u8>) -> Vec<u8> {
            self.pending.extend_from_slice(&m);
            m
        }
    }

    /// The messages, each behind its length prefix.
    fn framed_all(messages: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for m in messages {
            out.extend_from_slice(&(m.len() as u16).to_be_bytes());
            out.extend_from_slice(m);
        }
        out
    }

    /// Runs the reader on a connection whose server side writes `server` and closes.
    async fn run(server: Vec<u8>, limits: Limits) -> Result<Vec<Transferred>, Error> {
        let chunks = vec![(Duration::ZERO, server)];
        run_paced(
            chunks,
            true,
            limits,
            Duration::from_secs(5),
            Duration::from_secs(100),
        )
        .await
    }

    /// Runs the reader on a connection whose server side writes each chunk after its delay, then
    /// closes when `close` is set or stays silent otherwise. `per` and `whole` are the timeouts.
    async fn run_paced(
        chunks: Vec<(Duration, Vec<u8>)>,
        close: bool,
        limits: Limits,
        per: Duration,
        whole: Duration,
    ) -> Result<Vec<Transferred>, Error> {
        let zone = DomainName::parse("example.org").unwrap();
        let request = wire::Builder::query(&zone, TYPE_AXFR).finish().unwrap();
        let k = key();
        let (mut client, mut peer) = duplex(1 << 22);
        let writer = tokio::spawn(async move {
            let mut sink = vec![0u8; 512];
            let _ = peer.read(&mut sink).await;
            for (delay, chunk) in chunks {
                tokio::time::sleep(delay).await;
                if peer.write_all(&chunk).await.is_err() {
                    return;
                }
            }
            if close {
                let _ = peer.shutdown().await;
            }
            // Keep the peer open until the reader is done.
            let _ = peer.read(&mut sink).await;
        });
        let query = Query {
            zone: &zone,
            request: &request,
            id: ID,
            key: &k,
            request_mac: REQUEST_MAC.to_vec(),
            timeout: per,
            whole,
        };
        let mut rcode = None;
        let result = read_transfer(&mut client, b"\0\0", query, limits, &mut rcode).await;
        drop(client);
        writer.await.unwrap();
        result
    }

    fn protocol_with(result: Result<Vec<Transferred>, Error>, needle: &str) {
        let err = result.expect_err(needle);
        assert_eq!(err.kind(), ErrorKind::Protocol, "{needle}: {err:?}");
        assert!(err.to_string().contains(needle), "{needle}: {err}");
    }

    /// The helpers produce a transfer the client accepts: a signed first message, an unsigned
    /// one, a signed last one; the records come in order, the closing SOA is left out.
    #[tokio::test]
    async fn a_transfer_with_an_unsigned_message_is_read() {
        let mut s = Signer::new();
        let messages = [
            s.signed(first(&[soa(1), a(1)])),
            s.unsigned(later(&[a(2)])),
            s.signed(later(&[a(3), soa(1)])),
        ];
        let records = run(framed_all(&messages), UNLIMITED).await.unwrap();
        let rtypes: Vec<(u16, Vec<u8>)> = records
            .iter()
            .map(|r| (r.rtype, r.rdata[r.rdata.len().saturating_sub(1)..].to_vec()))
            .collect();
        assert_eq!(rtypes[1..], [(1, vec![1]), (1, vec![2]), (1, vec![3])]);
        assert_eq!(records[0].rtype, TYPE_SOA);
        assert_eq!(records.len(), 4);
    }

    /// The records of unsigned messages are read only once a signed message verified them: a
    /// run of unsigned messages that holds more than the decoded limit, followed by a message
    /// with a forged MAC, fails on the MAC, not on the limit, so nothing of the run was decoded.
    /// With a valid signature after the same run the records are read and the limit, named in
    /// the error, is reached.
    #[tokio::test]
    async fn unsigned_records_are_read_only_after_verification_and_count_against_the_limit() {
        let many: Vec<Vec<u8>> = (0..50).map(a).collect();
        let limits = Limits {
            decoded: 10 * (size_of::<Transferred>() + 40),
            ..UNLIMITED
        };
        let build = |forge: bool| {
            let mut s = Signer::new();
            let mut messages = vec![s.signed(first(&[soa(1)]))];
            for _ in 0..3 {
                messages.push(s.unsigned(later(&many)));
            }
            let mut last = s.signed(later(&[soa(1)]));
            if forge {
                // A bit of the MAC, which ends 6 octets before the message does.
                let at = last.len() - 7;
                last[at] ^= 1;
            }
            messages.push(last);
            framed_all(&messages)
        };
        protocol_with(run(build(true), limits).await, "does not verify");
        protocol_with(run(build(false), limits).await, "256 MiB");
        assert_eq!(run(build(false), UNLIMITED).await.unwrap().len(), 151);
    }

    /// An unsigned message that holds the closing SOA ends the transfer as `Protocol`, whatever
    /// its serial says; it does not pass for a zone that changed.
    #[tokio::test]
    async fn an_unsigned_closing_soa_is_protocol() {
        for serial in [1, 2] {
            let mut s = Signer::new();
            let messages = [
                s.signed(first(&[soa(1), a(1)])),
                s.unsigned(later(&[soa(serial)])),
            ];
            protocol_with(run(framed_all(&messages), UNLIMITED).await, "not signed");
        }
        // Signed, with another serial: the zone changed.
        let mut s = Signer::new();
        let messages = [s.signed(first(&[soa(1)])), s.signed(later(&[soa(2)]))];
        let err = run(framed_all(&messages), UNLIMITED).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Transient, "{err:?}");
    }

    /// RFC 5936 section 2.2: the transfer begins with the zone's SOA, and the closing SOA is the
    /// last record of its message; section 2.2.4: the authority section is empty.
    #[tokio::test]
    async fn the_shape_of_the_transfer_is_checked() {
        let one = |m: Vec<u8>| {
            let mut s = Signer::new();
            framed_all(&[s.signed(m)])
        };
        let begin = "does not begin with the SOA";
        protocol_with(run(one(first(&[a(1), soa(1)])), UNLIMITED).await, begin);
        protocol_with(run(one(first(&[])), UNLIMITED).await, begin);
        let other_soa = rr(b"\x03sub\x07example\x03org\x00", TYPE_SOA, &soa_rdata(1));
        protocol_with(run(one(first(&[other_soa])), UNLIMITED).await, begin);
        protocol_with(
            run(one(first(&[soa(1), a(1), soa(1), a(2)])), UNLIMITED).await,
            "records follow the closing SOA",
        );
        let ns = rr(ZONE, 2, b"\x03ns1\x07example\x03org\x00");
        protocol_with(
            run(
                one(message(ID, FLAGS, Some(TYPE_AXFR), &[soa(1)], &[ns])),
                UNLIMITED,
            )
            .await,
            "authority section",
        );
        protocol_with(
            run(
                one(first(&[
                    soa(1),
                    rr_class(b"\x01a\x07example\x03org\x00", 1, 3, &[1, 2, 3, 4]),
                ])),
                UNLIMITED,
            )
            .await,
            "class IN",
        );
    }

    /// RFC 5936 section 2.2.2: the first message and an error message copy the question; a
    /// later message copies it or leaves it empty, and never names another one. A signed error
    /// without the question is refused as malformed, not taken for the error it reports.
    #[tokio::test]
    async fn the_question_rules_are_checked() {
        let question = "does not repeat the question";
        let mut s = Signer::new();
        let m = [s.signed(message(ID, FLAGS, None, &[soa(1)], &[]))];
        protocol_with(run(framed_all(&m), UNLIMITED).await, question);
        let mut s = Signer::new();
        let m = [
            s.signed(first(&[soa(1)])),
            s.signed(message(ID, FLAGS, Some(1), &[soa(1)], &[])),
        ];
        protocol_with(run(framed_all(&m), UNLIMITED).await, question);
        // A later message that copies the question is accepted.
        let mut s = Signer::new();
        let m = [s.signed(first(&[soa(1)])), s.signed(first(&[a(1), soa(1)]))];
        assert_eq!(run(framed_all(&m), UNLIMITED).await.unwrap().len(), 2);
        // A signed REFUSED: with the question it is the refusal, without it is malformed.
        let refused = FLAGS | u16::from(rcode::REFUSED);
        let mut s = Signer::new();
        let m = [s.signed(message(ID, refused, Some(TYPE_AXFR), &[], &[]))];
        let err = run(framed_all(&m), UNLIMITED).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Forbidden, "{err:?}");
        let mut s = Signer::new();
        let m = [
            s.signed(first(&[soa(1)])),
            s.signed(message(ID, refused, None, &[], &[])),
        ];
        protocol_with(run(framed_all(&m), UNLIMITED).await, question);
    }

    /// A later message with another ID, without QR or with another opcode does not belong to
    /// the transfer; an unsigned message that reports an error is not believed; a later
    /// message signed with another key does not verify.
    #[tokio::test]
    async fn later_messages_must_belong_to_the_transfer() {
        for (id, flags) in [
            (ID + 1, FLAGS),
            (ID, FLAGS & !0x8000),
            (ID, FLAGS | (4 << 11)),
        ] {
            let mut s = Signer::new();
            let m = [
                s.signed(first(&[soa(1)])),
                s.signed(message(id, flags, None, &[soa(1)], &[])),
            ];
            protocol_with(
                run(framed_all(&m), UNLIMITED).await,
                "does not match the request",
            );
        }
        let mut s = Signer::new();
        let servfail = FLAGS | u16::from(rcode::SERVFAIL);
        let m = [
            s.signed(first(&[soa(1)])),
            s.unsigned(message(ID, servfail, Some(TYPE_AXFR), &[], &[])),
        ];
        protocol_with(
            run(framed_all(&m), UNLIMITED).await,
            "reports an error but is not signed",
        );
        let mut s = Signer::new();
        let mut last = later(&[soa(1)]);
        let opening = s.signed(first(&[soa(1)]));
        s.signed_with(&key_named("zw-other-key"), &mut last);
        protocol_with(
            run(framed_all(&[opening, last]), UNLIMITED).await,
            "another key",
        );
    }

    /// Two unsigned messages sent under one length prefix are refused: the digest covers their
    /// concatenation, so only the strict parse keeps their boundaries.
    #[tokio::test]
    async fn two_messages_under_one_prefix_are_refused() {
        let mut s = Signer::new();
        let opening = s.signed(first(&[soa(1)]));
        let merged = [s.unsigned(later(&[a(1)])), s.unsigned(later(&[a(2)]))].concat();
        let closing = s.signed(later(&[soa(1)]));
        protocol_with(
            run(framed_all(&[opening, merged, closing]), UNLIMITED).await,
            "not a well-formed DNS message",
        );
    }

    /// The read of a message after the first has its own timeout, and the attempt as a whole
    /// its deadline, which a server that sends a small message just inside each timeout reaches.
    #[tokio::test(start_paused = true)]
    async fn reads_and_the_whole_attempt_are_bounded_in_time() {
        let per = Duration::from_secs(5);
        let whole = Duration::from_secs(20);
        let mut s = Signer::new();
        let opening = framed_all(&[s.signed(first(&[soa(1)]))]);
        let err = run_paced(
            vec![(Duration::ZERO, opening.clone())],
            false,
            UNLIMITED,
            per,
            whole,
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Transient, "{err:?}");
        assert!(err.to_string().contains("next message"), "{err}");
        let mut chunks = vec![(Duration::ZERO, opening)];
        for _ in 0..30 {
            let empty = framed_all(&[s.unsigned(later(&[]))]);
            chunks.push((Duration::from_secs(3), empty));
        }
        let started = Instant::now();
        let err = run_paced(chunks, false, UNLIMITED, per, whole)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Transient, "{err:?}");
        assert!(err.to_string().contains("time limit"), "{err}");
        assert!(started.elapsed() >= whole && started.elapsed() < whole + per);
    }

    /// A length prefix is checked against the octet limit before anything is allocated, and the
    /// message count against its limit: with a limit of one message the first passes and the
    /// second fails. The error names the limit.
    #[tokio::test]
    async fn limits_are_checked_before_reading() {
        // One prefix announcing 65535 octets, nothing after it.
        let err = run(
            vec![0xff, 0xff],
            Limits {
                octets: 1000,
                ..UNLIMITED
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Protocol, "{err:?}");
        assert!(err.to_string().contains("64 MiB"), "{err}");
        let mut s = Signer::new();
        let m = [s.signed(first(&[soa(1)])), s.signed(later(&[soa(1)]))];
        let one = Limits {
            messages: 1,
            ..UNLIMITED
        };
        protocol_with(run(framed_all(&m), one).await, "100000");
        let two = Limits {
            messages: 2,
            ..UNLIMITED
        };
        assert_eq!(run(framed_all(&m), two).await.unwrap().len(), 1);
        // A prefix below a header, and a stream that ends inside a message.
        let err = run(vec![0, 4, 1, 2, 3, 4], UNLIMITED).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Protocol);
        let err = run(vec![0, 40, 0, 7, 0x80], UNLIMITED).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Transient);
        let err = run(Vec::new(), UNLIMITED).await.unwrap_err();
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
