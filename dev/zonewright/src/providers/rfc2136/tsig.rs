//! TSIG (RFC 8945): signing a request and verifying the signature of its answer.
//!
//! - The request MAC covers the message without the TSIG record and the TSIG variables (section
//!   4.3.3: key name and algorithm name in canonical wire form, class ANY, TTL 0, time signed,
//!   fudge, error, other length and data). The TSIG record is the last and only TSIG record of
//!   the additional section (section 5.1).
//! - The response MAC covers the request MAC with its length, the response without the TSIG
//!   record (ARCOUNT less one, the message ID replaced by the original ID), and the response's
//!   TSIG variables (sections 4.3.2 and 5.3). It is compared in constant time.
//! - The time of a verified response must lie within its fudge of the local clock (section
//!   5.2.3); the MAC is checked before the time (section 10.1). A verified answer that reports a
//!   TSIG error is exempt from the time check.
//! - Truncated MACs (section 5.2.2.1) are neither sent nor accepted.
//! - A multi-message answer (a zone transfer, section 5.3.1) is verified message by message by
//!   [`Stream`]: the first message as above; every later message that carries a TSIG over the
//!   MAC of the last signed message, the unsigned messages since it and this message, followed
//!   by its timers (Time Signed and Fudge) instead of all TSIG variables. The same checks apply
//!   to each signed message, in the same order. The section names the "Prior MAC" as the first
//!   component without repeating its layout; it is digested as the request MAC is (section
//!   4.3.1: MAC size as a 16-bit integer, then the MAC octets). RFC 8945 publishes no test vector
//!   for this digest. Three published implementations digest the prior MAC the same way, with
//!   its length, read in their source on 2026-11-16 (default branches):
//!   - BIND 9, `lib/dns/tsig.c`
//!     (<https://gitlab.isc.org/isc-projects/bind9/-/blob/main/lib/dns/tsig.c>): `dns_tsig_sign`
//!     puts `querytsig.siglen` as 16 bits and then the signature into the digest and, for a TCP
//!     continuation, only Time Signed and Fudge of the TSIG fields; `tsig_verify_tcp` digests the
//!     length of the previous signature and then its octets.
//!   - Knot DNS, `src/libknot/tsig-op.c`
//!     (<https://gitlab.nic.cz/knot/knot-dns/-/blob/master/src/libknot/tsig-op.c>):
//!     `knot_tsig_sign_next` writes the previous digest length as 16 bits, the previous digest,
//!     the message, then the timers.
//!   - PowerDNS, `pdns/dnssecinfra.cc`
//!     (<https://github.com/PowerDNS/pdns/blob/master/pdns/dnssecinfra.cc>): `makeTSIGPayload`
//!     prepends the 16-bit length and the previous MAC, and with `timersonly` writes only time
//!     and fudge.
//!
//! Algorithms: `hmac-sha256`, `hmac-sha384` and `hmac-sha512` (section 6, table 3: `hmac-sha256`
//! is mandatory to implement, the other two optional; each MAC is the full hash output, 32, 48
//! and 64 octets). Fudge 300 s, the value
//! section 10 recommends, as lego sends it (`providers/dns/rfc2136/rfc2136.go`, `SetTsig(…,
//! 300, …)`).
//!
//! Neither the key nor a MAC appears in an error, a `Debug` output or a `tracing` event.

use std::fmt;

use secrecy::{ExposeSecret as _, SecretSlice};

use crate::crypto::{
    hmac_sha256, hmac_sha256_verify, hmac_sha384, hmac_sha384_verify, hmac_sha512,
    hmac_sha512_verify,
};
use crate::error::Error;
use crate::name::DomainName;
use crate::redact::Detail;

use super::wire::{self, ARCOUNT_AT, CLASS_ANY, Reader, Response, TYPE_TSIG};

/// The allowed clock difference, in seconds (RFC 8945 section 10).
pub(super) const FUDGE: u16 = 300;

/// TSIG error codes (RFC 8945 section 3; the IANA "DNS RCODEs" registry).
pub(super) const BADSIG: u16 = 16;
/// The server does not know the key.
pub(super) const BADKEY: u16 = 17;
/// The time of the request is outside the fudge.
pub(super) const BADTIME: u16 = 18;
/// The MAC was truncated too far.
pub(super) const BADTRUNC: u16 = 22;

/// The largest time the 48-bit field holds.
const MAX_TIME: u64 = (1 << 48) - 1;

/// A TSIG algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Algorithm {
    /// `hmac-sha256`.
    HmacSha256,
    /// `hmac-sha384`.
    HmacSha384,
    /// `hmac-sha512`.
    HmacSha512,
}

impl Algorithm {
    /// Parses a setting: the algorithm name, any case, with or without a trailing dot.
    pub(super) fn parse(text: &str) -> Option<Algorithm> {
        let name = text.trim();
        let name = name.strip_suffix('.').unwrap_or(name);
        if name.eq_ignore_ascii_case("hmac-sha256") {
            Some(Algorithm::HmacSha256)
        } else if name.eq_ignore_ascii_case("hmac-sha384") {
            Some(Algorithm::HmacSha384)
        } else if name.eq_ignore_ascii_case("hmac-sha512") {
            Some(Algorithm::HmacSha512)
        } else {
            None
        }
    }

    /// The name as a setting spells it.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Algorithm::HmacSha256 => "hmac-sha256",
            Algorithm::HmacSha384 => "hmac-sha384",
            Algorithm::HmacSha512 => "hmac-sha512",
        }
    }

    /// The algorithm name in the spelling of [`Reader::name`].
    fn text_name(self) -> &'static str {
        match self {
            Algorithm::HmacSha256 => "hmac-sha256.",
            Algorithm::HmacSha384 => "hmac-sha384.",
            Algorithm::HmacSha512 => "hmac-sha512.",
        }
    }

    /// The algorithm name in canonical wire form (RFC 8945 section 6, table 3).
    fn wire_name(self) -> &'static [u8] {
        match self {
            Algorithm::HmacSha256 => b"\x0bhmac-sha256\x00",
            Algorithm::HmacSha384 => b"\x0bhmac-sha384\x00",
            Algorithm::HmacSha512 => b"\x0bhmac-sha512\x00",
        }
    }

    /// The length of an untruncated MAC.
    fn mac_len(self) -> usize {
        match self {
            Algorithm::HmacSha256 => 32,
            Algorithm::HmacSha384 => 48,
            Algorithm::HmacSha512 => 64,
        }
    }

    fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Algorithm::HmacSha256 => hmac_sha256(key, data).to_vec(),
            Algorithm::HmacSha384 => hmac_sha384(key, data).to_vec(),
            Algorithm::HmacSha512 => hmac_sha512(key, data).to_vec(),
        }
    }

    /// Constant time in the contents.
    fn verify(self, key: &[u8], data: &[u8], tag: &[u8]) -> bool {
        match self {
            Algorithm::HmacSha256 => hmac_sha256_verify(key, data, tag),
            Algorithm::HmacSha384 => hmac_sha384_verify(key, data, tag),
            Algorithm::HmacSha512 => hmac_sha512_verify(key, data, tag),
        }
    }
}

/// A TSIG key: name, algorithm and the shared secret.
pub(super) struct Key {
    name: DomainName,
    algorithm: Algorithm,
    secret: SecretSlice<u8>,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm.as_str())
            .finish_non_exhaustive()
    }
}

impl Key {
    pub(super) fn new(name: DomainName, algorithm: Algorithm, secret: SecretSlice<u8>) -> Key {
        Key {
            name,
            algorithm,
            secret,
        }
    }
}

fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

/// The TSIG variables (RFC 8945 section 4.3.3).
fn variables(key: &Key, time: u64, fudge: u16, error: u16, other: &[u8]) -> Option<Vec<u8>> {
    let mut v = Vec::with_capacity(300 + other.len());
    wire::put_name(&mut v, &key.name);
    v.extend_from_slice(&CLASS_ANY.to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(key.algorithm.wire_name());
    v.extend_from_slice(time.to_be_bytes().get(2..)?);
    v.extend_from_slice(&fudge.to_be_bytes());
    v.extend_from_slice(&error.to_be_bytes());
    v.extend_from_slice(&u16::try_from(other.len()).ok()?.to_be_bytes());
    v.extend_from_slice(other);
    Some(v)
}

/// Signs `msg` (a message without TSIG, ID set): appends the TSIG record and increments ARCOUNT.
/// Returns the request MAC, which the response MAC covers (RFC 8945 section 5.3). `now` is the
/// Unix time in seconds.
pub(super) fn sign(msg: &mut Vec<u8>, key: &Key, now: u64) -> Result<Vec<u8>, Error> {
    if now > MAX_TIME {
        return Err(protocol("the system time does not fit the TSIG time field"));
    }
    let malformed = || protocol("the request could not be signed");
    let id: [u8; 2] = msg
        .get(0..2)
        .and_then(|id| id.try_into().ok())
        .ok_or_else(malformed)?;
    let arcount = wire::be16(msg, ARCOUNT_AT)
        .ok_or_else(malformed)?
        .checked_add(1)
        .ok_or_else(malformed)?;
    let mut data = msg.clone();
    data.extend_from_slice(&variables(key, now, FUDGE, 0, &[]).ok_or_else(malformed)?);
    let mac = key.algorithm.mac(key.secret.expose_secret(), &data);

    let mut rdata = Vec::with_capacity(32 + mac.len());
    rdata.extend_from_slice(key.algorithm.wire_name());
    rdata.extend_from_slice(now.to_be_bytes().get(2..).ok_or_else(malformed)?);
    rdata.extend_from_slice(&FUDGE.to_be_bytes());
    rdata.extend_from_slice(
        &u16::try_from(mac.len())
            .map_err(|_| malformed())?
            .to_be_bytes(),
    );
    rdata.extend_from_slice(&mac);
    // Original ID, error 0 (RFC 8945 section 4.2: "In requests, this MUST be zero"), no other
    // data.
    rdata.extend_from_slice(&id);
    rdata.extend_from_slice(&0u16.to_be_bytes());
    rdata.extend_from_slice(&0u16.to_be_bytes());

    wire::put_name(msg, &key.name);
    msg.extend_from_slice(&TYPE_TSIG.to_be_bytes());
    msg.extend_from_slice(&CLASS_ANY.to_be_bytes());
    msg.extend_from_slice(&0u32.to_be_bytes());
    msg.extend_from_slice(
        &u16::try_from(rdata.len())
            .map_err(|_| malformed())?
            .to_be_bytes(),
    );
    msg.extend_from_slice(&rdata);
    if msg.len() > wire::MAX_MESSAGE {
        return Err(Error::InvalidInput {
            code: None,
            detail: Detail::constant("the signed DNS message would exceed 65535 octets"),
        });
    }
    msg.get_mut(ARCOUNT_AT..ARCOUNT_AT + 2)
        .ok_or_else(malformed)?
        .copy_from_slice(&arcount.to_be_bytes());
    Ok(mac)
}

/// The result of verifying a response's TSIG.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// The MAC verifies and the time is within the fudge; no TSIG error.
    Ok,
    /// The server reports a TSIG error: BADKEY or BADSIG with an empty MAC (RFC 8945 sections
    /// 5.2.1, 5.2.2 and 5.3.2: these answers are unsigned and cannot be verified), or any TSIG
    /// error in an answer whose MAC verifies against the request MAC (BADTIME, section 5.2.3).
    /// The time check is not applied to it.
    ServerError(u16),
    /// The response has no TSIG record.
    Unsigned,
    /// The TSIG record is malformed, of another key or algorithm, truncated, does not verify,
    /// or is outside the time window. The text is a constant.
    Invalid(&'static str),
}

/// Verifies the TSIG of the response `buf`, parsed as `response`, to a request whose MAC was
/// `request_mac`. `now` is the Unix time in seconds.
pub(super) fn verify(
    buf: &[u8],
    response: &Response,
    request_mac: &[u8],
    key: &Key,
    now: u64,
) -> Verdict {
    check(buf, response, key, now, Chain::First { request_mac }).verdict
}

/// What a response MAC covers before the message itself.
#[derive(Clone, Copy)]
enum Chain<'a> {
    /// A single answer, or the first message of a multi-message answer: the request MAC with
    /// its length (RFC 8945 section 4.3.1), then the message and all TSIG variables (sections
    /// 4.3.3 and 5.3).
    First { request_mac: &'a [u8] },
    /// A later message of a multi-message answer (section 5.3.1): the MAC of the last signed
    /// message ("Prior MAC"), digested like the request MAC, with its length; the unsigned
    /// messages since it, as received; then this message and the TSIG timers only (Time Signed,
    /// Fudge).
    Next {
        prior_mac: &'a [u8],
        unsigned: &'a [u8],
    },
}

/// The result of [`check`]: the verdict, and for `Verdict::Ok` the MAC and Time Signed of the
/// message.
struct Checked {
    verdict: Verdict,
    mac: Vec<u8>,
    time: u64,
}

impl Checked {
    fn failed(verdict: Verdict) -> Checked {
        Checked {
            verdict,
            mac: Vec::new(),
            time: 0,
        }
    }
}

/// Verifies the TSIG of one response message, in the order of the module documentation.
fn check(buf: &[u8], response: &Response, key: &Key, now: u64, chain: Chain<'_>) -> Checked {
    let fail = Checked::failed;
    let first = matches!(chain, Chain::First { .. });
    let tsig_records = response
        .additional
        .iter()
        .filter(|r| r.rtype == TYPE_TSIG)
        .count();
    let Some(record) = response.additional.last().filter(|r| r.rtype == TYPE_TSIG) else {
        if tsig_records > 0 {
            return fail(Verdict::Invalid(
                "the TSIG record of the response is not its last record",
            ));
        }
        return fail(Verdict::Unsigned);
    };
    if tsig_records != 1 {
        return fail(Verdict::Invalid(
            "the response has more than one TSIG record",
        ));
    }
    let mut r = Reader::new(buf, record.rdata.start);
    let parsed = (|| {
        let algorithm = r.name()?;
        let time = r.u48()?;
        let fudge = r.u16()?;
        let mac_len = usize::from(r.u16()?);
        let mac = r.bytes(mac_len)?;
        let original_id = r.u16()?;
        let error = r.u16()?;
        let other_len = usize::from(r.u16()?);
        let other = r.bytes(other_len)?;
        Ok::<_, wire::ParseError>((algorithm, time, fudge, mac, original_id, error, other))
    })();
    let malformed = || {
        fail(Verdict::Invalid(
            "the TSIG record of the response is malformed",
        ))
    };
    let Ok((algorithm, time, fudge, mac, original_id, error, other)) = parsed else {
        return malformed();
    };
    if r.pos() != record.rdata.end || record.class != CLASS_ANY || record.ttl != 0 {
        return malformed();
    }
    if record.name != key.name.as_str() || algorithm != key.algorithm.text_name() {
        return fail(Verdict::Invalid(
            "the response is signed with another key or algorithm",
        ));
    }
    // RFC 8945 sections 5.2.1, 5.2.2 and 5.3.2: a BADKEY or BADSIG answer is unsigned (MAC
    // size 0), so it cannot be verified; it is the only answer honored without a MAC. The
    // server checks the key and the MAC of the request, so only the first message of an answer
    // can be such an error.
    if first && (error == BADKEY || error == BADSIG) && mac.is_empty() {
        return fail(Verdict::ServerError(error));
    }
    // Every other answer, including one with another TSIG error (BADTIME must be signed, section
    // 5.2.3), must carry a full MAC that verifies (section 5.4).
    if mac.len() != key.algorithm.mac_len() {
        return fail(Verdict::Invalid(if error != 0 {
            "the answer reports a TSIG error that must be signed, but its MAC is missing or \
             truncated"
        } else {
            "the MAC of the response is truncated or missing"
        }));
    }
    let Some(body) = buf.get(..record.start) else {
        return malformed();
    };
    let mut body = body.to_vec();
    let arcount = wire::be16(&body, ARCOUNT_AT).and_then(|n| n.checked_sub(1));
    let (Some(arcount), Some(id_slot)) = (arcount, body.get_mut(0..2)) else {
        return malformed();
    };
    id_slot.copy_from_slice(&original_id.to_be_bytes());
    if let Some(slot) = body.get_mut(ARCOUNT_AT..ARCOUNT_AT + 2) {
        slot.copy_from_slice(&arcount.to_be_bytes());
    }
    let (before, before_body): (&[u8], &[u8]) = match chain {
        Chain::First { request_mac } => (request_mac, &[]),
        Chain::Next {
            prior_mac,
            unsigned,
        } => (prior_mac, unsigned),
    };
    let Ok(before_len) = u16::try_from(before.len()) else {
        return fail(Verdict::Invalid("the request MAC is too long"));
    };
    let after = if first {
        variables(key, time, fudge, error, other)
    } else {
        timers(time, fudge)
    };
    let Some(after) = after else {
        return malformed();
    };
    let mut data =
        Vec::with_capacity(2 + before.len() + before_body.len() + body.len() + after.len());
    data.extend_from_slice(&before_len.to_be_bytes());
    data.extend_from_slice(before);
    data.extend_from_slice(before_body);
    data.extend_from_slice(&body);
    data.extend_from_slice(&after);
    if !key.algorithm.verify(key.secret.expose_secret(), &data, mac) {
        return fail(Verdict::Invalid(if error != 0 {
            "the answer reports a TSIG error whose MAC does not verify"
        } else {
            "the MAC of the response does not verify"
        }));
    }
    // A verified TSIG error is honored before the time check: for BADTIME the clocks differ by
    // definition, and the MAC already binds the answer to this request (section 5.2.3). In a
    // later message of a multi-message answer the MAC does not cover the error field (section
    // 5.3.1 digests the timers only), and a server reports errors about the request in the first
    // message: a later one that reports an error is refused.
    if error != 0 {
        return fail(if first {
            Verdict::ServerError(error)
        } else {
            Verdict::Invalid(
                "a later message of the answer reports a TSIG error, which its MAC does not cover",
            )
        });
    }
    if now.abs_diff(time) > u64::from(fudge) {
        return fail(Verdict::Invalid(
            "the time of the response is outside its fudge",
        ));
    }
    Checked {
        verdict: Verdict::Ok,
        mac: mac.to_vec(),
        time,
    }
}

/// The TSIG timers (RFC 8945 section 4.3.3.1): Time Signed, then Fudge.
fn timers(time: u64, fudge: u16) -> Option<Vec<u8>> {
    let mut v = Vec::with_capacity(8);
    v.extend_from_slice(time.to_be_bytes().get(2..)?);
    v.extend_from_slice(&fudge.to_be_bytes());
    Some(v)
}

/// Most messages in a row without TSIG that a multi-message answer may carry (RFC 8945 section
/// 5.3.1: "MUST accept up to 99 intermediary messages without a TSIG").
pub(super) const MAX_UNSIGNED_IN_A_ROW: usize = 99;

/// How [`Stream::next`] took a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Link {
    /// The message carries a TSIG that verifies: it, and every unsigned message before it since
    /// the last signed one, are authenticated.
    Signed,
    /// An intermediate message without TSIG: authenticated only by the next signed message.
    Unsigned,
}

/// Verifies the messages of a multi-message answer in order (RFC 8945 section 5.3.1): the first
/// as a single answer, every later signed one over the prior MAC, the unsigned messages since
/// and its own timers. The first message must be signed, at most
/// [`MAX_UNSIGNED_IN_A_ROW`] messages in a row may be unsigned, and Time Signed does not
/// decrease from one signed message to the next ("successive TSIG records in the stream will
/// have non-decreasing Time Signed values"). Whether the last message is signed is the caller's
/// check: only the caller knows which message is the last.
pub(super) struct Stream<'k> {
    key: &'k Key,
    /// The MAC of the last signed message; the request MAC before the first message.
    prior_mac: Vec<u8>,
    /// The unsigned messages since the last signed one, as received, concatenated. The digest
    /// covers this concatenation, not the boundaries between the messages; that an attacker
    /// cannot merge an unsigned message into the one before it (and so drop its records while the
    /// digest still matches) rests on the framing and on `wire::parse` refusing octets after the
    /// last record of a message.
    unsigned: Vec<u8>,
    /// How many there are.
    unsigned_count: usize,
    /// Time Signed of the last signed message; `None` before the first message.
    last_time: Option<u64>,
}

impl fmt::Debug for Stream<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No MAC.
        f.debug_struct("Stream")
            .field("unsigned_count", &self.unsigned_count)
            .finish_non_exhaustive()
    }
}

impl<'k> Stream<'k> {
    /// A stream of answers to a request whose MAC was `request_mac`.
    pub(super) fn new(key: &'k Key, request_mac: Vec<u8>) -> Stream<'k> {
        Stream {
            key,
            prior_mac: request_mac,
            unsigned: Vec::new(),
            unsigned_count: 0,
            last_time: None,
        }
    }

    /// Takes the next message `buf`, parsed as `response`. `now` is the Unix time in seconds.
    /// A message that is refused gives the [`Verdict`] that says why, as [`verify`] would for a
    /// single answer.
    pub(super) fn next(
        &mut self,
        buf: &[u8],
        response: &Response,
        now: u64,
    ) -> Result<Link, Verdict> {
        let signed = response.additional.iter().any(|r| r.rtype == TYPE_TSIG);
        let Some(last_time) = self.last_time else {
            let checked = check(
                buf,
                response,
                self.key,
                now,
                Chain::First {
                    request_mac: &self.prior_mac,
                },
            );
            return self.accept(checked);
        };
        if !signed {
            if self.unsigned_count >= MAX_UNSIGNED_IN_A_ROW {
                return Err(Verdict::Invalid(
                    "more than 99 messages in a row of the answer are not signed (RFC 8945 \
                     section 5.3.1)",
                ));
            }
            self.unsigned.extend_from_slice(buf);
            self.unsigned_count += 1;
            return Ok(Link::Unsigned);
        }
        let checked = check(
            buf,
            response,
            self.key,
            now,
            Chain::Next {
                prior_mac: &self.prior_mac,
                unsigned: &self.unsigned,
            },
        );
        if checked.verdict == Verdict::Ok && checked.time < last_time {
            return Err(Verdict::Invalid(
                "the Time Signed of a message of the answer is earlier than the one before it",
            ));
        }
        self.accept(checked)
    }

    fn accept(&mut self, checked: Checked) -> Result<Link, Verdict> {
        if checked.verdict != Verdict::Ok {
            return Err(checked.verdict);
        }
        self.prior_mac = checked.mac;
        self.unsigned.clear();
        self.unsigned_count = 0;
        self.last_time = Some(checked.time);
        Ok(Link::Signed)
    }
}

/// The text of an `Error::Auth` for a TSIG error the server reported.
pub(super) fn error_text(error: u16) -> &'static str {
    match error {
        BADTIME => {
            "TSIG BADTIME: the clocks of this host and the server differ by more than the fudge \
             (300 s)"
        }
        BADKEY => "TSIG BADKEY: the server does not know this key name with this algorithm",
        BADSIG => "TSIG BADSIG: the secret does not match the server's key",
        BADTRUNC => "TSIG BADTRUNC: the server refused the MAC length",
        _ => "TSIG error: the server did not accept the signature",
    }
}

/// Signs a response message `msg` (ID set, no TSIG record) as a server does: the first message
/// of an answer over `prior` (the request MAC) with all TSIG variables, a later one over `prior`,
/// `unsigned` and its timers (RFC 8945 sections 5.3 and 5.3.1). Returns the MAC. For tests of
/// the transfer, which need answers the client did not build.
#[cfg(test)]
pub(super) fn sign_response(
    msg: &mut Vec<u8>,
    key: &Key,
    prior: &[u8],
    unsigned: &[u8],
    time: u64,
    first: bool,
) -> Vec<u8> {
    let id = [msg[0], msg[1]];
    let mut data = (prior.len() as u16).to_be_bytes().to_vec();
    data.extend_from_slice(prior);
    data.extend_from_slice(unsigned);
    data.extend_from_slice(msg);
    if first {
        data.extend_from_slice(&variables(key, time, FUDGE, 0, &[]).unwrap());
    } else {
        data.extend_from_slice(&timers(time, FUDGE).unwrap());
    }
    let mac = key.algorithm.mac(key.secret.expose_secret(), &data);
    let mut rd = key.algorithm.wire_name().to_vec();
    rd.extend_from_slice(&time.to_be_bytes()[2..]);
    rd.extend_from_slice(&FUDGE.to_be_bytes());
    rd.extend_from_slice(&(mac.len() as u16).to_be_bytes());
    rd.extend_from_slice(&mac);
    rd.extend_from_slice(&id);
    rd.extend_from_slice(&[0, 0, 0, 0]);
    wire::put_name(msg, &key.name);
    msg.extend_from_slice(&TYPE_TSIG.to_be_bytes());
    msg.extend_from_slice(&CLASS_ANY.to_be_bytes());
    msg.extend_from_slice(&0u32.to_be_bytes());
    msg.extend_from_slice(&(rd.len() as u16).to_be_bytes());
    msg.extend_from_slice(&rd);
    let arcount = wire::be16(msg, ARCOUNT_AT).unwrap() + 1;
    msg[ARCOUNT_AT..ARCOUNT_AT + 2].copy_from_slice(&arcount.to_be_bytes());
    mac
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::rfc2136::wire::{Builder, TYPE_TXT, parse};

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn key(algorithm: Algorithm, secret: &[u8]) -> Key {
        Key::new(
            DomainName::parse("zw-key").unwrap(),
            algorithm,
            SecretSlice::from(secret.to_vec()),
        )
    }

    /// The request MAC is HMAC over the unsigned message and the variables (RFC 8945 section
    /// 4.3); the TSIG record is last and ARCOUNT is incremented.
    #[test]
    fn sign_appends_tsig_and_mac_covers_message() {
        let k = key(Algorithm::HmacSha256, SECRET);
        let zone = DomainName::parse("example.org").unwrap();
        let unsigned = Builder::update(&zone).finish().unwrap().with_id(7);
        let mut msg = unsigned.clone();
        let mac = sign(&mut msg, &k, 1_700_000_000).unwrap();
        assert_eq!(mac.len(), 32);
        let p = parse(&msg).unwrap();
        let t = p.additional.last().unwrap();
        assert_eq!((t.rtype, t.name.as_str()), (TYPE_TSIG, "zw-key."));
        assert_eq!(&msg[ARCOUNT_AT..ARCOUNT_AT + 2], &[0, 1]);
        let mut data = unsigned;
        data.extend_from_slice(&variables(&k, 1_700_000_000, FUDGE, 0, &[]).unwrap());
        assert_eq!(hmac_sha256(SECRET, &data).to_vec(), mac);
        let mut r = Reader::new(&msg, t.rdata.start);
        assert_eq!(r.name().unwrap(), "hmac-sha256.");
        assert_eq!(r.u48().unwrap(), 1_700_000_000);
        assert_eq!(r.u16().unwrap(), FUDGE);

        let k512 = key(Algorithm::HmacSha512, &[7u8; 64]);
        let mut msg = Builder::query(&zone, TYPE_TXT).finish().unwrap().with_id(9);
        assert_eq!(sign(&mut msg, &k512, 1).unwrap().len(), 64);
        assert!(sign(&mut msg.clone(), &k512, MAX_TIME + 1).is_err());
        assert!(sign(&mut vec![0u8; 3], &k512, 1).is_err());

        let k384 = key(Algorithm::HmacSha384, &[5u8; 48]);
        let unsigned = Builder::update(&zone).finish().unwrap().with_id(11);
        let mut msg = unsigned.clone();
        let mac = sign(&mut msg, &k384, 1_700_000_000).unwrap();
        assert_eq!(mac.len(), 48);
        let p = parse(&msg).unwrap();
        let t = p.additional.last().unwrap();
        let mut data = unsigned;
        data.extend_from_slice(&variables(&k384, 1_700_000_000, FUDGE, 0, &[]).unwrap());
        assert_eq!(hmac_sha384(&[5u8; 48], &data).to_vec(), mac);
        let mut r = Reader::new(&msg, t.rdata.start);
        assert_eq!(r.name().unwrap(), "hmac-sha384.");
        assert_eq!(r.u48().unwrap(), 1_700_000_000);
        assert_eq!(r.u16().unwrap(), FUDGE);
        assert_eq!(usize::from(r.u16().unwrap()), 48);
    }

    /// Builds a signed answer to `request_mac` the way a server does (RFC 8945 section 5.3).
    fn answer(k: &Key, request_mac: &[u8], time: u64, corrupt: bool) -> Vec<u8> {
        let mac = if corrupt { Mac::Corrupt } else { Mac::Good };
        answer_with_error(k, request_mac, time, 0, &[], mac)
    }

    /// The MAC of an answer built by [`answer_with_error`].
    #[derive(Clone, Copy)]
    enum Mac {
        /// The MAC a server computes (RFC 8945 section 5.3).
        Good,
        /// That MAC with one bit flipped.
        Corrupt,
        /// MAC size 0, as in an unsigned error answer (section 5.3.2).
        Empty,
    }

    /// Like [`answer`], with the TSIG error and other data of the answer's TSIG record, which the
    /// MAC covers (section 4.3.3).
    fn answer_with_error(
        k: &Key,
        request_mac: &[u8],
        time: u64,
        error: u16,
        other: &[u8],
        mac: Mac,
    ) -> Vec<u8> {
        let zone = DomainName::parse("example.org").unwrap();
        let mut m = Builder::update(&zone).finish().unwrap().with_id(5);
        m[2] |= 0x80;
        let mut data = (request_mac.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(request_mac);
        data.extend_from_slice(&m);
        data.extend_from_slice(&variables(k, time, FUDGE, error, other).unwrap());
        let mut tag = k.algorithm.mac(SECRET, &data);
        match mac {
            Mac::Good => {}
            Mac::Corrupt => tag[0] ^= 1,
            Mac::Empty => tag.clear(),
        }
        let mut rd = k.algorithm.wire_name().to_vec();
        rd.extend_from_slice(&time.to_be_bytes()[2..]);
        rd.extend_from_slice(&FUDGE.to_be_bytes());
        rd.extend_from_slice(&(tag.len() as u16).to_be_bytes());
        rd.extend_from_slice(&tag);
        rd.extend_from_slice(&[0, 5]);
        rd.extend_from_slice(&error.to_be_bytes());
        rd.extend_from_slice(&(other.len() as u16).to_be_bytes());
        rd.extend_from_slice(other);
        m.extend_from_slice(b"\x06zw-key\x00\x00\xfa\x00\xff\0\0\0\0");
        m.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        m.extend_from_slice(&rd);
        m[11] = 1;
        m
    }

    /// RFC 8945: an unsigned answer is honored only for BADKEY and BADSIG (sections 5.2.1,
    /// 5.2.2, 5.3.2); every other TSIG error, BADTIME first (section 5.2.3), only when its MAC
    /// verifies against the request MAC (section 5.4). A verified TSIG error is not subject to
    /// the time check.
    #[test]
    fn verify_honors_a_tsig_error_only_unsigned_badkey_badsig_or_verified() {
        let k = key(Algorithm::HmacSha256, SECRET);
        let request_mac = [9u8; 32];
        let now = 1_700_000_000;
        let server_time = (now + 1000u64).to_be_bytes()[2..].to_vec();
        let check = |error: u16, time: u64, other: &[u8], mac: Mac, signed_over: &[u8]| {
            let buf = answer_with_error(&k, signed_over, time, error, other, mac);
            verify(&buf, &parse(&buf).unwrap(), &request_mac, &k, now)
        };
        let missing = Verdict::Invalid(
            "the answer reports a TSIG error that must be signed, but its MAC is missing or \
             truncated",
        );
        let forged = Verdict::Invalid("the answer reports a TSIG error whose MAC does not verify");

        // Unsigned BADKEY and BADSIG.
        assert_eq!(
            check(BADKEY, now, &[], Mac::Empty, &request_mac),
            Verdict::ServerError(BADKEY)
        );
        assert_eq!(
            check(BADSIG, now, &[], Mac::Empty, &request_mac),
            Verdict::ServerError(BADSIG)
        );
        // BADTIME signed over the request MAC with the client's time, and with a Time Signed
        // outside the fudge.
        assert_eq!(
            check(BADTIME, now, &server_time, Mac::Good, &request_mac),
            Verdict::ServerError(BADTIME)
        );
        assert_eq!(
            check(BADTIME, now + 1000, &server_time, Mac::Good, &request_mac),
            Verdict::ServerError(BADTIME)
        );
        // BADTIME with a corrupted MAC, without a MAC, and signed over another request MAC.
        assert_eq!(
            check(BADTIME, now, &server_time, Mac::Corrupt, &request_mac),
            forged
        );
        assert_eq!(
            check(BADTIME, now, &server_time, Mac::Empty, &request_mac),
            missing
        );
        assert_eq!(
            check(BADTIME, now, &server_time, Mac::Good, &[8u8; 32]),
            forged
        );
        // BADTRUNC.
        assert_eq!(
            check(BADTRUNC, now, &[], Mac::Good, &request_mac),
            Verdict::ServerError(BADTRUNC)
        );
        assert_eq!(check(BADTRUNC, now, &[], Mac::Empty, &request_mac), missing);
        // An unknown code.
        assert_eq!(check(99, now, &[], Mac::Empty, &request_mac), missing);
        assert_eq!(
            check(99, now, &[], Mac::Good, &request_mac),
            Verdict::ServerError(99)
        );
        // A signed BADSIG is honored when it verifies.
        assert_eq!(
            check(BADSIG, now, &[], Mac::Good, &request_mac),
            Verdict::ServerError(BADSIG)
        );
        assert_eq!(check(BADSIG, now, &[], Mac::Corrupt, &request_mac), forged);
    }

    #[test]
    fn verify_accepts_a_good_answer_and_refuses_others() {
        let k = key(Algorithm::HmacSha256, SECRET);
        let request_mac = [9u8; 32];
        let now = 1_700_000_000;
        let good = answer(&k, &request_mac, now, false);
        let check =
            |buf: &[u8], mac: &[u8], now: u64| verify(buf, &parse(buf).unwrap(), mac, &k, now);
        assert_eq!(check(&good, &request_mac, now), Verdict::Ok);
        assert_eq!(check(&good, &request_mac, now + 300), Verdict::Ok);
        assert!(matches!(
            check(&good, &request_mac, now + 301),
            Verdict::Invalid(_)
        ));
        // The request MAC is chained into the response MAC.
        assert!(matches!(check(&good, &[8u8; 32], now), Verdict::Invalid(_)));
        let bad = answer(&k, &request_mac, now, true);
        assert!(matches!(
            check(&bad, &request_mac, now),
            Verdict::Invalid(_)
        ));
        // Another key cannot verify it.
        let other = key(Algorithm::HmacSha256, b"another-secret-another-secret-!!");
        assert!(matches!(
            verify(&good, &parse(&good).unwrap(), &request_mac, &other, now),
            Verdict::Invalid(_)
        ));
        let other_alg = key(Algorithm::HmacSha512, SECRET);
        assert!(matches!(
            verify(&good, &parse(&good).unwrap(), &request_mac, &other_alg, now),
            Verdict::Invalid(_)
        ));
        // The same for an `hmac-sha384` key: its answer verifies, a 24-octet MAC (the length of
        // `hmac-sha384-192`, RFC 8945 section 6, table 3) is refused because truncated MACs are
        // not accepted (section 5.2.2.1), and an `hmac-sha512` key with the same secret cannot
        // verify it.
        let k384 = key(Algorithm::HmacSha384, SECRET);
        let request_mac = [9u8; 48];
        let good = answer(&k384, &request_mac, now, false);
        assert_eq!(
            verify(&good, &parse(&good).unwrap(), &request_mac, &k384, now),
            Verdict::Ok
        );
        let bad = answer(&k384, &request_mac, now, true);
        assert!(matches!(
            verify(&bad, &parse(&bad).unwrap(), &request_mac, &k384, now),
            Verdict::Invalid(_)
        ));
        assert!(matches!(
            verify(&good, &parse(&good).unwrap(), &request_mac, &other_alg, now),
            Verdict::Invalid(_)
        ));
        let truncated = answer_truncated(&k384, &request_mac, now, 24);
        assert!(matches!(
            verify(
                &truncated,
                &parse(&truncated).unwrap(),
                &request_mac,
                &k384,
                now
            ),
            Verdict::Invalid(_)
        ));
        // Without the TSIG record.
        let zone = DomainName::parse("example.org").unwrap();
        let unsigned = Builder::update(&zone).finish().unwrap().with_id(5);
        assert_eq!(check(&unsigned, &request_mac, now), Verdict::Unsigned);
    }

    /// Like [`answer`], with the correct MAC cut to its first `len` octets.
    fn answer_truncated(k: &Key, request_mac: &[u8], time: u64, len: usize) -> Vec<u8> {
        let full = answer(k, request_mac, time, false);
        let p = parse(&full).unwrap();
        let t = p.additional.last().unwrap();
        let mut r = Reader::new(&full, t.rdata.start);
        r.name().unwrap();
        r.u48().unwrap();
        r.u16().unwrap();
        let mac_len = usize::from(r.u16().unwrap());
        let mac_at = r.pos();
        let mut out = full[..mac_at - 2].to_vec();
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(&full[mac_at..mac_at + len]);
        out.extend_from_slice(&full[mac_at + mac_len..]);
        let rdlength_at = t.rdata.start - 2;
        let rdlength = (t.rdata.end - t.rdata.start - (mac_len - len)) as u16;
        out[rdlength_at..rdlength_at + 2].copy_from_slice(&rdlength.to_be_bytes());
        out
    }

    /// The shape of a signed answer for [`answer_shaped`].
    struct Shape {
        /// Records placed in the additional section before the TSIG record; the MAC covers them.
        extra: Vec<u8>,
        extra_count: u16,
        class: u16,
        ttl: u32,
        /// Octets appended to the TSIG RDATA after the other data, counted in RDLENGTH.
        trailing: Vec<u8>,
    }

    impl Default for Shape {
        fn default() -> Shape {
            Shape {
                extra: Vec::new(),
                extra_count: 0,
                class: CLASS_ANY,
                ttl: 0,
                trailing: Vec::new(),
            }
        }
    }

    /// Like [`answer`], with a correct MAC over whatever `shape` changes.
    fn answer_shaped(k: &Key, request_mac: &[u8], time: u64, shape: &Shape) -> Vec<u8> {
        let zone = DomainName::parse("example.org").unwrap();
        let mut m = Builder::update(&zone).finish().unwrap().with_id(5);
        m[2] |= 0x80;
        m.extend_from_slice(&shape.extra);
        m[10..12].copy_from_slice(&shape.extra_count.to_be_bytes());
        let mut data = (request_mac.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(request_mac);
        data.extend_from_slice(&m);
        data.extend_from_slice(&variables(k, time, FUDGE, 0, &[]).unwrap());
        let mac = k.algorithm.mac(SECRET, &data);
        let mut rd = k.algorithm.wire_name().to_vec();
        rd.extend_from_slice(&time.to_be_bytes()[2..]);
        rd.extend_from_slice(&FUDGE.to_be_bytes());
        rd.extend_from_slice(&(mac.len() as u16).to_be_bytes());
        rd.extend_from_slice(&mac);
        rd.extend_from_slice(&[0, 5, 0, 0, 0, 0]);
        rd.extend_from_slice(&shape.trailing);
        m.extend_from_slice(b"\x06zw-key\x00\x00\xfa");
        m.extend_from_slice(&shape.class.to_be_bytes());
        m.extend_from_slice(&shape.ttl.to_be_bytes());
        m.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        m.extend_from_slice(&rd);
        m[10..12].copy_from_slice(&(shape.extra_count + 1).to_be_bytes());
        m
    }

    /// RFC 8945 section 5.1: the TSIG record "MUST be the only TSIG RR in the message"; section
    /// 4.2: its CLASS "MUST be ANY" and its TTL "MUST be 0"; its RDATA is exactly the fields of
    /// section 4.2. An answer that breaks one of these is refused even though its MAC, which
    /// covers none of them, verifies.
    #[test]
    fn verify_refuses_a_misshapen_tsig_record() {
        let k = key(Algorithm::HmacSha256, SECRET);
        let request_mac = [9u8; 32];
        let now = 1_700_000_000;
        let check = |shape: Shape| {
            let buf = answer_shaped(&k, &request_mac, now, &shape);
            verify(&buf, &parse(&buf).unwrap(), &request_mac, &k, now)
        };
        // The helper itself produces an answer that verifies.
        assert_eq!(check(Shape::default()), Verdict::Ok);
        // A second TSIG record before the last one.
        let mut extra = b"\x06zw-key\x00\x00\xfa\x00\xff\0\0\0\0".to_vec();
        let mut rd = Algorithm::HmacSha256.wire_name().to_vec();
        rd.extend_from_slice(&[
            0, 0, 0x65, 0x53, 0xf1, 0x00, 0x01, 0x2c, 0, 0, 0, 5, 0, 0, 0, 0,
        ]);
        extra.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        extra.extend_from_slice(&rd);
        assert!(matches!(
            check(Shape {
                extra,
                extra_count: 1,
                ..Shape::default()
            }),
            Verdict::Invalid(_)
        ));
        assert!(matches!(
            check(Shape {
                class: 1,
                ..Shape::default()
            }),
            Verdict::Invalid(_)
        ));
        assert!(matches!(
            check(Shape {
                ttl: 60,
                ..Shape::default()
            }),
            Verdict::Invalid(_)
        ));
        assert!(matches!(
            check(Shape {
                trailing: vec![0],
                ..Shape::default()
            }),
            Verdict::Invalid(_)
        ));
    }

    /// One message of a multi-message answer, ID 5, QR set, built and signed the way RFC 8945
    /// section 5.3.1 describes a later message: over the prior MAC with its length, the unsigned
    /// messages since, the message and its timers. `None` leaves it unsigned.
    fn later_message(
        k: &Key,
        sign: Option<(&[u8], &[u8], u64, u16)>,
        txt: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        let zone = DomainName::parse("example.org").unwrap();
        let mut b = Builder::query(&zone, TYPE_TXT);
        b.add(
            &zone,
            TYPE_TXT,
            60,
            &[&[txt.len() as u8][..], txt.as_bytes()].concat(),
        )
        .unwrap();
        let mut m = b.finish().unwrap().with_id(5);
        m[2] |= 0x80;
        let Some((prior, unsigned, time, error)) = sign else {
            return (m, Vec::new());
        };
        let mut data = (prior.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(prior);
        data.extend_from_slice(unsigned);
        data.extend_from_slice(&m);
        data.extend_from_slice(&time.to_be_bytes()[2..]);
        data.extend_from_slice(&FUDGE.to_be_bytes());
        let mac = k.algorithm.mac(SECRET, &data);
        let mut rd = k.algorithm.wire_name().to_vec();
        rd.extend_from_slice(&time.to_be_bytes()[2..]);
        rd.extend_from_slice(&FUDGE.to_be_bytes());
        rd.extend_from_slice(&(mac.len() as u16).to_be_bytes());
        rd.extend_from_slice(&mac);
        rd.extend_from_slice(&[0, 5]);
        rd.extend_from_slice(&error.to_be_bytes());
        rd.extend_from_slice(&[0, 0]);
        m.extend_from_slice(b"\x06zw-key\x00\x00\xfa\x00\xff\0\0\0\0");
        m.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        m.extend_from_slice(&rd);
        m[11] = 1;
        (m, mac)
    }

    /// RFC 8945 section 5.3.1: the first message verifies over the request MAC, a later signed
    /// one over the prior MAC, the unsigned messages since and its timers; up to 99 unsigned
    /// messages in a row are accepted, the 100th is not; a change to an unsigned message, a
    /// signed message that skips one, a decreasing Time Signed and a TSIG error in a later
    /// message are refused.
    #[test]
    fn stream_verifies_every_message_in_order() {
        let k = key(Algorithm::HmacSha256, SECRET);
        let request_mac = [9u8; 32];
        let now = 1_700_000_000;
        let first = answer(&k, &request_mac, now, false);
        let first_mac = {
            let p = parse(&first).unwrap();
            let t = p.additional.last().unwrap();
            let mut r = Reader::new(&first, t.rdata.start);
            r.name().unwrap();
            r.u48().unwrap();
            r.u16().unwrap();
            let len = usize::from(r.u16().unwrap());
            r.bytes(len).unwrap().to_vec()
        };
        let take =
            |stream: &mut Stream<'_>, m: &[u8], at: u64| stream.next(m, &parse(m).unwrap(), at);

        // First, two unsigned, a signed one over both, then a signed one directly after it.
        let mut stream = Stream::new(&k, request_mac.to_vec());
        assert_eq!(take(&mut stream, &first, now), Ok(Link::Signed));
        let (u1, _) = later_message(&k, None, "u1");
        let (u2, _) = later_message(&k, None, "u2");
        let unsigned = [u1.clone(), u2.clone()].concat();
        let (s1, s1_mac) = later_message(&k, Some((&first_mac, &unsigned, now + 1, 0)), "s1");
        let (s2, _) = later_message(&k, Some((&s1_mac, &[], now + 1, 0)), "s2");
        assert_eq!(take(&mut stream, &u1, now), Ok(Link::Unsigned));
        assert_eq!(take(&mut stream, &u2, now), Ok(Link::Unsigned));
        assert_eq!(take(&mut stream, &s1, now), Ok(Link::Signed));
        assert_eq!(take(&mut stream, &s2, now), Ok(Link::Signed));

        // An unsigned message changed in transit, or left out, fails at the next signed one.
        for (taken, label) in [
            (vec![u1.clone()], "missing"),
            (vec![u2.clone(), u1.clone()], "order"),
        ] {
            let mut stream = Stream::new(&k, request_mac.to_vec());
            take(&mut stream, &first, now).unwrap();
            for m in &taken {
                assert_eq!(take(&mut stream, m, now), Ok(Link::Unsigned), "{label}");
            }
            assert!(
                matches!(take(&mut stream, &s1, now), Err(Verdict::Invalid(_))),
                "{label}"
            );
        }

        // 99 unsigned in a row are accepted; the 100th is not.
        let mut stream = Stream::new(&k, request_mac.to_vec());
        take(&mut stream, &first, now).unwrap();
        for _ in 0..MAX_UNSIGNED_IN_A_ROW {
            assert_eq!(take(&mut stream, &u1, now), Ok(Link::Unsigned));
        }
        assert!(matches!(
            take(&mut stream, &u1, now),
            Err(Verdict::Invalid(_))
        ));
        let mut ninety_nine = Vec::new();
        for _ in 0..MAX_UNSIGNED_IN_A_ROW {
            ninety_nine.extend_from_slice(&u1);
        }
        let (closing, _) = later_message(&k, Some((&first_mac, &ninety_nine, now, 0)), "end");
        assert_eq!(take(&mut stream, &closing, now), Ok(Link::Signed));

        // A Time Signed earlier than the previous one, outside the fudge, and a TSIG error in a
        // later message.
        for (time, error, at) in [(now - 1, 0, now), (now + 301, 0, now), (now, BADTIME, now)] {
            let mut stream = Stream::new(&k, request_mac.to_vec());
            take(&mut stream, &first, now).unwrap();
            let (m, _) = later_message(&k, Some((&first_mac, &[], time, error)), "x");
            assert!(
                matches!(take(&mut stream, &m, at), Err(Verdict::Invalid(_))),
                "{time} {error}"
            );
        }

        // The first message must be signed; an unsigned BADSIG there is the server's error.
        let mut stream = Stream::new(&k, request_mac.to_vec());
        assert_eq!(take(&mut stream, &u1, now), Err(Verdict::Unsigned));
        let badsig = answer_with_error(&k, &request_mac, now, BADSIG, &[], Mac::Empty);
        let mut stream = Stream::new(&k, request_mac.to_vec());
        assert_eq!(
            take(&mut stream, &badsig, now),
            Err(Verdict::ServerError(BADSIG))
        );
        // A later message with an empty MAC is not a server error.
        let mut stream = Stream::new(&k, request_mac.to_vec());
        take(&mut stream, &first, now).unwrap();
        assert!(matches!(
            take(&mut stream, &badsig, now),
            Err(Verdict::Invalid(_))
        ));
    }

    #[test]
    fn algorithms_parse() {
        assert_eq!(
            Algorithm::parse("HMAC-SHA256."),
            Some(Algorithm::HmacSha256)
        );
        assert_eq!(Algorithm::parse("hmac-sha384"), Some(Algorithm::HmacSha384));
        assert_eq!(
            Algorithm::parse(" Hmac-SHA384. "),
            Some(Algorithm::HmacSha384)
        );
        assert_eq!(Algorithm::parse("hmac-sha512"), Some(Algorithm::HmacSha512));
        for algorithm in [
            Algorithm::HmacSha256,
            Algorithm::HmacSha384,
            Algorithm::HmacSha512,
        ] {
            assert_eq!(Algorithm::parse(algorithm.as_str()), Some(algorithm));
            assert_eq!(Algorithm::parse(algorithm.text_name()), Some(algorithm));
            assert_eq!(algorithm.wire_name().len(), 13);
        }
        assert_eq!(Algorithm::parse("hmac-sha384-192"), None);
        assert_eq!(Algorithm::parse("hmac-sha224"), None);
        assert_eq!(Algorithm::parse("hmac-md5.sig-alg.reg.int"), None);
        assert_eq!(Algorithm::parse("hmac-sha1"), None);
    }

    #[test]
    fn key_debug_has_no_secret() {
        let k = key(Algorithm::HmacSha256, SECRET);
        let text = format!("{k:?}");
        assert!(text.contains("zw-key"));
        assert!(!text.contains("0123456789abcdef"));
    }
}
