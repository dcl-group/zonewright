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
    let tsig_records = response
        .additional
        .iter()
        .filter(|r| r.rtype == TYPE_TSIG)
        .count();
    let Some(record) = response.additional.last().filter(|r| r.rtype == TYPE_TSIG) else {
        if tsig_records > 0 {
            return Verdict::Invalid("the TSIG record of the response is not its last record");
        }
        return Verdict::Unsigned;
    };
    if tsig_records != 1 {
        return Verdict::Invalid("the response has more than one TSIG record");
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
    let Ok((algorithm, time, fudge, mac, original_id, error, other)) = parsed else {
        return Verdict::Invalid("the TSIG record of the response is malformed");
    };
    if r.pos() != record.rdata.end || record.class != CLASS_ANY || record.ttl != 0 {
        return Verdict::Invalid("the TSIG record of the response is malformed");
    }
    if record.name != key.name.as_str() || algorithm != key.algorithm.text_name() {
        return Verdict::Invalid("the response is signed with another key or algorithm");
    }
    // RFC 8945 sections 5.2.1, 5.2.2 and 5.3.2: a BADKEY or BADSIG answer is unsigned (MAC
    // size 0), so it cannot be verified; it is the only answer honored without a MAC.
    if (error == BADKEY || error == BADSIG) && mac.is_empty() {
        return Verdict::ServerError(error);
    }
    // Every other answer, including one with another TSIG error (BADTIME must be signed, section
    // 5.2.3), must carry a full MAC that verifies (section 5.4).
    if mac.len() != key.algorithm.mac_len() {
        return Verdict::Invalid(if error != 0 {
            "the answer reports a TSIG error that must be signed, but its MAC is missing or \
             truncated"
        } else {
            "the MAC of the response is truncated or missing"
        });
    }
    let Some(body) = buf.get(..record.start) else {
        return Verdict::Invalid("the TSIG record of the response is malformed");
    };
    let mut body = body.to_vec();
    let arcount = wire::be16(&body, ARCOUNT_AT).and_then(|n| n.checked_sub(1));
    let (Some(arcount), Some(id_slot)) = (arcount, body.get_mut(0..2)) else {
        return Verdict::Invalid("the TSIG record of the response is malformed");
    };
    id_slot.copy_from_slice(&original_id.to_be_bytes());
    if let Some(slot) = body.get_mut(ARCOUNT_AT..ARCOUNT_AT + 2) {
        slot.copy_from_slice(&arcount.to_be_bytes());
    }
    let Ok(request_mac_len) = u16::try_from(request_mac.len()) else {
        return Verdict::Invalid("the request MAC is too long");
    };
    let Some(vars) = variables(key, time, fudge, error, other) else {
        return Verdict::Invalid("the TSIG record of the response is malformed");
    };
    let mut data = Vec::with_capacity(2 + request_mac.len() + body.len() + vars.len());
    data.extend_from_slice(&request_mac_len.to_be_bytes());
    data.extend_from_slice(request_mac);
    data.extend_from_slice(&body);
    data.extend_from_slice(&vars);
    if !key.algorithm.verify(key.secret.expose_secret(), &data, mac) {
        return Verdict::Invalid(if error != 0 {
            "the answer reports a TSIG error whose MAC does not verify"
        } else {
            "the MAC of the response does not verify"
        });
    }
    // A verified TSIG error is honored before the time check: for BADTIME the clocks differ by
    // definition, and the MAC already binds the answer to this request (section 5.2.3).
    if error != 0 {
        return Verdict::ServerError(error);
    }
    if now.abs_diff(time) > u64::from(fudge) {
        return Verdict::Invalid("the time of the response is outside its fudge");
    }
    Verdict::Ok
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
