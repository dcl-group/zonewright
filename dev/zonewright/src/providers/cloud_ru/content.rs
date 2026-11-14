//! The mapping between the `values` text of a Cloud.ru record and canonical `RecordData`, one
//! pair of functions per record type, in both directions, and the API's spelling of each type.
//!
//! The OpenAPI document describes `values` only as "Значения записи публичной зоны" (a list of
//! strings) and lists the types `a, aaaa, srv, cname, mx, ns, spf, txt, caa`. The form of a value
//! per type is taken from the provider's page on the supported record types
//! (<https://cloud.ru/docs/evolution-dns/ug/topics/concepts__record-types>, read on 2026-11-14;
//! "record types page" below), which gives the format and examples of the "Значение" (value)
//! field of each type:
//!
//! | Type  | Record types page                                                                | Read          | Written                          |
//! | ----- | -------------------------------------------------------------------------------- | ------------- | -------------------------------- |
//! | A     | an IPv4 address: `192.0.2.125`                                                   | strict parser | canonical text                   |
//! | AAAA  | an IPv6 address: `2001:db8:85a3::8a2e:370:7334`                                  | strict parser | canonical text (the same form)   |
//! | CAA   | `<flags> <tag> <value>`, flags 0 or 128, tag `issue`, `issuewild` or `iodef`, value in `"`: `0 issue "letsencrypt.org"` | strict parser | canonical text |
//! | CNAME | the canonical name: `example.com` (for `www` in `example.com`)                   | strict parser | the name without the final dot   |
//! | MX    | `<preference> <exchange>`, a 16-bit preference and a full domain name: `10 mx1.example.com`, `0 .` | strict parser | the name without the final dot |
//! | NS    | a name server, for a subdomain only: `ns1.example.com`                            | strict parser | the name without the final dot   |
//! | SPF   | the policy text: `v=spf1 ip4:192.0.2.0/24 -all`                                  | one string    | one string                       |
//! | SRV   | `<priority> <weight> <port> <target>`, 0 to 65535 each, a full domain name: `10 70 8080 master-host.example.com` | strict parser | the name without the final dot |
//! | TXT   | text data, at most 65 000 characters                                             | `Auto`        | the text (`Raw`)                 |
//!
//! Names inside values are full domain names written without the final dot in every example (a
//! CNAME `example.com` for `www.example.com` makes the reading unambiguous), which is how
//! `RecordData::parse` reads a name without a trailing dot (design section 4.2). They are written
//! the way the page shows them; the root name is `.`, which the page shows for MX (`0 .`) only.
//!
//! What the sources do not establish is not sent ([`RrsetBase::can_send`] is false,
//! `Error::InvalidInput`), unless the record already holds the value, which is then written back
//! exactly as the API returned it:
//!
//! - escapes: no source says how the API treats a backslash or a `"` inside a value, so a value
//!   that would need one (a TXT, SPF or CAA value with `"`, `\`, a byte outside printable ASCII;
//!   a name with an unusual octet) is not sent, and provider text with a backslash is read as
//!   non-canonical data (design section 4.9) except in TXT, which the TXT value operations
//!   already read with the `Auto` rule;
//! - TXT and SPF values with leading or trailing spaces (they could be trimmed), empty ones, and
//!   values over the documented 65 000 characters; an SPF value is sent only when it is one
//!   character-string (at most 255 octets), since the page shows no form for several;
//! - the root name as a CNAME, NS or SRV target, and CAA flags and tags outside the documented
//!   ones.
//!
//! SPF has no canonical text of its own in the crate (design section 4.7): its canonical form is
//! the generic `\# <length> <hex>`, which is what the inspector produces from the wire. The text
//! is therefore converted to and from wire data here (one character-string), so a value read from
//! the provider compares equal to the same record seen on the wire.
//!
//! [`RrsetBase::can_send`]: crate::rrsets::RrsetBase::can_send

use crate::name::TargetName;
use crate::record::{Caa, Mx, RecordData, RecordType, Srv, Txt, TxtDialect};

/// SPF, which has no constant of its own (design section 4.7).
pub(super) const SPF: RecordType = RecordType::from_code(99);

/// The longest TXT value.
// Source: the record types page, TXT: "Ограничение — не более 65 000 символов".
const MAX_TEXT: usize = 65_000;

/// The longest character-string, the most one SPF string holds (RFC 1035 section 3.3).
const MAX_STRING: usize = 255;

/// The CAA flags and tags the page documents.
// Source: the record types page, CAA: `<flags>` "может принимать два значения: 0 ... 128";
// `<tag>` "может принимать значения: issue ... issuewild ... iodef".
const CAA_FLAGS: [u8; 2] = [0, 128];
const CAA_TAGS: [&str; 3] = ["issue", "issuewild", "iodef"];

/// How TXT text is read: quoted text as presentation format, anything else as the value; the
/// same rule as the TXT value operations.
const TXT_READ: TxtDialect = TxtDialect::Auto;

/// The API's name of a record type, lowercase; `None` for a type the API does not have.
// Source: the OpenAPI, `v1CreatePublicRecordSoleRequest.type` ("Возможные значения: a, aaaa,
// srv, cname, mx, ns, spf, txt, caa").
pub(super) fn api_type(rtype: RecordType) -> Option<&'static str> {
    Some(match rtype {
        RecordType::A => "a",
        RecordType::AAAA => "aaaa",
        RecordType::CAA => "caa",
        RecordType::CNAME => "cname",
        RecordType::MX => "mx",
        RecordType::NS => "ns",
        RecordType::SRV => "srv",
        RecordType::TXT => "txt",
        SPF => "spf",
        _ => return None,
    })
}

/// A value as the API returned it, for a record of `rtype`. Never fails: text this client cannot
/// make canonical is kept as non-canonical data (design section 4.9).
pub(super) fn read(rtype: RecordType, text: &str) -> RecordData {
    let parsed = if rtype == RecordType::TXT {
        read_txt(text)
    } else if rtype == SPF {
        read_spf(text)
    } else {
        read_plain(rtype, text)
    };
    parsed.unwrap_or_else(|| RecordData::non_canonical(text))
}

/// The API's text for a new value of `rtype`, or `None` when the client cannot send it:
/// non-canonical data, a type that is not written, or a value whose form the sources do not
/// establish (see the module documentation).
pub(super) fn encode(rtype: RecordType, data: &RecordData) -> Option<String> {
    if !data.is_canonical() {
        return None;
    }
    match rtype {
        RecordType::A | RecordType::AAAA => write_address(data),
        RecordType::CAA => write_caa(data),
        RecordType::CNAME | RecordType::NS => write_name(data),
        RecordType::MX => write_mx(data),
        RecordType::SRV => write_srv(data),
        RecordType::TXT => write_txt(data),
        SPF => write_spf(data),
        _ => None,
    }
}

// ---- Types whose documented form is read by the strict parser ------------------------------------

/// A, AAAA, CAA, CNAME, MX, NS, SRV (and any other type the API may list): the documented forms
/// are the presentation format with names written without the final dot, which the strict parser
/// reads as absolute names. A backslash is not read: the API's escapes are not documented.
// Source: the record types page, the section of each type.
fn read_plain(rtype: RecordType, text: &str) -> Option<RecordData> {
    if text.contains('\\') {
        return None;
    }
    RecordData::parse(rtype, text).ok()
}

/// A and AAAA: the canonical text, which is the documented form (four decimal octets; the
/// compressed lowercase IPv6 form of the page's example).
// Source: the record types page, A (`192.0.2.125`) and AAAA (`2001:db8:85a3::8a2e:370:7334`).
fn write_address(data: &RecordData) -> Option<String> {
    Some(data.as_str().to_owned())
}

/// A name as the page writes it: without the final dot. `None` for the root and for a name whose
/// text needs an escape.
fn name_text(name: &TargetName) -> Option<String> {
    let text = name.as_str();
    if name.is_root() || text.contains('\\') {
        return None;
    }
    text.strip_suffix('.').map(str::to_owned)
}

/// CNAME and NS: the target name.
// Source: the record types page, CNAME (`www` → `example.com`) and NS (`shop` →
// `ns1.example.com`).
fn write_name(data: &RecordData) -> Option<String> {
    let name = TargetName::parse(data.as_str()).ok()?;
    name_text(&name)
}

/// MX: `<preference> <exchange>`; the root exchange is `.` (a null MX).
// Source: the record types page, MX: "<preference> — приоритет сервера, 16-битное целое число",
// "<exchange> — полное доменное имя сервера"; examples `10 mx1.example.com` and `0 .`.
fn write_mx(data: &RecordData) -> Option<String> {
    let mx = Mx::from_data(data).ok()?;
    let exchange = if mx.exchange.is_root() {
        ".".to_owned()
    } else {
        name_text(&mx.exchange)?
    };
    Some(format!("{} {exchange}", mx.preference))
}

/// SRV: `<priority> <weight> <port> <target>`.
// Source: the record types page, SRV: "допустимые значения 0–65535" for priority, weight and
// port, "<target> — полное доменное имя сервера"; example `10 70 8080 master-host.example.com`.
fn write_srv(data: &RecordData) -> Option<String> {
    let srv = Srv::from_data(data).ok()?;
    let target = name_text(&srv.target)?;
    Some(format!(
        "{} {} {} {target}",
        srv.priority, srv.weight, srv.port
    ))
}

/// CAA: `<flags> <tag> "<value>"`, with the documented flags and tags and a value of printable
/// ASCII without `"` and `\`.
// Source: the record types page, CAA: "<value> — значение записи, заключается в двойные кавычки";
// examples `0 issue "letsencrypt.org"`, `128 iodef "mailto:admin@example.com"`,
// `128 issuewild ";"`.
fn write_caa(data: &RecordData) -> Option<String> {
    let caa = Caa::from_data(data).ok()?;
    if !CAA_FLAGS.contains(&caa.flags) || !CAA_TAGS.contains(&caa.tag.as_str()) {
        return None;
    }
    let value = std::str::from_utf8(&caa.value).ok()?;
    if value.is_empty() || !value.bytes().all(|b| plain_byte(b) && b != b' ') {
        return None;
    }
    Some(format!("{} {} \"{value}\"", caa.flags, caa.tag))
}

// ---- TXT and SPF ---------------------------------------------------------------------------------

/// A byte the client writes into a text value: printable ASCII or the space, without `"` and `\`.
fn plain_byte(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte) && byte != b'"' && byte != b'\\'
}

/// Text the client writes as a value of its own: 1 to `max` plain bytes without leading or
/// trailing spaces.
fn plain_text(bytes: &[u8], max: usize) -> Option<String> {
    let edges = bytes.first().zip(bytes.last());
    if bytes.len() > max
        || !bytes.iter().all(|&b| plain_byte(b))
        || edges.is_none_or(|(first, last)| *first == b' ' || *last == b' ')
    {
        return None;
    }
    String::from_utf8(bytes.to_vec()).ok()
}

/// TXT: quoted text as presentation format, anything else as the value itself (`Auto`).
// Source: the record types page, TXT ("текстовых данных"); the TXT value operations read the
// same way.
fn read_txt(text: &str) -> Option<RecordData> {
    TXT_READ.read(text)?.to_data().ok()
}

/// TXT: the value itself, at most 65 000 characters.
// Source: the record types page, TXT: "Ограничение — не более 65 000 символов". The space is
// written as itself, as the page's SPF examples (the same text form) show.
fn write_txt(data: &RecordData) -> Option<String> {
    let value = Txt::from_data(data).ok()?;
    plain_text(value.as_bytes(), MAX_TEXT)
}

/// SPF: the policy text as one character-string of the wire data. Quoted text, a backslash and
/// text over 255 octets are not read: the page shows only the plain form.
// Source: the record types page, SPF: "SPF-запись начинается с v=spf1"; examples
// `v=spf1 ip4:192.0.2.0/24 -all`, `v=spf1 a ip4:192.0.2.0/24 ip4:198.51.100.123 -all`.
fn read_spf(text: &str) -> Option<RecordData> {
    let text = text.trim();
    if text.starts_with('"') || text.contains('\\') || text.len() > MAX_STRING {
        return None;
    }
    let mut wire = Vec::with_capacity(text.len() + 1);
    wire.push(u8::try_from(text.len()).ok()?);
    wire.extend_from_slice(text.as_bytes());
    RecordData::from_wire(SPF, &wire).ok()
}

/// SPF: the one character-string of the wire data as plain text.
fn write_spf(data: &RecordData) -> Option<String> {
    let wire = data.to_wire(SPF).ok()?;
    let (&len, rest) = wire.split_first()?;
    if usize::from(len) != rest.len() {
        return None;
    }
    plain_text(rest, MAX_STRING)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(rtype: RecordType, text: &str) -> RecordData {
        RecordData::parse(rtype, text).unwrap()
    }

    #[test]
    fn documented_examples_read_as_canonical_data() {
        for (rtype, text, canonical) in [
            (RecordType::A, "192.0.2.125", "192.0.2.125"),
            (
                RecordType::AAAA,
                "2001:db8:85a3::8a2e:370:7334",
                "2001:db8:85a3::8a2e:370:7334",
            ),
            (
                RecordType::CAA,
                "0 issue \"letsencrypt.org\"",
                "0 issue \"letsencrypt.org\"",
            ),
            (
                RecordType::CAA,
                "128 iodef \"mailto:admin@example.com\"",
                "128 iodef \"mailto:admin@example.com\"",
            ),
            (
                RecordType::CAA,
                "128 issuewild \";\"",
                "128 issuewild \";\"",
            ),
            (RecordType::CNAME, "example.com", "example.com."),
            (RecordType::MX, "10 mx1.example.com", "10 mx1.example.com."),
            (RecordType::MX, "0 .", "0 ."),
            (RecordType::NS, "ns1.example.com", "ns1.example.com."),
            (
                RecordType::SRV,
                "10 70 8080 master-host.example.com",
                "10 70 8080 master-host.example.com.",
            ),
        ] {
            let read = read(rtype, text);
            assert_eq!(read, data(rtype, canonical), "{rtype} {text}");
            assert_eq!(encode(rtype, &read).as_deref(), Some(text), "{rtype}");
        }
    }

    #[test]
    fn txt_is_the_text_itself() {
        let spf_text = "v=spf1 ip4:192.0.2.0/24 -all";
        let value = Txt::new(spf_text).unwrap().to_data().unwrap();
        assert_eq!(read(RecordType::TXT, spf_text), value);
        assert_eq!(encode(RecordType::TXT, &value).as_deref(), Some(spf_text));
        // Quoted text is presentation format.
        assert_eq!(
            read(RecordType::TXT, "\"v=spf1 ip4:192.0.2.0/24 -all\""),
            value
        );
        // A long value is one string.
        let long = "k".repeat(MAX_TEXT);
        let value = Txt::new(long.as_bytes()).unwrap().to_data().unwrap();
        assert_eq!(encode(RecordType::TXT, &value), Some(long.clone()));
        assert_eq!(read(RecordType::TXT, &long), value);
        let over = Txt::new("k".repeat(MAX_TEXT + 1))
            .unwrap()
            .to_data()
            .unwrap();
        assert_eq!(encode(RecordType::TXT, &over), None);
        for unsendable in ["", " lead", "trail ", "q\"uote", "back\\slash", "caf\u{e9}"] {
            let value = Txt::new(unsendable.as_bytes()).unwrap().to_data().unwrap();
            assert_eq!(encode(RecordType::TXT, &value), None, "{unsendable}");
        }
    }

    #[test]
    fn spf_goes_through_wire_data() {
        let text = "v=spf1 a ip4:192.0.2.0/24 ip4:198.51.100.123 -all";
        let spf = read(SPF, text);
        assert!(spf.is_canonical());
        assert!(spf.as_str().starts_with("\\# "), "{spf}");
        assert_eq!(encode(SPF, &spf).as_deref(), Some(text));
        assert!(!read(SPF, "\"v=spf1 -all\"").is_canonical());
        assert!(!read(SPF, &"x".repeat(256)).is_canonical());
        // Two character-strings have no documented plain form.
        let two = RecordData::from_wire(SPF, b"\x06v=spf1\x04-all").unwrap();
        assert_eq!(encode(SPF, &two), None);
    }

    #[test]
    fn what_is_not_established_is_not_sent() {
        for (rtype, text) in [
            (RecordType::CNAME, "."),
            (RecordType::NS, "."),
            (RecordType::SRV, "0 0 0 ."),
            (RecordType::CNAME, "a\\.b.example.net."),
            (RecordType::CAA, "1 issue \"ca.example.net\""),
            (RecordType::CAA, "0 tbs \"x\""),
            (RecordType::CAA, "0 issue \"a\\\"b\""),
            (RecordType::CAA, "0 issue \"\""),
            (RecordType::SOA, "ns.example.org. a.example.org. 1 2 3 4 5"),
            (RecordType::TLSA, "3 1 1 0a1b"),
        ] {
            assert_eq!(encode(rtype, &data(rtype, text)), None, "{rtype} {text}");
        }
        assert_eq!(
            encode(RecordType::A, &RecordData::non_canonical("odd")),
            None
        );
        // A backslash in provider text is not interpreted.
        assert!(!read(RecordType::CNAME, "a\\046b.example.net").is_canonical());
        // The SOA of the page (commas) is not presentation format.
        let soa = read(
            RecordType::SOA,
            "evo-cns01.cloud.ru., admin.cloud.ru, 2026070606, 3600, 3600, 3600, 3600",
        );
        assert!(!soa.is_canonical());
    }

    #[test]
    fn api_types_are_lowercase() {
        assert_eq!(api_type(RecordType::AAAA), Some("aaaa"));
        assert_eq!(api_type(SPF), Some("spf"));
        assert_eq!(api_type(RecordType::SOA), None);
        assert_eq!(api_type(RecordType::PTR), None);
    }
}
