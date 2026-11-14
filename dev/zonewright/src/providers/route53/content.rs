//! The mapping between the `Value` text of a Route 53 resource record and canonical
//! `RecordData`, one pair of functions per record type, in both directions.
//!
//! Source of every row: Developer Guide, "Supported DNS record types"
//! (<https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html>, read
//! on 2026-11-14), which gives the `Value` format of each type with an API example:
//!
//! | Type        | Documented `Value` form                                   | Read                     | Written                                  |
//! | ----------- | --------------------------------------------------------- | ------------------------ | ---------------------------------------- |
//! | A           | `192.0.2.1`                                               | strict parser            | canonical text                           |
//! | AAAA        | `2001:0db8:85a3:0:0:8a2e:0370:7334`                       | strict parser            | eight groups, no `::` (the example form) |
//! | CAA         | `flags tag "value"`, value always quoted                  | strict parser            | canonical text                           |
//! | CNAME, NS, PTR | a domain name, the trailing dot optional               | strict parser            | canonical text                           |
//! | DS          | `key-tag algorithm digest-type digest`                    | fields to wire data      | fields from wire data                    |
//! | HTTPS, SVCB | `SvcPriority TargetName SvcParams`, no `keyNNNNN`         | strict parser            | canonical text, priority 0 to 32767      |
//! | MX          | `priority domain-name`                                    | strict parser            | canonical text                           |
//! | NAPTR       | `order preference "flags" "service" "regexp" replacement` | fields to wire data      | fields from wire data                    |
//! | SOA         | two names and five numbers                                | strict parser            | never (read-only)                        |
//! | SPF         | quoted strings, as TXT                                    | strings to wire data     | strings from wire data                   |
//! | SRV         | `priority weight port domain-name`                        | strict parser            | canonical text                           |
//! | SSHFP       | `algorithm hash-type fingerprint` (hex)                   | strict parser            | canonical text                           |
//! | TLSA        | `usage selector matching-type data` (hex)                 | strict parser            | canonical text                           |
//! | TXT         | quoted strings of at most 255 characters                  | strings to the value     | 255-octet quoted strings                 |
//!
//! The crate has no canonical text of its own for DS, NAPTR and SPF (design section 4.7): their
//! canonical form is the generic `\# <length> <hex>`, which is what the inspector produces from
//! the wire. The documented fields are therefore converted to and from wire data here, so a value
//! read from Route 53 compares equal to the same record seen on the wire.
//!
//! Escapes. Route 53 writes a backslash followed by three digits as an octal code
//! (`\three-digit octal code`, documented for TXT and NAPTR strings and for names), unlike the
//! decimal `\DDD` of zone-file text. So canonical text is never passed through when it holds a
//! backslash:
//!
//! - quoted strings (TXT, SPF, NAPTR) are decoded and encoded here, with octal escapes for the
//!   octets the page lists (0 to 32 and 127 to 255 decimal) and `\"` for a quotation mark. A
//!   space is written as itself, as every example on the page does. A backslash is written `\\`
//!   only in NAPTR, the one type for which the page documents it; a TXT or SPF value with a
//!   backslash is not sent;
//! - any other value with a backslash is read as non-canonical data (design section 4.9) and is
//!   not sent when the canonical text needs one (a CAA value with `"` or a byte outside
//!   printable ASCII, a name with an unusual octet).

use std::net::Ipv6Addr;

use crate::name::TargetName;
use crate::record::{RecordData, RecordType, Txt};

/// The record types without a canonical text of their own (design section 4.7).
const DS: RecordType = RecordType::from_code(43);
const NAPTR: RecordType = RecordType::from_code(35);
const SPF: RecordType = RecordType::from_code(99);

/// Most octets of one quoted string.
// Source: "Supported DNS record types", TXT: "A single string can include up to 255
// characters". Assumption (not documented): an octal escape stands for one character, the
// octet it encodes, since a string is a DNS character-string of at most 255 octets; if Route 53
// counted the escape's four characters, a long value with escapes would be refused (an error,
// nothing written).
const MAX_STRING: usize = 255;

/// Highest SvcPriority Route 53 accepts.
// Source: "Supported DNS record types", HTTPS and SVCB: "This value is an integer 0-32767 for
// Route 53".
const MAX_SVC_PRIORITY: u32 = 32_767;

/// A value as the API returned it, for a record of `rtype`. Never fails: text this client
/// cannot make canonical is kept as non-canonical data (design section 4.9).
pub(super) fn read(rtype: RecordType, text: &str) -> RecordData {
    let parsed = if rtype == RecordType::TXT {
        read_txt(text)
    } else if rtype == SPF {
        read_spf(text)
    } else if rtype == DS {
        read_ds(text)
    } else if rtype == NAPTR {
        read_naptr(text)
    } else {
        read_plain(rtype, text)
    };
    parsed.unwrap_or_else(|| RecordData::non_canonical(text))
}

/// The API's text for a new value of `rtype`, or `None` when the client cannot send it:
/// non-canonical data, a type that is never written, or a value whose encoding the
/// documentation does not establish (see the module documentation).
pub(super) fn encode(rtype: RecordType, data: &RecordData) -> Option<String> {
    if !data.is_canonical() {
        return None;
    }
    if rtype == RecordType::TXT {
        write_txt(data)
    } else if rtype == SPF {
        write_spf(data)
    } else if rtype == DS {
        write_ds(data)
    } else if rtype == NAPTR {
        write_naptr(data)
    } else if rtype == RecordType::AAAA {
        write_aaaa(data)
    } else if rtype == RecordType::HTTPS || rtype == RecordType::SVCB {
        write_svcb(data)
    } else if rtype == RecordType::SOA {
        None
    } else {
        write_plain(data)
    }
}

// ---- Types whose documented form is the canonical text -------------------------------------------

/// A, AAAA, CAA, CNAME, HTTPS, MX, NS, PTR, SOA, SRV, SSHFP, SVCB, TLSA: the documented forms
/// are the presentation format with absolute names (the trailing dot optional), which the strict
/// parser reads. A backslash is an octal escape here, never a decimal one: not parsed.
// Source: "Supported DNS record types", the section of each type.
fn read_plain(rtype: RecordType, text: &str) -> Option<RecordData> {
    if text.contains('\\') {
        return None;
    }
    RecordData::parse(rtype, text).ok()
}

/// The canonical text, unless it holds a backslash escape.
fn write_plain(data: &RecordData) -> Option<String> {
    (!data.as_str().contains('\\')).then(|| data.as_str().to_owned())
}

/// AAAA in the documented example's form: eight colon-separated groups in hexadecimal, without
/// the `::` compression of the canonical text.
// Source: "Supported DNS record types", AAAA: "colon-separated hexadecimal format", example
// `2001:0db8:85a3:0:0:8a2e:0370:7334`.
fn write_aaaa(data: &RecordData) -> Option<String> {
    let address: Ipv6Addr = data.as_str().parse().ok()?;
    let groups: Vec<String> = address
        .segments()
        .iter()
        .map(|group| format!("{group:x}"))
        .collect();
    Some(groups.join(":"))
}

/// HTTPS and SVCB: the canonical text, with a priority Route 53 accepts and no parameter in the
/// `keyNNNNN` form, which it does not support.
// Source: "Supported DNS record types", HTTPS and SVCB: priority "0-32767 for Route 53";
// "Route 53 does not support the arbitrary unknown-key presentation format keyNNNNN".
fn write_svcb(data: &RecordData) -> Option<String> {
    let text = write_plain(data)?;
    let mut fields = text.split(' ');
    let priority: u32 = fields.next()?.parse().ok()?;
    let _target = fields.next()?;
    let unknown_key = fields.any(|param| {
        param
            .strip_prefix("key")
            .and_then(|rest| rest.chars().next())
            .is_some_and(|c| c.is_ascii_digit())
    });
    (priority <= MAX_SVC_PRIORITY && !unknown_key).then_some(text)
}

// ---- Quoted strings: TXT and SPF -----------------------------------------------------------------

/// TXT: quoted strings joined into one value (design section 4.4). Text that does not start
/// with a quotation mark is the value itself, as the TXT value operations read it (`Auto`).
// Source: "Supported DNS record types", TXT: "one or more strings that are enclosed in double
// quotation marks"; octal escapes; `\"`.
fn read_txt(text: &str) -> Option<RecordData> {
    let trimmed = text.trim();
    let bytes = if trimmed.starts_with('"') {
        strings(trimmed)?.concat()
    } else if trimmed.contains('\\') || trimmed.contains(char::is_whitespace) {
        return None;
    } else {
        trimmed.as_bytes().to_vec()
    };
    Txt::new(bytes).ok()?.to_data().ok()
}

/// TXT: the value cut into 255-octet quoted strings.
fn write_txt(data: &RecordData) -> Option<String> {
    let value = Txt::from_data(data).ok()?;
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return Some("\"\"".to_owned());
    }
    let mut out = String::new();
    for (index, chunk) in bytes.chunks(MAX_STRING).enumerate() {
        if index > 0 {
            out.push(' ');
        }
        quote(&mut out, chunk, false)?;
    }
    Some(out)
}

/// SPF: the strings of a TXT-style value become the character-strings of the wire data.
// Source: "Supported DNS record types", SPF: the example is a quoted string as for TXT.
fn read_spf(text: &str) -> Option<RecordData> {
    let mut wire = Vec::new();
    for string in strings(text.trim())? {
        push_character_string(&mut wire, &string)?;
    }
    RecordData::from_wire(SPF, &wire).ok()
}

/// SPF: each character-string of the wire data as one quoted string.
fn write_spf(data: &RecordData) -> Option<String> {
    let wire = data.to_wire(SPF).ok()?;
    let mut rest = wire.as_slice();
    let mut out = String::new();
    while !rest.is_empty() {
        let (string, tail) = character_string(rest)?;
        if !out.is_empty() {
            out.push(' ');
        }
        quote(&mut out, string, false)?;
        rest = tail;
    }
    (!out.is_empty()).then_some(out)
}

/// The decoded strings of text made of quoted strings separated by whitespace. `None` for
/// anything else: text outside quotes, an unterminated string, an escape that is not three
/// octal digits of at most `377`, a string longer than 255 octets.
fn strings(text: &str) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut rest = text.trim_start();
    if rest.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        let (string, tail) = quoted(rest)?;
        out.push(string);
        if !tail.is_empty() && !tail.starts_with(char::is_whitespace) {
            return None;
        }
        rest = tail.trim_start();
    }
    Some(out)
}

/// One quoted string at the start of `text`: its octets and the text after the closing quote.
/// Escapes: `\` and three octal digits is that octet; `\` and any other character that is not
/// a digit is the character. Characters outside ASCII are their UTF-8 octets.
// Source: "Supported DNS record types", TXT ("escape codes in the format \three-digit octal
// code", "put a backslash (\) character before the quotation mark") and NAPTR ("precede it with
// a \ character: \"", "\\"). Assumption (not documented for TXT): `\` before another non-digit
// character stands for that character, as in zone-file text; it is only read, never written.
fn quoted(text: &str) -> Option<(Vec<u8>, &str)> {
    let inner = text.strip_prefix('"')?;
    let mut out = Vec::new();
    let mut chars = inner.char_indices();
    while let Some((index, c)) = chars.next() {
        match c {
            '"' => {
                if out.len() > MAX_STRING {
                    return None;
                }
                return Some((out, inner.get(index + 1..)?));
            }
            '\\' => {
                let (_, next) = chars.next()?;
                if let Some(first) = next.to_digit(10) {
                    let first = (first < 8).then_some(first)?;
                    let second = chars.next()?.1.to_digit(8)?;
                    let third = chars.next()?.1.to_digit(8)?;
                    out.push(u8::try_from(first * 64 + second * 8 + third).ok()?);
                } else {
                    let mut buffer = [0u8; 4];
                    out.extend_from_slice(next.encode_utf8(&mut buffer).as_bytes());
                }
            }
            c => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    None
}

/// Appends `bytes` as one quoted string in the documented escapes: printable ASCII and the
/// space as themselves, `\"` for a quotation mark, `\ooo` for every other octet. A backslash
/// is written `\\` when `backslash` allows it (NAPTR) and makes the value unsendable otherwise.
// Source: "Supported DNS record types", TXT: "Characters 000 to 040 octal ... Characters 177 to
// 377 octal" by "escape codes in the format \three-digit octal code"; the examples write spaces
// as they are ("v=spf1 ip4:192.168.0.1/16 -all"); NAPTR: `\\` for a backslash.
fn quote(out: &mut String, bytes: &[u8], backslash: bool) -> Option<()> {
    out.push('"');
    for &byte in bytes {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' if backslash => out.push_str("\\\\"),
            b'\\' => return None,
            0x20..=0x7e => out.push(char::from(byte)),
            _ => out.push_str(&format!("\\{byte:03o}")),
        }
    }
    out.push('"');
    Some(())
}

fn push_character_string(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    out.push(u8::try_from(bytes.len()).ok()?);
    out.extend_from_slice(bytes);
    Some(())
}

/// One character-string at the start of wire data, and the rest.
fn character_string(wire: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&len, rest) = wire.split_first()?;
    let len = usize::from(len);
    Some((rest.get(..len)?, rest.get(len..)?))
}

// ---- DS ------------------------------------------------------------------------------------------

/// DS: `key-tag algorithm digest-type digest`, decimal numbers and a hexadecimal digest.
// Source: "Supported DNS record types", DS: "The first three values are decimal numbers
// representing the key tag, algorithm, and digest type. The fourth value is the digest of the
// zone key"; the fields and their wire form are those of RFC 4034 section 5.
fn read_ds(text: &str) -> Option<RecordData> {
    let fields: Vec<&str> = text.split_whitespace().collect();
    let [tag, algorithm, digest_type, digest @ ..] = fields.as_slice() else {
        return None;
    };
    let mut wire = Vec::new();
    wire.extend_from_slice(&decimal::<u16>(tag)?.to_be_bytes());
    wire.push(decimal::<u8>(algorithm)?);
    wire.push(decimal::<u8>(digest_type)?);
    let digest = hex_decode(&digest.concat())?;
    if digest.is_empty() {
        return None;
    }
    wire.extend_from_slice(&digest);
    RecordData::from_wire(DS, &wire).ok()
}

/// DS: the four documented fields from the wire data.
fn write_ds(data: &RecordData) -> Option<String> {
    let wire = data.to_wire(DS).ok()?;
    let [tag_hi, tag_lo, algorithm, digest_type, digest @ ..] = wire.as_slice() else {
        return None;
    };
    if digest.is_empty() {
        return None;
    }
    let tag = u16::from_be_bytes([*tag_hi, *tag_lo]);
    Some(format!(
        "{tag} {algorithm} {digest_type} {}",
        hex_encode(digest)
    ))
}

// ---- NAPTR ---------------------------------------------------------------------------------------

/// NAPTR: `order preference "flags" "service" "regexp" replacement`.
// Source: "Supported DNS record types", NAPTR: "six space-separated values"; order and
// preference 0-65535; flags, service and regexp "Enclose ... in quotation marks"; replacement
// a fully qualified domain name, "." when a regexp is given; the wire form is RFC 3403 section
// 4.1.
fn read_naptr(text: &str) -> Option<RecordData> {
    let mut rest = text.trim();
    let (order, tail) = rest.split_once(char::is_whitespace)?;
    rest = tail.trim_start();
    let (preference, tail) = rest.split_once(char::is_whitespace)?;
    rest = tail.trim_start();
    let mut wire = Vec::new();
    wire.extend_from_slice(&decimal::<u16>(order)?.to_be_bytes());
    wire.extend_from_slice(&decimal::<u16>(preference)?.to_be_bytes());
    for _ in 0..3 {
        let (string, tail) = quoted(rest)?;
        if !tail.starts_with(char::is_whitespace) {
            return None;
        }
        push_character_string(&mut wire, &string)?;
        rest = tail.trim_start();
    }
    let replacement = rest.trim_end();
    if replacement.contains('\\') || replacement.contains(char::is_whitespace) {
        return None;
    }
    let target = TargetName::parse(replacement).ok()?;
    wire.extend_from_slice(target.wire());
    RecordData::from_wire(NAPTR, &wire).ok()
}

/// NAPTR: the six documented fields from the wire data. Flags and service are written only
/// when they are printable ASCII without `"` and `\` (the page gives no escapes for them); the
/// regexp with the documented escapes; the replacement only when its labels hold `a-z`, `0-9`
/// and `-`, the characters the page allows.
// Source: "Supported DNS record types", NAPTR, Regexp: printable ASCII, `\"`, `\\`, "Specify
// all other values ... in octal format"; Replacement: "The domain name can include a-z, 0-9,
// and - (hyphen)".
fn write_naptr(data: &RecordData) -> Option<String> {
    let wire = data.to_wire(NAPTR).ok()?;
    let (order, rest) = wire.split_at_checked(2)?;
    let (preference, rest) = rest.split_at_checked(2)?;
    let (flags, rest) = character_string(rest)?;
    let (service, rest) = character_string(rest)?;
    let (regexp, rest) = character_string(rest)?;
    let replacement = naptr_replacement(rest)?;
    let simple = |bytes: &[u8]| {
        bytes
            .iter()
            .all(|b| (0x20..=0x7e).contains(b) && *b != b'"' && *b != b'\\')
    };
    if !simple(flags) || !simple(service) {
        return None;
    }
    let mut out = format!(
        "{} {} ",
        u16::from_be_bytes([*order.first()?, *order.get(1)?]),
        u16::from_be_bytes([*preference.first()?, *preference.get(1)?])
    );
    quote(&mut out, flags, false)?;
    out.push(' ');
    quote(&mut out, service, false)?;
    out.push(' ');
    quote(&mut out, regexp, true)?;
    out.push(' ');
    out.push_str(&replacement);
    Some(out)
}

/// The replacement name of NAPTR wire data (the whole rest), in text, or `None` for a label
/// with a character the documentation does not allow.
fn naptr_replacement(wire: &[u8]) -> Option<String> {
    let mut labels = Vec::new();
    let mut rest = wire;
    loop {
        let (label, tail) = character_string(rest)?;
        if label.is_empty() {
            if !tail.is_empty() {
                return None;
            }
            break;
        }
        if !label
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        {
            return None;
        }
        labels.push(String::from_utf8(label.to_vec()).ok()?);
        rest = tail;
    }
    Some(if labels.is_empty() {
        ".".to_owned()
    } else {
        format!("{}.", labels.join("."))
    })
}

// ---- Numbers and hexadecimal ---------------------------------------------------------------------

/// A decimal number of type `T`, digits only.
fn decimal<T: std::str::FromStr>(text: &str) -> Option<T> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(rtype: RecordType, text: &str) -> RecordData {
        RecordData::parse(rtype, text).unwrap()
    }

    #[test]
    fn txt_strings_use_octal_escapes() {
        let value = Txt::new("ex\u{e4}mple \"q\"".as_bytes())
            .unwrap()
            .to_data()
            .unwrap();
        let text = encode(RecordType::TXT, &value).unwrap();
        assert_eq!(text, "\"ex\\303\\244mple \\\"q\\\"\"");
        assert_eq!(read(RecordType::TXT, &text), value);
        // The documented example: an accented e in octal.
        let e = read(RecordType::TXT, "\"caf\\351\"");
        assert!(e.is_canonical());
        assert_eq!(e.as_str(), "\"caf\\233\"");
        // A backslash is not sent; decimal-looking escapes that are not octal are not read.
        let backslash = Txt::new("a\\b").unwrap().to_data().unwrap();
        assert_eq!(encode(RecordType::TXT, &backslash), None);
        assert!(!read(RecordType::TXT, "\"a\\9bc\"").is_canonical());
        assert!(!read(RecordType::TXT, "\"a\\400\"").is_canonical());
        assert!(!read(RecordType::TXT, "\"open").is_canonical());
        assert!(!read(RecordType::TXT, "\"a\"x").is_canonical());
        // Unquoted text is the value itself.
        assert_eq!(
            read(RecordType::TXT, "plain"),
            Txt::new("plain").unwrap().to_data().unwrap()
        );
    }

    #[test]
    fn long_txt_is_cut_into_255_octet_strings() {
        let value = Txt::new(vec![b'x'; 600]).unwrap().to_data().unwrap();
        let text = encode(RecordType::TXT, &value).unwrap();
        let parts: Vec<&str> = text.split(' ').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 257);
        assert_eq!(read(RecordType::TXT, &text), value);
    }

    #[test]
    fn spf_ds_and_naptr_go_through_wire_data() {
        let spf = read(SPF, "\"v=spf1 -all\"");
        assert!(spf.is_canonical());
        assert!(spf.as_str().starts_with("\\# "), "{spf}");
        assert_eq!(encode(SPF, &spf).unwrap(), "\"v=spf1 -all\"");

        let ds = read(DS, "123 4 5 1234567890ABCDEF");
        assert!(ds.is_canonical(), "{ds}");
        assert_eq!(encode(DS, &ds).unwrap(), "123 4 5 1234567890abcdef");
        assert!(!read(DS, "123 4 5").is_canonical());
        assert!(!read(DS, "123 4 5 abc").is_canonical());

        let text = "100 50 \"u\" \"E2U+sip\" \"!^(\\\\+441632960083)$!sip:\\\\1@example.com!\" .";
        let naptr = read(NAPTR, text);
        assert!(naptr.is_canonical(), "{naptr}");
        assert_eq!(encode(NAPTR, &naptr).unwrap(), text);
        let replacement = read(NAPTR, "10 20 \"s\" \"SIP+D2U\" \"\" _sip._udp.example.com.");
        assert!(replacement.is_canonical());
        // `_` is not among the characters the page allows in a replacement.
        assert_eq!(encode(NAPTR, &replacement), None);
        let plain = read(NAPTR, "10 20 \"s\" \"SIP+D2U\" \"\" sip.example.com");
        assert_eq!(
            encode(NAPTR, &plain).unwrap(),
            "10 20 \"s\" \"SIP+D2U\" \"\" sip.example.com."
        );
    }

    #[test]
    fn other_types_read_the_documented_examples() {
        for (rtype, text, canonical) in [
            (RecordType::A, "192.0.2.1", "192.0.2.1"),
            (
                RecordType::AAAA,
                "2001:0db8:85a3:0:0:8a2e:0370:7334",
                "2001:db8:85a3::8a2e:370:7334",
            ),
            (
                RecordType::CAA,
                "0 issue \"ca.example.net\"",
                "0 issue \"ca.example.net\"",
            ),
            (
                RecordType::CNAME,
                "hostname.example.com",
                "hostname.example.com.",
            ),
            (
                RecordType::MX,
                "10 mail.example.com",
                "10 mail.example.com.",
            ),
            (
                RecordType::SRV,
                "10 5 80 hostname.example.com",
                "10 5 80 hostname.example.com.",
            ),
            (
                RecordType::SSHFP,
                "1 1 09F6A01D2175742B257C6B98B7C72C44C4040683",
                "1 1 09f6a01d2175742b257c6b98b7c72c44c4040683",
            ),
            (
                RecordType::HTTPS,
                "16 example.com alpn=\"h2,h3\" port=808",
                "16 example.com. alpn=\"h2,h3\" port=808",
            ),
            (
                RecordType::SOA,
                "ns-2048.awsdns-64.net hostmaster.awsdns.com 1 1 1 1 60",
                "ns-2048.awsdns-64.net. hostmaster.awsdns.com. 1 1 1 1 60",
            ),
        ] {
            let read = read(rtype, text);
            assert_eq!(read, data(rtype, canonical), "{rtype}");
        }
        assert!(!read(RecordType::CNAME, "a\\052b.example.com").is_canonical());
    }

    #[test]
    fn writes_avoid_what_is_not_established() {
        assert_eq!(
            encode(RecordType::AAAA, &data(RecordType::AAAA, "2001:db8::1")).unwrap(),
            "2001:db8:0:0:0:0:0:1"
        );
        let svcb = data(RecordType::SVCB, "1 . key65000=\"x\"");
        assert_eq!(encode(RecordType::SVCB, &svcb), None);
        let high = data(RecordType::HTTPS, "40000 example.com.");
        assert_eq!(encode(RecordType::HTTPS, &high), None);
        let caa = data(RecordType::CAA, "0 issue \"a\\\"b\"");
        assert_eq!(encode(RecordType::CAA, &caa), None);
        let soa = data(
            RecordType::SOA,
            "ns.example.org. admin.example.org. 1 2 3 4 5",
        );
        assert_eq!(encode(RecordType::SOA, &soa), None);
        assert_eq!(
            encode(RecordType::A, &RecordData::non_canonical("odd")),
            None
        );
    }
}
