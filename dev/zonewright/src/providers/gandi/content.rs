//! The mapping between an rrset value as the API spells it and `RecordData`, in both directions.
//! The record layer (`records.rs`) and the TXT value operations (`txt.rs`) use these functions
//! and nothing else, so both levels agree on what a value holds and what can be sent.
//!
//! An rrset carries its values as strings in `rrset_values` (LiveDNS API reference,
//! <https://api.gandi.net/docs/livedns/>). The form per type, with its source:
//!
//! | Type  | Value                                      | Source                                         |
//! | ----- | ------------------------------------------ | ---------------------------------------------- |
//! | A     | `192.0.2.1`                                | the reference's examples                       |
//! | AAAA  | `2001:db8::1`                              | the reference's examples                       |
//! | CNAME | `www.example.net.`                         | the reference's listing example                |
//! | MX    | `10 spool.mail.gandi.net.`                 | the reference's snapshot example               |
//! | TXT   | `"v=spf1 include:_mailcust.gandi.net ?all"` | the reference's create and listing examples   |
//! | NS    | `ns1.example.net.`                         | dns-update `providers/gandiv5.rs` (`into_fqdn`) |
//! | SRV   | `10 20 5060 sip.example.org.`              | dns-update `providers/gandiv5.rs` (`"{} {} {} {}"`) |
//!
//! These are the record types of `Capabilities::record_types`. CAA, TLSA and the other types of
//! the API's enumeration have no value form in the reference; dns-update writes CAA and TLSA
//! through a `to_string` of its own types, which does not show the form the API reads. They are
//! listed (canonical where their text parses) and not written.
//!
//! Names inside values. The reference spells them with the trailing dot (`www.example.net.`,
//! `10 spool.mail.gandi.net.`, the `PATCH` example `www.example.org.`), but its single-rrset
//! example reads `www.example.net` and its create examples write `www.example.org`, and it does
//! not say whether a name without the dot is relative to the zone or absolute. A value with a
//! name without the trailing dot is therefore read as non-canonical data (design section 4.9),
//! never as one reading or the other; the client writes names with the trailing dot.
//!
//! TXT (design section 4.4). The reference writes and lists TXT values as zone-file text in
//! double quotes: `"\"v=spf1 include:_mailcust.gandi.net ?all\""` in the create and replace
//! examples, the zone listing and the snapshot, and the quoted ACME token of the verification
//! example; dns-update writes `format!("\"{}\"", …)`. lego writes the value unquoted
//! (`internal/client.go`, `AddTXTRecord`), and the reference's examples of a create by name show
//! `"some-text-value"`. Reading is therefore `Auto`: text that starts with `"` is zone-file text
//! (one quoted string or several), anything else is the value itself, as long as it holds no
//! whitespace and no `"` (text the zone-file rule would split or that mixes the forms is
//! undecided). Writing is one quoted string. What no source establishes is not read as a value and
//! not sent:
//!
//! - a backslash in any value: no source says how the API treats an escape, so text with one is
//!   non-canonical data and never a value of the TXT value operations, and data whose canonical
//!   text needs one (a TXT value with `"` or `\`, a byte outside printable ASCII, a name with an
//!   escaped octet) is not sent;
//! - a TXT value over 255 octets, which needs several character-strings: none of the sources
//!   shows a value with several strings;
//! - an empty TXT value;
//! - the root name as a target (a null MX, an SRV "service not available").
//!
//! The documented limit of a value in a `PATCH` body is printable ASCII ("Pattern:
//! ^[\x20-\x7E]+$") of at most 16384 characters; every value the client writes is within it.

use crate::record::{RecordData, RecordType, Txt, TxtDialect};

/// How TXT text is read (module documentation).
const TXT_READ: TxtDialect = TxtDialect::Auto;

/// How a TXT value is written: one quoted string.
const TXT_WRITE: TxtDialect = TxtDialect::Presentation;

/// Most octets of a TXT value the client writes: one character-string (RFC 1035 section 3.3).
const MAX_STRING: usize = 255;

/// The value of TXT text, or `None` for text in a form no source settles (module
/// documentation): such a value is never equal to one of ours.
pub(super) fn read_txt(text: &str) -> Option<Txt> {
    if text.contains('\\') {
        return None;
    }
    let quoted = text.trim_start().starts_with('"');
    if !quoted && text.chars().any(|c| c.is_whitespace() || c == '"') {
        return None;
    }
    TXT_READ.read(text)
}

/// The positions (whitespace-separated fields) of the names in a value of `rtype`.
fn name_fields(rtype: RecordType) -> &'static [usize] {
    match rtype {
        RecordType::CNAME
        | RecordType::NS
        | RecordType::PTR
        | RecordType::DNAME
        | RecordType::ALIAS
        | RecordType::ANAME => &[0],
        RecordType::MX | RecordType::SVCB | RecordType::HTTPS => &[1],
        RecordType::SRV => &[3],
        RecordType::SOA => &[0, 1],
        _ => &[],
    }
}

/// Every name of the value is spelled with the trailing dot.
fn names_absolute(rtype: RecordType, text: &str) -> bool {
    let fields: Vec<&str> = text.split_whitespace().collect();
    name_fields(rtype)
        .iter()
        .all(|&at| fields.get(at).is_none_or(|field| field.ends_with('.')))
}

/// A value as `RecordData`: canonical where the text has the form of its type and every name in
/// it ends with a dot, non-canonical otherwise.
pub(super) fn read(rtype: RecordType, text: &str) -> RecordData {
    let canonical = if rtype == RecordType::TXT {
        read_txt(text).and_then(|value| value.to_data().ok())
    } else if text.contains('\\') || !names_absolute(rtype, text) {
        None
    } else {
        RecordData::parse(rtype, text).ok()
    };
    canonical.unwrap_or_else(|| RecordData::non_canonical(text))
}

/// The API's text for a new value of type `rtype` holding `data`, or `None` when the client
/// cannot send it (module documentation).
pub(super) fn write(rtype: RecordType, data: &RecordData) -> Option<String> {
    if !data.is_canonical() || data.as_str().contains('\\') {
        return None;
    }
    let last_field_is_root = || data.as_str().split_whitespace().last() == Some(".");
    match rtype {
        RecordType::A | RecordType::AAAA => Some(data.as_str().to_owned()),
        RecordType::CNAME | RecordType::NS | RecordType::MX | RecordType::SRV => {
            (!last_field_is_root()).then(|| data.as_str().to_owned())
        }
        RecordType::TXT => {
            let value = Txt::from_data(data).ok()?;
            let bytes = value.as_bytes();
            let usable = (1..=MAX_STRING).contains(&bytes.len())
                && bytes
                    .iter()
                    .all(|&b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\');
            if usable {
                TXT_WRITE.write(&value)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The API's text for a TXT value being added by the value operations: the record level's rule.
pub(super) fn write_txt(value: &Txt) -> Option<String> {
    write(RecordType::TXT, &value.to_data().ok()?)
}

#[cfg(test)]
mod tests {
    use super::{read, read_txt, write, write_txt};
    use crate::record::{RecordData, RecordType, Txt};

    fn rd(rtype: RecordType, text: &str) -> RecordData {
        RecordData::parse(rtype, text).unwrap()
    }

    #[test]
    fn values_round_trip_per_type() {
        for (rtype, text) in [
            (RecordType::A, "192.0.2.1"),
            (RecordType::AAAA, "2001:db8::1"),
            (RecordType::CNAME, "www.example.net."),
            (RecordType::NS, "ns1.example.net."),
            (RecordType::MX, "10 spool.mail.gandi.net."),
            (RecordType::SRV, "10 20 5060 sip.example.org."),
            (
                RecordType::TXT,
                "\"v=spf1 include:_mailcust.gandi.net ?all\"",
            ),
        ] {
            let data = rd(rtype, text);
            let sent = write(rtype, &data).unwrap();
            assert_eq!(sent, text, "{rtype}");
            assert_eq!(read(rtype, &sent), data, "{rtype}");
        }
    }

    #[test]
    fn txt_is_read_quoted_or_bare() {
        let value = |s: &str| Some(Txt::new(s).unwrap());
        assert_eq!(read_txt("\"abc\""), value("abc"));
        assert_eq!(read_txt("abc"), value("abc"));
        assert_eq!(read_txt("\"a b\" \"c\""), value("a bc"));
        assert_eq!(read_txt("\"a b\""), value("a b"));
        // Undecided forms.
        for text in ["a b", "ab\"c", "\"a\\\"b\"", "\"open", "x\\y"] {
            assert_eq!(read_txt(text), None, "{text}");
            assert!(!read(RecordType::TXT, text).is_canonical(), "{text}");
        }
    }

    #[test]
    fn names_without_the_dot_are_non_canonical() {
        for (rtype, text) in [
            (RecordType::CNAME, "www.example.net"),
            (RecordType::MX, "10 mail.example.org"),
            (RecordType::SRV, "0 5 443 host.example.org"),
            (RecordType::CNAME, "@"),
            (RecordType::A, "192.0.2"),
        ] {
            let data = read(rtype, text);
            assert!(!data.is_canonical(), "{rtype} {text}");
            assert_eq!(data.as_str(), text);
        }
    }

    #[test]
    fn what_no_source_establishes_is_not_sent() {
        for (rtype, text) in [
            (RecordType::TXT, "\"quo\\\"te\""),
            (RecordType::TXT, "\"back\\\\slash\""),
            (RecordType::TXT, "\"caf\\195\\169\""),
            (RecordType::TXT, "\"\""),
            (RecordType::MX, "0 ."),
            (RecordType::SRV, "0 0 0 ."),
            (RecordType::CNAME, "we\\.ird.example.org."),
            (RecordType::CAA, "0 issue \"ca.example.net\""),
            (RecordType::PTR, "host.example.org."),
        ] {
            assert_eq!(write(rtype, &rd(rtype, text)), None, "{rtype} {text}");
        }
        let long = format!("\"{}\"", "x".repeat(256));
        assert_eq!(write(RecordType::TXT, &rd(RecordType::TXT, &long)), None);
        assert_eq!(
            write(RecordType::A, &RecordData::non_canonical("192.0.2.1")),
            None
        );
    }

    #[test]
    fn value_operations_write_the_record_level_form() {
        assert_eq!(
            write_txt(&Txt::new("token-1").unwrap()).as_deref(),
            Some("\"token-1\"")
        );
        assert_eq!(write_txt(&Txt::new("a\"b").unwrap()), None);
    }
}
