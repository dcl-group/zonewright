//! The mapping between a record's `content` and `RecordData`, in both directions.
//!
//! `content` is a JSON array: "The exact length of the array depends on the type of rrset, each
//! individual record parameter must be a separate element of the array", with the examples
//! `SRV-record: [100, 1, 5061, "example.com"]` and `CNAME-record: ["the.target.domain"]` (the
//! Gcore spec and the EdgeCenter spec, `InputResourceRecord.content`). The form per type:
//!
//! | Type          | `content`                         | Source                                          |
//! | ------------- | --------------------------------- | ----------------------------------------------- |
//! | A, AAAA       | `["192.0.2.1"]`                   | the specs' examples; dns-update; the SDK        |
//! | CNAME, NS     | `["target.example.org"]`          | the specs' CNAME example; dns-update; the SDK   |
//! | MX            | `[10, "mail.example.org"]`        | dns-update (`record_to_content`); the SDK       |
//! | SRV           | `[10, 20, 5060, "sip.example.org"]` | the specs' example; dns-update; the SDK       |
//! | CAA           | `[0, "issue", "ca.example.net"]`  | dns-update; the SDK                             |
//! | TXT           | `["v=spf1 mx -all"]`              | Gcore's record guide (below); lego's fixture `create_rrset-request.json`; dns-update; the SDK |
//!
//! TXT: the string is the value itself, spaces inside included. Source for Gcore: the table of
//! `content` formats in
//! <https://docs.gcore.com/dns/dns-records/manage-dns-records-non-advanced-interface-mode>
//! ("TXT | `["text"]` | `["v=spf1 mx -all"]`"). For EdgeCenter no source shows a space: assumed
//! the same, by the common ancestry of the two APIs (the provider's certbot plugin expects
//! `"coexisting content"` in its own mock, which is the plugin's assumption, not an observation).
//! CAA: the value is one unquoted string as dns-update and the SDK write it; Gcore's control panel
//! asks for the value "enclosed in double quotes", which is a matter of the form, not of the
//! API's `content`.
//!
//! Sources: the specs (see `api.rs`); dns-update
//! <https://github.com/stalwartlabs/dns-update/blob/main/src/providers/gcore.rs>
//! (`record_to_content`, `parse_content`); the SDK `client_dto.go` (`ToContent`,
//! `ContentToString`). The specs' own MX example (`["mail1.example.com", "mail2.example.com"]`)
//! lists two hosts in one array, as their A and AAAA examples list two addresses, against the
//! rule "each individual record parameter must be a separate element"; the client follows the
//! rule and the two client codes, which agree.
//!
//! Names inside `content` are written as the specs' examples write them: fully qualified, without
//! the trailing dot (`the.target.domain`, `example.com`). They are read as absolute with or
//! without a trailing dot: the API spells every name that way (owner names, zone names), and
//! dns-update strips a trailing dot when it reads one.
//!
//! What no source establishes is not sent ([`write`] gives `None`, the record layer answers
//! `Error::InvalidInput`), unless the rrset already holds the value, which is then written back
//! exactly as the API returned it:
//!
//! - escapes: no source says how the API treats `"` or `\` inside a string, so a TXT or CAA value
//!   with either, or with a byte outside printable ASCII, and a name with an escaped octet are not
//!   sent; neither is TXT text with leading or trailing spaces (it could be trimmed);
//! - TXT values over 255 octets: whether the API splits or refuses a longer string is not
//!   documented, and a record with several strings has no documented form;
//! - the root name as a target.
//!
//! Content the client cannot read in this way (an element of another JSON type, a string with
//! whitespace, a quote or a backslash where the type has no text field, the wrong number of
//! elements) is kept as non-canonical data (design section 4.9), its text being the JSON array.

use serde_json::Value;

use crate::name::TargetName;
use crate::record::{Caa, Mx, RecordData, RecordType, Srv, Txt};

/// Most octets of a TXT string the client writes: one character-string (RFC 1035 section 3.3).
const MAX_STRING: usize = 255;

/// The text a number or a string element stands for in presentation format; `None` for an
/// element of another kind or a string that would not survive being joined with spaces.
fn element(value: &Value) -> Option<String> {
    match value {
        Value::Number(number) => number.as_u64().map(|n| n.to_string()),
        Value::String(text)
            if !text.is_empty()
                && !text
                    .chars()
                    .any(|c| c.is_whitespace() || c == '"' || c == '\\') =>
        {
            Some(text.clone())
        }
        _ => None,
    }
}

/// A non-negative number, as a JSON number or as a string of digits.
fn number(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
            text.parse().ok()
        }
        _ => None,
    }
}

/// `content` as non-canonical data: the JSON array as text.
pub(super) fn opaque(content: &[Value]) -> RecordData {
    RecordData::non_canonical(&serde_json::to_string(content).unwrap_or_default())
}

/// The value of TXT content: one string, whose bytes are the value. `None` for any other form
/// (no source gives one).
// Source: lego's fixture `create_rrset-request.json` (`"content": ["ADw2sEd8…"]`) and its reading
// of `content[0]`; dns-update `DnsRecord::TXT(content) => [String(content)]`; the EdgeCenter
// certbot plugin `record_content()` reads `content[0]`.
pub(super) fn read_txt(content: &[Value]) -> Option<Txt> {
    match content {
        [Value::String(text)] => Txt::new(text.as_bytes()).ok(),
        _ => None,
    }
}

/// A record's value as `RecordData`: canonical where the content has the form of its type,
/// non-canonical otherwise.
pub(super) fn read(rtype: RecordType, content: &[Value]) -> RecordData {
    let canonical = match rtype {
        RecordType::TXT => read_txt(content).and_then(|value| value.to_data().ok()),
        RecordType::CAA => match content {
            [flags, Value::String(tag), Value::String(value)] => number(flags)
                .and_then(|flags| u8::try_from(flags).ok())
                .and_then(|flags| {
                    Caa {
                        flags,
                        tag: tag.clone(),
                        value: value.as_bytes().to_vec(),
                    }
                    .to_data()
                    .ok()
                }),
            _ => None,
        },
        _ => content
            .iter()
            .map(element)
            .collect::<Option<Vec<String>>>()
            .filter(|parts| !parts.is_empty())
            .and_then(|parts| RecordData::parse(rtype, &parts.join(" ")).ok()),
    };
    canonical.unwrap_or_else(|| opaque(content))
}

/// Text the client writes as a string of its own: printable ASCII without `"` and `\`, without
/// leading or trailing spaces, 1 to `max` octets.
fn plain(bytes: &[u8], max: usize) -> Option<String> {
    let usable = (1..=max).contains(&bytes.len())
        && bytes
            .iter()
            .all(|&b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\')
        && bytes.first() != Some(&b' ')
        && bytes.last() != Some(&b' ');
    if usable {
        String::from_utf8(bytes.to_vec()).ok()
    } else {
        None
    }
}

/// A name as `content` carries it: absolute, without the trailing dot. `None` for the root and
/// for a name with an escaped octet.
fn name(target: &TargetName) -> Option<Value> {
    let text = target.to_string();
    if text.contains('\\') {
        return None;
    }
    text.strip_suffix('.')
        .filter(|name| !name.is_empty())
        .map(|name| Value::String(name.to_owned()))
}

/// The `content` of a new record holding `data`, or `None` when the client cannot send it (see
/// the module documentation).
pub(super) fn write(rtype: RecordType, data: &RecordData) -> Option<Vec<Value>> {
    if !data.is_canonical() {
        return None;
    }
    match rtype {
        RecordType::A | RecordType::AAAA => Some(vec![Value::String(data.as_str().to_owned())]),
        RecordType::CNAME | RecordType::NS => {
            let target = TargetName::parse(data.as_str()).ok()?;
            Some(vec![name(&target)?])
        }
        RecordType::MX => {
            let mx = Mx::from_data(data).ok()?;
            Some(vec![Value::from(mx.preference), name(&mx.exchange)?])
        }
        RecordType::SRV => {
            let srv = Srv::from_data(data).ok()?;
            Some(vec![
                Value::from(srv.priority),
                Value::from(srv.weight),
                Value::from(srv.port),
                name(&srv.target)?,
            ])
        }
        RecordType::CAA => {
            let caa = Caa::from_data(data).ok()?;
            let value = plain(&caa.value, usize::MAX)?;
            Some(vec![
                Value::from(caa.flags),
                Value::String(caa.tag),
                Value::String(value),
            ])
        }
        RecordType::TXT => {
            let txt = Txt::from_data(data).ok()?;
            Some(vec![Value::String(plain(txt.as_bytes(), MAX_STRING)?)])
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{read, write};
    use crate::record::{RecordData, RecordType};

    fn content(value: Value) -> Vec<Value> {
        match value {
            Value::Array(items) => items,
            other => panic!("not an array: {other}"),
        }
    }

    #[test]
    fn content_round_trips_per_type() {
        for (rtype, text, wire) in [
            (RecordType::A, "192.0.2.1", json!(["192.0.2.1"])),
            (RecordType::AAAA, "2001:db8::1", json!(["2001:db8::1"])),
            (
                RecordType::CNAME,
                "target.example.org.",
                json!(["target.example.org"]),
            ),
            (
                RecordType::NS,
                "ns1.example.net.",
                json!(["ns1.example.net"]),
            ),
            (
                RecordType::MX,
                "10 mail.example.org.",
                json!([10, "mail.example.org"]),
            ),
            (
                RecordType::SRV,
                "10 20 5060 sip.example.org.",
                json!([10, 20, 5060, "sip.example.org"]),
            ),
            (
                RecordType::CAA,
                "0 issue \"ca.example.net\"",
                json!([0, "issue", "ca.example.net"]),
            ),
            (RecordType::TXT, "\"v=spf1 -all\"", json!(["v=spf1 -all"])),
        ] {
            let data = RecordData::parse(rtype, text).unwrap();
            let sent = write(rtype, &data).unwrap();
            assert_eq!(Value::Array(sent.clone()), wire, "{rtype} {text}");
            assert_eq!(read(rtype, &sent), data, "{rtype} {text}");
        }
    }

    #[test]
    fn names_with_a_trailing_dot_and_numbers_as_strings_are_read() {
        let mx = RecordData::parse(RecordType::MX, "10 mail.example.org.").unwrap();
        assert_eq!(
            read(RecordType::MX, &content(json!([10, "mail.example.org."]))),
            mx
        );
        assert_eq!(
            read(RecordType::MX, &content(json!(["10", "mail.example.org"]))),
            mx
        );
    }

    #[test]
    fn other_forms_are_non_canonical() {
        for (rtype, wire) in [
            (RecordType::MX, json!(["mail.example.org"])),
            (RecordType::MX, json!([10, "mail.example.org", 3])),
            (RecordType::A, json!(["192.0.2.1", "192.0.2.2"])),
            (RecordType::A, json!([["192.0.2.1"]])),
            (RecordType::A, json!([])),
            (RecordType::CNAME, json!(["a b"])),
            (RecordType::TXT, json!(["a", "b"])),
            (RecordType::TXT, json!([1])),
            (RecordType::CAA, json!([256, "issue", "ca"])),
            (RecordType::SRV, json!([-1, 0, 0, "sip.example.org"])),
        ] {
            let data = read(rtype, &content(wire.clone()));
            assert!(!data.is_canonical(), "{rtype} {wire}");
            assert_eq!(data.as_str(), wire.to_string(), "{rtype} {wire}");
        }
    }

    #[test]
    fn what_no_source_establishes_is_not_sent() {
        for (rtype, text) in [
            (RecordType::TXT, "\"quo\\\"te\""),
            (RecordType::TXT, "\"back\\\\slash\""),
            (RecordType::TXT, "\"caf\\195\\169\""),
            (RecordType::TXT, "\" padded\""),
            (RecordType::CAA, "0 issue \"a\\\"b\""),
            (RecordType::MX, "0 ."),
            (RecordType::SRV, "0 0 0 ."),
            (RecordType::CNAME, "we\\.ird.example.org."),
            (RecordType::PTR, "host.example.org."),
            (RecordType::DNAME, "other.example.net."),
        ] {
            let data = RecordData::parse(rtype, text).unwrap();
            assert_eq!(write(rtype, &data), None, "{rtype} {text}");
        }
        let long = format!("\"{}\"", "x".repeat(256));
        let data = RecordData::parse(RecordType::TXT, &long).unwrap();
        assert_eq!(write(RecordType::TXT, &data), None);
    }
}
