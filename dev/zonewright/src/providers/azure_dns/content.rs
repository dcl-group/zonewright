//! Record content: the properties of a record set per type, and the mapping between the API's
//! record objects and `RecordData`. One rule per fact, used by the record layer (`records.rs`)
//! and the TXT value layer (`txt.rs`) alike.
//!
//! # Record objects
//!
//! Each type has its own property and object shape (Create Or Update, definitions and one
//! example per type, <https://learn.microsoft.com/en-us/rest/api/dns/record-sets/create-or-update?view=rest-dns-2018-05-01>):
//!
//! | Type  | Property      | Object                                                          |
//! | ----- | ------------- | --------------------------------------------------------------- |
//! | A     | `ARecords`    | `{"ipv4Address"}`                                               |
//! | AAAA  | `AAAARecords` | `{"ipv6Address"}`                                               |
//! | CAA   | `caaRecords`  | `{"flags", "tag", "value"}`                                     |
//! | CNAME | `CNAMERecord` | `{"cname"}`, one object, not a list                             |
//! | MX    | `MXRecords`   | `{"preference", "exchange"}`                                    |
//! | NS    | `NSRecords`   | `{"nsdname"}`                                                   |
//! | PTR   | `PTRRecords`  | `{"ptrdname"}`                                                  |
//! | SOA   | `SOARecord`   | `{"host", "email", "serialNumber", "refreshTime", "retryTime", "expireTime", "minimumTTL"}`, one object |
//! | SRV   | `SRVRecords`  | `{"priority", "weight", "port", "target"}`                      |
//! | TXT   | `TXTRecords`  | `{"value": [strings]}`                                          |
//!
//! # Names inside records
//!
//! The documentation's examples give every name without the trailing dot and as a full name
//! (`"exchange": "mail.contoso.com"`, `"ptrdname": "localhost"` in a reverse zone), so a name is
//! read as absolute whether or not it ends with a dot, and written without the dot. Whether the
//! service accepts a trailing dot is not documented. A name with a character outside printable
//! ASCII, a space, `"` or `\` is read as non-canonical data and never sent: the documentation
//! gives no escape rule for names. The root (`.`, a null MX or SRV target) is not sent either:
//! its spelling at the API is not documented. Both are assumptions, conservative.
//!
//! # TXT strings
//!
//! A TXT record is a list of strings ("When calling the Azure DNS REST API, you need to specify
//! each TXT string separately", "Each … can be up to 255 characters", Records,
//! <https://learn.microsoft.com/en-us/azure/dns/dns-zones-records>), and the service applies the
//! escape rules of RFC 1035 to them ("`\` escapes … To store `A\B` send `A\\B`", FAQ,
//! <https://learn.microsoft.com/en-us/azure/dns/dns-faq>). How a string with an escape is
//! returned is not documented. The rule of this client, for reading and writing alike: a string
//! of printable ASCII (`0x20` to `0x7e`) without `"` and `\` stands for itself. A value of such
//! bytes, one octet or longer, is sent as strings of at most 255 octets, the last one shorter;
//! a record whose strings are all of that form, at most 255 octets each and not all empty, is
//! read as their concatenation. Anything else is a foreign value the client never takes for
//! one of its own: it is kept as non-canonical data and written back exactly as read. That a
//! space stands for itself is an assumption, not observed against the live API. CAA values
//! follow the same rule.

use serde_json::{Map, Value, json};

use crate::error::Error;
use crate::record::{Caa, Mx, RecordData, RecordType, Srv, Txt};
use crate::redact::Detail;

use super::api::RecordSet;

/// The longest TXT string.
const STRING_MAX: usize = 255;

/// The record properties of the API, one per type.
const RECORD_KEYS: [&str; 10] = [
    "ARecords",
    "AAAARecords",
    "caaRecords",
    "CNAMERecord",
    "MXRecords",
    "NSRecords",
    "PTRRecords",
    "SOARecord",
    "SRVRecords",
    "TXTRecords",
];

/// Properties that are returned but not written: absent from the request body's definition of
/// Create Or Update, present in the `RecordSet` of its answers.
const READ_ONLY: [&str; 2] = ["fqdn", "provisioningState"];

/// The other properties of a record set the reference documents: `metadata`, `TTL` and
/// `targetResource`. A property outside these, [`RECORD_KEYS`] and [`READ_ONLY`] is unknown to
/// the client, and it does not write such a record set (assumed, conservative: it could carry
/// data a write would lose or change).
const OTHER_KEYS: [&str; 3] = ["metadata", "TTL", "targetResource"];

/// The property holding the records of `type_name` and whether it holds one object instead of
/// a list; `None` for a type the stable API version does not have.
pub(super) fn record_key(type_name: &str) -> Option<(&'static str, bool)> {
    Some(match type_name {
        "A" => ("ARecords", false),
        "AAAA" => ("AAAARecords", false),
        "CAA" => ("caaRecords", false),
        "CNAME" => ("CNAMERecord", true),
        "MX" => ("MXRecords", false),
        "NS" => ("NSRecords", false),
        "PTR" => ("PTRRecords", false),
        "SOA" => ("SOARecord", true),
        "SRV" => ("SRVRecords", false),
        "TXT" => ("TXTRecords", false),
        _ => return None,
    })
}

impl RecordSet {
    /// The TTL as returned, if it is a number of seconds the crate can hold.
    pub(super) fn ttl(&self) -> Option<u32> {
        self.properties
            .get("TTL")
            .and_then(Value::as_u64)
            .and_then(|ttl| u32::try_from(ttl).ok())
    }

    /// An alias record set: `targetResource` names an Azure resource ("A reference to an azure
    /// resource from where the dns resource value is taken", Create Or Update), and the record
    /// list is absent. Not a plain rrset (design section 3.4).
    pub(super) fn is_alias(&self) -> bool {
        has_id(self.properties.get("targetResource"))
    }

    /// The record objects of the set's own type: none when the property is absent or `null`. A
    /// type the client does not know, or a property of an unexpected shape, is an answer it
    /// cannot interpret.
    pub(super) fn records(&self) -> Result<Vec<Value>, Error> {
        let (key, single) = record_key(&self.type_name).ok_or_else(|| {
            protocol("the provider returned a record set of a type the client does not know")
        })?;
        match (self.properties.get(key), single) {
            (None | Some(Value::Null), _) => Ok(Vec::new()),
            (Some(object @ Value::Object(_)), true) => Ok(vec![object.clone()]),
            (Some(Value::Array(items)), false) if items.iter().all(Value::is_object) => {
                Ok(items.clone())
            }
            _ => Err(protocol(
                "the provider's record set holds its records in an unexpected form",
            )),
        }
    }

    /// Why the client does not write this record set back, if it does not: it is an alias, or
    /// it carries a property the client does not know, or records of another type.
    pub(super) fn unwritable(&self) -> Option<Error> {
        if self.is_alias() {
            return Some(not_plain());
        }
        let own = record_key(&self.type_name).map(|(key, _)| key);
        let unknown = self.properties.iter().any(|(key, value)| {
            let known = RECORD_KEYS.contains(&key.as_str())
                || READ_ONLY.contains(&key.as_str())
                || OTHER_KEYS.contains(&key.as_str());
            let foreign_records =
                RECORD_KEYS.contains(&key.as_str()) && Some(key.as_str()) != own && !empty(value);
            !known || foreign_records
        });
        unknown.then(|| Error::Rejected {
            status: None,
            detail: Detail::constant(
                "the record set carries a property the client does not know; it is not \
                 written, so that nothing of it is lost",
            ),
            code: None,
        })
    }

    /// The body of a `PUT` that replaces this record set (or, with `prior` `None`, creates
    /// one): the properties as read, without the read-only ones, with `records` under the
    /// type's property and the TTL. `ttl` `None` keeps the TTL as read and gives a set without
    /// one `fallback`.
    pub(super) fn body(
        prior: Option<&RecordSet>,
        type_name: &str,
        records: Vec<Value>,
        ttl: Option<u32>,
        fallback: u32,
    ) -> Result<Value, Error> {
        let (key, single) = record_key(type_name)
            .ok_or_else(|| protocol("the client cannot write a record set of this type"))?;
        let mut properties: Map<String, Value> =
            prior.map(|p| p.properties.clone()).unwrap_or_default();
        for key in READ_ONLY {
            properties.remove(key);
        }
        // An empty reference, an empty map and the empty record lists of other types carry
        // nothing.
        if properties
            .get("targetResource")
            .is_some_and(|t| !has_id(Some(t)))
        {
            properties.remove("targetResource");
        }
        if properties.get("metadata").is_some_and(Value::is_null) {
            properties.remove("metadata");
        }
        for other in RECORD_KEYS.iter().filter(|k| **k != key) {
            if properties.get(*other).is_some_and(empty) {
                properties.remove(*other);
            }
        }
        let ttl = match ttl {
            Some(ttl) => Value::from(ttl),
            None => properties
                .get("TTL")
                .filter(|t| t.is_u64())
                .cloned()
                .unwrap_or_else(|| Value::from(fallback)),
        };
        properties.insert("TTL".to_owned(), ttl);
        let records = if single {
            match <[Value; 1]>::try_from(records) {
                Ok([one]) => one,
                Err(_) => {
                    return Err(protocol(
                        "a record set of this type holds exactly one record",
                    ));
                }
            }
        } else {
            Value::Array(records)
        };
        properties.insert(key.to_owned(), records);
        Ok(json!({ "properties": properties }))
    }
}

/// `value` names a resource: an object with a non-empty string `id`.
fn has_id(value: Option<&Value>) -> bool {
    value
        .and_then(|t| t.get("id"))
        .and_then(Value::as_str)
        .is_some_and(|id| !id.is_empty())
}

/// `null`, an empty list or an empty object.
fn empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(items) => items.is_empty(),
        Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

/// A byte that stands for itself in a TXT string or a CAA value (module documentation).
fn plain_byte(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\'
}

/// The value of a TXT record object, by the rule of the module documentation; `None` for a
/// record outside it.
pub(super) fn read_txt(item: &Value) -> Option<Txt> {
    let strings = item.get("value")?.as_array()?;
    let mut data = Vec::new();
    for string in strings {
        let string = string.as_str()?;
        if string.len() > STRING_MAX || !string.bytes().all(plain_byte) {
            return None;
        }
        data.extend_from_slice(string.as_bytes());
    }
    if data.is_empty() {
        return None;
    }
    Txt::new(data).ok()
}

/// The strings of a TXT value, by the rule of the module documentation; `None` for a value the
/// client does not send.
pub(super) fn txt_strings(value: &Txt) -> Option<Vec<String>> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes.iter().copied().all(plain_byte) {
        return None;
    }
    bytes
        .chunks(STRING_MAX)
        .map(|chunk| String::from_utf8(chunk.to_vec()).ok())
        .collect()
}

/// A TXT record object holding `value`.
pub(super) fn txt_record(value: &Txt) -> Option<Value> {
    txt_strings(value).map(|strings| json!({ "value": strings }))
}

/// A name inside a record as the API returns it, as absolute text with the trailing dot; `None`
/// for a name outside the client's rule (module documentation).
fn read_name(item: &Value, key: &str) -> Option<String> {
    let name = item.get(key)?.as_str()?;
    let usable =
        !name.is_empty() && name != "." && name.bytes().all(|b| plain_byte(b) && b != b' ');
    usable.then(|| {
        if name.ends_with('.') {
            name.to_owned()
        } else {
            format!("{name}.")
        }
    })
}

/// A name of canonical record data as the API takes it: without the trailing dot; `None` for
/// the root and a name with an escape.
fn write_name(text: &str) -> Option<String> {
    let bare = text.strip_suffix('.')?;
    (!bare.is_empty() && bare.bytes().all(|b| plain_byte(b) && b != b' ')).then(|| bare.to_owned())
}

fn number(item: &Value, key: &str) -> Option<u64> {
    item.get(key)?.as_u64()
}

/// The canonical text of a record object of `rtype`, or `None` when it is outside the forms the
/// client reads.
fn text_of(rtype: RecordType, item: &Value) -> Option<String> {
    let text = |key: &str| item.get(key).and_then(Value::as_str).map(str::to_owned);
    Some(match rtype {
        RecordType::A => text("ipv4Address")?,
        RecordType::AAAA => text("ipv6Address")?,
        RecordType::CNAME => read_name(item, "cname")?,
        RecordType::NS => read_name(item, "nsdname")?,
        RecordType::PTR => read_name(item, "ptrdname")?,
        RecordType::MX => format!(
            "{} {}",
            number(item, "preference")?,
            read_name(item, "exchange")?
        ),
        RecordType::SRV => format!(
            "{} {} {} {}",
            number(item, "priority")?,
            number(item, "weight")?,
            number(item, "port")?,
            read_name(item, "target")?
        ),
        RecordType::CAA => {
            let flags = u8::try_from(number(item, "flags")?).ok()?;
            let tag = text("tag")?;
            let value = text("value")?;
            if !value.bytes().all(plain_byte) {
                return None;
            }
            let caa = Caa {
                flags,
                tag,
                value: value.into_bytes(),
            };
            return caa.to_data().ok().map(|data| data.as_str().to_owned());
        }
        RecordType::TXT => {
            return read_txt(item)?
                .to_data()
                .ok()
                .map(|data| data.as_str().to_owned());
        }
        RecordType::SOA => format!(
            "{} {} {} {} {} {} {}",
            read_name(item, "host")?,
            read_name(item, "email")?,
            number(item, "serialNumber")?,
            number(item, "refreshTime")?,
            number(item, "retryTime")?,
            number(item, "expireTime")?,
            number(item, "minimumTTL")?
        ),
        _ => return None,
    })
}

/// A record object of `rtype` as `RecordData`: canonical where it has a form the client reads,
/// otherwise non-canonical data holding the object's JSON text (design section 4.9).
pub(super) fn read(rtype: RecordType, item: &Value) -> RecordData {
    text_of(rtype, item)
        .and_then(|text| RecordData::parse(rtype, &text).ok())
        .unwrap_or_else(|| RecordData::non_canonical(&item.to_string()))
}

/// The record object of canonical `data` of `rtype`, or `None` when the client does not send it
/// (non-canonical data, a value outside the rules of the module documentation, SOA).
pub(super) fn write(rtype: RecordType, data: &RecordData) -> Option<Value> {
    if !data.is_canonical() {
        return None;
    }
    Some(match rtype {
        RecordType::A => json!({ "ipv4Address": data.as_str() }),
        RecordType::AAAA => json!({ "ipv6Address": data.as_str() }),
        RecordType::CNAME => json!({ "cname": write_name(data.as_str())? }),
        RecordType::NS => json!({ "nsdname": write_name(data.as_str())? }),
        RecordType::PTR => json!({ "ptrdname": write_name(data.as_str())? }),
        RecordType::MX => {
            let mx = Mx::from_data(data).ok()?;
            json!({
                "preference": mx.preference,
                "exchange": write_name(mx.exchange.as_str())?,
            })
        }
        RecordType::SRV => {
            let srv = Srv::from_data(data).ok()?;
            json!({
                "priority": srv.priority,
                "weight": srv.weight,
                "port": srv.port,
                "target": write_name(srv.target.as_str())?,
            })
        }
        RecordType::CAA => {
            let caa = Caa::from_data(data).ok()?;
            if !caa.value.iter().copied().all(plain_byte) {
                return None;
            }
            json!({
                "flags": caa.flags,
                "tag": caa.tag,
                "value": String::from_utf8(caa.value).ok()?,
            })
        }
        RecordType::TXT => txt_record(&Txt::from_data(data).ok()?)?,
        _ => return None,
    })
}

/// An alias record set: refused by every operation on its name and type (design section 3.4).
pub(super) fn not_plain() -> Error {
    Error::Rejected {
        status: None,
        detail: Detail::constant(
            "the record set is an alias to an Azure resource; it is not read or changed as an \
             rrset",
        ),
        code: None,
    }
}

pub(super) fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{read, read_txt, txt_strings, write};
    use crate::record::{RecordData, RecordType, Txt};

    fn rd(rtype: RecordType, text: &str) -> RecordData {
        RecordData::parse(rtype, text).unwrap()
    }

    #[test]
    fn records_are_read_in_the_documented_form() {
        for (rtype, item, text) in [
            (
                RecordType::A,
                json!({"ipv4Address": "127.0.0.1"}),
                "127.0.0.1",
            ),
            (RecordType::AAAA, json!({"ipv6Address": "::1"}), "::1"),
            (
                RecordType::CNAME,
                json!({"cname": "contoso.com"}),
                "contoso.com.",
            ),
            (
                RecordType::NS,
                json!({"nsdname": "ns1.contoso.com."}),
                "ns1.contoso.com.",
            ),
            (
                RecordType::PTR,
                json!({"ptrdname": "localhost"}),
                "localhost.",
            ),
            (
                RecordType::MX,
                json!({"preference": 0, "exchange": "mail.contoso.com"}),
                "0 mail.contoso.com.",
            ),
            (
                RecordType::SRV,
                json!({"priority": 0, "weight": 10, "port": 80, "target": "contoso.com"}),
                "0 10 80 contoso.com.",
            ),
            (
                RecordType::CAA,
                json!({"flags": 0, "tag": "issue", "value": "ca.contoso.com"}),
                "0 issue \"ca.contoso.com\"",
            ),
            (
                RecordType::TXT,
                json!({"value": ["string1", "string2"]}),
                "\"string1string2\"",
            ),
            (
                RecordType::SOA,
                json!({"host": "ns1.contoso.com", "email": "hostmaster.contoso.com",
                       "serialNumber": 1, "refreshTime": 3600, "retryTime": 300,
                       "expireTime": 2419200, "minimumTTL": 300}),
                "ns1.contoso.com. hostmaster.contoso.com. 1 3600 300 2419200 300",
            ),
        ] {
            let data = read(rtype, &item);
            assert!(data.is_canonical(), "{rtype} {item}");
            assert_eq!(data, rd(rtype, text), "{rtype} {item}");
        }
        for (rtype, item) in [
            (RecordType::A, json!({"ipv4Address": "not-an-address"})),
            (RecordType::CNAME, json!({"cname": "a b"})),
            (RecordType::CNAME, json!({"cname": ""})),
            (RecordType::MX, json!({"exchange": "mail"})),
            (RecordType::TXT, json!({"value": ["a\\\"b"]})),
            (RecordType::TXT, json!({"value": []})),
            (RecordType::TXT, json!({"value": ["ключ"]})),
            (
                RecordType::CAA,
                json!({"flags": 300, "tag": "issue", "value": "x"}),
            ),
        ] {
            assert!(!read(rtype, &item).is_canonical(), "{rtype} {item}");
        }
    }

    #[test]
    fn records_are_written_in_the_documented_form() {
        for (rtype, text, item) in [
            (
                RecordType::A,
                "192.0.2.1",
                json!({"ipv4Address": "192.0.2.1"}),
            ),
            (
                RecordType::CNAME,
                "target.example.net.",
                json!({"cname": "target.example.net"}),
            ),
            (
                RecordType::MX,
                "10 mail.example.org.",
                json!({"preference": 10, "exchange": "mail.example.org"}),
            ),
            (
                RecordType::SRV,
                "1 2 3 sip.example.org.",
                json!({"priority": 1, "weight": 2, "port": 3, "target": "sip.example.org"}),
            ),
            (
                RecordType::CAA,
                "128 issue \"letsencrypt.org\"",
                json!({"flags": 128, "tag": "issue", "value": "letsencrypt.org"}),
            ),
            (
                RecordType::TXT,
                "\"v=spf1 -all\"",
                json!({"value": ["v=spf1 -all"]}),
            ),
        ] {
            let data = rd(rtype, text);
            assert_eq!(write(rtype, &data), Some(item.clone()), "{rtype} {text}");
            assert_eq!(read(rtype, &item), data, "{rtype} {text}");
        }
        for (rtype, text) in [
            (RecordType::MX, "0 ."),
            (RecordType::CAA, "0 issue \"a\\\\b\""),
            (RecordType::TXT, "\"say \\\"hi\\\"\""),
            (RecordType::TXT, "\"\""),
        ] {
            assert_eq!(write(rtype, &rd(rtype, text)), None, "{rtype} {text}");
        }
        assert_eq!(write(RecordType::A, &RecordData::non_canonical("x")), None);
    }

    #[test]
    fn long_txt_values_are_split() {
        let value = Txt::new("x".repeat(300)).unwrap();
        let strings = txt_strings(&value).unwrap();
        assert_eq!(strings, ["x".repeat(255), "x".repeat(45)]);
        assert_eq!(read_txt(&json!({ "value": strings })), Some(value));
        assert_eq!(read_txt(&json!({ "value": ["x".repeat(256)] })), None);
        assert_eq!(txt_strings(&Txt::new("").unwrap()), None);
        assert_eq!(txt_strings(&Txt::new("a\u{7f}").unwrap()), None);
    }
}
