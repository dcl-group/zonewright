//! TXT value operations: the `WholeSet` shape of the value layer over the strict record set
//! call.
//!
//! The record set is the native unit, addressed by name and type, and it is replaced through
//! `updateRecordSets`, whose deletions must match the record set at the provider exactly. Every
//! write therefore carries the old set as the client read it and the provider refuses the write
//! if the set changed in between: `ValueGuarantee::Conditional` (design sections 3.4 and 3.5).
//! The value layer takes the per-name lock, reads, computes the new member list and calls
//! [`WholeSet::write`] or [`WholeSet::delete`]; this file maps those onto the API:
//!
//! - read: `getRecordSet` with the name relative to the zone and type `TXT`, under the zone-ID
//!   cache. A `404` with a freshly resolved zone ID is "no record set"; with a cached ID the zone
//!   is first confirmed with `DnsZone.get`, since the same status answers a missing zone;
//! - write without a prior set: `additions` only, with the configured or requested TTL;
//! - write over a prior set: `deletions` with the JSON object read, unchanged (design section
//!   11.3), and `additions` with the same name, TTL and description and the new data;
//! - delete: `deletions` only. A record set cannot hold no data (documented `data` range 1 to
//!   100), so the last value is removed by deleting the set.
//!
//! Which status or operation error a failed condition produces is not documented; a refusal is
//! interpreted against a new read (`rrset.rs`), and a changed set is `Error::Conflict`, which the
//! value layer answers by running the operation once more. A write sent once and answered with an
//! unknown outcome (a 5xx, a timeout, an operation still running) is `Error::Transient`.
//!
//! TXT dialect (design sections 4.4 and 11.2): read by [`read_txt`], the one rule both levels
//! read TXT data by, so that the record level and these operations agree on what a record
//! holds. Plain values, the only ones the capabilities accept, are written unquoted, as the
//! TXT-level version proven against the live API did and as lego does (`Data:
//! []string{value}`, yandexcloud.go:224-238), except a value with `;`, `(` or `)`, which is
//! written in double quotes ([`write_txt`]). Either form reads back as the same value at both
//! levels.

use serde_json::{Map, Value};

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{RrsetTtl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::values::{Member, SetRead, SetState, TxtBase, TxtRecord, TxtSet, WholeSet, WriteTtl};

use super::client::YandexCloud;
use super::rrset::{RecordSet, data_of, relative, ttl_of};

/// Characters the master file format gives a meaning outside double quotes, other than
/// whitespace, `"` and `\`: `;` starts a comment, `(` and `)` group lines.
// Source: https://yandex.cloud/en/docs/dns/concepts/resource-record, TXT ("The service uses
// MASTER FILES format.", linked to RFC 1035 section 5; "According to the format specification,
// `;` outside double quotes marks the beginning of a comment"), read 2026-11-15; RFC 1035
// section 5.1 (`(` and `)`).
const SPECIAL: [char; 3] = [';', '(', ')'];

/// The value of TXT data, the one rule both levels read TXT by: the record level
/// (`records.rs`) and these operations.
///
/// The record types page says, in its TXT section, that the service uses the master file format
/// and that "The space character serves as a separator. If an input string has spaces, it will
/// be perceived as multiple strings." So the data are read as master-file character-strings
/// separated by whitespace, each quoted (with the escapes of RFC 1035 section 5.1) or unquoted,
/// and the value is their concatenation (design section 4.4): `"ab" "c"`, `ab c`, `"ab" c` and
/// `abc` all hold `abc`. What the format leaves the API to decide is `None`, read as
/// non-canonical data by the record level and never taken for a value of ours here (an add puts
/// the value next to it, a remove answers `NotPresent`):
///
/// - an unquoted string with `;`, `(` or `)`: a comment or a group in the format, so the value
///   the API returns them in is not the record's value (the page: to use `;`, "enclose the
///   string containing it in double quotes");
/// - strings not separated by whitespace (`"a""b"`, `a"b"`), an unterminated quote, data that
///   hold no string, and data with a character outside ASCII (the page: "Resource records only
///   support ASCII characters").
// Source: https://yandex.cloud/en/docs/dns/concepts/resource-record, TXT, read 2026-11-15. The
// page's ANAME section shows unquoted TXT examples with spaces and `;` (`v=spf1
// redirect=_spf.example.com`, `v=DKIM1; k=rsa; t=s; p=`) that the TXT section's rule reads as
// several strings and as a comment; the rule of the TXT section is followed.
pub(super) fn read_txt(data: &str) -> Option<Txt> {
    let blank = |c: char| c.is_ascii_whitespace();
    if !data.is_ascii() {
        return None;
    }
    let mut value = Vec::new();
    let mut rest = data.trim_matches(blank);
    if rest.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        let end = if rest.starts_with('"') {
            closing_quote(rest)? + 1
        } else {
            rest.find(|c: char| blank(c) || c == '"')
                .unwrap_or(rest.len())
        };
        let (token, tail) = rest.split_at(end);
        if !token.starts_with('"') && token.contains(SPECIAL) {
            return None;
        }
        if tail.chars().next().is_some_and(|c| !blank(c)) {
            return None;
        }
        let string = TxtDialect::Presentation.read(token)?;
        value.extend_from_slice(string.as_bytes());
        rest = tail.trim_start_matches(blank);
    }
    Txt::new(value).ok()
}

/// The byte offset of the `"` that closes the quoted string `text` starts with, skipping
/// backslash escapes.
fn closing_quote(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut at = 1;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'\\' => at += 2,
            b'"' => return Some(at),
            _ => at += 1,
        }
    }
    None
}

/// The data element for a plain value being added: the value itself, unquoted, or in double
/// quotes when it holds a character of [`SPECIAL`], which unquoted would be a comment or a group
/// ([`read_txt`]). A plain value holds no `"`, `\` or whitespace, so the quoted form needs no
/// escape. `None` for a value that is not valid UTF-8.
// Source: https://yandex.cloud/en/docs/dns/concepts/resource-record, TXT ("If you want to use
// the `;` character in a TXT record, enclose the string containing it in double quotes"), read
// 2026-11-15.
pub(super) fn write_txt(value: &Txt) -> Option<String> {
    let text = TxtDialect::Raw.write(value)?;
    if text.contains(SPECIAL) {
        TxtDialect::Presentation.write(value)
    } else {
        Some(text)
    }
}

/// The record type as the API spells it.
const TXT: &str = "TXT";

/// Most data elements of one record set.
// Source: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/updateRecordSets (`data[]`: "The
// number of elements must be in the range 1-100").
pub(super) const MAX_DATA: usize = 100;

impl TxtBase for YandexCloud {
    fn provider(&self) -> ProviderId {
        ProviderId::YandexCloud
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl WholeSet for YandexCloud {
    /// The data element as the API returned it.
    type Handle = String;
    type Snapshot = RecordSet;
    /// The zone identifier the read used.
    type Context = String;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> SetRead<String, RecordSet, String> {
        let (zone_id, set) = self.read_set(zone, name, TXT).await?;
        Ok(SetState {
            context: zone_id,
            set: set.map(txt_set).transpose()?,
        })
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        zone_id: &String,
        prior: Option<&RecordSet>,
        members: &[Member<'_, String>],
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let data = data(members)?;
        let (deletions, addition) = match prior {
            None => (Vec::new(), self.new_set(zone, name, data, ttl)?),
            Some(prior) => (vec![prior.0.clone()], replaced(prior, data)),
        };
        let written = self
            .api
            .update_record_sets(zone_id, &deletions, &[addition])
            .await?;
        self.settle(zone, name, TXT, zone_id, prior, written, false)
            .await
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        zone_id: &String,
        prior: &RecordSet,
    ) -> Result<(), Error> {
        let written = self
            .api
            .update_record_sets(zone_id, std::slice::from_ref(&prior.0), &[])
            .await?;
        self.settle(zone, name, TXT, zone_id, Some(prior), written, true)
            .await
    }
}

impl YandexCloud {
    /// A new record set: the name relative to the zone, the caller's or the configured TTL.
    /// The API carries the TTL as a string (an int64 in proto3 JSON).
    fn new_set(
        &self,
        zone: &DomainName,
        name: &DomainName,
        data: Vec<Value>,
        ttl: WriteTtl,
    ) -> Result<Value, Error> {
        let ttl = match ttl {
            WriteTtl::New(Some(RrsetTtl::Explicit(ttl)))
            | WriteTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => ttl.as_secs(),
            WriteTtl::New(None | Some(RrsetTtl::ProviderDefault))
            | WriteTtl::Existing(None | Some(RrsetTtl::ProviderDefault)) => self.ttl,
        };
        let mut set = Map::new();
        set.insert(
            "name".into(),
            Value::String(relative(zone, name)?.to_owned()),
        );
        set.insert("type".into(), Value::String(TXT.to_owned()));
        set.insert("ttl".into(), Value::String(ttl.to_string()));
        set.insert("data".into(), Value::Array(data));
        Ok(Value::Object(set))
    }
}

/// The value layer's view of a record set. A set without its `data` list or with a data element
/// that is not a string is an answer the client cannot interpret.
fn txt_set(set: Value) -> Result<TxtSet<String, RecordSet>, Error> {
    let ttl = ttl_of(&set).and_then(|secs| RrsetTtl::from_secs(secs).ok());
    let records = data_of(&set)?
        .into_iter()
        .map(|text| TxtRecord {
            value: read_txt(text),
            ttl,
            handle: text.to_owned(),
        })
        .collect();
    Ok(TxtSet {
        records,
        ttl,
        snapshot: RecordSet(set),
    })
}

/// The data to write: the elements kept, unchanged, then the value added.
fn data(members: &[Member<'_, String>]) -> Result<Vec<Value>, Error> {
    let mut data = Vec::with_capacity(members.len());
    for member in members {
        let text = match member {
            Member::Kept(record) => record.handle.clone(),
            Member::Added(value) => write_txt(value).ok_or(Error::InvalidInput {
                detail: Detail::constant("the TXT value cannot be written in this dialect"),
                code: None,
            })?,
        };
        data.push(Value::String(text));
    }
    if data.len() > MAX_DATA {
        return Err(Error::InvalidInput {
            detail: Detail::constant("a Yandex Cloud record set holds at most 100 values"),
            code: None,
        });
    }
    Ok(data)
}

/// The record set that replaces `prior`: its name, type, TTL and description as read, with
/// `data`. An existing record set keeps its TTL (design section 3.6).
// Source: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/updateRecordSets (`RecordSet`:
// `name`, `type`, `ttl`, `data[]`, `description`).
fn replaced(prior: &RecordSet, data: Vec<Value>) -> Value {
    let mut set = Map::new();
    for key in ["name", "type", "ttl", "description"] {
        if let Some(value) = prior.0.get(key) {
            set.insert(key.to_owned(), value.clone());
        }
    }
    set.insert("data".into(), Value::Array(data));
    Value::Object(set)
}
