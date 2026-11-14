//! Record-level operations: the `PerRecord` shape of the record layer (`crate::rrsets`) over the
//! record API, the listing of a domain, and the mapping between the API's record fields and
//! `RecordData`.
//!
//! The native unit is the individual record with an identifier, hence the per-record shape,
//! `Preconditions::ReadThenWrite` and no `atomic_rrset_write`: replacing an rrset is several
//! requests, creates first and deletes last (the record layer decides the order). The record
//! layer does the checks, takes the per-name lock, reads, evaluates the expectation and computes
//! the requests; this file turns them into the API's calls:
//!
//! - read: `GET …/dns`, every page (the listing has no filter by name or type), an exact name and
//!   type match on the client's side;
//! - create: `POST …/dns`, sent once, with the name relative to the domain (`@` for the apex,
//!   see `api::write_name`), the type's fields and the TTL the layer chose (the API requires a
//!   TTL, so the configured one stands in when the set's TTL was not reported);
//! - update: `POST …/dns/{recordId}` (the edit call), sent once, with the type, the name, the TTL
//!   and the type's fields: the record's own as read for a TTL change, the new value for a CNAME
//!   replaced in place. A `404` means the record went away after the read: nothing was written,
//!   `Error::Conflict`, and the caller's repeat reads again;
//! - delete: `DELETE …/dns/{recordId}`, repeated by the transport (idempotent). A `404` counts as
//!   done (the record layer's rule for a per-record API).
//!
//! # Fields per type
//!
//! Source of every row: the API reference, opened for this client on 2026-11-14 —
//! "Create", <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Create>
//! (request body), "List", <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_List>
//! (`v1Record`) and "Edit",
//! <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Edit.md> (request
//! body). The type enum of all three is `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `SRV`, `NS`, `CAA`.
//!
//! | Type  | API fields → canonical text                                   | Edit |
//! | ----- | ------------------------------------------------------------- | ---- |
//! | A     | `address` ("address for an A or AAAA record")                 | yes  |
//! | AAAA  | `address`                                                     | yes  |
//! | CNAME | `target` ("target for a CNAME or SRV record") (1)             | yes  |
//! | MX    | `<preference> <exchange>` (1)                                 | yes  |
//! | SRV   | `<priority> <weight> <port> <target>` (1)                     | yes  |
//! | CAA   | `<flag> <tag> <value>`, `value` "enclosed in double quotes"   | no   |
//! | TXT   | `text` ("content of a TXT record") (2)                        | yes  |
//!
//! (1) Host names. Read with or without a trailing dot as absolute names. Written absolute with
//! the trailing dot. Assumption (not documented): no source states whether the API wants the
//! trailing dot or reads a name without one relative to the domain; the examples are
//! placeholders (`example`). The trailing dot is written because it is absolute in either
//! reading; a wrong guess makes the API refuse the write (`Error::Rejected`, nothing written) or
//! store the dot, which reads back as the same absolute name. To be confirmed against the live
//! API.
//! (2) TXT dialect `Raw` on write (lego providers/dns/yandex360/yandex360.go lines 127 to 132
//! send the value itself), `Auto` on read (design section 11.2). Only plain values are written
//! (`Txt::is_plain`: 1 to 255 printable ASCII octets without space, `"` or `\`), the values the
//! TXT value operations send: how the API treats spaces, quotes, escapes and values longer than
//! one character-string is not established.
//!
//! NS is in the type enum, but no page names the field that holds its name server, so NS records
//! cannot be read or written: a listing reports them in `skipped`, and NS is not among
//! `record_types`. The apex NS set would not be writable anyway (design section 3.4). A type
//! name the client does not know is reported in `skipped` as well.
//!
//! Writing stays within what the sources show, and `RrsetBase::can_send` refuses everything else
//! with `Error::InvalidInput` before any write:
//!
//! - host names: never the root (`.`, a null MX or an SRV "no service": no source shows how the
//!   API takes it) and never with a backslash escape;
//! - CAA: flag 0 to 255, any tag the record model accepts, and a value of printable ASCII
//!   (space included) without `"` and `\`, written between double quotes as the pages' example
//!   `"ca.example.net"`; how the API escapes a quote or a backslash inside is not established.
//!
//! The edit call has no CAA fields, so an existing CAA record cannot be changed in place: a TTL
//! change of CAA records that stay is refused with `Error::InvalidInput` before any write (the
//! record layer changes TTLs before it creates or deletes anything). Replacing CAA values works
//! by creating and deleting records.
//!
//! The API documents no disabled record, no comment and no other attribute the model does not
//! carry; the per-record TTL is the one, and the layer keeps it: a write without a TTL leaves
//! every record's own, a write with one sets it on every record (design section 3.6). An edit
//! sends the record's fields as they were read, so a TTL change does not alter its value.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::{DomainName, TargetName};
use crate::provider::{SkipReason, ZoneListing};
use crate::record::{Caa, Mx, RecordData, RecordType, Srv, Ttl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::rrsets::{
    self, Listing, PerRecord, RecordUpdate, RecordsRead, RrsetBase, SetTtl, Stored,
};

use super::api::{Fields, NewRecord, Record, Written, owner_name, write_name};
use super::client::Yandex360;

/// How TXT data is read: quoted text as presentation format, anything else as the value
/// (design section 11.2).
const TXT_READ: TxtDialect = TxtDialect::Auto;

/// How TXT data is written: the value itself (lego yandex360.go lines 127 to 132).
const TXT_WRITE: TxtDialect = TxtDialect::Raw;

/// Whether the client maps the fields of `rtype` (see the module documentation).
fn mapped(rtype: RecordType) -> bool {
    [
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::SRV,
        RecordType::CAA,
        RecordType::TXT,
    ]
    .contains(&rtype)
}

// ---- Reading -------------------------------------------------------------------------------------

/// A value as the API returned it, for a type the client maps: canonical where the type's fields
/// parse, non-canonical otherwise (design section 4.9).
pub(super) fn read_record(rtype: RecordType, record: &Record) -> RecordData {
    let fields = &record.fields;
    match rtype {
        RecordType::A | RecordType::AAAA => read_address(rtype, fields),
        RecordType::CNAME => read_cname(fields),
        RecordType::MX => read_mx(fields),
        RecordType::SRV => read_srv(fields),
        RecordType::CAA => read_caa(fields),
        _ => read_txt(fields),
    }
}

/// A string field, or the empty text when it is absent or not a string.
fn text(field: Option<&Value>) -> &str {
    Fields::text_of(field).unwrap_or_default()
}

/// A field as it is shown in non-canonical data: a string as itself, anything else as JSON.
fn shown(field: Option<&Value>) -> String {
    match field {
        None => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// A and AAAA: the address in `address`.
// Source: Create, List: `address`, "address for an A or AAAA record".
fn read_address(rtype: RecordType, fields: &Fields) -> RecordData {
    RecordData::from_provider(rtype, text(fields.address.as_ref()), None, TXT_READ)
}

/// CNAME: the target name in `target`, absolute with or without its trailing dot.
// Source: Create, List: `target`, "target for a CNAME or SRV record".
fn read_cname(fields: &Fields) -> RecordData {
    RecordData::from_provider(
        RecordType::CNAME,
        text(fields.target.as_ref()),
        None,
        TXT_READ,
    )
}

/// MX: `preference` and the exchange in `exchange`.
// Source: Create, List: `exchange` ("EXCHANGE for an MX record"), `preference` ("PREFERENCE for an
// MX record", an integer).
fn read_mx(fields: &Fields) -> RecordData {
    let exchange = text(fields.exchange.as_ref());
    match Fields::number_of(fields.preference.as_ref()) {
        Some(preference) => RecordData::from_provider(
            RecordType::MX,
            &format!("{preference} {exchange}"),
            None,
            TXT_READ,
        ),
        None => {
            RecordData::non_canonical(&format!("{} {exchange}", shown(fields.preference.as_ref())))
        }
    }
}

/// SRV: `priority`, `weight`, `port` and the target name in `target`.
// Source: Create, List: `priority`, `weight`, `port` ("priority / weight / port for an SRV
// record", integers) and `target`.
fn read_srv(fields: &Fields) -> RecordData {
    let target = text(fields.target.as_ref());
    let numbers = (
        Fields::number_of(fields.priority.as_ref()),
        Fields::number_of(fields.weight.as_ref()),
        Fields::number_of(fields.port.as_ref()),
    );
    match numbers {
        (Some(priority), Some(weight), Some(port)) => RecordData::from_provider(
            RecordType::SRV,
            &format!("{priority} {weight} {port} {target}"),
            None,
            TXT_READ,
        ),
        _ => RecordData::non_canonical(&format!(
            "{} {} {} {target}",
            shown(fields.priority.as_ref()),
            shown(fields.weight.as_ref()),
            shown(fields.port.as_ref()),
        )),
    }
}

/// CAA: `flag`, `tag` and the value in `value`, quoted (an unquoted value is accepted too).
// Source: Create, List: `flag` ("flag for a CAA record", an integer), `tag` ("tag for a CAA
// record"), `value` ("a CAA record enclosed in double quotes, for example `"ca.example.net"`").
fn read_caa(fields: &Fields) -> RecordData {
    let tag = text(fields.tag.as_ref());
    let value = text(fields.value.as_ref());
    match Fields::number_of(fields.flag.as_ref()) {
        Some(flag) => RecordData::from_provider(
            RecordType::CAA,
            &format!("{flag} {tag} {value}"),
            None,
            TXT_READ,
        ),
        None => {
            RecordData::non_canonical(&format!("{} {tag} {value}", shown(fields.flag.as_ref())))
        }
    }
}

/// TXT: the value in `text`, read with the `Auto` rule.
// Source: Create, List: `text`, "content of a TXT record"; lego yandex360.go lines 127 to 132
// (the value itself); design section 11.2 (`Auto` on read).
fn read_txt(fields: &Fields) -> RecordData {
    RecordData::from_provider(RecordType::TXT, text(fields.text.as_ref()), None, TXT_READ)
}

// ---- Writing -------------------------------------------------------------------------------------

/// The API's fields for a canonical value of `rtype`, or `None` when the client cannot send it
/// (see the module documentation).
pub(super) fn encode(rtype: RecordType, data: &RecordData) -> Option<Fields> {
    if !data.is_canonical() {
        return None;
    }
    match rtype {
        RecordType::A | RecordType::AAAA => write_address(data),
        RecordType::CNAME => write_cname(data),
        RecordType::MX => write_mx(data),
        RecordType::SRV => write_srv(data),
        RecordType::CAA => write_caa(data),
        RecordType::TXT => write_txt(data),
        _ => None,
    }
}

fn string(text: String) -> Option<Value> {
    Some(Value::String(text))
}

fn number(value: impl Into<u64>) -> Option<Value> {
    Some(Value::from(value.into()))
}

/// A and AAAA: the canonical address as `address`.
// Source: Create: `address`, "address for an A or AAAA record".
fn write_address(data: &RecordData) -> Option<Fields> {
    Some(Fields {
        address: string(data.as_str().to_owned()),
        ..Fields::default()
    })
}

/// CNAME: the target, absolute with its trailing dot, as `target`.
// Source: Create: `target`, "target for a CNAME or SRV record". The trailing dot is an assumption
// (module documentation, note 1).
fn write_cname(data: &RecordData) -> Option<Fields> {
    let target = TargetName::parse(data.as_str()).ok()?;
    Some(Fields {
        target: string(host(&target)?),
        ..Fields::default()
    })
}

/// MX: the preference as `preference`, the exchange, absolute with its trailing dot, as
/// `exchange`.
// Source: Create: `exchange`, `preference`. The trailing dot is an assumption (note 1).
fn write_mx(data: &RecordData) -> Option<Fields> {
    let mx = Mx::from_data(data).ok()?;
    Some(Fields {
        exchange: string(host(&mx.exchange)?),
        preference: number(mx.preference),
        ..Fields::default()
    })
}

/// SRV: `priority`, `weight`, `port`, and the target, absolute with its trailing dot, as
/// `target`.
// Source: Create: `priority`, `weight`, `port`, `target`. The trailing dot is an assumption
// (note 1).
fn write_srv(data: &RecordData) -> Option<Fields> {
    let srv = Srv::from_data(data).ok()?;
    Some(Fields {
        target: string(host(&srv.target)?),
        priority: number(srv.priority),
        weight: number(srv.weight),
        port: number(srv.port),
        ..Fields::default()
    })
}

/// CAA: `flag`, `tag`, and the value between double quotes as `value`.
// Source: Create: `flag`, `tag`, `value` ("a CAA record enclosed in double quotes, for example
// `"ca.example.net"`").
fn write_caa(data: &RecordData) -> Option<Fields> {
    let caa = Caa::from_data(data).ok()?;
    let plain = !caa.value.is_empty()
        && caa
            .value
            .iter()
            .all(|&b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\');
    if !plain {
        return None;
    }
    let value = String::from_utf8(caa.value).ok()?;
    Some(Fields {
        flag: number(caa.flags),
        tag: string(caa.tag),
        value: string(format!("\"{value}\"")),
        ..Fields::default()
    })
}

/// TXT: a plain value, itself, as `text`.
// Source: Create: `text`; lego yandex360.go lines 127 to 132.
fn write_txt(data: &RecordData) -> Option<Fields> {
    let txt = Txt::from_data(data).ok().filter(Txt::is_plain)?;
    Some(Fields {
        text: string(TXT_WRITE.write(&txt)?),
        ..Fields::default()
    })
}

/// A host name: absolute with its trailing dot; `None` for the root and for a name whose
/// canonical text needs a backslash escape.
fn host(name: &TargetName) -> Option<String> {
    let text = name.as_str();
    (!name.is_root() && !text.contains('\\')).then(|| text.to_owned())
}

// ---- The record layer ----------------------------------------------------------------------------

impl RrsetBase for Yandex360 {
    fn provider(&self) -> ProviderId {
        ProviderId::Yandex360
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }

    fn can_send(&self, rtype: RecordType, data: &RecordData) -> bool {
        encode(rtype, data).is_some()
    }
}

fn not_sendable() -> Error {
    Error::InvalidInput {
        detail: Detail::constant("the provider's encoding of this record data is not established"),
    }
}

impl Yandex360 {
    /// The TTL a write sends: the API requires one, so the configured TTL stands in when the
    /// layer has none.
    fn write_ttl(&self, ttl: Option<Ttl>) -> u32 {
        ttl.map_or(self.ttl, Ttl::as_secs)
    }
}

impl PerRecord for Yandex360 {
    /// The record as read: its identifier, and its fields for an edit that keeps them.
    type Handle = Record;
    /// The domain's name is the key of every path: nothing to carry.
    type Context = ();

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<RecordsRead<Record, ()>, Error> {
        let records = self
            .api
            .records(zone)
            .await?
            .into_iter()
            .filter(|record| {
                record.rtype.parse::<RecordType>().ok() == Some(rtype)
                    && owner_name(&record.name, zone).as_ref() == Some(name)
            })
            .map(|record| Stored {
                data: read_record(rtype, &record),
                // The API has no disabled records.
                enabled: true,
                ttl: record.ttl.and_then(|secs| Ttl::from_secs(secs).ok()),
                handle: record,
            })
            .collect();
        Ok(RecordsRead {
            context: (),
            records,
        })
    }

    async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &(),
        data: &RecordData,
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let fields = encode(rtype, data).ok_or_else(not_sendable)?;
        let ttl = match ttl {
            SetTtl::Requested(ttl) | SetTtl::Existing(Some(ttl)) => ttl.as_secs(),
            // The API requires a TTL: the configured one for a new set, and for a set whose TTL
            // was not reported.
            SetTtl::Default | SetTtl::Existing(None) => self.ttl,
        };
        let owner = write_name(name, zone)
            .ok_or_else(|| Error::name_outside_zone(name.clone(), zone.clone()))?;
        let type_name = rtype.to_string();
        let record = NewRecord {
            rtype: &type_name,
            name: owner,
            ttl,
            fields,
        };
        match self.api.create_record(zone, &record).await? {
            Written::Done => Ok(()),
            // The domain does not exist (any more): nothing was written.
            Written::NotFound => Err(Error::zone_not_found(zone.clone())),
        }
    }

    async fn update(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &(),
        record: &Stored<Record>,
        update: &RecordUpdate<'_>,
    ) -> Result<(), Error> {
        if update.enable {
            // Every record this client reads is enabled, so the layer never asks for this.
            return Err(Error::Protocol {
                detail: Detail::constant("the provider has no disabled records to enable"),
            });
        }
        if rtype == RecordType::CAA {
            // Source: Edit, request body: no `flag`, `tag` or `value`. An edit could not state
            // the record's value, so none is sent. The layer changes TTLs before it creates or
            // deletes anything, so nothing has been written when this is returned.
            return Err(Error::InvalidInput {
                detail: Detail::constant(
                    "the provider's edit call has no CAA fields, so the TTL of an existing CAA \
                     record cannot be changed; delete the rrset and create it again",
                ),
            });
        }
        let fields = match update.data {
            Some(data) => encode(rtype, data).ok_or_else(not_sendable)?,
            // The record's own fields as read, so that only the TTL changes.
            None => record.handle.fields.for_edit(),
        };
        let owner = write_name(name, zone)
            .ok_or_else(|| Error::name_outside_zone(name.clone(), zone.clone()))?;
        let type_name = rtype.to_string();
        let edit = NewRecord {
            rtype: &type_name,
            name: owner,
            // The edit requires a TTL: the requested one, else the record's own as read.
            ttl: self.write_ttl(update.ttl.or(record.ttl)),
            fields,
        };
        match self
            .api
            .edit_record(zone, record.handle.record_id, &edit)
            .await?
        {
            Written::Done => Ok(()),
            // The record, or the domain, went away after the read; nothing was written.
            Written::NotFound => Err(Error::Conflict {
                detail: Detail::constant("the record was removed between the read and the update"),
            }),
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        _name: &DomainName,
        _rtype: RecordType,
        _context: &(),
        record: &Stored<Record>,
    ) -> Result<(), Error> {
        // "Not found" counts as done: the record is gone (the record layer's rule for a
        // per-record API).
        match self
            .api
            .delete_record(zone, record.handle.record_id)
            .await?
        {
            Written::Done | Written::NotFound => Ok(()),
        }
    }
}

// ---- Listing -------------------------------------------------------------------------------------

/// The records of one owner name and type, as the listing gathers them.
struct Group {
    name: Option<DomainName>,
    type_name: String,
    rtype: Option<RecordType>,
    ttl: Option<Ttl>,
    records: Vec<RecordData>,
}

impl Yandex360 {
    /// `list_rrsets`: every record of the domain, all pages, grouped by owner name and type.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let all = self.api.records(zone).await?;
        let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
        for record in &all {
            let name = owner_name(&record.name, zone);
            let rtype = record.rtype.parse::<RecordType>().ok();
            // Spellings of one name or type that mean the same land in one group.
            let key = (
                name.as_ref()
                    .map_or_else(|| format!("raw:{}", record.name), |n| n.as_str().to_owned()),
                rtype.map_or_else(|| format!("raw:{}", record.rtype), |t| t.to_string()),
            );
            let ttl = record.ttl.and_then(|secs| Ttl::from_secs(secs).ok());
            let group = groups.entry(key).or_insert_with(|| Group {
                name,
                type_name: record.rtype.clone(),
                rtype,
                ttl: None,
                records: Vec::new(),
            });
            // The smallest TTL of the set (design section 3.6, `TtlSupport::PerRecord`).
            group.ttl = Listing::smallest_ttl([group.ttl, ttl]);
            if let Some(rtype) = rtype.filter(|&t| mapped(t)) {
                group.records.push(read_record(rtype, record));
            }
        }
        let mut listing = Listing::new(zone);
        for group in groups.into_values() {
            let type_name = group
                .rtype
                .map_or_else(|| group.type_name.clone(), |rtype| rtype.to_string());
            match group.rtype {
                Some(rtype) if mapped(rtype) => {
                    listing.push(group.name, &type_name, group.ttl, group.records);
                }
                // A type whose value field no source names (NS), or that is no record type at
                // all: reported, never dropped. A name that is not valid, or not within the
                // zone, is reported under the zone's name, as `Listing::push` does.
                rtype => match group.name.filter(|n| n.is_within(zone)) {
                    None => listing.skip(zone.clone(), &type_name, SkipReason::UnsupportedName),
                    Some(name) => {
                        let reason = match rtype {
                            Some(_) => SkipReason::NotPlainRecords,
                            None => SkipReason::UnknownType,
                        };
                        listing.skip(name, &type_name, reason);
                    }
                },
            }
        }
        listing.finish(ProviderId::Yandex360)
    }
}

#[cfg(test)]
mod tests {
    use super::{encode, read_record};
    use crate::providers::yandex_360::api::Record;
    use crate::record::{RecordData, RecordType};

    fn record(rtype: &str, fields: serde_json::Value) -> Record {
        let mut json = serde_json::json!({
            "recordId": 1, "type": rtype, "name": "www", "ttl": 300
        });
        if let (Some(target), Some(extra)) = (json.as_object_mut(), fields.as_object()) {
            for (k, v) in extra {
                target.insert(k.clone(), v.clone());
            }
        }
        serde_json::from_value(json).unwrap()
    }

    fn read(rtype: RecordType, fields: serde_json::Value) -> RecordData {
        read_record(rtype, &record(&rtype.to_string(), fields))
    }

    fn data(rtype: RecordType, text: &str) -> RecordData {
        RecordData::parse(rtype, text).unwrap()
    }

    #[test]
    fn each_type_reads_into_canonical_text() {
        use serde_json::json;
        for (rtype, fields, canonical) in [
            (RecordType::A, json!({"address": "192.0.2.1"}), "192.0.2.1"),
            (
                RecordType::AAAA,
                json!({"address": "2001:DB8:0::1"}),
                "2001:db8::1",
            ),
            (
                RecordType::CNAME,
                json!({"target": "Target.example.net"}),
                "target.example.net.",
            ),
            (
                RecordType::CNAME,
                json!({"target": "target.example.net."}),
                "target.example.net.",
            ),
            (
                RecordType::MX,
                json!({"exchange": "mx.yandex.net.", "preference": 10}),
                "10 mx.yandex.net.",
            ),
            (
                RecordType::SRV,
                json!({"target": "sip.example.org", "priority": 1, "weight": 5, "port": 5060}),
                "1 5 5060 sip.example.org.",
            ),
            (
                RecordType::CAA,
                json!({"flag": 0, "tag": "issue", "value": "\"ca.example.net\""}),
                "0 issue \"ca.example.net\"",
            ),
            (
                RecordType::CAA,
                json!({"flag": 128, "tag": "IODEF", "value": "mailto:sec@example.org"}),
                "128 iodef \"mailto:sec@example.org\"",
            ),
            (
                RecordType::TXT,
                json!({"text": "v=spf1 redirect=_spf.yandex.net"}),
                "\"v=spf1 redirect=_spf.yandex.net\"",
            ),
            (
                RecordType::TXT,
                json!({"text": "\"quoted\" \"two\""}),
                "\"quotedtwo\"",
            ),
        ] {
            let got = read(rtype, fields.clone());
            assert!(got.is_canonical(), "{rtype} {fields}");
            assert_eq!(got.as_str(), canonical, "{rtype} {fields}");
        }
    }

    #[test]
    fn unparseable_fields_are_non_canonical() {
        use serde_json::json;
        for (rtype, fields, kept) in [
            (
                RecordType::A,
                json!({"address": "not an address"}),
                "not an address",
            ),
            (RecordType::A, json!({}), ""),
            (RecordType::CNAME, json!({"target": "@"}), "@"),
            (
                RecordType::MX,
                json!({"exchange": "mail.example.org"}),
                "mail.example.org",
            ),
            (
                RecordType::MX,
                json!({"exchange": "mail.example.org", "preference": 70000}),
                "70000 mail.example.org",
            ),
            (
                RecordType::MX,
                json!({"exchange": "mail.example.org", "preference": "10"}),
                "10 mail.example.org",
            ),
            (
                RecordType::SRV,
                json!({"target": "sip.example.org", "priority": 1, "port": 5060}),
                "1  5060 sip.example.org",
            ),
            (
                RecordType::CAA,
                json!({"flag": 300, "tag": "issue", "value": "\"ca.example.net\""}),
                "300 issue \"ca.example.net\"",
            ),
            (
                RecordType::CAA,
                json!({"tag": "issue", "value": "\"ca.example.net\""}),
                "issue \"ca.example.net\"",
            ),
        ] {
            let got = read(rtype, fields.clone());
            assert!(!got.is_canonical(), "{rtype} {fields}");
            assert_eq!(got.as_str(), kept, "{rtype} {fields}");
        }
    }

    #[test]
    fn each_type_writes_the_documented_fields() {
        use serde_json::json;
        for (rtype, text, expected) in [
            (RecordType::A, "192.0.2.1", json!({"address": "192.0.2.1"})),
            (
                RecordType::AAAA,
                "2001:db8::1",
                json!({"address": "2001:db8::1"}),
            ),
            (
                RecordType::CNAME,
                "target.example.net.",
                json!({"target": "target.example.net."}),
            ),
            (
                RecordType::MX,
                "10 mail.example.org.",
                json!({"exchange": "mail.example.org.", "preference": 10}),
            ),
            (
                RecordType::SRV,
                "1 5 5060 sip.example.org.",
                json!({"target": "sip.example.org.", "priority": 1, "weight": 5, "port": 5060}),
            ),
            (
                RecordType::CAA,
                "128 issuewild \"ca.example.net; account=1\"",
                json!({"flag": 128, "tag": "issuewild", "value": "\"ca.example.net; account=1\""}),
            ),
            (RecordType::TXT, "\"v1\"", json!({"text": "v1"})),
        ] {
            let fields = encode(rtype, &data(rtype, text)).unwrap();
            assert_eq!(serde_json::to_value(&fields).unwrap(), expected, "{rtype}");
            // Read back through the same fields, the value is the same.
            assert_eq!(read(rtype, expected), data(rtype, text), "{rtype}");
        }
    }

    #[test]
    fn values_without_an_established_encoding_are_not_sent() {
        for (rtype, text) in [
            (RecordType::MX, "0 ."),
            (RecordType::SRV, "0 0 0 ."),
            (RecordType::CNAME, "a\\.b.example.net."),
            (RecordType::TXT, "\"two words\""),
            (RecordType::TXT, "\"quo\\\"te\""),
            (RecordType::CAA, "0 issue \"\""),
            (RecordType::CAA, "0 issue \"a\\\"b\""),
            (RecordType::CAA, "0 issue \"a\\\\b\""),
            (RecordType::NS, "ns1.example.net."),
            (RecordType::TLSA, "3 1 1 0a1b"),
        ] {
            assert!(
                encode(rtype, &data(rtype, text)).is_none(),
                "{rtype} {text}"
            );
        }
        assert!(encode(RecordType::A, &RecordData::non_canonical("x")).is_none());
    }
}
