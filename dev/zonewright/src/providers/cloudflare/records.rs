//! Record-level operations: the `PerRecord` shape of the record layer (`crate::rrsets`) over the
//! record API, the listing of a zone, and the mapping between the API's record fields and
//! `RecordData`.
//!
//! The native unit is the individual record with an identifier. The record layer does the checks,
//! takes the per-name lock, reads, evaluates the expectation and computes the difference; it
//! creates the missing records before it deletes the surplus ones, so a replacement that fails
//! part-way leaves a superset of the old or the new values and its repeat completes it. A
//! replacement is several requests: `atomic_rrset_write` is false and the expectation is checked
//! by a read before the writes (`Preconditions::ReadThenWrite`).
//!
//! The documented batch endpoint (`POST /zones/{zone_id}/dns_records/batch`) runs its deletes,
//! patches, puts and posts "in a single database transaction" and applies nothing when one of them
//! fails, but always in that order, deletes first, and "the propagation of changes is not atomic"
//! (<https://developers.cloudflare.com/dns/manage-dns-records/how-to/batch-record-changes/>). It
//! is not used: the name servers could serve the name without any of its values while a
//! replacement propagates, which the create-before-delete order of single requests avoids, and
//! the number of changes one batch takes depends on the zone's plan, which the client cannot see.
//!
//! # Fields per type
//!
//! Sources: the OpenAPI document (<https://github.com/cloudflare/api-schemas>, `openapi.json`,
//! read on 2026-11-14; "the schema"), the developer documentation of the record types
//! (<https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/>, "the
//! type reference") and `dns-update` (`src/providers/cloudflare.rs`, read on 2026-11-14):
//!
//! | Type   | Fields written                                    | Source                                       |
//! | ------ | ------------------------------------------------- | -------------------------------------------- |
//! | A      | `content`: IPv4 address                           | schema `dns-records_ARecord`                 |
//! | AAAA   | `content`: IPv6 address                           | schema `dns-records_AAAARecord`              |
//! | CNAME  | `content`: host name, no trailing dot             | schema `dns-records_CNAMERecord`; type ref.  |
//! | NS     | `content`: host name, no trailing dot             | schema `dns-records_NSRecord` (example)      |
//! | PTR    | `content`: domain name, no trailing dot           | schema `dns-records_PTRRecord` (example)     |
//! | MX     | `content`: host name; `priority`                  | schema `dns-records_MXRecord`; dns-update    |
//! | TXT    | `content`: quoted character strings               | schema `dns-records_TXTRecord`; type ref.    |
//! | CAA    | `data`: `flags`, `tag`, `value` (the value as is) | schema `dns-records_CAARecord`; dns-update   |
//! | SRV    | `data`: `priority`, `weight`, `port`, `target`    | schema `dns-records_SRVRecord`; type ref.    |
//! | TLSA   | `data`: `usage`, `selector`, `matching_type`, `certificate` (hex) | schema `dns-records_TLSARecord`; dns-update |
//!
//! Host names are sent in Punycode (the create and update notes of the schema: "Domain names are
//! always represented in Punycode") and without the trailing dot, as every example of the schema,
//! the type reference and `dns-update` spells them. A name the answer gives without the dot is
//! read as absolute (`RecordData::parse`). Three limits keep the client within the sources:
//!
//! - No source says how a name that needs an escape (`\.`, `\DDD`), or the root name (null MX,
//!   SRV "no service"), is written. Such a value is not sent ([`RrsetBase::can_send`] is false,
//!   `Error::InvalidInput`) unless a record with it exists already, which is then left as it is.
//! - TXT: the schema and the type reference establish quoted strings with spaces and the
//!   automatic split of long strings, but not how the API treats a backslash escape. A value
//!   whose canonical text needs one (`"`, `\`, a byte outside printable ASCII) is not sent. CAA
//!   values outside printable ASCII are not sent either.
//! - SSHFP, HTTPS and SVCB have `data` objects in the schema, but no source gives the encoding of
//!   the SSHFP fingerprint, nor the spelling of a non-root HTTPS or SVCB target or the syntax of
//!   their `value` beyond one example. They are not in `record_types`; a listing carries them as
//!   their formatted `content` (canonical where it parses), like CERT, DNSKEY, DS, LOC, NAPTR,
//!   OPENPGPKEY, SMIMEA and URI. The API has no SOA record; the zone's own NS set is not a record
//!   of the listing either, and the record layer refuses writes to an apex NS set anyway.
//!
//! The structured types are read from `data` (the schema marks their `content` read-only and
//! formatted, and the SRV `content` of the type reference leaves the priority out). A record
//! whose fields do not give a valid value is carried as non-canonical data (its `content`), never
//! dropped and never fixed up (design section 4.9).
//!
//! # Attributes the model does not carry
//!
//! `comment`, `tags`, `proxied`, `private_routing` (A and AAAA) and `settings` (`ipv4_only`,
//! `ipv6_only`, `flatten_cname`) belong to each record (schema `dns-records_dns-record-shared-
//! fields`). The layer leaves a record that keeps its value alone, so all of them survive; a TTL
//! change and the in-place change of a CNAME are `PATCH` requests that name only the changed
//! field. A new record in an existing rrset takes over `proxied`, `private_routing` and
//! `settings` when every record read agrees on them, since they change what the name servers
//! answer; when the records disagree, a write that has to create a record is refused
//! (`Error::InvalidInput`) instead of choosing for the caller. A new record gets no comment and
//! no tags.
//!
//! # TTL
//!
//! A TTL of `1` means automatic and reads as no TTL; the rrset's TTL is the smallest explicit
//! one (design section 3.6, `TtlSupport::PerRecord`). "All proxied records have a TTL of Auto
//! ... This value cannot be edited"
//! (<https://developers.cloudflare.com/dns/manage-dns-records/reference/ttl/>): a requested TTL
//! for a proxied record is `Error::InvalidInput`. The read puts proxied records first, so that
//! the layer, which changes TTLs in the order of the read and before any create, meets that
//! refusal before it has written anything.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::error::Error;
use crate::http::{Attempt, ZoneId};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::provider::ZoneListing;
use crate::record::{Caa, RecordData, RecordType, Tlsa, Ttl, TxtDialect};
use crate::redact::Detail;
use crate::rrsets::{
    self, Listing, PerRecord, RecordUpdate, RecordsRead, RrsetBase, SetTtl, Stored,
};

use super::api::{NewRecord, Record, RecordPatch, Written};
use super::client::Cloudflare;
use super::config::TTL_AUTOMATIC;

/// The records of one name and type in a listing: the parsed name and the records.
type Group<'a> = (Option<DomainName>, Vec<&'a Record>);

/// How TXT content is read: quoted text as presentation format, anything else as the value.
const TXT_READ: TxtDialect = TxtDialect::Auto;

// ---- Reading -------------------------------------------------------------------------------------

/// A JSON number as an integer within `T`'s range.
fn number<T: TryFrom<u64>>(value: Option<&Value>) -> Option<T> {
    value
        .and_then(Value::as_u64)
        .and_then(|n| T::try_from(n).ok())
}

/// A string field of a `data` object.
fn text_field<'a>(data: &'a Value, key: &str) -> Option<&'a str> {
    data.get(key).and_then(Value::as_str)
}

/// The value of one record (see the module documentation).
pub(super) fn read_value(rtype: RecordType, record: &Record) -> RecordData {
    let parsed = match rtype {
        RecordType::MX => read_mx(record),
        RecordType::SRV => record.data.as_ref().and_then(read_srv),
        RecordType::CAA => record.data.as_ref().and_then(read_caa),
        RecordType::TLSA => record.data.as_ref().and_then(read_tlsa),
        _ => None,
    };
    match (parsed, record.content.as_deref()) {
        (Some(data), _) => data,
        // MX, SRV, CAA and TLSA without usable fields: the formatted content, non-canonical.
        (None, Some(content))
            if matches!(
                rtype,
                RecordType::MX | RecordType::SRV | RecordType::CAA | RecordType::TLSA
            ) =>
        {
            RecordData::non_canonical(content)
        }
        // Every other type: its content, through the strict parser.
        // Source: the schema gives `content` as the value of A, AAAA, CNAME, NS, PTR and TXT;
        // for the other types it is the "formatted content", carried as data where it parses.
        (None, Some(content)) => RecordData::from_provider(rtype, content, None, TXT_READ),
        (None, None) => RecordData::non_canonical(""),
    }
}

/// MX: `priority`, then the host name in `content`.
// Source: the schema, `dns-records_MXRecord` (`content`: "A valid mail server hostname";
// `priority`: 0 to 65535, "Required for MX"); dns-update reads the same two fields.
fn read_mx(record: &Record) -> Option<RecordData> {
    let preference: u16 = number(record.priority.as_ref())?;
    let exchange = record.content.as_deref()?;
    RecordData::parse(RecordType::MX, &format!("{preference} {exchange}")).ok()
}

/// SRV: the four components of `data`.
// Source: the schema, `dns-records_SRVRecord.data` (`priority`, `weight`, `port`: 0 to 65535;
// `target`: a host name); the type reference's example sends exactly these four.
fn read_srv(data: &Value) -> Option<RecordData> {
    let priority: u16 = number(data.get("priority"))?;
    let weight: u16 = number(data.get("weight"))?;
    let port: u16 = number(data.get("port"))?;
    let target = text_field(data, "target")?;
    RecordData::parse(
        RecordType::SRV,
        &format!("{priority} {weight} {port} {target}"),
    )
    .ok()
}

/// CAA: `flags`, `tag` and the value itself.
// Source: the schema, `dns-records_CAARecord.data` (`flags` 0 to 255, `tag` "Name of the property
// controlled by this record", `value` "Value of the record"); dns-update builds the value from
// the same string. Tags compare case-insensitively (RFC 8659 section 4.1), so the tag is
// lowercased as the canonical form writes it (design section 4.5).
fn read_caa(data: &Value) -> Option<RecordData> {
    let caa = Caa {
        flags: number(data.get("flags"))?,
        tag: text_field(data, "tag")?.to_ascii_lowercase(),
        value: text_field(data, "value")?.as_bytes().to_vec(),
    };
    caa.to_data().ok()
}

/// TLSA: the three numbers and the association data in hex.
// Source: the schema, `dns-records_TLSARecord.data` (`usage`, `selector`, `matching_type` 0 to
// 255, `certificate`); dns-update reads and writes `certificate` as hex.
fn read_tlsa(data: &Value) -> Option<RecordData> {
    let usage: u8 = number(data.get("usage"))?;
    let selector: u8 = number(data.get("selector"))?;
    let matching: u8 = number(data.get("matching_type"))?;
    let certificate = text_field(data, "certificate")?;
    RecordData::parse(
        RecordType::TLSA,
        &format!("{usage} {selector} {matching} {certificate}"),
    )
    .ok()
}

/// A record's TTL: `None` for automatic.
pub(super) fn read_ttl(record: &Record) -> Option<Ttl> {
    record
        .ttl
        .filter(|&ttl| ttl != TTL_AUTOMATIC)
        .and_then(|ttl| Ttl::from_secs(ttl).ok())
}

// ---- Writing -------------------------------------------------------------------------------------

/// The fields of a value as the API takes them.
#[derive(Debug, PartialEq)]
pub(super) enum Encoded {
    /// `content`.
    Content(String),
    /// `content` and `priority` (MX).
    WithPriority(String, u16),
    /// `data`.
    Data(Value),
}

/// A name in canonical text as the API spells it: without the trailing dot. `None` for the
/// root and for a name with an escape (see the module documentation).
fn write_name(text: &str) -> Option<&str> {
    let bare = text.strip_suffix('.')?;
    (!bare.is_empty() && !bare.contains('\\')).then_some(bare)
}

/// The API's fields for a canonical value, or `None` when the client cannot send it (see the
/// module documentation).
pub(super) fn encode(rtype: RecordType, data: &RecordData) -> Option<Encoded> {
    if !data.is_canonical() {
        return None;
    }
    let text = data.as_str();
    match rtype {
        RecordType::A | RecordType::AAAA => Some(Encoded::Content(text.to_owned())),
        RecordType::CNAME | RecordType::NS | RecordType::PTR => {
            write_name(text).map(|name| Encoded::Content(name.to_owned()))
        }
        RecordType::MX => encode_mx(text),
        RecordType::TXT => encode_txt(text),
        RecordType::SRV => encode_srv(text),
        RecordType::CAA => encode_caa(data),
        RecordType::TLSA => encode_tlsa(data),
        _ => None,
    }
}

/// MX: the canonical text is `<preference> <name>`.
// Source: the schema, `dns-records_MXRecord`; dns-update sends `content` and `priority`.
fn encode_mx(text: &str) -> Option<Encoded> {
    let (preference, exchange) = text.split_once(' ')?;
    Some(Encoded::WithPriority(
        write_name(exchange)?.to_owned(),
        preference.parse().ok()?,
    ))
}

/// TXT: the canonical quoted text, when it needs no escape.
// Source: the schema, `dns-records_TXTRecord.content` ("quoted \"character strings\" (RFC 1035),
// each with a length of up to 255 bytes"), and the type reference (strings delimited by double
// quotes, spaces inside).
fn encode_txt(text: &str) -> Option<Encoded> {
    (!text.contains('\\')).then(|| Encoded::Content(text.to_owned()))
}

/// SRV: the canonical text is `<priority> <weight> <port> <target>`.
// Source: the schema, `dns-records_SRVRecord.data`; the type reference's create example.
fn encode_srv(text: &str) -> Option<Encoded> {
    let mut fields = text.splitn(4, ' ');
    let priority: u16 = fields.next()?.parse().ok()?;
    let weight: u16 = fields.next()?.parse().ok()?;
    let port: u16 = fields.next()?.parse().ok()?;
    let target = write_name(fields.next()?)?;
    Some(Encoded::Data(json!({
        "priority": priority,
        "weight": weight,
        "port": port,
        "target": target,
    })))
}

/// CAA: the value as a string, printable ASCII only.
// Source: the schema, `dns-records_CAARecord.data`; dns-update.
fn encode_caa(data: &RecordData) -> Option<Encoded> {
    let caa = Caa::from_data(data).ok()?;
    let value = std::str::from_utf8(&caa.value).ok()?;
    if !value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return None;
    }
    Some(Encoded::Data(json!({
        "flags": caa.flags,
        "tag": caa.tag,
        "value": value,
    })))
}

/// TLSA: the association data in lowercase hex.
// Source: the schema, `dns-records_TLSARecord.data`; dns-update writes `certificate` as hex.
fn encode_tlsa(data: &RecordData) -> Option<Encoded> {
    let tlsa = Tlsa::from_data(data).ok()?;
    let certificate: String = tlsa.data.iter().map(|b| format!("{b:02x}")).collect();
    Some(Encoded::Data(json!({
        "usage": tlsa.usage,
        "selector": tlsa.selector,
        "matching_type": tlsa.matching_type,
        "certificate": certificate,
    })))
}

fn not_sendable() -> Error {
    Error::InvalidInput {
        detail: Detail::constant("the provider's encoding of this record data is not established"),
    }
}

// ---- Attributes ----------------------------------------------------------------------------------

/// The attributes of a record that change what the name servers answer and that a new record
/// of the same rrset takes over (see the module documentation).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Attributes {
    /// `proxied`.
    proxied: bool,
    /// `private_routing`.
    private_routing: bool,
    /// `settings` without the entries that hold their documented default, `false`; `None` when
    /// nothing is left.
    // Source: the schema, `dns-records_settings` and the CNAME `settings`: `ipv4_only`,
    // `ipv6_only` and `flatten_cname`, each with `"default": false`.
    settings: Option<Value>,
}

impl Attributes {
    fn of(record: &Record) -> Attributes {
        let settings = match &record.settings {
            Some(Value::Object(map)) => {
                let kept: Map<String, Value> = map
                    .iter()
                    .filter(|(_, v)| **v != Value::Bool(false))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                (!kept.is_empty()).then_some(Value::Object(kept))
            }
            // Absent or null: nothing set. Anything else is kept as read, so it only ever
            // compares equal to the same thing.
            None | Some(Value::Null) => None,
            Some(other) => Some(other.clone()),
        };
        Attributes {
            proxied: record.proxied.unwrap_or(false),
            private_routing: record.private_routing.unwrap_or(false),
            settings,
        }
    }
}

/// One record as the layer sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Handle {
    /// The record's identifier.
    id: String,
    /// Its attributes.
    attributes: Attributes,
}

/// What the read hands to every write.
#[derive(Debug)]
pub(crate) struct ReadContext {
    /// The zone identifier the read used.
    zone_id: String,
    /// The attributes a new record takes over: those every record read agrees on (the defaults
    /// for an rrset without records), `None` when the records disagree.
    inherit: Option<Attributes>,
}

// ---- The layer's traits --------------------------------------------------------------------------

impl RrsetBase for Cloudflare {
    fn provider(&self) -> ProviderId {
        ProviderId::Cloudflare
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

impl PerRecord for Cloudflare {
    type Handle = Handle;
    type Context = ReadContext;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<RecordsRead<Handle, ReadContext>, Error> {
        let (zone_id, records) = self.read_records(zone, name, rtype).await?;
        let mut stored: Vec<Stored<Handle>> = records
            .iter()
            .map(|record| Stored {
                data: read_value(rtype, record),
                enabled: true,
                ttl: read_ttl(record),
                handle: Handle {
                    id: record.id.clone(),
                    attributes: Attributes::of(record),
                },
            })
            .collect();
        // Proxied records first (see the module documentation); the sort is stable.
        stored.sort_by_key(|record| !record.handle.attributes.proxied);
        let inherit = match stored.split_first() {
            None => Some(Attributes::default()),
            Some((first, rest)) => rest
                .iter()
                .all(|r| r.handle.attributes == first.handle.attributes)
                .then(|| first.handle.attributes.clone()),
        };
        Ok(RecordsRead {
            context: ReadContext { zone_id, inherit },
            records: stored,
        })
    }

    async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        context: &ReadContext,
        data: &RecordData,
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let Some(inherit) = &context.inherit else {
            return Err(Error::InvalidInput {
                detail: Detail::constant(
                    "the records of the rrset differ in their proxy status, private routing or \
                     settings, so a new record cannot take them over",
                ),
            });
        };
        let encoded = encode(rtype, data).ok_or_else(not_sendable)?;
        let ttl = if inherit.proxied {
            match ttl {
                SetTtl::Requested(_) => return Err(proxied_ttl()),
                _ => TTL_AUTOMATIC,
            }
        } else {
            match ttl {
                SetTtl::Requested(ttl) | SetTtl::Existing(Some(ttl)) => ttl.as_secs(),
                // The records read report no TTL: they are automatic, and so is the new one.
                SetTtl::Existing(None) => TTL_AUTOMATIC,
                SetTtl::Default => self.ttl,
            }
        };
        let type_name = rtype.to_string();
        let (content, priority, fields) = match &encoded {
            Encoded::Content(content) => (Some(content.as_str()), None, None),
            Encoded::WithPriority(content, priority) => {
                (Some(content.as_str()), Some(*priority), None)
            }
            Encoded::Data(fields) => (None, None, Some(fields)),
        };
        let record = NewRecord {
            rtype: &type_name,
            name: name.without_dot(),
            content,
            priority,
            data: fields,
            ttl,
            proxied: inherit.proxied.then_some(true),
            private_routing: inherit.private_routing.then_some(true),
            settings: inherit.settings.as_ref(),
        };
        match self.api.create_record(&context.zone_id, &record).await? {
            Written::Done => Ok(()),
            Written::NotFound => {
                self.forget_zone(zone);
                Err(vanished())
            }
            // The API documents no refusal for a record that exists already, so a refused
            // create is followed by a new read (design section 3.5): the value found there now
            // was created by another writer after this operation's read, nothing was written,
            // and the repeat of the operation finds it. Otherwise, or when the read fails, the
            // refusal is the error.
            Written::Refused(
                e @ Error::Rejected {
                    status: Some(400..=499),
                    ..
                },
            ) => match self.read_records(zone, name, rtype).await {
                Ok((_, records)) if records.iter().any(|r| read_value(rtype, r) == *data) => {
                    Err(Error::Conflict {
                        detail: Detail::constant(
                            "the record was created by another writer between the read and the \
                             write",
                        ),
                    })
                }
                _ => Err(e),
            },
            Written::Refused(e) => Err(e),
        }
    }

    async fn update(
        &self,
        zone: &DomainName,
        _name: &DomainName,
        rtype: RecordType,
        context: &ReadContext,
        record: &Stored<Handle>,
        update: &RecordUpdate<'_>,
    ) -> Result<(), Error> {
        // Every record is enabled (the API has no disabled records), so `update.enable` is
        // never asked for and there is nothing to send for it.
        if update.ttl.is_some() && record.handle.attributes.proxied {
            return Err(proxied_ttl());
        }
        let encoded = match update.data {
            Some(data) => Some(encode(rtype, data).ok_or_else(not_sendable)?),
            None => None,
        };
        let type_name = rtype.to_string();
        let (content, priority, fields) = match &encoded {
            Some(Encoded::Content(content)) => (Some(content.as_str()), None, None),
            Some(Encoded::WithPriority(content, priority)) => {
                (Some(content.as_str()), Some(*priority), None)
            }
            Some(Encoded::Data(fields)) => (None, None, Some(fields)),
            None => (None, None, None),
        };
        let patch = RecordPatch {
            rtype: &type_name,
            content,
            priority,
            data: fields,
            ttl: update.ttl.map(Ttl::as_secs),
        };
        match self
            .api
            .update_record(&context.zone_id, &record.handle.id, &patch)
            .await?
        {
            Written::Done => Ok(()),
            Written::NotFound => {
                self.forget_zone(zone);
                Err(vanished())
            }
            Written::Refused(e) => Err(e),
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        context: &ReadContext,
        record: &Stored<Handle>,
    ) -> Result<(), Error> {
        match self
            .api
            .delete_record(&context.zone_id, &record.handle.id)
            .await?
        {
            Written::Done => Ok(()),
            // The record is gone, or the zone identifier is (a zone recreated with the record
            // in it). Only a new read under a freshly looked-up zone tells them apart.
            Written::NotFound => {
                self.forget_zone(zone);
                let (_, records) = self.read_records(zone, name, rtype).await?;
                if records.iter().any(|r| read_value(rtype, r) == record.data) {
                    Err(Error::Conflict {
                        detail: Detail::constant(
                            "the record was found again after its delete was answered \"not \
                             found\"; the zone changed between the read and the delete",
                        ),
                    })
                } else {
                    Ok(())
                }
            }
            Written::Refused(e) => Err(e),
        }
    }
}

/// A requested TTL for a proxied record.
fn proxied_ttl() -> Error {
    Error::InvalidInput {
        detail: Detail::constant(
            "the TTL of a proxied record is automatic at the provider and cannot be set",
        ),
    }
}

/// A write addressed a zone or a record that no longer exists: it changed after the read, and
/// nothing was written.
fn vanished() -> Error {
    Error::Conflict {
        detail: Detail::constant(
            "the zone or the record was removed between the read and the write",
        ),
    }
}

impl Cloudflare {
    /// The records of `name` and `rtype`, exact match, under the zone cache, with the zone
    /// identifier the read ended with.
    async fn read_records(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<(String, Vec<Record>), Error> {
        let type_name = rtype.to_string();
        let (zone_id, records) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| self.fetch(zone, id, Some(name), Some(&type_name)),
            )
            .await?;
        Ok((zone_id.id, records))
    }

    /// The read phase under the zone cache: the records of the zone `id` (of `name` and of type
    /// `rtype` where given, compared exactly), or `Stale` when the API does not know the zone
    /// (`404`) or refuses a read made with a cached identifier.
    pub(super) async fn fetch(
        &self,
        zone: &DomainName,
        id: ZoneId,
        name: Option<&DomainName>,
        rtype: Option<&str>,
    ) -> Result<Attempt<Vec<Record>>, Error> {
        match self
            .api
            .records(zone, &id.id, name.map(DomainName::without_dot), rtype)
            .await
        {
            // The API's name filter is case-insensitive and may be looser than exact: names and
            // types are compared again here.
            Ok(records) => Ok(Attempt::Done(
                records
                    .into_iter()
                    .filter(|r| rtype.is_none_or(|t| r.rtype == t))
                    .filter(|r| {
                        name.is_none_or(|name| DomainName::parse(&r.name).as_ref() == Ok(name))
                    })
                    .collect(),
            )),
            Err(Error::ZoneNotFound { .. }) => Ok(Attempt::Stale),
            // Assumption (not documented): the schema names no status for a zone identifier
            // the API no longer knows, so `404` may not be what a stale one gets. Any refusal
            // of a read made with a cached identifier is therefore treated as possibly stale:
            // the zone is looked up again and the read repeated once. Reads change nothing, so
            // being wrong costs one lookup; a refusal under a fresh identifier is the error.
            Err(
                Error::Rejected {
                    status: Some(400..=499),
                    ..
                }
                | Error::Forbidden { .. },
            ) if !id.fresh => Ok(Attempt::Stale),
            Err(e) => Err(e),
        }
    }

    /// `list_rrsets`: every record of the zone, all pages, under the zone-ID cache, grouped by
    /// name and type. The TTL of a group is the smallest explicit one.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let (_, all) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| self.fetch(zone, id, None, None),
            )
            .await?;
        // Grouped by the parsed name (the raw spelling when it does not parse) and the type.
        let mut groups: BTreeMap<(String, String), Group<'_>> = BTreeMap::new();
        for record in &all {
            let name = DomainName::parse(&record.name).ok();
            let key = name
                .as_ref()
                .map_or_else(|| format!("raw {}", record.name), DomainName::to_string);
            groups
                .entry((key, record.rtype.clone()))
                .or_insert_with(|| (name, Vec::new()))
                .1
                .push(record);
        }
        let mut listing = Listing::new(zone);
        for ((_, type_name), (name, records)) in groups {
            let ttl = records.iter().filter_map(|r| read_ttl(r)).min();
            // A type name that maps to no record type is skipped by the listing, whatever the
            // records hold; the content is then never parsed.
            let values = match type_name.parse::<RecordType>() {
                Ok(rtype) => records.iter().map(|r| read_value(rtype, r)).collect(),
                Err(_) => records
                    .iter()
                    .map(|r| RecordData::non_canonical(r.content.as_deref().unwrap_or_default()))
                    .collect(),
            };
            listing.push(name, &type_name, ttl, values);
        }
        listing.finish(ProviderId::Cloudflare)
    }
}
