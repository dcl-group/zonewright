//! Record-level operations: the `PerRecord` shape of the record layer (`crate::rrsets`) over the
//! record API, the listing of a zone, and the mapping between the API's record fields and
//! `RecordData`.
//!
//! The native unit is the individual record with an identifier, hence the per-record shape,
//! `Preconditions::ReadThenWrite` and no `atomic_rrset_write`: replacing an rrset is several
//! requests, creates first and deletes last (the record layer decides the order). The record
//! layer does the checks, takes the per-name lock, reads, evaluates the expectation and computes
//! the requests; this file turns them into the API's calls:
//!
//! - read: `GET …/records?type=&name=`, every page, an exact name and type match on the client's
//!   side (the filters' exactness is not documented);
//! - create: `POST …/records`, sent once, with the absolute name (the form `txt.rs` sends, see
//!   `api::NewRecord`), the type's fields and the TTL the layer chose;
//! - update: `PATCH …/records/{id}`, sent once, with the type and only the attributes that change
//!   (a TTL, or the value of a CNAME replaced in place). A `404` means the record went away after
//!   the read: nothing was written, `Error::Conflict`, and the caller's repeat reads again;
//! - delete: `DELETE …/records/{id}`, repeated by the transport (idempotent). A `404` counts as
//!   done (the layer's rule for a per-record API).
//!
//! # Fields per type
//!
//! The API carries a value in `data` plus, for some types, `priority`, `port`, `weight`, `flags`
//! and `tag` (OpenAPI `models/domain_record.yml`). Which type uses which field, and how `data` is
//! spelled, is taken from these sources, all opened for this client:
//!
//! - "API": the reference, <https://docs.digitalocean.com/reference/api/reference/domain-records/>,
//!   and the OpenAPI description it is built from (<https://github.com/digitalocean/openapi>,
//!   commit `9981928`, `specification/resources/domains/`): the field descriptions, the required
//!   fields per type (`models/domain_record_types.yml`), the examples (`examples.yml`: an answer
//!   with `NS` data `ns1.digitalocean.com`, without a trailing dot, and `A` data `1.2.3.4`);
//! - "dns-update": `src/providers/digitalocean.rs` at commit `f46313b` (lines 73 to 104 the
//!   fields per type, lines 329 to 335 and 373 to 408 the values it sends: host names made
//!   absolute with a trailing dot, CAA as flags, tag and the bare value);
//! - "lego": `providers/dns/digitalocean/digitalocean.go` line 129 (TXT: the value itself in
//!   `data`);
//! - "limits": <https://docs.digitalocean.com/products/networking/dns/details/limits/> (CAA: no
//!   `;` as the value and no name-value parameters after the CA name).
//!
//! | Type  | Canonical text from the API's fields  | Source                  |
//! | ----- | ------------------------------------- | ----------------------- |
//! | A     | `data`, the address                   | API, dns-update         |
//! | AAAA  | `data`, the address                   | API, dns-update         |
//! | CNAME | `data`, the target (1)                | dns-update              |
//! | NS    | `data`, the name server (1)           | API example, dns-update |
//! | MX    | `<priority> <data>` (1)               | API, dns-update         |
//! | SRV   | `<priority> <weight> <port> <data>`   | API, dns-update         |
//! | CAA   | `<flags> <tag> "<data>"` (2)          | API, dns-update, limits |
//! | TXT   | `data`, the value itself (3)          | lego, dns-update        |
//! | SOA   | `data`, read only (4)                 | API                     |
//!
//! (1) Written absolute with a trailing dot. (2) `data` is the bare property value. (3) TXT
//! dialect `Raw` on write, `Auto` on read. (4) Through the strict parser, else non-canonical.
//!
//! Reading: a host name in `data` without a trailing dot is absolute (the API's own NS example
//! states `ns1.digitalocean.com`), which is how `RecordData::parse` reads it. Assumption (not
//! documented): that the API never states a host name in `data` relative to the domain; such a
//! name would be read as absolute, which can only make a value compare unequal to the one a
//! caller expects, never delete a record that was not read. Text the parser refuses — `@`, a
//! missing `priority`, a field out of range — is kept as non-canonical data (design section
//! 4.9): listed, compared by text, written back only as it is.
//!
//! Writing stays within what the sources show, and [`RrsetBase::can_send`] refuses everything
//! else with `Error::InvalidInput` before any write:
//!
//! - host names: absolute with a trailing dot, never the root (`.`, a null MX or an SRV "no
//!   service": no source shows how the API takes it) and never with a backslash escape;
//! - TXT: plain values only (`Txt::is_plain`: 1 to 255 printable ASCII octets without space, `"`
//!   or `\`), the values the TXT value operations send. How the API treats spaces, quotes,
//!   escapes and values longer than one character-string is not established;
//! - CAA: the tags `issue`, `issuewild` and `iodef` (the API: "Valid values are ..."), flags 0 to
//!   255, and a value of printable ASCII without space, `"`, `\` and `;` (limits: no `;` value and
//!   no parameters).
//!
//! The API documents no record that is disabled, no comment and no other attribute the model
//! does not carry; per-record TTLs are the one, and the layer keeps them: a write without a TTL
//! leaves every record's own, a write with one sets it on every record (design section 3.6).
//!
//! SOA: "Can only have ttl changed, cannot be deleted" (the API's record type table): read only.
//! The NS rrset at the apex holds the provider's name servers ("NS records pointing at
//! DigitalOcean's name servers are automatically created",
//! <https://docs.digitalocean.com/products/networking/dns/how-to/manage-records/>); the record
//! layer refuses writes to it before any request. DS, TLSA and the other types are not documented
//! for the API: a listing carries them, they cannot be read alone or written.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::{DomainName, TargetName};
use crate::provider::ZoneListing;
use crate::record::{Caa, Mx, RecordData, RecordType, Srv, Ttl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::rrsets::{
    self, Listing, PerRecord, RecordUpdate, RecordsRead, RrsetBase, SetTtl, Stored,
};

use super::api::{Extra, NewRecord, Record, RecordPatch, Written, normalize_name};
use super::client::DigitalOcean;

/// How TXT data is read: quoted text as presentation format, anything else as the value
/// (design section 11.2).
const TXT_READ: TxtDialect = TxtDialect::Auto;

/// How TXT data is written: the value itself (lego digitalocean.go line 129).
const TXT_WRITE: TxtDialect = TxtDialect::Raw;

/// The CAA tags the API accepts.
// Source: OpenAPI `models/domain_record.yml`, `tag`: "Valid values are "issue", "issuewild", or
// "iodef"".
const CAA_TAGS: &[&str] = &["issue", "issuewild", "iodef"];

// ---- Reading -------------------------------------------------------------------------------------

/// A value as the API returned it: canonical where the type's fields parse, non-canonical
/// otherwise (see the module documentation).
pub(super) fn read_record(rtype: RecordType, record: &Record) -> RecordData {
    let data = record.data.as_deref().unwrap_or_default();
    match rtype {
        RecordType::A => read_a(data),
        RecordType::AAAA => read_aaaa(data),
        RecordType::CNAME => read_cname(data),
        RecordType::NS => read_ns(data),
        RecordType::MX => read_mx(record, data),
        RecordType::SRV => read_srv(record, data),
        RecordType::CAA => read_caa(record, data),
        RecordType::TXT => read_txt(data),
        other => read_other(other, data),
    }
}

/// A: the IPv4 address in `data`.
// Source: API, `data`: "the "data" value for an A record would be the IPv4 address"; the example
// `1.2.3.4`. dns-update digitalocean.rs line 75 (`data: Ipv4Addr`).
fn read_a(data: &str) -> RecordData {
    RecordData::from_provider(RecordType::A, data, None, TXT_READ)
}

/// AAAA: the IPv6 address in `data`.
// Source: dns-update digitalocean.rs line 78 (`data: Ipv6Addr`); the API's type table ("used to
// map an IPv6 address to a hostname").
fn read_aaaa(data: &str) -> RecordData {
    RecordData::from_provider(RecordType::AAAA, data, None, TXT_READ)
}

/// CNAME: the target name in `data`, absolute with or without its trailing dot.
// Source: dns-update digitalocean.rs lines 80 to 82 and 380 to 382 (the target in `data`).
fn read_cname(data: &str) -> RecordData {
    RecordData::from_provider(RecordType::CNAME, data, None, TXT_READ)
}

/// NS: the name server in `data`, absolute with or without its trailing dot.
// Source: API, `examples.yml` `domain_records_all` (`data: ns1.digitalocean.com`); dns-update
// digitalocean.rs lines 83 to 85.
fn read_ns(data: &str) -> RecordData {
    RecordData::from_provider(RecordType::NS, data, None, TXT_READ)
}

/// MX: `priority` and the exchange in `data`.
// Source: API, `priority`: "The priority for SRV and MX records"; `domain_record_mx` requires
// `data` and `priority`. dns-update digitalocean.rs lines 86 to 89.
fn read_mx(record: &Record, data: &str) -> RecordData {
    match number(record.priority.as_ref()) {
        Some(priority) => RecordData::from_provider(
            RecordType::MX,
            &format!("{priority} {data}"),
            None,
            TXT_READ,
        ),
        None => RecordData::non_canonical(data),
    }
}

/// SRV: `priority`, `weight`, `port` and the target in `data`.
// Source: API, `priority`, `port` ("The port for SRV records") and `weight` ("The weight for SRV
// records"). dns-update digitalocean.rs lines 93 to 98.
fn read_srv(record: &Record, data: &str) -> RecordData {
    let fields = (
        number(record.priority.as_ref()),
        number(record.weight.as_ref()),
        number(record.port.as_ref()),
    );
    match fields {
        (Some(priority), Some(weight), Some(port)) => RecordData::from_provider(
            RecordType::SRV,
            &format!("{priority} {weight} {port} {data}"),
            None,
            TXT_READ,
        ),
        _ => RecordData::non_canonical(data),
    }
}

/// CAA: `flags`, `tag` and the property value, bare, in `data`.
// Source: API, `flags` ("An unsigned integer between 0-255 used for CAA records"), `tag` ("The
// parameter tag for CAA records") and `data` ("For a CAA record, it would contain the domain name
// of the CA"). dns-update digitalocean.rs lines 99 to 103 and 398 to 405 (the value in `data`,
// unquoted).
fn read_caa(record: &Record, data: &str) -> RecordData {
    let flags = number(record.flags.as_ref()).and_then(|f| u8::try_from(f).ok());
    let tag = record.tag.as_deref();
    if let (Some(flags), Some(tag)) = (flags, tag) {
        let caa = Caa {
            flags,
            // Tags compare case-insensitively (RFC 8659 section 4.1; design section 4.5).
            tag: tag.to_ascii_lowercase(),
            value: data.as_bytes().to_vec(),
        };
        if let Ok(parsed) = caa.to_data() {
            return parsed;
        }
    }
    let shown = |v: Option<String>| v.unwrap_or_default();
    RecordData::non_canonical(&format!(
        "{} {} {data}",
        shown(record.flags.as_ref().map(Value::to_string)),
        shown(tag.map(str::to_owned)),
    ))
}

/// TXT: the value in `data`, read with the `Auto` rule.
// Source: lego digitalocean.go line 129 (the value itself in `data`); design section 11.2
// (`Auto` on read).
fn read_txt(data: &str) -> RecordData {
    RecordData::from_provider(RecordType::TXT, data, None, TXT_READ)
}

/// SOA and every type the client does not write: `data` through the strict parser.
// Source: none for the text form (the API documents none); text the parser refuses is carried as
// non-canonical data, which is harmless for a type that is only read or listed.
fn read_other(rtype: RecordType, data: &str) -> RecordData {
    RecordData::from_provider(rtype, data, None, TXT_READ)
}

/// A non-negative integer field.
fn number(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64)
}

// ---- Writing -------------------------------------------------------------------------------------

/// A value as the API takes it: `data` and the type's other fields.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Encoded {
    /// The `data` field.
    pub(super) data: String,
    /// MX preference or SRV priority.
    priority: Option<u16>,
    /// SRV port.
    port: Option<u16>,
    /// SRV weight.
    weight: Option<u16>,
    /// CAA flags.
    flags: Option<u8>,
    /// CAA tag.
    tag: Option<String>,
}

impl Encoded {
    fn data(data: String) -> Encoded {
        Encoded {
            data,
            priority: None,
            port: None,
            weight: None,
            flags: None,
            tag: None,
        }
    }

    /// The fields beyond `data`, for a request body.
    pub(super) fn extra(&self) -> Extra<'_> {
        Extra {
            priority: self.priority,
            port: self.port,
            weight: self.weight,
            flags: self.flags,
            tag: self.tag.as_deref(),
        }
    }
}

/// The API's fields for a canonical value of `rtype`, or `None` when the client cannot send it
/// (see the module documentation).
pub(super) fn encode(rtype: RecordType, data: &RecordData) -> Option<Encoded> {
    if !data.is_canonical() {
        return None;
    }
    match rtype {
        RecordType::A => write_a(data),
        RecordType::AAAA => write_aaaa(data),
        RecordType::CNAME => write_cname(data),
        RecordType::NS => write_ns(data),
        RecordType::MX => write_mx(data),
        RecordType::SRV => write_srv(data),
        RecordType::CAA => write_caa(data),
        RecordType::TXT => write_txt(data),
        _ => None,
    }
}

/// A: the canonical address (four decimal octets) as `data`.
// Source: API, the create example (`"type":"A"`, `"data":"162.10.66.0"`); dns-update
// digitalocean.rs line 378.
fn write_a(data: &RecordData) -> Option<Encoded> {
    Some(Encoded::data(data.as_str().to_owned()))
}

/// AAAA: the canonical address (RFC 5952) as `data`.
// Source: dns-update digitalocean.rs line 379 (`DnsRecord::AAAA(content)` into `data`).
fn write_aaaa(data: &RecordData) -> Option<Encoded> {
    Some(Encoded::data(data.as_str().to_owned()))
}

/// CNAME: the target, absolute with its trailing dot, as `data`.
// Source: dns-update digitalocean.rs lines 380 to 382 (`ensure_absolute`, lines 329 to 335).
fn write_cname(data: &RecordData) -> Option<Encoded> {
    TargetName::parse(data.as_str())
        .ok()
        .and_then(|target| host(&target))
        .map(Encoded::data)
}

/// NS: the name server, absolute with its trailing dot, as `data`.
// Source: dns-update digitalocean.rs lines 383 to 385.
fn write_ns(data: &RecordData) -> Option<Encoded> {
    TargetName::parse(data.as_str())
        .ok()
        .and_then(|target| host(&target))
        .map(Encoded::data)
}

/// MX: the preference as `priority`, the exchange, absolute with its trailing dot, as `data`.
// Source: API, `domain_record_mx` (`data`, `priority` required); dns-update digitalocean.rs lines
// 386 to 389.
fn write_mx(data: &RecordData) -> Option<Encoded> {
    let mx = Mx::from_data(data).ok()?;
    Some(Encoded {
        priority: Some(mx.preference),
        ..Encoded::data(host(&mx.exchange)?)
    })
}

/// SRV: `priority`, `weight`, `port`, and the target, absolute with its trailing dot, as
/// `data`.
// Source: API, `domain_record_srv` (`name`, `data`, `priority`, `port` required; `weight` "for
// SRV records"); dns-update digitalocean.rs lines 391 to 396.
fn write_srv(data: &RecordData) -> Option<Encoded> {
    let srv = Srv::from_data(data).ok()?;
    Some(Encoded {
        priority: Some(srv.priority),
        weight: Some(srv.weight),
        port: Some(srv.port),
        ..Encoded::data(host(&srv.target)?)
    })
}

/// CAA: `flags`, `tag`, and the bare value as `data`.
// Source: API, `domain_record_caa` (`name`, `data`, `flags`, `tag` required), the valid tags;
// dns-update digitalocean.rs lines 398 to 405; limits (no `;` value, no parameters).
fn write_caa(data: &RecordData) -> Option<Encoded> {
    let caa = Caa::from_data(data).ok()?;
    if !CAA_TAGS.contains(&caa.tag.as_str()) {
        return None;
    }
    let plain = !caa.value.is_empty()
        && caa
            .value
            .iter()
            .all(|&b| (0x21..=0x7e).contains(&b) && !matches!(b, b'"' | b'\\' | b';'));
    if !plain {
        return None;
    }
    let value = String::from_utf8(caa.value).ok()?;
    Some(Encoded {
        flags: Some(caa.flags),
        tag: Some(caa.tag),
        ..Encoded::data(value)
    })
}

/// TXT: a plain value, itself, as `data`.
// Source: lego digitalocean.go line 129; dns-update digitalocean.rs line 390.
fn write_txt(data: &RecordData) -> Option<Encoded> {
    let txt = Txt::from_data(data).ok().filter(Txt::is_plain)?;
    TXT_WRITE.write(&txt).map(Encoded::data)
}

/// A host name as `data`: absolute with its trailing dot; `None` for the root and for a name
/// whose canonical text needs a backslash escape.
fn host(name: &TargetName) -> Option<String> {
    let text = name.as_str();
    (!name.is_root() && !text.contains('\\')).then(|| text.to_owned())
}

// ---- The record layer ----------------------------------------------------------------------------

impl RrsetBase for DigitalOcean {
    fn provider(&self) -> ProviderId {
        ProviderId::DigitalOcean
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

impl PerRecord for DigitalOcean {
    /// The record's identifier.
    type Handle = u64;
    /// The domain's name is the key of every path: nothing to carry.
    type Context = ();

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<RecordsRead<u64, ()>, Error> {
        let records = self
            .api
            .records(zone, name, &rtype.to_string())
            .await?
            .into_iter()
            .filter(|record| {
                record.rtype.parse::<RecordType>().ok() == Some(rtype)
                    && record
                        .name
                        .as_deref()
                        .and_then(|stated| normalize_name(stated, zone))
                        .as_ref()
                        == Some(name)
            })
            .map(|record| Stored {
                data: read_record(rtype, &record),
                // The API has no disabled records.
                enabled: true,
                ttl: record.ttl.and_then(|secs| Ttl::from_secs(secs).ok()),
                handle: record.id,
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
        let encoded = encode(rtype, data).ok_or_else(not_sendable)?;
        let ttl = match ttl {
            SetTtl::Requested(ttl) | SetTtl::Existing(Some(ttl)) => Some(ttl.as_secs()),
            SetTtl::Default => Some(self.ttl),
            // The set's TTL was not reported: send none, so that the provider decides.
            SetTtl::Existing(None) => None,
        };
        let type_name = rtype.to_string();
        let record = NewRecord {
            rtype: &type_name,
            name: name.as_str(),
            data: &encoded.data,
            ttl,
            extra: encoded.extra(),
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
        _name: &DomainName,
        rtype: RecordType,
        _context: &(),
        record: &Stored<u64>,
        update: &RecordUpdate<'_>,
    ) -> Result<(), Error> {
        if update.enable {
            // Every record this client reads is enabled, so the layer never asks for this.
            return Err(Error::Protocol {
                detail: Detail::constant("the provider has no disabled records to enable"),
            });
        }
        let encoded = match update.data {
            Some(data) => Some(encode(rtype, data).ok_or_else(not_sendable)?),
            None => None,
        };
        let type_name = rtype.to_string();
        let patch = RecordPatch {
            rtype: &type_name,
            data: encoded.as_ref().map(|e| e.data.as_str()),
            ttl: update.ttl.map(Ttl::as_secs),
            extra: encoded.as_ref().map(Encoded::extra).unwrap_or_default(),
        };
        match self.api.update_record(zone, record.handle, &patch).await? {
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
        record: &Stored<u64>,
    ) -> Result<(), Error> {
        // "Not found" counts as done: the record is gone (the record layer's rule for a
        // per-record API).
        match self.api.delete_record(zone, record.handle).await? {
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

impl DigitalOcean {
    /// `list_rrsets`: every record of the domain, all pages, grouped by owner name and type.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let all = self.api.all_records(zone).await?;
        let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
        for record in &all {
            let stated = record.name.as_deref().unwrap_or_default();
            let name = normalize_name(stated, zone);
            let rtype = record.rtype.parse::<RecordType>().ok();
            // Spellings of one name or type that mean the same land in one group.
            let key = (
                name.as_ref()
                    .map_or_else(|| format!("raw:{stated}"), |n| n.as_str().to_owned()),
                rtype.map_or_else(|| format!("raw:{}", record.rtype), |t| t.to_string()),
            );
            let data = match rtype {
                Some(rtype) => read_record(rtype, record),
                // A type name that maps to no record type is skipped by the listing whatever
                // the record holds; the data is then never parsed.
                None => RecordData::non_canonical(record.data.as_deref().unwrap_or_default()),
            };
            let ttl = record.ttl.and_then(|secs| Ttl::from_secs(secs).ok());
            let group = groups.entry(key).or_insert_with(|| Group {
                name,
                type_name: record.rtype.clone(),
                rtype,
                ttl: None,
                records: Vec::new(),
            });
            // The smallest TTL of the set (design section 3.6, `TtlSupport::PerRecord`).
            group.ttl = match (group.ttl, ttl) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            group.records.push(data);
        }
        let mut listing = Listing::new(zone);
        for group in groups.into_values() {
            let type_name = group
                .rtype
                .map_or(group.type_name, |rtype| rtype.to_string());
            listing.push(group.name, &type_name, group.ttl, group.records);
        }
        listing.finish(ProviderId::DigitalOcean)
    }
}

#[cfg(test)]
mod tests {
    use super::{Encoded, encode, read_record};
    use crate::providers::digitalocean::api::Record;
    use crate::record::{RecordData, RecordType};

    fn record(rtype: &str, data: &str, fields: serde_json::Value) -> Record {
        let mut json = serde_json::json!({
            "id": 1, "type": rtype, "name": "www", "data": data, "ttl": 1800,
            "priority": null, "port": null, "weight": null, "flags": null, "tag": null
        });
        if let (Some(target), Some(extra)) = (json.as_object_mut(), fields.as_object()) {
            for (k, v) in extra {
                target.insert(k.clone(), v.clone());
            }
        }
        serde_json::from_value(json).unwrap()
    }

    fn read(rtype: RecordType, data: &str, fields: serde_json::Value) -> RecordData {
        read_record(rtype, &record(&rtype.to_string(), data, fields))
    }

    fn data(rtype: RecordType, text: &str) -> RecordData {
        RecordData::parse(rtype, text).unwrap()
    }

    #[test]
    fn each_type_reads_into_canonical_text() {
        let none = serde_json::json!({});
        for (rtype, api, fields, canonical) in [
            (RecordType::A, "192.0.2.1", none.clone(), "192.0.2.1"),
            (
                RecordType::AAAA,
                "2001:DB8:0::1",
                none.clone(),
                "2001:db8::1",
            ),
            (
                RecordType::CNAME,
                "Target.example.net",
                none.clone(),
                "target.example.net.",
            ),
            (
                RecordType::CNAME,
                "target.example.net.",
                none.clone(),
                "target.example.net.",
            ),
            (
                RecordType::NS,
                "ns1.digitalocean.com",
                none.clone(),
                "ns1.digitalocean.com.",
            ),
            (
                RecordType::MX,
                "mail.example.org",
                serde_json::json!({"priority": 10}),
                "10 mail.example.org.",
            ),
            (
                RecordType::SRV,
                "sip.example.org.",
                serde_json::json!({"priority": 1, "weight": 5, "port": 5060}),
                "1 5 5060 sip.example.org.",
            ),
            (
                RecordType::CAA,
                "letsencrypt.org",
                serde_json::json!({"flags": 0, "tag": "issue"}),
                "0 issue \"letsencrypt.org\"",
            ),
            (
                RecordType::CAA,
                "mailto:sec@example.org",
                serde_json::json!({"flags": 128, "tag": "IODEF"}),
                "128 iodef \"mailto:sec@example.org\"",
            ),
            (
                RecordType::TXT,
                "v=spf1 -all",
                none.clone(),
                "\"v=spf1 -all\"",
            ),
            (
                RecordType::TXT,
                "\"quoted\" \"two\"",
                none.clone(),
                "\"quotedtwo\"",
            ),
        ] {
            let got = read(rtype, api, fields);
            assert!(got.is_canonical(), "{rtype} {api}");
            assert_eq!(got.as_str(), canonical, "{rtype} {api}");
        }
    }

    #[test]
    fn unparseable_fields_are_non_canonical() {
        for (rtype, api, fields, kept) in [
            (
                RecordType::A,
                "not an address",
                serde_json::json!({}),
                "not an address",
            ),
            (RecordType::CNAME, "@", serde_json::json!({}), "@"),
            (
                RecordType::MX,
                "mail.example.org",
                serde_json::json!({}),
                "mail.example.org",
            ),
            (
                RecordType::MX,
                "mail.example.org",
                serde_json::json!({"priority": 70000}),
                "70000 mail.example.org",
            ),
            (
                RecordType::SRV,
                "sip.example.org",
                serde_json::json!({"priority": 1, "port": 5060}),
                "sip.example.org",
            ),
            (
                RecordType::CAA,
                "ca.example.net",
                serde_json::json!({"flags": 300, "tag": "issue"}),
                "300 issue ca.example.net",
            ),
            (
                RecordType::CAA,
                "ca.example.net",
                serde_json::json!({"flags": 0, "tag": "bad tag"}),
                "0 bad tag ca.example.net",
            ),
            (RecordType::SOA, "1800", serde_json::json!({}), "1800"),
        ] {
            let got = read(rtype, api, fields);
            assert!(!got.is_canonical(), "{rtype} {api}");
            assert_eq!(got.as_str(), kept, "{rtype} {api}");
        }
    }

    fn fields(e: &Encoded) -> serde_json::Value {
        let mut value = serde_json::to_value(e.extra()).unwrap();
        value["data"] = serde_json::json!(e.data);
        value
    }

    #[test]
    fn each_type_writes_the_documented_fields() {
        for (rtype, text, expected) in [
            (
                RecordType::A,
                "192.0.2.1",
                serde_json::json!({"data": "192.0.2.1"}),
            ),
            (
                RecordType::AAAA,
                "2001:db8::1",
                serde_json::json!({"data": "2001:db8::1"}),
            ),
            (
                RecordType::CNAME,
                "target.example.net.",
                serde_json::json!({"data": "target.example.net."}),
            ),
            (
                RecordType::NS,
                "ns1.example.net.",
                serde_json::json!({"data": "ns1.example.net."}),
            ),
            (
                RecordType::MX,
                "10 mail.example.org.",
                serde_json::json!({"data": "mail.example.org.", "priority": 10}),
            ),
            (
                RecordType::SRV,
                "1 5 5060 sip.example.org.",
                serde_json::json!({
                    "data": "sip.example.org.", "priority": 1, "weight": 5, "port": 5060
                }),
            ),
            (
                RecordType::CAA,
                "128 issuewild \"ca.example.net\"",
                serde_json::json!({"data": "ca.example.net", "flags": 128, "tag": "issuewild"}),
            ),
            (RecordType::TXT, "\"v1\"", serde_json::json!({"data": "v1"})),
        ] {
            let encoded = encode(rtype, &data(rtype, text)).unwrap();
            assert_eq!(fields(&encoded), expected, "{rtype} {text}");
            // Read back through the same fields, the value is the same.
            let mut extra = expected.clone();
            let api = extra["data"].as_str().unwrap().to_owned();
            extra.as_object_mut().unwrap().remove("data");
            assert_eq!(read(rtype, &api, extra), data(rtype, text), "{rtype}");
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
            (RecordType::CAA, "0 issue \";\""),
            (RecordType::CAA, "0 issue \"ca.example.net; account=1\""),
            (RecordType::CAA, "0 issue \"\""),
            (RecordType::CAA, "0 contactemail \"a@example.org\""),
            (
                RecordType::SOA,
                "ns1.example.org. admin.example.org. 1 7200 3600 1209600 300",
            ),
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
