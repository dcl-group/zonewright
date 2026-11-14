//! Record-level operations: the `PerRecord` shape of the record layer (`crate::rrsets`) over the
//! record API, the listing of a zone, and the mapping between the API's record fields and
//! `RecordData`.
//!
//! The native unit is the individual record with an identifier, hence the per-record shape,
//! `Preconditions::ReadThenWrite` and no `atomic_rrset_write`: replacing an rrset is several
//! requests, creates first and deletes last (the record layer decides the order). The record
//! layer does the checks, takes the per-name lock, reads, evaluates the expectation and computes
//! the requests; this file turns them into the API's calls, all addressed to the owner name
//! itself (the zone, or the full name below it), as the TXT value operations are (`txt.rs`):
//!
//! - read: `GET /v1/domains/{name}/dns-records`, every page, then the records of exactly the
//!   requested type at exactly the requested name, selected on the client's side. A listing of a
//!   name below the zone that states a record without a name is `Error::Protocol`;
//! - create: `POST /v2/domains/{name}/dns-records`, sent once, with the type's fields and the
//!   TTL the layer chose. A `404` is told apart by a lookup of the zone (`Error::ZoneNotFound`,
//!   or the provider's refusal of the name);
//! - update: `PATCH /v2/domains/{name}/dns-records/{id}`, sent once. Its body is the create's
//!   whole per-type object, so it carries the record's value (the new one for a CNAME replaced in
//!   place, otherwise the value exactly as the listing stated it), the MX priority, and the TTL
//!   (the requested one, otherwise the record's own as read). A `404` means the record went away
//!   after the read: nothing was written, `Error::Conflict`, and the caller's repeat reads again;
//! - delete: `DELETE /v2/domains/{name}/dns-records/{id}`, repeated by the transport
//!   (idempotent). A `404` counts as done once a new read no longer shows the value: the domain
//!   may have been deleted and created again with the value under a new identifier, which is
//!   `Error::Conflict`.
//!
//! # Fields per type
//!
//! Source of every row: the public API description, <https://timeweb.cloud/api-docs> (the
//! OpenAPI document `https://timeweb.cloud/api-docs-data/bundle.json`, version `1.0.0`, read on
//! 2026-11-14): the write side is the per-type request objects of the schema `create-dns-v2`,
//! the body of the `v2` create and update; the read side is the listing's record schema
//! `dns-record`, whose `data` has `value`, `priority` and `subdomain` only.
//!
//! | Type  | Written as                                   | Canonical text from the listing |
//! | ----- | -------------------------------------------- | ------------------------------- |
//! | A     | `value`, "IPv4 address"                      | `value`                         |
//! | AAAA  | `value`, "IPv6 address" (example `2001:db8::1`) | `value`                      |
//! | CNAME | `value`, "canonical name (the target domain)" (1) | `value` (2)                |
//! | MX    | `value`, "mail server name" (1), and `priority` | `<priority> <value>` (2)     |
//! | TXT   | `value`, "the record's text value" (3)       | `value` (3)                     |
//!
//! (1) Written without a trailing dot, as every example of the description spells a host name
//! (`somedomain.ru`); never the root (a null MX: no source shows how the API takes it) and never
//! a name whose canonical text needs a backslash escape. (2) A host name without a trailing dot
//! is absolute, which is how `RecordData::parse` reads it. Assumption (not documented): that the
//! API never states a host name relative to the domain; such a name would be read as absolute,
//! which can only make a value compare unequal to what a caller expects, never delete a record
//! that was not read. (3) TXT dialect `Raw` on write, `Auto` on read (design section 11.2), and
//! only plain values are written (`Txt::is_plain`), as for the TXT value operations: how the API
//! treats spaces, quotes, escapes and long values is not established.
//!
//! Text the parser refuses (an MX without a whole-number `priority`, an address that does not
//! parse) is kept as non-canonical data (design section 4.9): listed, compared by text, written
//! back only as it is.
//!
//! SRV is not a record-level type here: its create object (`service`, `protocol`, `priority`,
//! `port`, `host`) has no weight, and the listing documents no field for its port and target, so
//! an SRV record can neither be written nor read in full. A listing carries an SRV record, and
//! any type the description does not name, with its `value` through the strict parser, which
//! normally keeps it as non-canonical data.
//!
//! # Attributes the model does not carry
//!
//! The listing documents none besides the per-record TTL: no disabled records, no comments. The
//! A create has an optional `app_id` (an App Platform application to bind the name to) that the
//! listing does not return; this client never sends it, and a TTL update sends the A record's
//! value and TTL only, since nothing else is known about it. Per-record TTLs are kept by the
//! layer: a write without a TTL leaves every record's own, a write with one sets it on every
//! record (design section 3.6).
//!
//! # The listing of a zone
//!
//! The listing of a domain is "all user DNS records of a domain or subdomain"; whether the
//! domain's listing includes the records of its subdomains is not stated. The description
//! requires a record below the domain to be at a subdomain created beforehand, and the domain's
//! answer (`GET /v1/domains/{zone}`, `domain.subdomains`, required) states every subdomain with
//! its full name. `list_rrsets` therefore reads the zone's listing and the listing of every
//! stated subdomain, and takes each record once (by its identifier), the subdomains' listings
//! first: a record in the listing of the name it can denote is at that name, the same selection
//! a read makes, and any other record is at the reading of its stated name that lies within the
//! zone (see `api::owner`). A
//! record at a name that is neither the zone nor a stated subdomain, and that the zone's listing
//! does not show either, cannot be found: the description rules such a record out, while lego
//! creates records without creating a subdomain first (see `api.rs`); only a live run tells
//! whether the provider then creates the subdomain. The provider's "default DNS records"
//! (`GET /v1/domains/{fqdn}/default-dns-records`) are a separate listing whose relation to the
//! published zone is not described; they are not part of what this client reads or writes.

use std::collections::{BTreeMap, HashSet};

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::{DomainName, TargetName};
use crate::provider::ZoneListing;
use crate::record::{Mx, RecordData, RecordType, Ttl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::rrsets::{
    self, Listing, Neighbors, PerRecord, RecordUpdate, RecordsRead, RrsetBase, SetTtl, Stored,
};

use super::api::{Created, Deleted, NewRecord, Record, Updated, check_named, owner, stated_names};
use super::client::TimewebCloud;

/// How TXT data is read: quoted text as presentation format, anything else as the value
/// (design section 11.2).
const TXT_READ: TxtDialect = TxtDialect::Auto;

/// How TXT data is written: the value itself (lego timewebcloud.go line 115 at commit
/// `012a2c1e01`).
const TXT_WRITE: TxtDialect = TxtDialect::Raw;

// ---- Reading -------------------------------------------------------------------------------------

/// A value as the listing states it: canonical where the type's fields parse, non-canonical
/// otherwise (see the module documentation).
pub(super) fn read_record(rtype: RecordType, record: &Record) -> RecordData {
    let value = record.value().unwrap_or_default();
    match rtype {
        RecordType::A => read_a(value),
        RecordType::AAAA => read_aaaa(value),
        RecordType::CNAME => read_cname(value),
        RecordType::MX => read_mx(record, value),
        RecordType::TXT => read_txt(value),
        other => read_other(other, value),
    }
}

/// A: the IPv4 address in `value`.
// Source: `dns-record` `data.value` ("the DNS record's value", example `98.76.54.32`).
fn read_a(value: &str) -> RecordData {
    RecordData::from_provider(RecordType::A, value, None, TXT_READ)
}

/// AAAA: the IPv6 address in `value`.
// Source: `dns-record` `data.value`; `dns-record-v2` example `2001:db8::1` for AAAA.
fn read_aaaa(value: &str) -> RecordData {
    RecordData::from_provider(RecordType::AAAA, value, None, TXT_READ)
}

/// CNAME: the target in `value`, absolute with or without its trailing dot.
// Source: `dns-record` `data.value`; `dns-record-v2` example `somedomain.ru` for CNAME.
fn read_cname(value: &str) -> RecordData {
    RecordData::from_provider(RecordType::CNAME, value, None, TXT_READ)
}

/// MX: `priority` and the exchange in `value`.
// Source: `dns-record` `data.priority` ("the DNS record's priority") and `data.value`;
// `dns-record-v2` example for MX (`value` `somedomain.ru`, `priority` 10).
fn read_mx(record: &Record, value: &str) -> RecordData {
    match (record.priority(), record.priority_text()) {
        (Some(priority), _) => RecordData::from_provider(
            RecordType::MX,
            &format!("{priority} {value}"),
            None,
            TXT_READ,
        ),
        (None, Some(stated)) => RecordData::non_canonical(&format!("{stated} {value}")),
        (None, None) => RecordData::non_canonical(value),
    }
}

/// TXT: the value in `value`, read with the `Auto` rule.
// Source: `dns-record` `data.value`; design section 11.2 (`Auto` on read).
fn read_txt(value: &str) -> RecordData {
    RecordData::from_provider(RecordType::TXT, value, None, TXT_READ)
}

/// SRV and every type the description does not name: `value` through the strict parser.
// Source: none for the text form (the listing documents only `value` and `priority`); text the
// parser refuses is carried as non-canonical data, which is harmless for a type that is only
// listed.
fn read_other(rtype: RecordType, value: &str) -> RecordData {
    RecordData::from_provider(rtype, value, None, TXT_READ)
}

// ---- Writing -------------------------------------------------------------------------------------

/// A value as the API takes it: `value` and, for MX, `priority`.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Encoded {
    /// The `value` field.
    pub(super) value: String,
    /// The MX `priority`.
    pub(super) priority: Option<u64>,
}

impl Encoded {
    fn value(value: String) -> Encoded {
        Encoded {
            value,
            priority: None,
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
        RecordType::MX => write_mx(data),
        RecordType::TXT => write_txt(data),
        _ => None,
    }
}

/// A: the canonical address (four decimal octets) as `value`.
// Source: `create-dns-v2` "A запись": `type`, `value` ("IPv4 address", example `192.168.1.0`)
// required, `ttl` optional.
fn write_a(data: &RecordData) -> Option<Encoded> {
    Some(Encoded::value(data.as_str().to_owned()))
}

/// AAAA: the canonical address (RFC 5952) as `value`.
// Source: `create-dns-v2` "AAAA запись": `type`, `value` ("IPv6 address", example
// `2001:db8::1`) required, `ttl` optional.
fn write_aaaa(data: &RecordData) -> Option<Encoded> {
    Some(Encoded::value(data.as_str().to_owned()))
}

/// CNAME: the target, without its trailing dot, as `value`.
// Source: `create-dns-v2` "CNAME запись": `type`, `value` ("canonical name (the target
// domain)", example `somedomain.ru`) required, `ttl` optional.
fn write_cname(data: &RecordData) -> Option<Encoded> {
    TargetName::parse(data.as_str())
        .ok()
        .and_then(|target| host(&target))
        .map(Encoded::value)
}

/// MX: the preference as `priority`, the exchange, without its trailing dot, as `value`.
// Source: `create-dns-v2` "MX запись": `type`, `value` ("mail server name", example
// `somedomain.ru`) and `priority` ("the mail server's priority (the lower the value, the higher
// the priority)", example 10) required, `ttl` optional.
fn write_mx(data: &RecordData) -> Option<Encoded> {
    let mx = Mx::from_data(data).ok()?;
    Some(Encoded {
        priority: Some(u64::from(mx.preference)),
        ..Encoded::value(host(&mx.exchange)?)
    })
}

/// TXT: a plain value, itself, as `value`.
// Source: `create-dns-v2` "TXT запись": `type`, `value` ("the record's text value") required,
// `ttl` optional; lego timewebcloud.go line 115 (commit `012a2c1e01`) sends the value unquoted.
fn write_txt(data: &RecordData) -> Option<Encoded> {
    let txt = Txt::from_data(data).ok().filter(Txt::is_plain)?;
    TXT_WRITE.write(&txt).map(Encoded::value)
}

/// A host name as `value`: without its trailing dot, as the description's examples spell it;
/// `None` for the root and for a name whose canonical text needs a backslash escape.
fn host(name: &TargetName) -> Option<String> {
    let text = name.as_str();
    if name.is_root() || text.contains('\\') {
        return None;
    }
    Some(text.strip_suffix('.').unwrap_or(text).to_owned())
}

// ---- The record layer ----------------------------------------------------------------------------

/// What a write back needs of a listed record: its identifier, and its `value` and `priority`
/// exactly as the listing stated them.
#[derive(Clone, Debug)]
pub(crate) struct Handle {
    /// The identifier; the listing's schema allows a record without one, which can be read but
    /// neither changed nor deleted.
    id: Option<u64>,
    /// `data.value` as stated.
    value: Option<String>,
    /// `data.priority` as stated, when a non-negative whole number.
    priority: Option<u64>,
}

impl RrsetBase for TimewebCloud {
    fn provider(&self) -> ProviderId {
        ProviderId::TimewebCloud
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

fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

/// The identifier of a record the layer wants to change or delete.
fn identifier(record: &Stored<Handle>) -> Result<u64, Error> {
    record.handle.id.ok_or_else(|| {
        protocol("the provider lists the record without an identifier, so it cannot be changed")
    })
}

impl PerRecord for TimewebCloud {
    type Handle = Handle;
    /// The owner name is the key of every path, so no identifier is carried; the read lists
    /// every record of the name and carries what else is there.
    type Context = Neighbors;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<RecordsRead<Handle, Neighbors>, Error> {
        let listed = self.api.records(zone, name).await?;
        check_named(&listed, name == zone)?;
        let (records, others): (Vec<Record>, Vec<Record>) = listed
            .into_iter()
            .filter(|record| stated_names(record.subdomain(), zone).contains(name))
            .partition(|record| record.rtype.parse::<RecordType>().ok() == Some(rtype));
        // The listing holds the records of the name of every type, and the API documents no
        // disabled records: the other records are all the data there besides this type.
        let neighbors = Neighbors::of(
            rtype,
            others
                .iter()
                .map(|record| record.rtype.parse::<RecordType>().ok()),
        );
        let records = records
            .into_iter()
            .map(|record| Stored {
                data: read_record(rtype, &record),
                // The API documents no disabled records.
                enabled: true,
                ttl: record.ttl().and_then(|secs| Ttl::from_secs(secs).ok()),
                handle: Handle {
                    id: record.id(),
                    value: record.value().map(str::to_owned),
                    priority: record.priority(),
                },
            })
            .collect();
        Ok(RecordsRead {
            context: neighbors,
            records,
        })
    }

    async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &Neighbors,
        data: &RecordData,
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let encoded = encode(rtype, data).ok_or_else(not_sendable)?;
        let ttl = match ttl {
            SetTtl::Requested(ttl) | SetTtl::Existing(Some(ttl)) => Some(ttl.as_secs()),
            // The configured TTL; none leaves the choice to the provider.
            SetTtl::Default => self.ttl,
            // The set's TTL was not reported: send none, so that the provider decides.
            SetTtl::Existing(None) => None,
        };
        let type_name = rtype.to_string();
        let record = NewRecord {
            rtype: &type_name,
            value: &encoded.value,
            priority: encoded.priority,
            ttl,
        };
        match self.api.create_record(name, &record).await? {
            Created::Done => Ok(()),
            // Nothing was written. Either the domain does not exist (any more), or the provider
            // does not take the name as a subdomain of it; only a lookup tells them apart.
            Created::NotFound(refusal) => Err(if self.api.zone_exists(zone).await? {
                refusal
            } else {
                Error::zone_not_found(zone.clone())
            }),
        }
    }

    async fn update(
        &self,
        _zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &Neighbors,
        record: &Stored<Handle>,
        update: &RecordUpdate<'_>,
    ) -> Result<(), Error> {
        if update.enable {
            // Every record this client reads is enabled, so the layer never asks for this.
            return Err(protocol("the provider has no disabled records to enable"));
        }
        let id = identifier(record)?;
        let (value, priority) =
            match update.data {
                Some(data) => {
                    let encoded = encode(rtype, data).ok_or_else(not_sendable)?;
                    (encoded.value, encoded.priority)
                }
                // The body is the whole object: the value goes back exactly as it was listed.
                None => (
                    record.handle.value.clone().ok_or_else(|| {
                        protocol("the provider lists the record without its value")
                    })?,
                    record.handle.priority,
                ),
            };
        if rtype == RecordType::MX && priority.is_none() {
            return Err(protocol(
                "the provider lists the MX record without a usable priority, so it cannot be \
                 written back",
            ));
        }
        let type_name = rtype.to_string();
        let body = NewRecord {
            rtype: &type_name,
            value: &value,
            priority: if rtype == RecordType::MX {
                priority
            } else {
                None
            },
            // A TTL that is not changed is sent as read: whether an update without one keeps it
            // is not documented.
            ttl: update.ttl.or(record.ttl).map(Ttl::as_secs),
        };
        match self.api.update_record(name, id, &body).await? {
            Updated::Done => Ok(()),
            // The record, or the domain, went away after the read; nothing was written.
            Updated::NotFound => Err(Error::Conflict {
                detail: Detail::constant("the record was removed between the read and the update"),
            }),
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &Neighbors,
        record: &Stored<Handle>,
    ) -> Result<(), Error> {
        let id = identifier(record)?;
        if let Deleted::NotFound = self.api.delete_record(name, id).await? {
            // The record is gone, or the domain is and was created again. Only a new read tells
            // them apart.
            let now = self.read(zone, name, rtype).await?;
            if now.records.iter().any(|r| r.data == record.data) {
                return Err(Error::Conflict {
                    detail: Detail::constant(
                        "the value was found again after its delete was answered \
                         \"not found\"; the domain changed between the read and the delete",
                    ),
                });
            }
        }
        Ok(())
    }

    fn holds_cname(&self, _rtype: RecordType, context: &Neighbors) -> Option<bool> {
        context.holds_cname()
    }

    fn holds_other_data(&self, _rtype: RecordType, context: &Neighbors) -> Option<bool> {
        context.holds_other_data()
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

impl TimewebCloud {
    /// `list_rrsets`: the zone's listing and the listing of every subdomain the provider states
    /// for the zone, all pages, each record once, grouped by owner name and type (see the module
    /// documentation).
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let subdomains = self.api.subdomains(zone).await?;
        let mut listings: Vec<(Option<DomainName>, Vec<Record>)> =
            vec![(Some(zone.clone()), self.api.records(zone, zone).await?)];
        let mut listed: HashSet<String> = HashSet::new();
        for stated in &subdomains {
            let text = stated.trim();
            let text = text.strip_suffix('.').unwrap_or(text);
            let parsed = DomainName::parse(text)
                .ok()
                .filter(|name| name.is_within(zone));
            match parsed {
                Some(name) if &name == zone => {}
                Some(name) => {
                    if listed.insert(name.as_str().to_owned()) {
                        let records = self.api.records(zone, &name).await?;
                        listings.push((Some(name), records));
                    }
                }
                // A name the client cannot hold, or one outside the zone: its listing is read
                // by the text as stated, and its records are placed by their own stated names,
                // or skipped when they have none the model can hold.
                None => {
                    if listed.insert(format!("raw:{text}"))
                        && let Some(records) = self.api.records_of(text).await?
                    {
                        listings.push((None, records));
                    }
                }
            }
        }

        let mut seen: HashSet<u64> = HashSet::new();
        let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
        // The subdomains' listings first: a record they show is placed at the listed name, as a
        // read of that name places it, before the zone's listing could place it by a reading
        // of its stated name alone.
        for (listed, records) in listings.iter().rev() {
            check_named(records, listed.as_ref() == Some(zone))?;
            for record in records {
                // A record shown by two listings (the zone's and a subdomain's) is one record.
                if let Some(id) = record.id()
                    && !seen.insert(id)
                {
                    continue;
                }
                let stated = record.subdomain().unwrap_or_default();
                let name = owner(listed.as_ref(), record.subdomain(), zone);
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
                    None => RecordData::non_canonical(record.value().unwrap_or_default()),
                };
                let ttl = record.ttl().and_then(|secs| Ttl::from_secs(secs).ok());
                let group = groups.entry(key).or_insert_with(|| Group {
                    name,
                    type_name: record.rtype.clone(),
                    rtype,
                    ttl: None,
                    records: Vec::new(),
                });
                // The smallest TTL of the set (design section 3.6, `TtlSupport::PerRecord`).
                group.ttl = Listing::smallest_ttl([group.ttl, ttl]);
                group.records.push(data);
            }
        }
        let mut listing = Listing::new(zone);
        for group in groups.into_values() {
            let type_name = group
                .rtype
                .map_or(group.type_name, |rtype| rtype.to_string());
            listing.push(group.name, &type_name, group.ttl, group.records);
        }
        listing.finish(ProviderId::TimewebCloud)
    }
}

#[cfg(test)]
mod tests {
    use super::{Encoded, encode, read_record};
    use crate::providers::timeweb_cloud::api::Record;
    use crate::record::{RecordData, RecordType};

    fn record(rtype: &str, value: &str, priority: serde_json::Value) -> Record {
        serde_json::from_value(serde_json::json!({
            "id": 1, "type": rtype, "ttl": 600,
            "data": {"subdomain": "www", "value": value, "priority": priority}
        }))
        .unwrap()
    }

    fn read(rtype: RecordType, value: &str, priority: serde_json::Value) -> RecordData {
        read_record(rtype, &record(&rtype.to_string(), value, priority))
    }

    fn data(rtype: RecordType, text: &str) -> RecordData {
        RecordData::parse(rtype, text).unwrap()
    }

    #[test]
    fn each_type_reads_into_canonical_text() {
        let none = serde_json::Value::Null;
        for (rtype, api, priority, canonical) in [
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
                RecordType::MX,
                "mail.example.org",
                serde_json::json!(10),
                "10 mail.example.org.",
            ),
            (
                RecordType::MX,
                "mail.example.org",
                serde_json::json!(10.0),
                "10 mail.example.org.",
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
            let got = read(rtype, api, priority);
            assert!(got.is_canonical(), "{rtype} {api}");
            assert_eq!(got.as_str(), canonical, "{rtype} {api}");
        }
    }

    #[test]
    fn unparseable_fields_are_non_canonical() {
        for (rtype, api, priority, kept) in [
            (
                RecordType::A,
                "not an address",
                serde_json::Value::Null,
                "not an address",
            ),
            (RecordType::CNAME, "@", serde_json::Value::Null, "@"),
            (
                RecordType::MX,
                "mail.example.org",
                serde_json::Value::Null,
                "mail.example.org",
            ),
            (
                RecordType::MX,
                "mail.example.org",
                serde_json::json!(70000),
                "70000 mail.example.org",
            ),
            (
                RecordType::MX,
                "mail.example.org",
                serde_json::json!(1.5),
                "1.5 mail.example.org",
            ),
            (
                RecordType::SRV,
                "sip.example.org",
                serde_json::json!(10),
                "sip.example.org",
            ),
        ] {
            let got = read(rtype, api, priority);
            assert!(!got.is_canonical(), "{rtype} {api}");
            assert_eq!(got.as_str(), kept, "{rtype} {api}");
        }
    }

    #[test]
    fn each_type_writes_the_documented_fields() {
        for (rtype, text, value, priority) in [
            (RecordType::A, "192.0.2.1", "192.0.2.1", None),
            (RecordType::AAAA, "2001:db8::1", "2001:db8::1", None),
            (
                RecordType::CNAME,
                "target.example.net.",
                "target.example.net",
                None,
            ),
            (
                RecordType::MX,
                "10 mail.example.org.",
                "mail.example.org",
                Some(10),
            ),
            (RecordType::TXT, "\"v1\"", "v1", None),
        ] {
            let encoded = encode(rtype, &data(rtype, text)).unwrap();
            assert_eq!(
                encoded,
                Encoded {
                    value: value.to_owned(),
                    priority
                },
                "{rtype} {text}"
            );
            // Read back through the same fields, the value is the same.
            let priority = priority.map_or(serde_json::Value::Null, |p| serde_json::json!(p));
            assert_eq!(read(rtype, value, priority), data(rtype, text), "{rtype}");
        }
    }

    #[test]
    fn values_without_an_established_encoding_are_not_sent() {
        for (rtype, text) in [
            (RecordType::MX, "0 ."),
            (RecordType::CNAME, "a\\.b.example.net."),
            (RecordType::TXT, "\"two words\""),
            (RecordType::TXT, "\"quo\\\"te\""),
            (RecordType::SRV, "1 5 5060 sip.example.org."),
            (RecordType::CAA, "0 issue \"ca.example.net\""),
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
