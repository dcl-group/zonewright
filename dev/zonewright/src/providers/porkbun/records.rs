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
//! - read: `GET /dns/retrieve/{domain}`, every record of the domain, matched on the client's
//!   side by fully qualified name and type. The read sees every record at the name, so it tells
//!   the layer whether a CNAME or other data is there (`holds_cname`, `holds_other_data`);
//! - create: `POST /dns/create/{domain}`, sent once, with the name relative to the domain, the
//!   type's fields and the TTL the layer chose. A refusal `DUPLICATE_RECORD` is confirmed by a
//!   new read: the value found there now was created by another writer after the read, and the
//!   result is `Error::Conflict`; otherwise the refusal is the error;
//! - update: `POST /dns/edit/{domain}/{id}`, sent once, with the whole record: `name`, `type`,
//!   and `content`, `ttl` and `prio` new where they change (a TTL, or the value of a CNAME
//!   replaced in place) and as read otherwise; the record's `notes`, which the model does not
//!   carry, are left out and so kept. `INVALID_RECORD_ID` means the record went away after the
//!   read: nothing was written, `Error::Conflict`, and the caller's repeat reads again;
//! - plan: a create whose `content` a record of the type at the name has already, or that the
//!   plan creates twice, is refused with `Error::InvalidInput` before any write. The provider
//!   refuses such a create as a duplicate, and for MX and SRV the priority is outside `content`:
//!   changing only the priority of a value cannot be done by a create and a delete;
//! - delete: `POST /dns/delete/{domain}/{id}`, repeated by the transport (idempotent). An
//!   `INVALID_RECORD_ID` counts as done only when a new read finds no record with the value at
//!   the name.
//!
//! The calls addressed by name and type (`editByNameType`, `deleteByNameType`) act on every
//! record of a name and type at once and are never used: they would change or delete values the
//! operation did not read as its own.
//!
//! # Fields per type
//!
//! The API carries a value in `content` plus, for MX and SRV, `prio` (the spec's
//! `CreateDnsRequest`). How `content` is spelled per type is taken from these sources:
//!
//! - "spec": <https://porkbun.com/api/json/v3/spec>, version 3.79 (`content` "The record value",
//!   examples `1.2.3.4`; `prio` "Priority for MX and SRV records"; the type list `A, AAAA, MX,
//!   CNAME, ALIAS, TXT, NS, SRV, TLSA, CAA, SSHFP, HTTPS, SVCB, DS`);
//! - "kb": the provider's knowledge base, <https://kb.porkbun.com/article/109> (SRV: "Specify the
//!   "Weight", "Port", and "Target". These should all go in the same line with a space in
//!   between each value (e.g. 5 5060 sip.goosehollow.design)", the priority in its own field)
//!   and <https://kb.porkbun.com/article/231> (the answer of CNAME, MX and NS records is "a fully
//!   qualified domain name");
//! - "dns-update": `src/providers/porkbun.rs` at commit `e1ef020` (lines 555 to 587: host names
//!   without their trailing dot, MX and SRV with `prio`, SRV `content` as "weight port target",
//!   CAA as `flags tag "value"` and TLSA as `usage selector matching hex`, both through
//!   `src/utils.rs` lines 104 to 120 and 173 to 233);
//! - "lego": `providers/dns/porkbun/porkbun.go` line 129 (TXT: the value itself in `content`).
//!
//! | Type  | Canonical text from the API's fields | Source                |
//! | ----- | ------------------------------------ | --------------------- |
//! | A     | `content`, the address               | spec, dns-update      |
//! | AAAA  | `content`, the address               | spec, dns-update      |
//! | CNAME | `content`, the target (1)            | kb, dns-update        |
//! | NS    | `content`, the name server (1)       | kb, dns-update        |
//! | MX    | `<prio> <content>` (1)               | spec, kb, dns-update  |
//! | SRV   | `<prio> <content>`, `content` "weight port target" (1) | kb, dns-update |
//! | CAA   | `content`, `<flags> <tag> "<value>"` | dns-update            |
//! | TLSA  | `content`, `<usage> <selector> <matching> <hex>` | dns-update |
//! | TXT   | `content`, the value itself (2)      | lego, dns-update      |
//!
//! (1) Written without the trailing dot. (2) TXT dialect `Raw` on write, `Auto` on read.
//!
//! Reading: a host name in `content` without a trailing dot is absolute, which is how
//! `RecordData::parse` reads it. Text the parser refuses — an MX without `prio`, a field out of
//! range — is kept as non-canonical data (design section 4.9): listed, compared by text, written
//! back only as it is.
//!
//! Writing stays within what the sources show, and [`RrsetBase::can_send`] refuses everything
//! else with `Error::InvalidInput` before any write:
//!
//! - host names: never the root (`.`: a null MX or an SRV "no service", which no source shows)
//!   and never with a backslash escape;
//! - TXT: plain values only (`Txt::is_plain`), the values the TXT value operations send;
//! - CAA: the tags `issue`, `issuewild` and `iodef` (the ones dns-update writes), flags 0 to 255,
//!   and a value of printable ASCII without space, `"`, `\` and `;`.
//!
//! The API's only attribute the model does not carry is `notes`; edits leave it out and so keep
//! it, and the layer never rewrites a record it does not change. Per-record TTLs are kept as the
//! layer decides: a write without a TTL leaves every record's own, a write with one sets it on
//! every record (design section 3.6).
//!
//! SOA and the provider's default NS records are not in the API's listing ("SOA records and
//! Porkbun default NS records are excluded", `/dns/retrieve`); the record layer refuses writes to
//! the NS rrset at the apex before any request. ALIAS, SSHFP, HTTPS, SVCB and DS records are
//! listed but cannot be read alone or written: no source shows their `content` form.

use std::collections::BTreeMap;

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::{DomainName, TargetName};
use crate::provider::ZoneListing;
use crate::record::{Caa, Mx, RecordData, RecordType, RrsetTtl, Srv, Tlsa, Ttl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::rrsets::{
    self, Listing, Neighbors, PerRecord, RecordUpdate, RecordsRead, RrsetBase, SetTtl, Step, Stored,
};

use super::api::{Created, NewRecord, Record, RecordEdit, Written};
use super::client::Porkbun;

/// How TXT data is read: quoted text as presentation format, anything else as the value
/// (design section 11.2).
pub(super) const TXT_READ: TxtDialect = TxtDialect::Auto;

/// How TXT data is written: the value itself (lego porkbun.go line 129).
pub(super) const TXT_WRITE: TxtDialect = TxtDialect::Raw;

/// The CAA tags the client writes.
// Source: dns-update `src/utils.rs` lines 133 to 172 (`issue`, `issuewild`, `iodef`).
const CAA_TAGS: &[&str] = &["issue", "issuewild", "iodef"];

// ---- Reading -------------------------------------------------------------------------------------

/// A value as the API returned it: canonical where the type's fields parse, non-canonical
/// otherwise (see the module documentation).
pub(super) fn read_record(rtype: RecordType, record: &Record) -> RecordData {
    let content = record.content.as_deref().unwrap_or_default();
    match rtype {
        // MX: `prio` and the exchange. SRV: `prio` and "weight port target" (kb article 109;
        // dns-update porkbun.rs lines 416 to 435).
        RecordType::MX | RecordType::SRV => match record.prio() {
            Some(prio) => {
                RecordData::from_provider(rtype, &format!("{prio} {content}"), None, TXT_READ)
            }
            None => RecordData::non_canonical(content),
        },
        _ => RecordData::from_provider(rtype, content, None, TXT_READ),
    }
}

// ---- Writing -------------------------------------------------------------------------------------

/// A value as the API takes it: `content` and, for MX and SRV, `prio`.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Encoded {
    /// The `content` field.
    pub(super) content: String,
    /// MX preference or SRV priority.
    pub(super) prio: Option<u16>,
}

impl Encoded {
    fn content(content: String) -> Encoded {
        Encoded {
            content,
            prio: None,
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
        // The canonical address. Source: the spec's create example (`"type":"A"`,
        // `"content":"1.2.3.4"`); dns-update porkbun.rs lines 558 and 559.
        RecordType::A | RecordType::AAAA => Some(Encoded::content(data.as_str().to_owned())),
        // The target without its trailing dot. Source: dns-update porkbun.rs lines 560 to 565.
        RecordType::CNAME | RecordType::NS => TargetName::parse(data.as_str())
            .ok()
            .and_then(|target| host(&target))
            .map(Encoded::content),
        // Source: dns-update porkbun.rs lines 566 to 569; kb article 231.
        RecordType::MX => {
            let mx = Mx::from_data(data).ok()?;
            Some(Encoded {
                prio: Some(mx.preference),
                ..Encoded::content(host(&mx.exchange)?)
            })
        }
        // Source: kb article 109; dns-update porkbun.rs lines 571 to 579.
        RecordType::SRV => {
            let srv = Srv::from_data(data).ok()?;
            Some(Encoded {
                prio: Some(srv.priority),
                ..Encoded::content(format!(
                    "{} {} {}",
                    srv.weight,
                    srv.port,
                    host(&srv.target)?
                ))
            })
        }
        RecordType::CAA => write_caa(data),
        RecordType::TLSA => write_tlsa(data),
        RecordType::TXT => {
            // Source: lego porkbun.go line 129; dns-update porkbun.rs line 570.
            let txt = Txt::from_data(data).ok().filter(Txt::is_plain)?;
            TXT_WRITE.write(&txt).map(Encoded::content)
        }
        _ => None,
    }
}

/// CAA: `<flags> <tag> "<value>"` in `content`.
// Source: dns-update porkbun.rs lines 583 to 585 (`caa.to_string()`) and `src/utils.rs` lines
// 173 to 233 (the flags, the tag and the quoted value).
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
    Some(Encoded::content(format!(
        "{} {} \"{value}\"",
        caa.flags, caa.tag
    )))
}

/// TLSA: `<usage> <selector> <matching type> <hex>` in `content`, the data in lowercase hex.
// Source: dns-update porkbun.rs lines 580 to 582 (`tlsa.to_string()`) and `src/utils.rs` lines
// 104 to 120.
fn write_tlsa(data: &RecordData) -> Option<Encoded> {
    let tlsa = Tlsa::from_data(data).ok()?;
    let mut hex = String::with_capacity(tlsa.data.len() * 2);
    for byte in &tlsa.data {
        hex.push_str(&format!("{byte:02x}"));
    }
    Some(Encoded::content(format!(
        "{} {} {} {hex}",
        tlsa.usage, tlsa.selector, tlsa.matching_type
    )))
}

/// A host name as `content`: without its trailing dot; `None` for the root and for a name whose
/// canonical text needs a backslash escape.
fn host(name: &TargetName) -> Option<String> {
    let text = name.as_str();
    if name.is_root() || text.contains('\\') {
        return None;
    }
    Some(text.strip_suffix('.').unwrap_or(text).to_owned())
}

/// The owner name as the API takes it: relative to the domain, empty for the apex.
// Source: the spec, `CreateDnsRequest.name`: "Subdomain for the record (e.g. 'www', '*' for
// wildcard, blank for root). Do not include the domain name itself."
pub(super) fn relative<'a>(name: &'a DomainName, zone: &DomainName) -> Result<&'a str, Error> {
    name.relative_to(zone)
        .ok_or_else(|| Error::name_outside_zone(name.clone(), zone.clone()))
}

/// The TTL a create carries: the requested or existing number, else the client's setting. In
/// this model the provider has no "no TTL of its own" (`provider_default_ttl` is `Absent`), so a
/// TTL the read did not state is the client's setting, never left out (design section 3.6):
/// without `ttl` the provider would apply the account's minimum.
pub(super) fn create_ttl(ttl: Option<RrsetTtl>, setting: u32) -> u32 {
    ttl.and_then(RrsetTtl::explicit)
        .map_or(setting, Ttl::as_secs)
}

// ---- The record layer ----------------------------------------------------------------------------

impl RrsetBase for Porkbun {
    fn provider(&self) -> ProviderId {
        ProviderId::Porkbun
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
        code: None,
    }
}

fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

/// One record as read: what an edit writes back unchanged and a delete names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Handle {
    /// The identifier, when the listing states one.
    id: Option<u64>,
    /// `content` as read.
    content: Option<String>,
    /// `ttl` as read, when the listing states one the model can hold.
    ttl: Option<u32>,
    /// `prio` as read, when the listing states one.
    prio: Option<u16>,
}

/// What the read hands to every write: what else is at the name, and the `content` of every
/// record of the operation's type there.
#[derive(Clone, Debug)]
pub(crate) struct ReadContext {
    neighbors: Neighbors,
    contents: Vec<String>,
}

/// The identifier of a record the layer wants to change or delete.
fn identifier(record: &Stored<Handle>) -> Result<u64, Error> {
    record
        .handle
        .id
        .ok_or_else(|| protocol("the provider lists the record without an identifier"))
}

/// The refusal of a plan that creates a record whose `content` another record of the type at
/// the name already has, or that the plan creates twice.
// Source: the spec, "Error codes", `DUPLICATE_RECORD`: "A record with this exact name, type and
// content already exists, so nothing was created." For MX and SRV the priority is not part of
// `content` (`CreateDnsRequest.prio`), so a value that differs only in its priority would be
// refused, and the record layer creates before it deletes: the plan could never complete.
fn same_content() -> Error {
    Error::InvalidInput {
        detail: Detail::constant(
            "the provider refuses a second record with the same name, type and content, and the              priority of an MX or SRV value is not part of its content: delete the rrset first              to change only the priority of a value",
        ),
        code: None,
    }
}

impl Porkbun {
    /// The records of `name` and type `rtype` of the domain, and the types of the other records
    /// at the name.
    pub(super) async fn records_at(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<(Vec<Record>, Neighbors), Error> {
        let mut matching = Vec::new();
        let mut others = Vec::new();
        for record in self.api.records(zone).await? {
            if record.owner(zone).as_ref() != Some(name) {
                continue;
            }
            match record.record_type() {
                Some(stated) if stated == rtype => matching.push(record),
                stated => others.push(stated),
            }
        }
        // The listing holds every record of the domain the API lists, and the API documents
        // no disabled record: the other records are all the data at the name besides this type.
        Ok((matching, Neighbors::of(rtype, others)))
    }
}

impl PerRecord for Porkbun {
    /// The record as read.
    type Handle = Handle;
    /// The domain's name is the key of every path; the read carries what else is at the name and
    /// the `content` of the records of the type.
    type Context = ReadContext;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<RecordsRead<Handle, ReadContext>, Error> {
        let (records, neighbors) = self.records_at(zone, name, rtype).await?;
        let contents = records.iter().filter_map(|r| r.content.clone()).collect();
        let records = records
            .iter()
            .map(|record| Stored {
                data: read_record(rtype, record),
                // The API documents no disabled records.
                enabled: true,
                ttl: record.ttl(),
                handle: Handle {
                    id: record.id(),
                    content: record.content.clone(),
                    ttl: record.ttl().and_then(RrsetTtl::explicit).map(Ttl::as_secs),
                    prio: record.prio().and_then(|p| u16::try_from(p).ok()),
                },
            })
            .collect();
        Ok(RecordsRead {
            context: ReadContext {
                neighbors,
                contents,
            },
            records,
        })
    }

    /// Refuses, before any write, a plan with a create the provider would refuse as a duplicate
    /// (see [`same_content`]).
    fn check_plan(
        &self,
        _zone: &DomainName,
        _name: &DomainName,
        rtype: RecordType,
        context: &ReadContext,
        steps: &[Step<'_, Handle>],
    ) -> Result<(), Error> {
        let mut contents: Vec<String> = context.contents.clone();
        for step in steps {
            if let Step::Create { data, .. } = step {
                let encoded = encode(rtype, data).ok_or_else(not_sendable)?;
                if contents.contains(&encoded.content) {
                    return Err(same_content());
                }
                contents.push(encoded.content);
            }
        }
        Ok(())
    }

    async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &ReadContext,
        data: &RecordData,
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let encoded = encode(rtype, data).ok_or_else(not_sendable)?;
        let type_name = rtype.to_string();
        let record = NewRecord {
            name: relative(name, zone)?,
            rtype: &type_name,
            content: &encoded.content,
            ttl: create_ttl(
                ttl.resolve(RrsetTtl::Explicit(Ttl::clamped(self.ttl))),
                self.ttl,
            ),
            prio: encoded.prio,
        };
        match self.api.create(zone, &record).await? {
            Created::Done => Ok(()),
            Created::Duplicate(refusal) => {
                // "A record with this exact name, type and content already exists": it was not
                // there when the operation read the name. Only a new read shows whether it is
                // the value asked for (created by another writer since) or something the
                // provider compares differently.
                let now = <Self as PerRecord>::read(self, zone, name, rtype).await?;
                if now.records.iter().any(|r| r.data == *data) {
                    Err(Error::Conflict {
                        detail: Detail::constant(
                            "the value was created by another writer after the read",
                        ),
                    })
                } else {
                    Err(refusal)
                }
            }
        }
    }

    async fn update(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &ReadContext,
        record: &Stored<Handle>,
        update: &RecordUpdate<'_>,
    ) -> Result<(), Error> {
        if update.enable {
            // Every record this client reads is enabled, so the layer never asks for this.
            return Err(protocol("the provider has no disabled records to enable"));
        }
        let id = identifier(record)?;
        // The whole record goes out (`api::RecordEdit`): the new value or the one read, and so
        // for the TTL and the priority.
        let (content, prio) =
            match update.data {
                Some(data) => {
                    let encoded = encode(rtype, data).ok_or_else(not_sendable)?;
                    (encoded.content, encoded.prio)
                }
                None => (
                    record.handle.content.clone().ok_or_else(|| {
                        protocol("the provider lists the record without its value")
                    })?,
                    record.handle.prio,
                ),
            };
        let prioritized = matches!(rtype, RecordType::MX | RecordType::SRV);
        if prioritized && prio.is_none() {
            return Err(protocol(
                "the provider lists the record without a usable priority, so it cannot be \
                 written back",
            ));
        }
        let type_name = rtype.to_string();
        let edit = RecordEdit {
            name: relative(name, zone)?,
            rtype: &type_name,
            content: &content,
            ttl: update
                .ttl
                .and_then(RrsetTtl::explicit)
                .map(Ttl::as_secs)
                .or(record.handle.ttl),
            prio: if prioritized { prio } else { None },
        };
        match self.api.edit(zone, id, &edit).await? {
            Written::Done => Ok(()),
            // The record, or the domain, went away after the read; nothing was written.
            Written::Gone => Err(Error::Conflict {
                detail: Detail::constant("the record was removed between the read and the update"),
            }),
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &ReadContext,
        record: &Stored<Handle>,
    ) -> Result<(), Error> {
        match self.api.delete(zone, identifier(record)?).await? {
            Written::Done => Ok(()),
            // The record is gone, or the domain is and was created again with the value under
            // a new identifier. Only a new read tells them apart (the record layer's rule for a
            // per-record API, design sections 3.5 and 3.8).
            Written::Gone => {
                let now = <Self as PerRecord>::read(self, zone, name, rtype).await?;
                if now.records.iter().any(|r| r.data == record.data) {
                    Err(Error::Conflict {
                        detail: Detail::constant(
                            "the record was found again after its delete was answered \"not \
                             found\"; the domain changed between the read and the delete",
                        ),
                    })
                } else {
                    Ok(())
                }
            }
        }
    }

    fn holds_cname(&self, _rtype: RecordType, context: &ReadContext) -> Option<bool> {
        context.neighbors.holds_cname()
    }

    fn holds_other_data(&self, _rtype: RecordType, context: &ReadContext) -> Option<bool> {
        context.neighbors.holds_other_data()
    }
}

// ---- Listing -------------------------------------------------------------------------------------

/// The records of one owner name and type, as the listing gathers them.
struct Group {
    name: Option<DomainName>,
    type_name: String,
    ttl: Option<RrsetTtl>,
    records: Vec<RecordData>,
}

impl Porkbun {
    /// `list_rrsets`: every record of the domain, grouped by owner name and type.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let all = self.api.records(zone).await?;
        let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
        for record in &all {
            let stated = record.name.as_deref().unwrap_or_default();
            let name = record.owner(zone);
            let type_stated = record.rtype.as_deref().unwrap_or_default();
            let rtype = record.record_type();
            // Spellings of one name or type that mean the same land in one group.
            let key = (
                name.as_ref()
                    .map_or_else(|| format!("raw:{stated}"), |n| n.as_str().to_owned()),
                rtype.map_or_else(|| format!("raw:{type_stated}"), |t| t.to_string()),
            );
            let data = match rtype {
                Some(rtype) => read_record(rtype, record),
                // A type name that maps to no record type is skipped by the listing whatever
                // the record holds; the data is then never parsed.
                None => RecordData::non_canonical(record.content.as_deref().unwrap_or_default()),
            };
            let group = groups.entry(key).or_insert_with(|| Group {
                name,
                type_name: rtype.map_or_else(|| type_stated.to_owned(), |t| t.to_string()),
                ttl: None,
                records: Vec::new(),
            });
            // The smallest TTL of the set (design section 3.6, `TtlSupport::PerRecord`).
            group.ttl = Listing::smallest_ttl([group.ttl, record.ttl()]);
            group.records.push(data);
        }
        let mut listing = Listing::new(zone);
        for group in groups.into_values() {
            listing.push(group.name, &group.type_name, group.ttl, group.records);
        }
        listing.finish(ProviderId::Porkbun)
    }
}

#[cfg(test)]
mod tests {
    use super::{Encoded, encode, read_record};
    use crate::providers::porkbun::api::Record;
    use crate::record::{RecordData, RecordType};

    fn record(rtype: &str, content: &str, prio: serde_json::Value) -> Record {
        serde_json::from_value(serde_json::json!({
            "id": "1", "name": "www.example.org", "type": rtype, "content": content,
            "ttl": "600", "prio": prio, "notes": null
        }))
        .unwrap()
    }

    fn read(rtype: RecordType, content: &str, prio: serde_json::Value) -> RecordData {
        read_record(rtype, &record(&rtype.to_string(), content, prio))
    }

    fn data(rtype: RecordType, text: &str) -> RecordData {
        RecordData::parse(rtype, text).unwrap()
    }

    #[test]
    fn each_type_reads_into_canonical_text() {
        let null = serde_json::Value::Null;
        for (rtype, content, prio, canonical) in [
            (RecordType::A, "192.0.2.1", null.clone(), "192.0.2.1"),
            (
                RecordType::AAAA,
                "2001:DB8:0::1",
                null.clone(),
                "2001:db8::1",
            ),
            (
                RecordType::CNAME,
                "Target.example.net",
                null.clone(),
                "target.example.net.",
            ),
            (
                RecordType::NS,
                "ns1.example.net.",
                null.clone(),
                "ns1.example.net.",
            ),
            (
                RecordType::MX,
                "mail.example.org",
                serde_json::json!("10"),
                "10 mail.example.org.",
            ),
            (
                RecordType::SRV,
                "5 5060 sip.example.org",
                serde_json::json!("1"),
                "1 5 5060 sip.example.org.",
            ),
            (
                RecordType::CAA,
                "0 issue \"letsencrypt.org\"",
                null.clone(),
                "0 issue \"letsencrypt.org\"",
            ),
            (RecordType::TXT, "v1", null.clone(), "\"v1\""),
            (
                RecordType::TXT,
                "\"quoted\" \"two\"",
                null.clone(),
                "\"quotedtwo\"",
            ),
        ] {
            let got = read(rtype, content, prio);
            assert!(got.is_canonical(), "{rtype} {content}");
            assert_eq!(got.as_str(), canonical, "{rtype} {content}");
        }
        let tlsa = read(RecordType::TLSA, "3 1 1 0a1b", null);
        assert!(tlsa.is_canonical());
        assert_eq!(tlsa, data(RecordType::TLSA, "3 1 1 0A1B"));
    }

    #[test]
    fn unparseable_fields_are_non_canonical() {
        for (rtype, content, prio) in [
            (RecordType::A, "not an address", serde_json::Value::Null),
            (RecordType::MX, "mail.example.org", serde_json::Value::Null),
            (
                RecordType::MX,
                "mail.example.org",
                serde_json::json!("70000"),
            ),
            (
                RecordType::SRV,
                "5060 sip.example.org",
                serde_json::json!("1"),
            ),
        ] {
            let got = read(rtype, content, prio);
            assert!(!got.is_canonical(), "{rtype} {content}");
        }
    }

    #[test]
    fn each_type_writes_the_documented_fields() {
        for (rtype, text, content, prio) in [
            (RecordType::A, "192.0.2.1", "192.0.2.1", None),
            (RecordType::AAAA, "2001:db8::1", "2001:db8::1", None),
            (
                RecordType::CNAME,
                "target.example.net.",
                "target.example.net",
                None,
            ),
            (RecordType::NS, "ns1.example.net.", "ns1.example.net", None),
            (
                RecordType::MX,
                "10 mail.example.org.",
                "mail.example.org",
                Some(10),
            ),
            (
                RecordType::SRV,
                "1 5 5060 sip.example.org.",
                "5 5060 sip.example.org",
                Some(1),
            ),
            (
                RecordType::CAA,
                "128 issuewild \"ca.example.net\"",
                "128 issuewild \"ca.example.net\"",
                None,
            ),
            (RecordType::TLSA, "3 1 1 0A1B", "3 1 1 0a1b", None),
            (RecordType::TXT, "\"v1\"", "v1", None),
        ] {
            let encoded = encode(rtype, &data(rtype, text)).unwrap();
            assert_eq!(
                encoded,
                Encoded {
                    content: content.to_owned(),
                    prio
                },
                "{rtype} {text}"
            );
            // Read back through the same fields, the value is the same.
            let prio = prio.map_or(serde_json::Value::Null, |p| {
                serde_json::json!(p.to_string())
            });
            assert_eq!(read(rtype, content, prio), data(rtype, text), "{rtype}");
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
            (RecordType::PTR, "host.example.net."),
        ] {
            assert!(
                encode(rtype, &data(rtype, text)).is_none(),
                "{rtype} {text}"
            );
        }
        assert!(encode(RecordType::A, &RecordData::non_canonical("x")).is_none());
    }
}
