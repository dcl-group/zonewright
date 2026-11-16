//! Record-level operations: the `PerRecord` shape of the record layer (`crate::rrsets`) over the
//! record API, the listing of a zone, and the mapping between the API's record members and
//! `RecordData`.
//!
//! The native unit is the individual record with an identifier, hence the per-record shape,
//! `Preconditions::ReadThenWrite` and no `atomic_rrset_write`: replacing an rrset is several
//! requests, creates first and deletes last (the record layer decides the order). The record
//! layer does the checks, takes the per-name lock, reads, evaluates the expectation and computes
//! the requests; this file turns them into the API's calls:
//!
//! - read: `GET …/records?type=`, every page, an exact name and type match on the client's side.
//!   The `name` filter is not sent: the documentation does not say how it treats letter case or
//!   an empty string (the apex's name is `""`), and a filter stricter than the client's own
//!   comparison would make a read come back short, after which a write could duplicate a value;
//! - create: `POST …/records`, sent once, with the name relative to the zone, the type's members
//!   and the TTL the layer chose;
//! - update: `PATCH …/records/{id}`, sent once, with only the members that change (a TTL, or the
//!   value of a CNAME replaced in place). A `404` means the record went away after the read:
//!   nothing was written, `Error::Conflict`, and the caller's repeat reads again;
//! - delete: `DELETE …/records/{id}`, repeated by the transport (idempotent). A `404` counts as
//!   done only when a new read finds no record with the value at the name: the zone may have
//!   been deleted and created again with the value under a new identifier.
//!
//! # Records the client does not change
//!
//! - A record with `system_record` true "is a system generated record and thus is not
//!   modifiable" (OpenAPI `ZoneRecord`); the documented listing shows the SOA and the apex NS
//!   records as system records. A plan that updates or deletes one is refused before any write
//!   (`Error::InvalidInput`); the TXT value layer never deletes one either. The SOA type and the
//!   apex NS rrset are refused earlier by the record layer.
//! - A record with `regions` other than none or exactly `global` is published only in some
//!   regions (Records, "Record Regions"; see `api::Record::is_global`): the name then has no
//!   one set of values. A read of such a name and type is `Error::Rejected` and writes nothing,
//!   and a listing reports the set in `skipped` with `SkipReason::NotPlainRecords`.
//!
//! # Content per type
//!
//! The API carries a value in `content` plus, for MX and SRV, `priority` (OpenAPI `ZoneRecord`:
//! "The priority value for MX and SRV records"). Which type uses which member, and how
//! `content` is spelled, is taken from these sources:
//!
//! - "API": the reference, <https://developer.dnsimple.com/v2/zones/records/>, and the OpenAPI
//!   description (`content`: "IP address for A records, hostname for CNAME records"; the
//!   examples: MX `content` `mxa.example.com` with `priority` 10, NS `content`
//!   `ns1.dnsimple-edge.com`, A `127.0.0.1`, the SOA's `content` in zone-file order);
//! - "dns-update": `src/providers/dnsimple.rs` (the MX exchange in `content` with `priority`;
//!   SRV as `<weight> <port> <target>` in `content` with `priority`; CAA as `flags tag "value"`;
//!   TXT as the value itself);
//! - "lego": `providers/dns/dnsimple/dnsimple.go` (TXT: the value itself in `content`);
//! - "TXT article": <https://support.dnsimple.com/articles/txt-record-format/> (an unquoted value
//!   is wrapped in quotes by DNSimple, a quoted one is kept as it is);
//! - "CAA article": <https://support.dnsimple.com/articles/caa-record-format/> (flags "only 0 ...
//!   and 128 ... are defined"; the tags issue, issuewild, issuemail, iodef, contactemail and
//!   contactphone; the canonical form `0 issue "letsencrypt.org"`).
//!
//! | Type  | Canonical text from the API's members | Source                    |
//! | ----- | ------------------------------------- | ------------------------- |
//! | A     | `content`, the address                | API, dns-update           |
//! | AAAA  | `content`, the address                | API, dns-update           |
//! | CNAME | `content`, the target (1)             | API, dns-update           |
//! | NS    | `content`, the name server (1)        | API example, dns-update   |
//! | MX    | `<priority> <content>` (1)            | API example, dns-update   |
//! | SRV   | `<priority> <content>` (1) (2)        | dns-update                |
//! | CAA   | `content`, `flags tag "value"` (3)    | dns-update, CAA article   |
//! | TXT   | `content`, the value itself (4)       | lego, dns-update          |
//! | SOA   | `content`, read only                  | API example               |
//!
//! (1) Host names are written without a trailing dot, as every example of the API states them,
//! and read as absolute with or without one. (2) `content` is `<weight> <port> <target>`.
//! (3) Written with the value in quotes. (4) TXT dialect `Raw` on write, `Auto` on read: the
//! TXT article says DNSimple wraps an unquoted value in quotes and keeps a quoted one, and the
//! API documentation does not say which of the two forms `content` answers, so text that starts
//! with `"` is read as zone-file text and anything else as the value itself.
//!
//! Reading: text the parser refuses — a missing `priority`, a field out of range — is kept as
//! non-canonical data (design section 4.9): listed, compared by text, written back only as it
//! is. Assumption (not documented): that a host name in `content` is never relative to the zone;
//! such a name would be read as absolute, which can only make a value compare unequal to the one
//! a caller expects, never delete a record that was not read.
//!
//! Writing stays within what the sources show, and [`RrsetBase::can_send`] refuses everything
//! else with `Error::InvalidInput` before any write:
//!
//! - host names: never the root (`.`: a null MX or an SRV "no service"; no source shows how the
//!   API takes it) and never with a backslash escape;
//! - TXT: plain values only (`Txt::is_plain`: 1 to 255 printable ASCII octets without space, `"`
//!   or `\`), the values the TXT value operations send. How the API treats spaces, quotes,
//!   escapes and values longer than one character-string is not established for the API (the
//!   TXT article describes the web editor);
//! - CAA: flags 0 or 128, the tags of the CAA article, and a value of printable ASCII without
//!   space, `"` and `\`.
//!
//! The model does not carry `regions` or `integrated_zones`; an update never sends them, so the
//! record keeps its own, and a create sends neither, which the API documents as "global" and "the
//! DNSimple zone and all integrated zones". Per-record TTLs are kept: a write without a TTL leaves
//! every record's own, a write with one sets it on every record (design section 3.6). DS, TLSA,
//! ALIAS and the other types have no content form a source establishes: a listing carries them,
//! they cannot be read alone or written.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::{DomainName, TargetName};
use crate::provider::{SkipReason, ZoneListing};
use crate::record::{Caa, Mx, RecordData, RecordType, RrsetTtl, Srv, Ttl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::rrsets::{
    self, Listing, PerRecord, RecordUpdate, RecordsRead, RrsetBase, SetTtl, Step, Stored,
};

use super::api::{NewRecord, Record, RecordPatch, Written, normalize_name, relative_name};
use super::client::Dnsimple;

/// How TXT data is read: quoted text as zone-file text, anything else as the value (module
/// documentation, note 4). The one rule of both layers.
pub(super) const TXT_READ: TxtDialect = TxtDialect::Auto;

/// How TXT data is written: the value itself (lego dnsimple.go, `newTxtRecord`).
pub(super) const TXT_WRITE: TxtDialect = TxtDialect::Raw;

/// The CAA flags the client sends.
// Source: CAA article: "Currently, only 0 (no flags set) and 128 (critical flag) are defined."
const CAA_FLAGS: &[u8] = &[0, 128];

/// The CAA tags the client sends.
// Source: CAA article: "Defined tags include issue, issuewild, issuemail, iodef, contactemail,
// and contactphone."
const CAA_TAGS: &[&str] = &[
    "issue",
    "issuewild",
    "issuemail",
    "iodef",
    "contactemail",
    "contactphone",
];

/// What a write needs of a record that was read: its identifier, and whether the provider
/// marks it as a system record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Handle {
    /// The record's identifier.
    pub(crate) id: u64,
    /// `system_record`: "not modifiable".
    pub(crate) system: bool,
}

impl Handle {
    pub(super) fn of(record: &Record) -> Handle {
        Handle {
            id: record.id,
            system: record.system_record,
        }
    }
}

/// A record limited to some regions at the name and type: it is not read or changed as an
/// rrset (module documentation). The TXT value operations refuse it in the same way.
pub(super) fn not_plain() -> Error {
    Error::Rejected {
        status: None,
        detail: Detail::constant(
            "a record of the name and type is published only in some regions; the name has no \
             one set of values to read or change",
        ),
        code: None,
    }
}

/// A plan that would change or delete a system record.
pub(super) fn system_record() -> Error {
    Error::InvalidInput {
        detail: Detail::constant(
            "the provider marks the record as a system record, which is not modifiable",
        ),
        code: None,
    }
}

/// A name the layers let through that is not within the zone; they check it first, so this is
/// never expected.
pub(super) fn outside_zone(name: &DomainName, zone: &DomainName) -> Error {
    Error::name_outside_zone(name.clone(), zone.clone())
}

// ---- Reading -------------------------------------------------------------------------------------

/// A value as the API returned it: canonical where the type's members parse, non-canonical
/// otherwise (see the module documentation).
pub(super) fn read_record(rtype: RecordType, record: &Record) -> RecordData {
    let content = record.content.as_str();
    match rtype {
        // API: the MX example (`content` the exchange, `priority` 10); dns-update.
        RecordType::MX => with_priority(RecordType::MX, record, content),
        // dns-update: `content` `<weight> <port> <target>`, `priority` the SRV priority.
        RecordType::SRV => with_priority(RecordType::SRV, record, content),
        // A, AAAA, CNAME, NS, CAA, TXT, SOA and the types the client does not write: `content`
        // through the strict parser, TXT with the `Auto` rule.
        other => RecordData::from_provider(other, content, None, TXT_READ),
    }
}

/// `<priority> <content>`, or the content alone as non-canonical data without a priority.
fn with_priority(rtype: RecordType, record: &Record, content: &str) -> RecordData {
    match record.priority.as_ref().and_then(Value::as_u64) {
        Some(priority) => {
            RecordData::from_provider(rtype, &format!("{priority} {content}"), None, TXT_READ)
        }
        None => RecordData::non_canonical(content),
    }
}

// ---- Writing -------------------------------------------------------------------------------------

/// A value as the API takes it: `content` and, for MX and SRV, `priority`.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Encoded {
    /// The `content` member.
    pub(super) content: String,
    /// The `priority` member.
    pub(super) priority: Option<u16>,
}

impl Encoded {
    fn content(content: String) -> Encoded {
        Encoded {
            content,
            priority: None,
        }
    }
}

/// The API's members for a canonical value of `rtype`, or `None` when the client cannot send it
/// (see the module documentation).
pub(super) fn encode(rtype: RecordType, data: &RecordData) -> Option<Encoded> {
    if !data.is_canonical() {
        return None;
    }
    match rtype {
        // API: "IP address for A records"; the canonical text of an address is its only form.
        RecordType::A | RecordType::AAAA => Some(Encoded::content(data.as_str().to_owned())),
        // API: "hostname for CNAME records"; the NS example; dns-update.
        RecordType::CNAME | RecordType::NS => TargetName::parse(data.as_str())
            .ok()
            .and_then(|target| host(&target))
            .map(Encoded::content),
        RecordType::MX => {
            let mx = Mx::from_data(data).ok()?;
            Some(Encoded {
                priority: Some(mx.preference),
                ..Encoded::content(host(&mx.exchange)?)
            })
        }
        RecordType::SRV => {
            let srv = Srv::from_data(data).ok()?;
            let target = host(&srv.target)?;
            Some(Encoded {
                priority: Some(srv.priority),
                ..Encoded::content(format!("{} {} {target}", srv.weight, srv.port))
            })
        }
        RecordType::CAA => write_caa(data),
        RecordType::TXT => {
            let txt = Txt::from_data(data).ok().filter(Txt::is_plain)?;
            TXT_WRITE.write(&txt).map(Encoded::content)
        }
        _ => None,
    }
}

/// CAA: `flags tag "value"`, within the flags and tags of the CAA article and a value without
/// space, quote or backslash.
fn write_caa(data: &RecordData) -> Option<Encoded> {
    let caa = Caa::from_data(data).ok()?;
    if !CAA_FLAGS.contains(&caa.flags) || !CAA_TAGS.contains(&caa.tag.as_str()) {
        return None;
    }
    let plain = !caa.value.is_empty()
        && caa
            .value
            .iter()
            .all(|&b| (0x21..=0x7e).contains(&b) && !matches!(b, b'"' | b'\\'));
    if !plain {
        return None;
    }
    let value = String::from_utf8(caa.value).ok()?;
    Some(Encoded::content(format!(
        "{} {} \"{value}\"",
        caa.flags, caa.tag
    )))
}

/// A host name as `content`: absolute without its trailing dot; `None` for the root and for a
/// name whose canonical text needs a backslash escape.
fn host(name: &TargetName) -> Option<String> {
    let text = name.as_str();
    if name.is_root() || text.contains('\\') {
        return None;
    }
    Some(text.strip_suffix('.').unwrap_or(text).to_owned())
}

// ---- The record layer ----------------------------------------------------------------------------

impl Dnsimple {
    /// Every record of `rtype` at `name`: the zone's records of that type, matched by name and
    /// type on the client's side.
    pub(super) async fn records_at(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Vec<Record>, Error> {
        Ok(self
            .api
            .records(zone, &rtype.to_string())
            .await?
            .into_iter()
            .filter(|record| {
                record.rtype.parse::<RecordType>().ok() == Some(rtype)
                    && normalize_name(&record.name, zone).as_ref() == Some(name)
            })
            .collect())
    }
}

impl Dnsimple {
    /// The error of a create answered `404`: `ZoneNotFound` when a read of the zone is answered
    /// `404` too, otherwise the create's refusal as the provider stated it (the Overview: 404 is
    /// "doesn't exist or ... doesn't have permissions to access the resource").
    pub(super) async fn create_refused(&self, zone: &DomainName, refusal: Error) -> Error {
        match self.api.zone(zone).await {
            Ok(None) => Error::zone_not_found(zone.clone()),
            Ok(Some(_)) => refusal,
            Err(e) => e,
        }
    }
}

impl RrsetBase for Dnsimple {
    fn provider(&self) -> ProviderId {
        ProviderId::Dnsimple
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

impl PerRecord for Dnsimple {
    /// The record's identifier and its system flag.
    type Handle = Handle;
    /// The zone's name is the key of every path: nothing to carry.
    type Context = ();

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<RecordsRead<Handle, ()>, Error> {
        let records = self.records_at(zone, name, rtype).await?;
        if records.iter().any(|record| !record.is_global()) {
            return Err(not_plain());
        }
        let records = records
            .iter()
            .map(|record| Stored {
                data: read_record(rtype, record),
                // The API has no disabled records.
                enabled: true,
                ttl: RrsetTtl::from_secs(record.ttl).ok(),
                handle: Handle::of(record),
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
            SetTtl::Requested(RrsetTtl::Explicit(ttl))
            | SetTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => ttl.as_secs(),
            // Every record states its TTL (`provider_default_ttl` is `Absent`): the configured
            // TTL stands for a set without one (design section 3.6).
            SetTtl::Default
            | SetTtl::Requested(RrsetTtl::ProviderDefault)
            | SetTtl::Existing(None | Some(RrsetTtl::ProviderDefault)) => self.ttl,
        };
        let type_name = rtype.to_string();
        let record = NewRecord {
            name: relative_name(name, zone).ok_or_else(|| outside_zone(name, zone))?,
            rtype: &type_name,
            content: &encoded.content,
            ttl,
            priority: encoded.priority,
        };
        match self.api.create_record(zone, &record).await? {
            Written::Done => Ok(()),
            // Nothing was written; the zone is gone, or the token may not write to it.
            Written::NotFound(refusal) => Err(self.create_refused(zone, refusal).await),
        }
    }

    async fn update(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &(),
        record: &Stored<Handle>,
        update: &RecordUpdate<'_>,
    ) -> Result<(), Error> {
        if update.enable {
            // Every record this client reads is enabled, so the layer never asks for this.
            return Err(Error::Protocol {
                detail: Detail::constant("the provider has no disabled records to enable"),
            });
        }
        if record.handle.system {
            return Err(system_record());
        }
        let encoded = match update.data {
            Some(data) => Some(encode(rtype, data).ok_or_else(not_sendable)?),
            None => None,
        };
        let patch = RecordPatch {
            content: encoded.as_ref().map(|e| e.content.as_str()),
            ttl: update.ttl.and_then(RrsetTtl::explicit).map(Ttl::as_secs),
            priority: encoded.as_ref().and_then(|e| e.priority),
        };
        match self
            .api
            .update_record(zone, record.handle.id, &patch)
            .await?
        {
            Written::Done => Ok(()),
            // Nothing was written. The record went away after the read, or it is still there
            // and the token may not change it: a new read tells them apart.
            Written::NotFound(refusal) => {
                let now = self.records_at(zone, name, rtype).await?;
                if now.iter().any(|r| r.id == record.handle.id) {
                    Err(refusal)
                } else {
                    Err(Error::Conflict {
                        detail: Detail::constant(
                            "the record was removed between the read and the update",
                        ),
                    })
                }
            }
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &(),
        record: &Stored<Handle>,
    ) -> Result<(), Error> {
        if record.handle.system {
            return Err(system_record());
        }
        match self.api.delete_record(zone, record.handle.id).await? {
            Written::Done => Ok(()),
            // The record is gone, or the zone is and was created again with the value under a
            // new identifier, or the record is still there and the token may not delete it.
            // Only a new read tells them apart (the record layer's rule for a per-record API,
            // design sections 3.5 and 3.8).
            Written::NotFound(refusal) => {
                let now = self.records_at(zone, name, rtype).await?;
                if now.iter().any(|r| r.id == record.handle.id) {
                    Err(refusal)
                } else if now.iter().any(|r| read_record(rtype, r) == record.data) {
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
        }
    }

    /// Refuses, before any write, a plan that changes or deletes a system record.
    fn check_plan(
        &self,
        _zone: &DomainName,
        _name: &DomainName,
        _rtype: RecordType,
        _context: &(),
        steps: &[Step<'_, Handle>],
    ) -> Result<(), Error> {
        steps.iter().try_for_each(|step| match step {
            Step::Update { record, .. } | Step::Delete(record) if record.handle.system => {
                Err(system_record())
            }
            _ => Ok(()),
        })
    }
}

// ---- Listing -------------------------------------------------------------------------------------

/// The records of one owner name and type, as the listing gathers them.
struct Group {
    name: Option<DomainName>,
    type_name: String,
    rtype: Option<RecordType>,
    ttl: Option<RrsetTtl>,
    records: Vec<RecordData>,
    /// A record of the group is limited to some regions.
    regional: bool,
}

impl Dnsimple {
    /// `list_rrsets`: every record of the zone, all pages, grouped by owner name and type.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let all = self.api.all_records(zone).await?;
        let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
        for record in &all {
            let name = normalize_name(&record.name, zone);
            let rtype = record.rtype.parse::<RecordType>().ok();
            // Spellings of one name or type that mean the same land in one group.
            let key = (
                name.as_ref()
                    .map_or_else(|| format!("raw:{}", record.name), |n| n.as_str().to_owned()),
                rtype.map_or_else(|| format!("raw:{}", record.rtype), |t| t.to_string()),
            );
            let data = match rtype {
                Some(rtype) => read_record(rtype, record),
                // A type name that maps to no record type is skipped by the listing whatever
                // the record holds; the data is then never parsed.
                None => RecordData::non_canonical(&record.content),
            };
            let ttl = RrsetTtl::from_secs(record.ttl).ok();
            let group = groups.entry(key).or_insert_with(|| Group {
                name,
                type_name: record.rtype.clone(),
                rtype,
                ttl: None,
                records: Vec::new(),
                regional: false,
            });
            // The smallest TTL of the set (design section 3.6, `TtlSupport::PerRecord`).
            group.ttl = Listing::smallest_ttl([group.ttl, ttl]);
            group.records.push(data);
            group.regional |= !record.is_global();
        }
        let mut listing = Listing::new(zone);
        for group in groups.into_values() {
            let type_name = group
                .rtype
                .map_or(group.type_name, |rtype| rtype.to_string());
            match group.name {
                Some(name) if group.regional && name.is_within(zone) => {
                    listing.skip(name, &type_name, SkipReason::NotPlainRecords);
                }
                name => listing.push(name, &type_name, group.ttl, group.records),
            }
        }
        listing.finish(ProviderId::Dnsimple)
    }
}

#[cfg(test)]
mod tests {
    use super::{Encoded, encode, read_record};
    use crate::providers::dnsimple::api::Record;
    use crate::record::{RecordData, RecordType};

    fn record(rtype: &str, content: &str, priority: serde_json::Value) -> Record {
        serde_json::from_value(serde_json::json!({
            "id": 1, "zone_id": "example.org", "parent_id": null, "type": rtype, "name": "www",
            "content": content, "ttl": 3600, "priority": priority, "regions": ["global"],
            "system_record": false, "created_at": "2016-01-07T17:45:13Z",
            "updated_at": "2016-01-07T17:45:13Z"
        }))
        .unwrap()
    }

    fn read(rtype: RecordType, content: &str, priority: serde_json::Value) -> RecordData {
        read_record(rtype, &record(&rtype.to_string(), content, priority))
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
                RecordType::NS,
                "ns1.dnsimple-edge.com",
                none.clone(),
                "ns1.dnsimple-edge.com.",
            ),
            (
                RecordType::MX,
                "mxa.example.com",
                serde_json::json!(10),
                "10 mxa.example.com.",
            ),
            (
                RecordType::SRV,
                "5 5060 sip.example.org",
                serde_json::json!(1),
                "1 5 5060 sip.example.org.",
            ),
            (
                RecordType::CAA,
                "0 issue \"letsencrypt.org\"",
                none.clone(),
                "0 issue \"letsencrypt.org\"",
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
            (RecordType::TXT, "\"v1\"", none.clone(), "\"v1\""),
            (
                RecordType::SOA,
                "ns1.dnsimple-edge.com admin.dnsimple.com 1458642070 86400 7200 604800 300",
                none.clone(),
                "ns1.dnsimple-edge.com. admin.dnsimple.com. 1458642070 86400 7200 604800 300",
            ),
        ] {
            let got = read(rtype, api, priority);
            assert!(got.is_canonical(), "{rtype} {api}");
            assert_eq!(got.as_str(), canonical, "{rtype} {api}");
        }
    }

    #[test]
    fn unparseable_members_are_non_canonical() {
        for (rtype, api, priority, kept) in [
            (
                RecordType::A,
                "not an address",
                serde_json::Value::Null,
                "not an address",
            ),
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
                RecordType::SRV,
                "5060 sip.example.org",
                serde_json::json!(1),
                "1 5060 sip.example.org",
            ),
        ] {
            let got = read(rtype, api, priority);
            assert!(!got.is_canonical(), "{rtype} {api}");
            assert_eq!(got.as_str(), kept, "{rtype} {api}");
        }
    }

    #[test]
    fn each_type_writes_the_documented_members() {
        for (rtype, text, content, priority) in [
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
            (RecordType::CAA, "0 issue \";\"", "0 issue \";\"", None),
            (RecordType::TXT, "\"v1\"", "v1", None),
        ] {
            let encoded = encode(rtype, &data(rtype, text)).unwrap();
            assert_eq!(
                encoded,
                Encoded {
                    content: content.to_owned(),
                    priority
                },
                "{rtype} {text}"
            );
            // Read back through the same members, the value is the same.
            let priority = priority.map_or(serde_json::Value::Null, serde_json::Value::from);
            assert_eq!(read(rtype, content, priority), data(rtype, text), "{rtype}");
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
            (RecordType::CAA, "1 issue \"ca.example.net\""),
            (RecordType::CAA, "0 issue \"\""),
            (RecordType::CAA, "0 tbs \"x\""),
            (RecordType::CAA, "0 issue \"ca.example.net; account=1\""),
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
