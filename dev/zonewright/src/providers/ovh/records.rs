//! Record-level operations: the `PerRecord` shape of the record layer (`crate::rrsets`) over the
//! record API, the listing of a zone, and the mapping between the API's `target` and
//! `RecordData`.
//!
//! The native unit is the individual record with an identifier, hence the per-record shape,
//! `Preconditions::ReadThenWrite` and no `atomic_rrset_write`: replacing an rrset is several
//! requests, creates first and deletes last (the record layer decides the order). The record
//! layer does the checks, takes the per-name lock, reads, evaluates the expectation and computes
//! the requests; this file turns them into the API's calls. Every write is staged by the API
//! and published by the refresh the client sends at the end of the operation (`client.rs`).
//!
//! - read: `GET …/record?fieldType=&subDomain=` (no `subDomain` for the apex), then
//!   `GET …/record/{id}` for each identifier, at most [`MAX_RECORDS`](super::api::MAX_RECORDS);
//!   type and name are compared exactly on the client's side, since both filters are patterns;
//! - create: `POST …/record`, sent once, with `fieldType`, `subDomain` (left out for the apex),
//!   `target` and the TTL the layer chose;
//! - update: `PUT …/record/{id}`, sent once, with `target` and `ttl` and `subDomain` as read
//!   unless they change. A `404` is `Error::Conflict` when a new read no longer finds the record,
//!   else the refusal;
//! - delete: `DELETE …/record/{id}`, repeated by the transport (idempotent). A `404` counts as
//!   done only when a new read finds no record with the value at the name.
//!
//! # Content per type
//!
//! The API carries a value in one string, `target` (Schema, `domain.zone.Record`). Its form per
//! type is taken from these sources:
//!
//! - "dns-update": `src/providers/ovh.rs`, `OvhRecordFormat::from`: A and AAAA the address;
//!   CNAME and NS the host name with a trailing dot; MX `<priority> <exchange>.`; SRV
//!   `<priority> <weight> <port> <target>.`; TLSA and CAA their zone-file text; TXT the value
//!   itself. Its comparison (`target_equivalent`) treats a host name with and without a trailing
//!   dot as the same name, and TLSA without regard to letter case. Its CAA reader takes the tags
//!   `issue`, `issuewild` and `iodef`, the value with or without quotes;
//! - "lego": `providers/dns/ovh/ovh.go`: TXT, the value itself in `target`;
//! - "Terraform": `resource_domain_zone_record.go`: "The API silently quotes TXT fields, and
//!   splits long ones in 255 chars strings".
//!
//! | Type  | `target`                                     | Source                  |
//! | ----- | -------------------------------------------- | ----------------------- |
//! | A     | the address                                  | dns-update              |
//! | AAAA  | the address                                  | dns-update              |
//! | CNAME | the host name, trailing dot (1)              | dns-update              |
//! | NS    | the host name, trailing dot (1)              | dns-update              |
//! | MX    | `<priority> <exchange>.` (1)                 | dns-update              |
//! | SRV   | `<priority> <weight> <port> <target>.` (1)   | dns-update              |
//! | CAA   | `<flags> <tag> "<value>"` (2)                | dns-update              |
//! | TLSA  | `<usage> <selector> <matching> <hex>`        | dns-update              |
//! | TXT   | the value itself (3)                         | lego, dns-update        |
//!
//! (1) Written with a trailing dot; read as absolute with or without one (dns-update compares
//! them so). Assumption (not documented, not observed against the live API): that a host name in
//! `target` is never relative to the zone; such a name would be read as absolute, which can only
//! make a value compare unequal to the one a caller expects. (2) Written with the value in
//! quotes, read with or without them through the strict parser. (3) TXT dialect `Raw` on write,
//! `Auto` on read: the API quotes the value and splits it into strings of 255 characters
//! (Terraform), so text that starts with `"` is read as zone-file text and anything else as the
//! value itself.
//!
//! Reading: text the parser refuses is kept as non-canonical data (design section 4.9): listed,
//! compared by text, written back only as it is. The other types of `domain.zone.RecordTypeEnum`
//! (DKIM, DMARC, DNAME, HTTPS, LOC, NAPTR, PTR, RP, SPF, SSHFP, SVCB) have no `target` form a
//! source shows: a listing carries them, they cannot be read alone or written.
//!
//! Writing stays within what the sources show, and [`RrsetBase::can_send`] refuses everything
//! else with `Error::InvalidInput` before any write:
//!
//! - host names: never the root (`.`: a null MX or an SRV "no service"; no source shows how the
//!   API takes it) and never with a backslash escape;
//! - TXT: plain values only (`Txt::is_plain`), the values the TXT value operations send. How the
//!   API treats spaces, quotes, escapes and values longer than one character-string is not
//!   established: it quotes and splits values itself;
//! - CAA: flags 0 or 128, the tags dns-update reads, and a value of printable ASCII without
//!   space, `"` and `\`.
//!
//! TTL: a record states its own (`ttl`). A record read with `ttl` `null` or `0` is reported
//! without a TTL ([`stated_ttl`](super::api::stated_ttl)); a write without a TTL leaves every
//! record's own, a write with one sets it on every record (design section 3.6).

use std::collections::BTreeMap;

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::{DomainName, TargetName};
use crate::provider::ZoneListing;
use crate::record::{Caa, Mx, RecordData, RecordType, RrsetTtl, Srv, Txt, TxtDialect};
use crate::redact::Detail;
use crate::rrsets::{
    self, Listing, PerRecord, RecordUpdate as LayerUpdate, RecordsRead, RrsetBase, SetTtl, Stored,
};

use super::api::{Filter, NewRecord, Record, RecordUpdate, Written, filter_for, owner, stated_ttl};
use super::client::Ovh;

/// How TXT data is read: quoted text as zone-file text, anything else as the value (module
/// documentation, note 3). The one rule of both layers.
pub(super) const TXT_READ: TxtDialect = TxtDialect::Auto;

/// How TXT data is written: the value itself (lego ovh.go, `Present`).
pub(super) const TXT_WRITE: TxtDialect = TxtDialect::Raw;

/// The CAA flags the client sends: 0 and the issuer-critical flag 128 (RFC 8659 section 4.1;
/// dns-update reads bit 0x80 as `issuer_critical`).
const CAA_FLAGS: &[u8] = &[0, 128];

/// The CAA tags the client sends: those dns-update's reader takes (`parse_caa`).
const CAA_TAGS: &[&str] = &["issue", "issuewild", "iodef"];

/// What a write needs of a record that was read: everything an update writes back unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Handle {
    /// The record's identifier.
    pub(crate) id: u64,
    /// `subDomain` as read.
    pub(crate) sub_domain: Option<String>,
    /// `target` as read.
    pub(crate) target: String,
    /// `ttl` as read.
    pub(crate) ttl: Option<i64>,
}

impl Handle {
    pub(super) fn of(record: &Record) -> Handle {
        Handle {
            id: record.id,
            sub_domain: record.sub_domain.clone(),
            target: record.target.clone(),
            ttl: record.ttl,
        }
    }
}

/// The record's TTL for the layers.
pub(super) fn ttl_of(record: &Record) -> Option<RrsetTtl> {
    stated_ttl(record.ttl).and_then(|t| RrsetTtl::from_secs(t).ok())
}

/// A name the layers let through that is not within the zone; they check it first, so this is
/// never expected.
pub(super) fn outside_zone(name: &DomainName, zone: &DomainName) -> Error {
    Error::name_outside_zone(name.clone(), zone.clone())
}

// ---- Reading -------------------------------------------------------------------------------------

/// A value as the API returned it: canonical where `target` parses, non-canonical otherwise.
pub(super) fn read_record(rtype: RecordType, target: &str) -> RecordData {
    RecordData::from_provider(rtype, target, None, TXT_READ)
}

// ---- Writing -------------------------------------------------------------------------------------

/// The `target` for a canonical value of `rtype`, or `None` when the client cannot send it (see
/// the module documentation).
pub(super) fn encode(rtype: RecordType, data: &RecordData) -> Option<String> {
    if !data.is_canonical() {
        return None;
    }
    match rtype {
        RecordType::A | RecordType::AAAA => Some(data.as_str().to_owned()),
        RecordType::CNAME | RecordType::NS => {
            let target = TargetName::parse(data.as_str()).ok()?;
            host(&target)
        }
        RecordType::MX => {
            let mx = Mx::from_data(data).ok()?;
            Some(format!("{} {}", mx.preference, host(&mx.exchange)?))
        }
        RecordType::SRV => {
            let srv = Srv::from_data(data).ok()?;
            Some(format!(
                "{} {} {} {}",
                srv.priority,
                srv.weight,
                srv.port,
                host(&srv.target)?
            ))
        }
        RecordType::CAA => write_caa(data),
        // The canonical text: `<usage> <selector> <matching> <hex>`.
        RecordType::TLSA => Some(data.as_str().to_owned()),
        RecordType::TXT => {
            let txt = Txt::from_data(data).ok().filter(Txt::is_plain)?;
            TXT_WRITE.write(&txt)
        }
        _ => None,
    }
}

/// CAA: `flags tag "value"`, within [`CAA_FLAGS`], [`CAA_TAGS`] and a value without space,
/// quote or backslash.
fn write_caa(data: &RecordData) -> Option<String> {
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
    Some(format!("{} {} \"{value}\"", caa.flags, caa.tag))
}

/// A host name as the API takes it: absolute with its trailing dot; `None` for the root and for
/// a name whose canonical text needs a backslash escape.
fn host(name: &TargetName) -> Option<String> {
    let text = name.as_str();
    if name.is_root() || text.contains('\\') {
        return None;
    }
    Some(text.to_owned())
}

// ---- The record layer ----------------------------------------------------------------------------

impl Ovh {
    /// Every record of `rtype` at `name`, matched by name and type on the client's side.
    pub(super) async fn records_at(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Vec<Record>, Error> {
        let relative = name
            .relative_to(zone)
            .ok_or_else(|| outside_zone(name, zone))?;
        let type_name = rtype.to_string();
        let filter = filter_for(relative, &type_name);
        Ok(self
            .api
            .records(zone, filter)
            .await?
            .into_iter()
            .filter(|record| {
                record.field_type.parse::<RecordType>().ok() == Some(rtype)
                    && owner(record.sub_domain.as_deref(), zone).as_ref() == Some(name)
            })
            .collect())
    }

    /// The TTL of a new record: the layer's choice when it is a number, else the setting.
    fn new_ttl(&self, ttl: SetTtl) -> u32 {
        match ttl {
            SetTtl::Requested(RrsetTtl::Explicit(ttl))
            | SetTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => ttl.as_secs(),
            // Every record the client writes states its TTL (`provider_default_ttl` is
            // `Absent`): the configured TTL stands for a set without one (design section 3.6).
            SetTtl::Default
            | SetTtl::Requested(RrsetTtl::ProviderDefault)
            | SetTtl::Existing(None | Some(RrsetTtl::ProviderDefault)) => self.ttl,
        }
    }
}

impl RrsetBase for Ovh {
    fn provider(&self) -> ProviderId {
        ProviderId::Ovh
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

impl PerRecord for Ovh {
    /// The record as read.
    type Handle = Handle;
    /// The zone's name is the key of every path: nothing to carry.
    type Context = ();

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<RecordsRead<Handle, ()>, Error> {
        let records = self
            .records_at(zone, name, rtype)
            .await?
            .iter()
            .map(|record| Stored {
                data: read_record(rtype, &record.target),
                // The API has no disabled records.
                enabled: true,
                ttl: ttl_of(record),
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
        let target = encode(rtype, data).ok_or_else(not_sendable)?;
        let relative = name
            .relative_to(zone)
            .ok_or_else(|| outside_zone(name, zone))?;
        let type_name = rtype.to_string();
        let record = NewRecord {
            field_type: &type_name,
            sub_domain: (!relative.is_empty()).then_some(relative),
            target: &target,
            ttl: self.new_ttl(ttl),
        };
        self.api.create_record(zone, &record).await
    }

    async fn update(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &(),
        record: &Stored<Handle>,
        update: &LayerUpdate<'_>,
    ) -> Result<(), Error> {
        if update.enable {
            // Every record this client reads is enabled, so the layer never asks for this.
            return Err(Error::Protocol {
                detail: Detail::constant("the provider has no disabled records to enable"),
            });
        }
        let target = match update.data {
            Some(data) => encode(rtype, data).ok_or_else(not_sendable)?,
            None => record.handle.target.clone(),
        };
        let ttl = match update.ttl.and_then(RrsetTtl::explicit) {
            Some(ttl) => Some(i64::from(ttl.as_secs())),
            None => record.handle.ttl,
        };
        let body = RecordUpdate {
            sub_domain: record
                .handle
                .sub_domain
                .as_deref()
                .filter(|sub| !sub.is_empty()),
            target: &target,
            ttl,
        };
        match self
            .api
            .update_record(zone, record.handle.id, &body)
            .await?
        {
            Written::Done => Ok(()),
            // The meaning of `404` is not documented: a new read tells whether the record went
            // away after the read (nothing was written, the caller's repeat reads again).
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
        match self.api.delete_record(zone, record.handle.id).await? {
            Written::Done => Ok(()),
            // The record is gone, or the zone is and was created again with the value under a
            // new identifier. Only a new read tells them apart (the record layer's rule for a
            // per-record API, design sections 3.5 and 3.8).
            Written::NotFound(_) => {
                let now = <Self as PerRecord>::read(self, zone, name, rtype).await?;
                if now.records.iter().any(|r| r.data == record.data) {
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
}

// ---- Listing -------------------------------------------------------------------------------------

/// The records of one owner name and type, as the listing gathers them.
struct Group {
    name: Option<DomainName>,
    type_name: String,
    ttl: Option<RrsetTtl>,
    records: Vec<RecordData>,
}

impl Ovh {
    /// `list_rrsets`: every record of the zone, read one by one, grouped by owner name and
    /// type.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let all = self.api.records(zone, Filter::default()).await?;
        let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
        for record in &all {
            let name = owner(record.sub_domain.as_deref(), zone);
            let rtype = record.field_type.parse::<RecordType>().ok();
            // Spellings of one name or type that mean the same land in one group.
            let key = (
                name.as_ref().map_or_else(
                    || format!("raw:{}", record.sub_domain.as_deref().unwrap_or("")),
                    |n| n.as_str().to_owned(),
                ),
                rtype.map_or_else(|| format!("raw:{}", record.field_type), |t| t.to_string()),
            );
            let data = match rtype {
                Some(rtype) => read_record(rtype, &record.target),
                // A type name that maps to no record type is skipped by the listing whatever
                // the record holds; the data is then never parsed.
                None => RecordData::non_canonical(&record.target),
            };
            let group = groups.entry(key).or_insert_with(|| Group {
                name,
                type_name: rtype.map_or_else(|| record.field_type.clone(), |t| t.to_string()),
                ttl: None,
                records: Vec::new(),
            });
            // The smallest TTL of the set (design section 3.6, `TtlSupport::PerRecord`).
            group.ttl = Listing::smallest_ttl([group.ttl, ttl_of(record)]);
            group.records.push(data);
        }
        let mut listing = Listing::new(zone);
        for group in groups.into_values() {
            listing.push(group.name, &group.type_name, group.ttl, group.records);
        }
        listing.finish(ProviderId::Ovh)
    }
}

#[cfg(test)]
mod tests {
    use super::{encode, read_record};
    use crate::record::{RecordData, RecordType};

    fn data(rtype: RecordType, text: &str) -> RecordData {
        RecordData::parse(rtype, text).unwrap()
    }

    #[test]
    fn each_type_reads_into_canonical_text() {
        for (rtype, target, canonical) in [
            (RecordType::A, "192.0.2.1", "192.0.2.1"),
            (RecordType::AAAA, "2001:DB8:0::1", "2001:db8::1"),
            (
                RecordType::CNAME,
                "Target.example.net.",
                "target.example.net.",
            ),
            (
                RecordType::CNAME,
                "target.example.net",
                "target.example.net.",
            ),
            (RecordType::NS, "ns1.example.net.", "ns1.example.net."),
            (
                RecordType::MX,
                "10 mail.example.org.",
                "10 mail.example.org.",
            ),
            (
                RecordType::SRV,
                "1 5 5060 sip.example.org.",
                "1 5 5060 sip.example.org.",
            ),
            (
                RecordType::CAA,
                "0 issue \"letsencrypt.org\"",
                "0 issue \"letsencrypt.org\"",
            ),
            (RecordType::TLSA, "3 1 1 0A1B", "3 1 1 0a1b"),
            (RecordType::TXT, "v=spf1", "\"v=spf1\""),
            (RecordType::TXT, "\"quoted\" \"two\"", "\"quotedtwo\""),
            (RecordType::TXT, "\"v1\"", "\"v1\""),
        ] {
            let got = read_record(rtype, target);
            assert!(got.is_canonical(), "{rtype} {target}");
            assert_eq!(got.as_str(), canonical, "{rtype} {target}");
        }
        let odd = read_record(RecordType::A, "not an address");
        assert!(!odd.is_canonical());
        assert_eq!(odd.as_str(), "not an address");
    }

    #[test]
    fn each_type_writes_the_documented_target() {
        for (rtype, text, target) in [
            (RecordType::A, "192.0.2.1", "192.0.2.1"),
            (RecordType::AAAA, "2001:db8::1", "2001:db8::1"),
            (
                RecordType::CNAME,
                "target.example.net.",
                "target.example.net.",
            ),
            (RecordType::NS, "ns1.example.net.", "ns1.example.net."),
            (
                RecordType::MX,
                "10 mail.example.org.",
                "10 mail.example.org.",
            ),
            (
                RecordType::SRV,
                "1 5 5060 sip.example.org.",
                "1 5 5060 sip.example.org.",
            ),
            (
                RecordType::CAA,
                "128 issuewild \"ca.example.net\"",
                "128 issuewild \"ca.example.net\"",
            ),
            (RecordType::TLSA, "3 1 1 0a1b", "3 1 1 0a1b"),
            (RecordType::TXT, "\"v1\"", "v1"),
        ] {
            assert_eq!(
                encode(rtype, &data(rtype, text)).as_deref(),
                Some(target),
                "{rtype} {text}"
            );
            // Read back, the value is the same.
            assert_eq!(read_record(rtype, target), data(rtype, text), "{rtype}");
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
            (RecordType::CAA, "0 issuemail \"ca.example.net\""),
            (RecordType::CAA, "0 issue \"\""),
            (RecordType::CAA, "0 issue \"ca.example.net; account=1\""),
            (RecordType::PTR, "host.example.org."),
        ] {
            assert!(
                encode(rtype, &data(rtype, text)).is_none(),
                "{rtype} {text}"
            );
        }
        assert!(encode(RecordType::A, &RecordData::non_canonical("x")).is_none());
    }
}
