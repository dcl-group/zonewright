//! Record-level operations: the `WholeSet` shape of the record layer (`crate::rrsets`) over the
//! rrset primitives of `rrset.rs`, the listing of a zone, and the mapping between the API's
//! record `value` text and `RecordData`.
//!
//! # Writing a whole set
//!
//! The API's unit is the rrset, identified by name and type (reference, Zone RRSets). Making an
//! rrset hold exactly a given set of records is done as the provider's own command-line client
//! does it (`hcloud zone set-records`, `internal/cmd/zone/rrset/set_records.go`): read the
//! rrset; when there is none, create it with `POST /zones/{id}/rrsets` (records and TTL in one
//! request); otherwise send `set_records`, which "overwrites the resource records (RRs) of an
//! existing RRSet" in one request. The records of a set are therefore replaced by one request,
//! never by a delete followed by a create. The API checks no condition
//! on the rrset as the client read it, hence `Preconditions::ReadThenWrite`: a change another
//! process makes between the read and the write is overwritten.
//!
//! The TTL of an existing rrset is not part of `set_records`; it is changed by the separate
//! `change_ttl` action, as the provider's Terraform provider does it
//! (`internal/zonerrset/resource.go`, `Update`). A write that changes both sends `set_records`
//! first and `change_ttl` second, each sent once and each waited for; a write that changes only
//! one of them sends only that one. If the second fails, the records are already replaced and
//! the TTL is not; the error is returned, and the caller's repeat reads that state and sends
//! only `change_ttl`. Since such a replacement is two requests, `atomic_rrset_write` is false:
//! it holds for the records alone and for a new rrset, not for every replacement.
//!
//! # What the model does not carry
//!
//! - Record comments. A record kept by a write is sent back with its `value` and `comment`
//!   exactly as the API returned them (design section 3.4); a new record gets no comment.
//! - Rrset labels. No write of this client sends them: `set_records` and `change_ttl` take no
//!   labels, and the labels of an existing rrset stay as they are. A new rrset gets none.
//! - Change protection. A protected rrset "cannot be changed" (`protection.change`: "Prevent
//!   the Resource from being changed"); a write or delete of one is refused with
//!   `Error::Rejected` after the read and before any write, instead of sending a request the
//!   API refuses (`423` `protected`, reference, Errors). A set that is already as requested is
//!   `Unchanged` without a write, protected or not.
//! - A TTL of `null` ("If not set, the Zone's Default TTL is used"). Such an rrset reads with
//!   `ttl() == None`; a write without a requested TTL leaves it so (no `change_ttl` is sent),
//!   and a write with one sets it. The client never sets a TTL back to `null`: a new rrset
//!   gets the requested or the configured TTL.
//!
//! # Values per type
//!
//! The reference describes a record's `value` only as the "Value of the record" and points to
//! the DNS record types documentation (<https://docs.hetzner.com/networking/dns/record-types/overview/>)
//! for the accepted values. A type is in `record_types` only where a source gives its value
//! form; each mapping below cites it:
//!
//! | Type  | Value form                               | Source                                    |
//! | ----- | ---------------------------------------- | ----------------------------------------- |
//! | A     | `203.0.113.1`                            | A record page, Usage                       |
//! | AAAA  | `2001:db8:1234::1`                       | AAAA record page, Usage                    |
//! | CNAME | `example.com.`                           | CNAME record page, Usage                   |
//! | MX    | `10 smtp.example.com.`                   | reference, tag Zone RRSets                 |
//! | NS    | `hydrogen.ns.hetzner.com.`               | NS record page, Usage                      |
//! | PTR   | `foo._app._tcp` (relative)               | PTR record page, Usage                     |
//! | SRV   | `10 60 5060 bigbox.example.org.`         | SRV record page, zone-file example         |
//! | TLSA  | `3 1 1 1306c288…`                        | TLSA record page, "Zone file"              |
//! | TXT   | `"hello " "world"`, "has to be quoted"   | TXT record page, Usage; Terraform docs     |
//! | SOA   | `hydrogen.ns.hetzner.com. dns.hetzner.com. 0 86400 10800 3600000 3600` | Terraform docs (read only) |
//!
//! ("Terraform docs": `docs/resources/zone_rrset.md` of the provider's Terraform provider,
//! commit `06cf2c1`: "The format of TXT records must consist of one or many quoted strings of
//! 255 characters", and the SOA example.) Domain names follow the documented rule "No period at
//! the end of the (sub)domain: the zone itself is appended automatically ... Period at the end:
//! the entry is used exactly as provided" (<https://docs.hetzner.com/networking/dns/faq/records/>,
//! "How do you format domains in DNS records?"), which is zone-file semantics with the zone as
//! the origin. So a value is read with `RecordData::from_provider` with the zone as the origin
//! and TXT by the `Auto` rule, and written as its canonical text, whose names always end with a
//! dot. Two limits keep the client within what the sources establish:
//!
//! - Escapes. No source says how the API treats a backslash escape (`\"`, `\\`, `\DDD`) inside
//!   a value. Canonical text needs one for a TXT value with `"`, `\` or a byte outside
//!   printable ASCII, and for a name with such a label. Such a value is not sent
//!   ([`RrsetBase::can_send`] is false, `Error::InvalidInput`) unless the rrset already holds a
//!   record with that value, which is then written back exactly as the API returned it.
//!   Printable ASCII without `"` and `\`, spaces included and of any length in quoted
//!   255-octet chunks (the chunk size of the TXT page and the Terraform docs), is sent.
//! - Types. CAA, DS, HINFO, HTTPS, RP and SVCB are in the API's type enumeration, but their
//!   documentation pages describe the fields of the Hetzner Console, not the text of the API's
//!   `value` (how flags, tag and value of CAA, or priority, target and parameters of HTTPS and
//!   SVCB, are joined and quoted). They are not in `record_types`: they appear in a listing
//!   (canonical where their text parses, non-canonical otherwise) and cannot be read alone or
//!   written. SOA is read-only (design section 3.4; the Terraform docs: "SOA records are
//!   created or deleted by the Hetzner Cloud API when creating or deleting the parent Zone").
//!
//! The NS rrset at the apex is created with the zone ("The `SOA` record and three `NS` records
//! are always created automatically", FAQ page above); the record layer refuses writes to it
//! before any request.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::provider::ZoneListing;
use crate::record::{RecordData, RecordType, TxtDialect};
use crate::redact::Detail;
use crate::rrsets::{self, Current, Found, Listing, Member, RrsetBase, SetTtl, Stored, WholeSet};

use super::api::{MAX_RECORDS_PER_CALL, NewRrset, Record, Rrset};
use super::client::Hetzner;
use super::rrset::{rr_name, rrset_ttl};

/// How TXT values are read: quoted text as presentation format, anything else as the value.
const TXT_READ: TxtDialect = TxtDialect::Auto;

/// A value as the API returned it, names relative to the zone (see the module documentation).
fn read_value(zone: &DomainName, rtype: RecordType, value: &str) -> RecordData {
    RecordData::from_provider(rtype, value, Some(zone), TXT_READ)
}

/// The API's text for a value, or `None` when the client cannot send it: non-canonical data,
/// and canonical text with a backslash escape (see the module documentation).
fn write_value(data: &RecordData) -> Option<String> {
    (data.is_canonical() && !data.as_str().contains('\\')).then(|| data.as_str().to_owned())
}

impl RrsetBase for Hetzner {
    fn provider(&self) -> ProviderId {
        ProviderId::Hetzner
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }

    /// The most records `set_records` takes. `POST /zones/{id}/rrsets` states no limit, but an
    /// rrset created larger could not be replaced afterwards, so the same limit applies to it.
    // Source: the reference, `set_records`, `records`: "maxItems": 50.
    fn max_records(&self) -> Option<usize> {
        Some(MAX_RECORDS_PER_CALL)
    }

    fn can_send(&self, _rtype: RecordType, data: &RecordData) -> bool {
        write_value(data).is_some()
    }
}

/// What the read hands to a write: the zone identifier it used and the rrset's name relative
/// to the zone.
#[derive(Debug)]
pub(crate) struct Target {
    zone_id: String,
    rr: String,
}

/// The record layer's view of an rrset the API returned. The API has no disabled records.
fn found(
    zone: &DomainName,
    rtype: RecordType,
    rrset: Rrset,
) -> Result<Found<Record, Rrset>, Error> {
    let records = rrset
        .records
        .iter()
        .map(|record| Stored {
            data: read_value(zone, rtype, &record.value),
            enabled: true,
            ttl: None,
            handle: record.clone(),
        })
        .collect();
    Ok(Found {
        records,
        ttl: rrset_ttl(&rrset)?,
        snapshot: rrset,
    })
}

/// A protected rrset is not written (see the module documentation).
fn refuse_protected(prior: &Rrset) -> Result<(), Error> {
    if prior.is_protected() {
        return Err(Error::Rejected {
            status: None,
            detail: Detail::constant(
                "the rrset has change protection enabled at the provider and cannot be changed \
                 or deleted",
            ),
        });
    }
    Ok(())
}

impl WholeSet for Hetzner {
    type Handle = Record;
    type Snapshot = Rrset;
    type Context = Target;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Current<Record, Rrset, Target>, Error> {
        let rr = rr_name(zone, name)?;
        let (zone_id, rrset) = self.read_rrset(zone, &rr, &rtype.to_string()).await?;
        let found = match rrset {
            Some(rrset) => Some(found(zone, rtype, rrset)?),
            None => None,
        };
        Ok(Current {
            context: Target { zone_id, rr },
            found,
        })
    }

    async fn write(
        &self,
        zone: &DomainName,
        _name: &DomainName,
        rtype: RecordType,
        target: &Target,
        prior: Option<&Rrset>,
        members: &[Member<'_, Record>],
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let records = members
            .iter()
            .map(|member| match member {
                // Written back exactly as read, comment included. The API has no disabled
                // records, so the layer never asks to enable one; were it to, the record is
                // the same record.
                Member::Kept(record) | Member::Enabled(record) => Ok(record.handle.clone()),
                Member::Added(data) => Ok(Record {
                    value: write_value(data).ok_or(Error::InvalidInput {
                        detail: Detail::constant(
                            "the provider's encoding of this record data is not established",
                        ),
                    })?,
                    comment: None,
                }),
            })
            .collect::<Result<Vec<Record>, Error>>()?;
        let rtype = rtype.to_string();
        let Some(prior) = prior else {
            let ttl = match ttl {
                SetTtl::Requested(ttl) | SetTtl::Existing(Some(ttl)) => ttl.as_secs(),
                SetTtl::Existing(None) | SetTtl::Default => self.ttl,
            };
            let rrset = NewRrset {
                name: &target.rr,
                rtype: &rtype,
                ttl,
                records: &records,
            };
            return self.create_rrset(zone, &target.zone_id, &rrset).await;
        };
        refuse_protected(prior)?;
        // The records change unless every record read is kept and nothing is added.
        let kept = members
            .iter()
            .filter(|member| matches!(member, Member::Kept(_)))
            .count();
        if kept != members.len() || kept != prior.records.len() {
            self.set_records(zone, &target.zone_id, &target.rr, &rtype, &records)
                .await?;
        }
        // The TTL changes only when one is requested and the rrset has another one; without a
        // request the rrset keeps its TTL, a `null` one included (design section 3.6).
        if let SetTtl::Requested(ttl) = ttl
            && prior.ttl != Some(ttl.as_secs())
        {
            self.change_ttl(zone, &target.zone_id, &target.rr, &rtype, ttl.as_secs())
                .await?;
        }
        Ok(())
    }

    async fn delete(
        &self,
        zone: &DomainName,
        _name: &DomainName,
        rtype: RecordType,
        target: &Target,
        prior: &Rrset,
    ) -> Result<(), Error> {
        refuse_protected(prior)?;
        self.delete_rrset_checked(zone, &target.zone_id, &target.rr, &rtype.to_string())
            .await
    }
}

impl Hetzner {
    /// `list_rrsets`: every rrset of the zone, all pages, under the zone-ID cache.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let all = self.read_zone_rrsets(zone).await?;
        let mut listing = Listing::new(zone);
        for rrset in all {
            // Names are relative to the zone, `@` for the apex (reference, Zone RRSets, `name`).
            let name = DomainName::from_relative(&rrset.name, zone).ok();
            let ttl = rrset_ttl(&rrset)?;
            // A type name that maps to no record type is skipped by the listing, whatever the
            // records hold; the values are then never parsed.
            let records = match rrset.rtype.parse::<RecordType>() {
                Ok(rtype) => rrset
                    .records
                    .iter()
                    .map(|record| read_value(zone, rtype, &record.value))
                    .collect(),
                Err(_) => rrset
                    .records
                    .iter()
                    .map(|record| RecordData::non_canonical(&record.value))
                    .collect(),
            };
            listing.push(name, &rrset.rtype, ttl, records);
        }
        listing.finish(ProviderId::Hetzner)
    }
}
