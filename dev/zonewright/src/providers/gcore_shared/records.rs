//! Record-level operations: the `WholeSet` shape of the record layer (`crate::rrsets`) over the
//! rrset primitives of the core, the listing of a zone, and the use of `content.rs`.
//!
//! The native unit is the rrset, created by `POST` and replaced whole by `PUT`, one request
//! each, without a condition the provider checks (no ETag, If-Match or version in either spec),
//! hence `Preconditions::ReadThenWrite` and `atomic_rrset_write`. The record layer does the
//! checks, takes the per-name lock, reads, evaluates the expectation and computes the member
//! list; this file turns members into the API's records and back.
//!
//! # What the model does not carry
//!
//! - A disabled record (`enabled: false`) is not published (design section 3.4): it is not part
//!   of the rrset as read, a write keeps it disabled and in place, a requested value that a
//!   disabled record holds enables that record, and a delete of an rrset with disabled records
//!   writes them back alone instead of deleting the rrset.
//! - Per-record metadata (`meta`) travels back unchanged on every replacement; a new record has
//!   none.
//! - An rrset with pickers (Gcore), filters (EdgeCenter), a filter set or rrset metadata selects
//!   its answers per query: the replacement of its records without them would remove that
//!   configuration ("if previously set, must re-send when updating or CDN integration will be
//!   removed for this RRSet", the Gcore spec, `OutputRRSet.meta`). Such an rrset is not an rrset
//!   the model can hold: a listing reports it in `skipped` with `SkipReason::NotPlainRecords`,
//!   and `get_rrset`, `set_rrset` and `delete_rrset` at its name and type fail with
//!   `Error::Rejected` after their read and before any write.
//!
//! The SOA rrset and the NS rrset at the apex are the provider's: "The response also includes
//! system records such as NS"
//! (<https://docs.gcore.com/dns/dns-records/manage-dns-records-non-advanced-interface-mode>).
//! SOA is read-only in the capabilities, and the record layer refuses writes to the apex NS set
//! before any request.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::provider::{SkipReason, ZoneListing};
use crate::record::{RecordData, RecordType, RrsetTtl};
use crate::redact::Detail;
use crate::rrsets::{self, Current, Found, Listing, Member, RrsetBase, SetTtl, Stored, WholeSet};

use super::api::{Record, Rrset};
use super::{Core, content, not_plain};

impl RrsetBase for Core {
    fn provider(&self) -> ProviderId {
        self.flavor.provider
    }

    fn capabilities(&self) -> &Capabilities {
        self.flavor.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }

    fn can_send(&self, rtype: RecordType, data: &RecordData) -> bool {
        content::write(rtype, data).is_some()
    }
}

/// The record layer's view of an rrset the API returned.
fn found(rtype: RecordType, rrset: Rrset) -> Found<Record, Rrset> {
    let records = rrset
        .records
        .iter()
        .map(|record| Stored {
            data: content::read(rtype, &record.content),
            enabled: record.enabled,
            ttl: None,
            handle: record.clone(),
        })
        .collect();
    Found {
        records,
        ttl: rrset.ttl.and_then(|ttl| RrsetTtl::from_secs(ttl).ok()),
        snapshot: rrset,
    }
}

impl WholeSet for Core {
    type Handle = Record;
    type Snapshot = Rrset;
    /// Nothing: the zone name is the key of every path.
    type Context = ();

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Current<Record, Rrset, ()>, Error> {
        let rrset = self.read_rrset(zone, name, &rtype.to_string()).await?;
        if rrset.as_ref().is_some_and(|rrset| rrset.dynamic) {
            return Err(not_plain());
        }
        Ok(Current {
            context: (),
            found: rrset.map(|rrset| found(rtype, rrset)),
        })
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _: &(),
        prior: Option<&Rrset>,
        members: &[Member<'_, Record>],
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let records =
            members
                .iter()
                .map(|member| match member {
                    Member::Kept(record) => Ok(record.handle.clone()),
                    Member::Enabled(record) => Ok(Record {
                        enabled: true,
                        ..record.handle.clone()
                    }),
                    Member::Added(data) => content::write(rtype, data).map(Record::new).ok_or(
                        Error::InvalidInput {
                            detail: Detail::constant(
                                "the provider's encoding of this record data is not established",
                            ),
                            code: None,
                        },
                    ),
                })
                .collect::<Result<Vec<Record>, Error>>()?;
        let ttl = match ttl {
            SetTtl::Requested(RrsetTtl::Explicit(ttl))
            | SetTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => ttl.as_secs(),
            // An existing rrset whose TTL the model cannot hold (above 2^31 - 1) keeps the number
            // the API returned.
            SetTtl::Existing(None) => prior.and_then(|prior| prior.ttl).unwrap_or(self.ttl),
            // No default TTL of its own that a read shows: the layer never passes it, and the
            // setting stands in.
            SetTtl::Existing(Some(RrsetTtl::ProviderDefault))
            | SetTtl::Default
            | SetTtl::Requested(RrsetTtl::ProviderDefault) => self.ttl,
        };
        let rtype = rtype.to_string();
        match prior {
            None => self.create_rrset(zone, name, &rtype, &records, ttl).await,
            Some(_) => self.replace_rrset(zone, name, &rtype, &records, ttl).await,
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _: &(),
        _: &Rrset,
    ) -> Result<(), Error> {
        self.delete_rrset(zone, name, &rtype.to_string()).await
    }
}

impl Core {
    /// `list_rrsets`: every rrset of the zone, all pages.
    pub(in crate::providers) async fn list_zone(
        &self,
        zone: &DomainName,
    ) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let mut listing = Listing::new(zone);
        for rrset in self.api.rrsets(zone).await? {
            let name = DomainName::parse(&rrset.name).ok();
            if rrset.dynamic
                && let Some(name) = name.clone().filter(|name| name.is_within(zone))
            {
                listing.skip(name, &rrset.rtype, SkipReason::NotPlainRecords);
                continue;
            }
            let ttl = rrset.ttl.and_then(|ttl| RrsetTtl::from_secs(ttl).ok());
            let enabled = rrset.records.iter().filter(|record| record.enabled);
            // A type name that maps to no record type is skipped by the listing, whatever the
            // records hold; the content is then never parsed.
            let records: Vec<RecordData> = match rrset.rtype.parse::<RecordType>() {
                Ok(rtype) => enabled
                    .map(|record| content::read(rtype, &record.content))
                    .collect(),
                Err(_) => enabled
                    .map(|record| content::opaque(&record.content))
                    .collect(),
            };
            listing.push(name, &rrset.rtype, ttl, records);
        }
        listing.finish(self.flavor.provider)
    }
}
