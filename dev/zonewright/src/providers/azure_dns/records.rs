//! Record-level operations: the `WholeSet` shape of the record layer (`crate::rrsets`) over the
//! record set primitives of `rrset.rs`, and the listing of a zone.
//!
//! The native unit is the record set, replaced whole by one `PUT` that the service makes
//! conditional on the etag read or on the absence of a set, hence `Preconditions::Atomic` and
//! `atomic_rrset_write`: a change by another writer between the read and the write makes the
//! write fail, the layer runs the operation once more from the read, and a second failure is
//! `Error::Conflict`. The record layer does the checks, takes the per-name lock, reads,
//! evaluates the expectation and computes the member list; this file turns members into record
//! objects (`content.rs`) and back.
//!
//! What the model does not carry is written back unchanged: the record objects of values that
//! stay are sent as the API returned them, and the record set's `metadata` stays in the body.
//! A record set the client cannot write back whole is refused before any write
//! (`content::RecordSet::unwritable`): an alias, and a set with a property the reference does
//! not document.
//!
//! # Sets that are not plain records
//!
//! An alias record set (`targetResource` with an `id`) takes its value from another Azure
//! resource and has no records of its own (Create Or Update, "Create A recordset with alias
//! target resource"). A listing reports it in `skipped` with `SkipReason::NotPlainRecords`;
//! `get_rrset`, `set_rrset` and `delete_rrset` at that name and type fail with
//! `Error::Rejected` (status `None`) after their read and before any write, and so do the TXT
//! value operations. A listed set of a type the stable API version does not have (the preview
//! version adds DS, NAPTR and TLSA) has no documented record property for this version and is
//! skipped the same way: an assumption, conservative.
//!
//! # Types
//!
//! The ten types of the `RecordType` enumeration of version `2018-05-01`. SOA is read-only
//! ("Record sets of type SOA can be updated but not created", Create Or Update; the crate never
//! writes SOA, design section 3.4). The NS record set at the apex is created with the zone and
//! its Azure name servers cannot be removed (Records); the record layer refuses writes to it
//! before any request.

use serde_json::Value;

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::provider::{SkipReason, ZoneListing};
use crate::record::{RecordData, RecordType, RrsetTtl};
use crate::rrsets::{
    self, Current, Found, Listing, Member, RrsetBase, SetTtl, Stored, WholeChange, WholeSet,
};

use super::api::RecordSet;
use super::client::AzureDns;
use super::content::{self, not_plain, protocol};

impl RrsetBase for AzureDns {
    fn provider(&self) -> ProviderId {
        ProviderId::AzureDns
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }

    fn can_send(&self, rtype: RecordType, data: &RecordData) -> bool {
        content::write(rtype, data).is_some()
    }
}

/// The record layer's view of a record set the API returned.
fn found(rtype: RecordType, set: RecordSet) -> Result<Found<Value, RecordSet>, Error> {
    let records = set
        .records()?
        .into_iter()
        .map(|item| Stored {
            data: content::read(rtype, &item),
            enabled: true,
            ttl: None,
            handle: item,
        })
        .collect();
    Ok(Found {
        records,
        ttl: set.ttl().and_then(|ttl| RrsetTtl::from_secs(ttl).ok()),
        snapshot: set,
    })
}

impl WholeSet for AzureDns {
    /// The record object as the API returned it.
    type Handle = Value;
    type Snapshot = RecordSet;
    /// Nothing: the zone name is the key of every path.
    type Context = ();

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Current<Value, RecordSet, ()>, Error> {
        let set = self.read_record_set(zone, name, &rtype.to_string()).await?;
        let found = match set {
            Some(set) if set.is_alias() => return Err(not_plain()),
            Some(set) => Some(found(rtype, set)?),
            None => None,
        };
        Ok(Current { context: (), found })
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _: &(),
        prior: Option<&RecordSet>,
        members: &[Member<'_, Value>],
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let records = members
            .iter()
            .map(|member| match member {
                Member::Kept(record) | Member::Enabled(record) => Ok(record.handle.clone()),
                Member::Added(data) => content::write(rtype, data).ok_or(Error::InvalidInput {
                    detail: crate::redact::Detail::constant(
                        "the provider's encoding of this record data is not established",
                    ),
                    code: None,
                }),
            })
            .collect::<Result<Vec<Value>, Error>>()?;
        let ttl = match ttl {
            SetTtl::Requested(RrsetTtl::Explicit(ttl))
            | SetTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => Some(ttl.as_secs()),
            // An existing record set whose TTL the read did not state keeps what the API
            // returned, if anything.
            SetTtl::Existing(None) => None,
            // No default TTL of its own: the layer never passes it, and the setting stands in.
            SetTtl::Existing(Some(RrsetTtl::ProviderDefault))
            | SetTtl::Default
            | SetTtl::Requested(RrsetTtl::ProviderDefault) => Some(self.ttl),
        };
        self.write_record_set(zone, name, &rtype.to_string(), prior, records, ttl)
            .await
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _: &(),
        prior: &RecordSet,
    ) -> Result<(), Error> {
        self.delete_record_set(zone, name, &rtype.to_string(), prior)
            .await
    }

    /// A record set the client cannot write back whole is refused before the write.
    fn check_write(
        &self,
        _: &DomainName,
        _: &DomainName,
        _: RecordType,
        _: &(),
        change: &WholeChange<'_, Value, RecordSet>,
    ) -> Result<(), Error> {
        match change {
            WholeChange::Write {
                prior: Some(prior), ..
            } => prior.unwritable().map_or(Ok(()), Err),
            WholeChange::Write { prior: None, .. } | WholeChange::Delete { .. } => Ok(()),
        }
    }
}

impl AzureDns {
    /// `list_rrsets`: every record set of the zone, all pages.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let sets = match self.api.record_sets(zone).await? {
            Some(sets) => sets,
            None if self.api.zone_exists(zone).await? => {
                return Err(protocol(
                    "the provider answered \"not found\" to the listing of a zone it holds",
                ));
            }
            None => return Err(Error::zone_not_found(zone.clone())),
        };
        let mut listing = Listing::new(zone);
        for set in sets {
            let Some(owner) = set.owner.clone() else {
                listing.skip(zone.clone(), &set.type_name, SkipReason::UnsupportedName);
                continue;
            };
            let rtype = match set.type_name.parse::<RecordType>() {
                Ok(rtype) => rtype,
                Err(_) => {
                    listing.skip(owner, &set.type_name, SkipReason::UnknownType);
                    continue;
                }
            };
            if set.is_alias() || content::record_key(&set.type_name).is_none() {
                listing.skip(owner, &set.type_name, SkipReason::NotPlainRecords);
                continue;
            }
            let ttl = set.ttl().and_then(|ttl| RrsetTtl::from_secs(ttl).ok());
            let records: Vec<RecordData> = set
                .records()?
                .iter()
                .map(|item| content::read(rtype, item))
                .collect();
            listing.push(Some(owner), &set.type_name, ttl, records);
        }
        listing.finish(ProviderId::AzureDns)
    }
}
