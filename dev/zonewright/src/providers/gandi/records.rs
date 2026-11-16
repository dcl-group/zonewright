//! Record-level operations: the `WholeSet` shape of the record layer (`crate::rrsets`) over the
//! rrset primitives of `rrset.rs`, and the listing of a zone. Values are read and written by the
//! rules of `content.rs`.
//!
//! The native unit is the rrset, addressed by domain, owner name and type. Making an rrset hold
//! exactly a given set of values is one request: a create (`POST`) when the read found none, a
//! replacement (`PUT`, "Overwrites a single record") otherwise, each carrying every value and the
//! TTL. The API checks no condition on the rrset as the client read it (no ETag, version or
//! precondition in the reference), hence `Preconditions::ReadThenWrite`: a change another
//! process makes between the read and the write is overwritten. A create is refused when an
//! rrset exists (documented `409`), so a set created by another writer after the read is never
//! overwritten by a create.
//!
//! The model carries everything an rrset of this API has (name, type, values, TTL): there are no
//! disabled records, comments or per-record attributes to keep. Values kept by a write are sent
//! back exactly as the API returned them.
//!
//! TTL. An rrset's `rrset_ttl` is optional in an answer, and what the API does with an rrset
//! written without one is not documented, so the client always sends one: the requested TTL,
//! else the rrset's as read, else (an rrset read without one, or a new rrset) the `ttl` setting.
//!
//! The NS rrset at the apex is refused by the record layer before any request; whether the API
//! lists SOA or apex NS rrsets, or refuses writes to them, is not documented.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::provider::ZoneListing;
use crate::record::{RecordData, RecordType, RrsetTtl};
use crate::redact::Detail;
use crate::rrsets::{self, Current, Found, Listing, Member, RrsetBase, SetTtl, Stored, WholeSet};

use super::api::Rrset;
use super::client::Gandi;
use super::content;
use super::rrset::rr_name;

impl RrsetBase for Gandi {
    fn provider(&self) -> ProviderId {
        ProviderId::Gandi
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

/// The TTL of an rrset as read.
fn rrset_ttl(rrset: &Rrset) -> Option<RrsetTtl> {
    rrset.ttl.and_then(|ttl| RrsetTtl::from_secs(ttl).ok())
}

/// The record layer's view of an rrset the API returned.
fn found(rtype: RecordType, rrset: Rrset) -> Found<String, Rrset> {
    let records = rrset
        .values
        .iter()
        .map(|value| Stored {
            data: content::read(rtype, value),
            enabled: true,
            ttl: None,
            handle: value.clone(),
        })
        .collect();
    Found {
        records,
        ttl: rrset_ttl(&rrset),
        snapshot: rrset,
    }
}

impl WholeSet for Gandi {
    /// The value exactly as the API returned it.
    type Handle = String;
    type Snapshot = Rrset;
    /// The owner name relative to the zone.
    type Context = String;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Current<String, Rrset, String>, Error> {
        let rr = rr_name(zone, name)?;
        let rrset = self.read_rrset(zone, &rr, &rtype.to_string()).await?;
        Ok(Current {
            context: rr,
            found: rrset.map(|rrset| found(rtype, rrset)),
        })
    }

    async fn write(
        &self,
        zone: &DomainName,
        _name: &DomainName,
        rtype: RecordType,
        rr: &String,
        prior: Option<&Rrset>,
        members: &[Member<'_, String>],
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let values = members
            .iter()
            .map(|member| match member {
                // The API has no disabled records, so the layer never asks to enable one; were
                // it to, the value is the same value.
                Member::Kept(record) | Member::Enabled(record) => Ok(record.handle.clone()),
                Member::Added(data) => content::write(rtype, data).ok_or(Error::InvalidInput {
                    detail: Detail::constant(
                        "the provider's encoding of this record data is not established",
                    ),
                    code: None,
                }),
            })
            .collect::<Result<Vec<String>, Error>>()?;
        let ttl = match ttl {
            SetTtl::Requested(RrsetTtl::Explicit(ttl))
            | SetTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => ttl.as_secs(),
            // An rrset read without a TTL (or with one the model cannot hold) keeps the number
            // the API returned where there is one, else gets the setting.
            SetTtl::Existing(None) => prior.and_then(|prior| prior.ttl).unwrap_or(self.ttl),
            // No default TTL of the provider's own: the layer never passes it (the capabilities
            // refuse it), and the setting stands in.
            SetTtl::Existing(Some(RrsetTtl::ProviderDefault))
            | SetTtl::Default
            | SetTtl::Requested(RrsetTtl::ProviderDefault) => self.ttl,
        };
        let rtype = rtype.to_string();
        match prior {
            None => self.create_rrset(zone, rr, &rtype, &values, ttl).await,
            Some(_) => self.replace_rrset(zone, rr, &rtype, &values, ttl).await,
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        _name: &DomainName,
        rtype: RecordType,
        rr: &String,
        _prior: &Rrset,
    ) -> Result<(), Error> {
        self.delete_rrset(zone, rr, &rtype.to_string()).await
    }
}

impl Gandi {
    /// `list_rrsets`: every rrset of the zone, all pages.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let mut listing = Listing::new(zone);
        for rrset in self.api.rrsets(zone).await? {
            // Names are relative to the zone, `@` for the apex (the reference, `rrset_name`).
            let name = DomainName::from_relative(&rrset.name, zone).ok();
            let ttl = rrset_ttl(&rrset);
            // A type name that maps to no record type is skipped by the listing, whatever the
            // values hold; they are then never parsed.
            let records: Vec<RecordData> = match rrset.rtype.parse::<RecordType>() {
                Ok(rtype) => rrset
                    .values
                    .iter()
                    .map(|value| content::read(rtype, value))
                    .collect(),
                Err(_) => rrset
                    .values
                    .iter()
                    .map(|value| RecordData::non_canonical(value))
                    .collect(),
            };
            listing.push(name, &rrset.rtype, ttl, records);
        }
        listing.finish(ProviderId::Gandi)
    }
}
