//! The rrset primitives both layers build on: read one rrset by name and type under the zone
//! cache, create it, replace it, delete it. `txt.rs` (the TXT value layer) and `records.rs` (the
//! record layer) call these with the API's type name; the rules for each answer live here once.
//!
//! - read: `GET …/rrset?name=&rrset_types=`, exact name and type match (the filters match
//!   substrings), under the zone-ID cache: a `404` with a cached zone ID resolves the zone afresh
//!   and reads once more (design section 3.8).
//! - create: `POST …/rrset` in the zone the read used, sent once. What the API answers to a
//!   create of a name and type that exists is not documented, so any refusal is followed by a
//!   new read: an rrset found there now is `Error::Conflict` (someone created it after our read;
//!   nothing was overwritten), otherwise the refusal is the error (design section 3.5).
//! - update: `PATCH …/rrset/{id}` with the full record list and the TTL, sent once, carrying the
//!   comment in the body and the managing resource in `X-Managed-By` as read, since whether an
//!   update without them clears them is not established (design section 11.3).
//! - delete: `DELETE …/rrset/{id}`, sent once. A `404` is success only when a new read under a
//!   freshly looked-up zone finds no rrset: the zone may have been recreated with the rrset in
//!   it, and then its values are still published (`Error::Conflict`). An rrset that a web
//!   resource manages (`managed_by` read) is deleted like any other: taking a record over from
//!   an external tool is the application's decision. The delete carries the managing resource
//!   in `X-Managed-By` as read, the header the OpenAPI documents for `DELETE` as for `PATCH`; a
//!   refusal is the error it maps to, and the delete is not sent again without the header.
//!
//! An update or a delete answered `404` drops the cached zone ID: the zone or the rrset changed
//! after the read and nothing was written; the caller's repeat starts with a fresh read.

use crate::error::Error;
use crate::http::{Attempt, ZoneId};
use crate::name::DomainName;
use crate::redact::Detail;

use super::api::{NewRrset, Record, Rrset, RrsetUpdate, Written};
use super::client::SelectelV2;

impl SelectelV2 {
    /// The rrset of `name` and type `rtype` (the API's spelling), with the zone identifier the
    /// read ended with.
    pub(super) async fn read_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
    ) -> Result<(String, Option<Rrset>), Error> {
        let (zone_id, rrset) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| self.read_rrset_in(zone, name, rtype, id),
            )
            .await?;
        Ok((zone_id.id, rrset))
    }

    /// The read phase under the zone cache: the rrset in the zone `id`, or `Stale` when the API
    /// does not know the zone (`404`).
    async fn read_rrset_in(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        id: ZoneId,
    ) -> Result<Attempt<Option<Rrset>>, Error> {
        let unicode = name.to_unicode();
        let filter = unicode.strip_suffix('.').unwrap_or(&unicode);
        match self.api.rrsets(zone, &id.id, filter, rtype).await {
            Ok(rrsets) => Ok(Attempt::Done(rrsets.into_iter().find(|r| {
                r.rtype == rtype && DomainName::parse(&r.name).as_ref() == Ok(name)
            }))),
            Err(Error::ZoneNotFound { .. }) => Ok(Attempt::Stale),
            Err(e) => Err(e),
        }
    }

    /// Creates the rrset in the zone the read used. Names are sent in Unicode form, absolute
    /// (design section 11.3).
    pub(super) async fn create_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        zone_id: &str,
        records: &[Record],
        ttl: u32,
    ) -> Result<(), Error> {
        let unicode = name.to_unicode();
        let rrset = NewRrset {
            name: &unicode,
            rtype,
            ttl,
            records,
        };
        let refusal = match self.api.create_rrset(zone_id, &rrset).await? {
            Written::Done => return Ok(()),
            Written::NotFound => {
                self.forget_zone(zone);
                vanished()
            }
            Written::Refused(e) => e,
        };
        // The answer to a duplicate create is not documented: read again. An rrset there now
        // was created by someone else after our read, and nothing of it was overwritten.
        match self.read_rrset(zone, name, rtype).await?.1 {
            Some(_) => Err(Error::Conflict {
                detail: Detail::constant(
                    "an rrset of this name and type was created between the read and the write",
                ),
            }),
            None => Err(refusal),
        }
    }

    /// Replaces the records and the TTL of `prior`, keeping its comment and managing resource.
    pub(super) async fn update_rrset(
        &self,
        zone: &DomainName,
        zone_id: &str,
        prior: &Rrset,
        records: &[Record],
        ttl: u32,
    ) -> Result<(), Error> {
        let update = RrsetUpdate {
            ttl,
            records,
            comment: prior.comment.as_deref(),
        };
        let managed_by = prior.managed_by.as_deref();
        match self
            .api
            .update_rrset(zone_id, &prior.id, managed_by, &update)
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

    /// Deletes `prior`, managed by a web resource or not. A `404` is success only when a new
    /// read finds no rrset.
    pub(super) async fn delete_rrset_checked(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        zone_id: &str,
        prior: &Rrset,
    ) -> Result<(), Error> {
        let managed_by = prior.managed_by.as_deref();
        match self
            .api
            .delete_rrset(zone_id, &prior.id, managed_by)
            .await?
        {
            Written::Done => Ok(()),
            // The rrset is gone, or the zone identifier is (a zone recreated with the rrset in
            // it). Only a new read under a freshly looked-up zone tells them apart.
            Written::NotFound => {
                self.forget_zone(zone);
                match self.read_rrset(zone, name, rtype).await?.1 {
                    None => Ok(()),
                    Some(_) => Err(Error::Conflict {
                        detail: Detail::constant(
                            "the rrset was found again after its delete was answered \
                             \"not found\"; the zone changed between the read and the delete",
                        ),
                    }),
                }
            }
            Written::Refused(e) => Err(e),
        }
    }
}

/// A write addressed a zone or an rrset that no longer exists: it changed after the read, and
/// nothing was written.
fn vanished() -> Error {
    Error::Conflict {
        detail: Detail::constant(
            "the zone or the rrset was removed between the read and the write",
        ),
    }
}
