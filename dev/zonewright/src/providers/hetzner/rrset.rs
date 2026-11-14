//! The rrset primitives both layers build on: read one rrset by name and type under the zone
//! cache, list a zone, create an rrset, replace its records, change its TTL, delete it, and wait
//! for the action each write starts. `txt.rs` (the TXT value layer) and `records.rs` (the record
//! layer) call these; the rules for each answer live here once.
//!
//! - read: `GET …/rrsets/{rr_name}/{rr_type}` under the zone-ID cache. The `404` answer cannot
//!   tell a missing rrset from a missing zone: under an identifier resolved in this call it
//!   means the rrset is absent; under a cached one the zone is looked up again and the read
//!   repeated (design section 3.8).
//! - create: `POST …/rrsets` in the zone the read used, sent once. What the API answers to a
//!   create of a name and type that exists is not documented, so a refusal is followed by a new
//!   read: an rrset found there now is `Error::Conflict` (someone created it after our read;
//!   nothing was overwritten), otherwise the refusal is the error (design section 3.5).
//! - set records, change TTL: actions on the existing rrset, each sent once.
//! - delete: `DELETE …/rrsets/{rr_name}/{rr_type}`, sent once. A `404` is success only when a
//!   new read under a freshly looked-up zone finds no rrset: the zone may have been recreated
//!   with the rrset in it, and then its values are still published (`Error::Conflict`).
//!
//! A write answered `404` (other than the delete) drops the cached zone ID: the zone or the
//! rrset changed after the read and nothing was written (`Error::Conflict`); the caller's repeat
//! starts with a fresh read. Every write that the API accepted is followed by a wait for its
//! action (design section 3.7).

use crate::error::Error;
use crate::http::{Attempt, ZoneId};
use crate::name::DomainName;
use crate::record::Ttl;
use crate::redact::Detail;

use super::api::{Action, NewRrset, Record, Rrset};
use super::client::Hetzner;

impl Hetzner {
    /// The rrset of `rr` (the name relative to the zone) and type `rtype` (the API's spelling),
    /// with the zone identifier the read ended with.
    pub(super) async fn read_rrset(
        &self,
        zone: &DomainName,
        rr: &str,
        rtype: &str,
    ) -> Result<(String, Option<Rrset>), Error> {
        let (zone_id, rrset) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| self.read_rrset_in(rr, rtype, id),
            )
            .await?;
        Ok((zone_id.id, rrset))
    }

    /// The read phase under the zone cache: the rrset in the zone `id`, or `Stale` when the API
    /// does not know it under a cached identifier.
    async fn read_rrset_in(
        &self,
        rr: &str,
        rtype: &str,
        id: ZoneId,
    ) -> Result<Attempt<Option<Rrset>>, Error> {
        match self.api.rrset(&id.id, rr, rtype).await? {
            Some(set) => Ok(Attempt::Done(Some(set))),
            // The zone was resolved in this call: it exists, so the rrset does not.
            None if id.fresh => Ok(Attempt::Done(None)),
            // A cached identifier: the zone may have been deleted and created again.
            None => Ok(Attempt::Stale),
        }
    }

    /// Every rrset of the zone, all pages, under the zone-ID cache.
    pub(super) async fn read_zone_rrsets(&self, zone: &DomainName) -> Result<Vec<Rrset>, Error> {
        let (_, all) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| async move {
                    match self.api.rrsets(zone, &id.id).await {
                        Ok(all) => Ok(Attempt::Done(all)),
                        Err(Error::ZoneNotFound { .. }) => Ok(Attempt::Stale),
                        Err(e) => Err(e),
                    }
                },
            )
            .await?;
        Ok(all)
    }

    /// Creates the rrset in the zone the read used and waits for the action.
    pub(super) async fn create_rrset(
        &self,
        zone: &DomainName,
        zone_id: &str,
        rrset: &NewRrset<'_>,
    ) -> Result<(), Error> {
        let refusal = match self.api.create_rrset(zone_id, rrset).await {
            Ok(Some(action)) => return self.api.wait(&self.poller, action).await,
            Ok(None) => {
                self.forget_zone(zone);
                return Err(vanished());
            }
            // A refusal of the provider (a 4xx with its error body); anything else, a
            // transient failure above all, says nothing about who created what.
            Err(e @ (Error::Rejected { .. } | Error::Conflict { .. })) => e,
            Err(e) => return Err(e),
        };
        // The answer to a duplicate create is not documented: read again. An rrset there now
        // was created by someone else after our read, and nothing of it was overwritten.
        match self.read_rrset(zone, rrset.name, rrset.rtype).await?.1 {
            Some(_) => Err(Error::Conflict {
                detail: Detail::constant(
                    "an rrset of this name and type was created between the read and the write",
                ),
            }),
            None => Err(refusal),
        }
    }

    /// Replaces the records of the existing rrset and waits for the action.
    pub(super) async fn set_records(
        &self,
        zone: &DomainName,
        zone_id: &str,
        rr: &str,
        rtype: &str,
        records: &[Record],
    ) -> Result<(), Error> {
        let action = self.api.set_records(zone_id, rr, rtype, records).await?;
        self.finish(zone, action).await
    }

    /// Changes the TTL of the existing rrset and waits for the action.
    pub(super) async fn change_ttl(
        &self,
        zone: &DomainName,
        zone_id: &str,
        rr: &str,
        rtype: &str,
        ttl: u32,
    ) -> Result<(), Error> {
        let action = self.api.change_ttl(zone_id, rr, rtype, ttl).await?;
        self.finish(zone, action).await
    }

    /// Deletes the rrset and waits for the action. A `404` is success only when a new read
    /// finds no rrset.
    pub(super) async fn delete_rrset_checked(
        &self,
        zone: &DomainName,
        zone_id: &str,
        rr: &str,
        rtype: &str,
    ) -> Result<(), Error> {
        match self.api.delete_rrset(zone_id, rr, rtype).await? {
            Some(action) => self.api.wait(&self.poller, action).await,
            // The rrset is gone, or the zone identifier is (a zone recreated with the rrset in
            // it). Only a new read under a freshly looked-up zone tells them apart.
            None => {
                self.forget_zone(zone);
                match self.read_rrset(zone, rr, rtype).await?.1 {
                    None => Ok(()),
                    Some(_) => Err(Error::Conflict {
                        detail: Detail::constant(
                            "the rrset was found again after its delete was answered \
                             \"not found\"; the zone changed between the read and the delete",
                        ),
                    }),
                }
            }
        }
    }

    /// Waits for the action of a write, or reports the `404` the write was answered with.
    async fn finish(&self, zone: &DomainName, action: Option<Action>) -> Result<(), Error> {
        match action {
            Some(action) => self.api.wait(&self.poller, action).await,
            None => {
                self.forget_zone(zone);
                Err(vanished())
            }
        }
    }
}

/// The TTL of an rrset the API returned; `None` when the zone's default applies.
///
/// A TTL outside the crate's range is outside the documented one (60 to 2147483647) too. Read
/// as "no TTL" it would make a write keep or send none and could change the rrset's TTL (design
/// section 3.6), so it is an answer the client cannot use.
pub(super) fn rrset_ttl(rrset: &Rrset) -> Result<Option<Ttl>, Error> {
    match rrset.ttl {
        None => Ok(None),
        Some(secs) => Ttl::from_secs(secs).map(Some).map_err(|_| Error::Protocol {
            detail: Detail::constant("the provider's rrset has an unusable TTL"),
        }),
    }
}

/// The owner name relative to the zone, `@` for the apex.
// Source: the reference, Zone RRSets, `rr_name`: "must not end with a dot or the Zone name ...
// For the Zone apex, use `@`".
pub(super) fn rr_name(zone: &DomainName, name: &DomainName) -> Result<String, Error> {
    match name.relative_to(zone) {
        None => Err(Error::name_outside_zone(name.clone(), zone.clone())),
        Some("") => Ok("@".to_owned()),
        Some(relative) => Ok(relative.to_owned()),
    }
}

/// A write addressed a zone or rrset that no longer exists: it changed after the read, and
/// nothing was written.
pub(super) fn vanished() -> Error {
    Error::Conflict {
        detail: Detail::constant(
            "the zone or the rrset was removed between the read and the write",
        ),
    }
}
