//! The rrset primitives both layers build on: read one rrset by name and type, create it,
//! replace it, delete it. `txt.rs` (the TXT value layer) and `records.rs` (the record layer)
//! call these; the rules for each answer live here once.
//!
//! - read: `GET …/records/{name}/{type}`. A `404` answers a missing rrset; whether it also
//!   answers a missing domain is not documented, so the domain is then looked up, and a missing
//!   domain is `Error::ZoneNotFound`.
//! - create: `POST`, sent once. The reference documents the answer to a create of an rrset that
//!   exists: `409`, or `200` when its values are the same. Either means that another writer
//!   created the rrset after the read; nothing was overwritten, and the result is
//!   `Error::Conflict`, which the caller's repeat resolves with a fresh read.
//! - replace: `PUT`, sent once.
//! - delete: `DELETE`, sent once. A `404` is success only when a new read finds no rrset;
//!   otherwise the rrset was created again after the read and its values are published
//!   (`Error::Conflict`).
//!
//! A write answered `404` (other than the delete) addressed a domain or an rrset that is gone:
//! it changed after the read and nothing was written (`Error::Conflict`).
//!
//! The zone name is the key of every path, so there are no zone identifiers to cache and none
//! to go stale.

use crate::error::Error;
use crate::name::DomainName;
use crate::redact::Detail;

use super::api::{Created, Rrset, Written};
use super::client::Gandi;

impl Gandi {
    /// The rrset of `rr` (relative to the zone, `@` for the apex) and type `rtype` (the API's
    /// spelling).
    pub(super) async fn read_rrset(
        &self,
        zone: &DomainName,
        rr: &str,
        rtype: &str,
    ) -> Result<Option<Rrset>, Error> {
        if let Some(rrset) = self.api.rrset(zone, rr, rtype).await? {
            return Ok(Some(rrset));
        }
        match self.api.domain(zone).await? {
            Some(_) => Ok(None),
            None => Err(Error::zone_not_found(zone.clone())),
        }
    }

    /// Creates the rrset.
    pub(super) async fn create_rrset(
        &self,
        zone: &DomainName,
        rr: &str,
        rtype: &str,
        values: &[String],
        ttl: u32,
    ) -> Result<(), Error> {
        match self.api.create(zone, rr, rtype, values, ttl).await? {
            Created::Done => Ok(()),
            Created::Exists => Err(Error::Conflict {
                detail: Detail::constant(
                    "an rrset of this name and type was created between the read and the write",
                ),
            }),
            Created::NotFound => Err(vanished()),
            // "A status the documentation lists without a meaning has none": only `201` says
            // "created".
            Created::Undocumented => Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider answered the create with a status its documentation does not \
                     give; whether the rrset was created is not known",
                ),
            }),
            Created::Refused(e) => Err(e),
        }
    }

    /// Replaces the values and the TTL of the rrset.
    pub(super) async fn replace_rrset(
        &self,
        zone: &DomainName,
        rr: &str,
        rtype: &str,
        values: &[String],
        ttl: u32,
    ) -> Result<(), Error> {
        match self.api.replace(zone, rr, rtype, values, ttl).await? {
            Written::Done => Ok(()),
            Written::NotFound => Err(vanished()),
            Written::Refused(e) => Err(e),
        }
    }

    /// Deletes the rrset. A `404` is success only when a new read finds no rrset.
    pub(super) async fn delete_rrset(
        &self,
        zone: &DomainName,
        rr: &str,
        rtype: &str,
    ) -> Result<(), Error> {
        match self.api.delete(zone, rr, rtype).await? {
            Written::Done => Ok(()),
            Written::NotFound => match self.read_rrset(zone, rr, rtype).await? {
                None => Ok(()),
                Some(_) => Err(Error::Conflict {
                    detail: Detail::constant(
                        "the rrset was found again after its delete was answered \
                         \"not found\"; it changed between the read and the delete",
                    ),
                }),
            },
            Written::Refused(e) => Err(e),
        }
    }
}

/// The owner name relative to the zone, `@` for the apex.
// Source: the reference, `rrset_name` examples `"@"` and `"www"`; lego
// `dns01.ExtractSubDomain`; dns-update `strip_origin_from_name`.
pub(super) fn rr_name(zone: &DomainName, name: &DomainName) -> Result<String, Error> {
    match name.relative_to(zone) {
        None => Err(Error::name_outside_zone(name.clone(), zone.clone())),
        Some("") => Ok("@".to_owned()),
        Some(relative) => Ok(relative.to_owned()),
    }
}

/// A write addressed a zone or an rrset that no longer exists: it changed after the read, and
/// nothing was written.
pub(super) fn vanished() -> Error {
    Error::Conflict {
        detail: Detail::constant(
            "the zone or the rrset was removed between the read and the write",
        ),
    }
}
