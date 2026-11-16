//! The rrset primitives both layers build on: read one rrset by name and type, create it,
//! replace its records and TTL, delete it. `txt.rs` (the TXT value layer) and `records.rs` (the
//! record layer) call these with the API's type name; the rules for each answer live here once.
//!
//! - read: `GET …/rrsets/{subname}/{type}/`. A `404` answers a missing rrset and a domain the
//!   account does not own alike, so the domain is then read: a missing one is
//!   `Error::ZoneNotFound`.
//! - create: `POST …/rrsets/`, sent once. The API answers a create of an rrset that exists with
//!   `400`, which it also answers for invalid content, so any refusal is followed by a new read:
//!   an rrset found there now was created by someone else after the operation's read, nothing of
//!   it was overwritten, and the result is `Error::Conflict` (design section 3.5); otherwise the
//!   refusal is the error, with the provider's message.
//! - change: `PATCH …/rrsets/{subname}/{type}/` with the whole record list and the TTL, sent
//!   once. A `404` means the rrset or the domain went away after the read: `Error::Conflict`,
//!   nothing written.
//! - delete: `DELETE …/rrsets/{subname}/{type}/`, sent once; `204` also for an rrset that is not
//!   there. A `404` can only be the domain; a new read then reports it.
//!
//! The zone name is the key of every path, so there are no zone identifiers to cache and none
//! to go stale.

use crate::error::Error;
use crate::name::DomainName;
use crate::redact::Detail;

use super::api::{Rrset, Written};
use super::client::Desec;

impl Desec {
    /// The rrset of `name` and `rtype` (the API's spelling), or `None`; a domain the account
    /// does not own is `Error::ZoneNotFound`.
    pub(super) async fn read_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
    ) -> Result<Option<Rrset>, Error> {
        if let Some(rrset) = self.api.rrset(zone, name, rtype).await? {
            return Ok(Some(rrset));
        }
        match self.api.zone(zone).await? {
            Some(_) => Ok(None),
            None => Err(Error::zone_not_found(zone.clone())),
        }
    }

    /// Creates the rrset. When the read after a refusal fails, its error is returned in place
    /// of the refusal: the state is then unknown, which is what the read's error says.
    pub(super) async fn create_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        records: &[String],
        ttl: u32,
    ) -> Result<(), Error> {
        let refusal = match self.api.create(zone, name, rtype, ttl, records).await? {
            Written::Done => return Ok(()),
            Written::NotFound => return Err(vanished()),
            Written::Refused(e) => e,
        };
        match self.read_rrset(zone, name, rtype).await? {
            Some(_) => Err(Error::Conflict {
                detail: Detail::constant(
                    "an rrset of this name and type was created between the read and the write",
                ),
            }),
            None => Err(refusal),
        }
    }

    /// Replaces the records and the TTL of the rrset.
    pub(super) async fn replace_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        records: &[String],
        ttl: u32,
    ) -> Result<(), Error> {
        match self.api.change(zone, name, rtype, ttl, records).await? {
            Written::Done => Ok(()),
            Written::NotFound => Err(vanished()),
            Written::Refused(e) => Err(e),
        }
    }

    /// Deletes the rrset. A `404` is followed by a new read, which reports a domain that went
    /// away; should the rrset be found there after all, its values are still published
    /// (`Error::Conflict`).
    pub(super) async fn delete_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
    ) -> Result<(), Error> {
        match self.api.delete(zone, name, rtype).await? {
            Written::Done => Ok(()),
            Written::NotFound => match self.read_rrset(zone, name, rtype).await? {
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

/// A write addressed a domain or an rrset that no longer exists: it changed after the read, and
/// nothing was written.
fn vanished() -> Error {
    Error::Conflict {
        detail: Detail::constant(
            "the zone or the rrset was removed between the read and the write",
        ),
    }
}
