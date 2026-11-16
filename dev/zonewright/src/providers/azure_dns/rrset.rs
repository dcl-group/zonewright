//! The record set primitives both layers build on: read one record set by name and type, write
//! it whole under a condition, delete it under a condition. `txt.rs` (the TXT value layer) and
//! `records.rs` (the record layer) call these; the rules for each answer live here once.
//!
//! - read: `GET …/{type}/{name}`. A `404` answers a missing record set, and may answer a
//!   missing zone, so the zone is then read: a missing one is `Error::ZoneNotFound`.
//! - write: `PUT …/{type}/{name}` with the whole record set, sent once, with `If-None-Match: *`
//!   when the read found none and `If-Match: <etag>` when it found one. The status of a refused
//!   condition is not documented (the reference names only `CloudError` for every status other
//!   than `200` and `201`). So any refusal is followed by a new read: a record set that appeared,
//!   vanished or has another etag now means the condition failed, and the result is
//!   `Error::Conflict` (nothing was written; the layers run the operation once more from the
//!   read); otherwise the refusal is the error, with the provider's message and code.
//! - delete: `DELETE …/{type}/{name}` with `If-Match: <etag>`, sent once. `200` is done. `204`
//!   ("The record set was not found") and any refusal are followed by a new read: no record set
//!   there now is done; one with another etag is `Error::Conflict`; the same one again is the
//!   refusal's error (for `204`, a `Conflict`: the set is still published).
//!
//! The zone name, the subscription and the resource group are the keys of every path, so there
//! are no zone identifiers to cache and none to go stale.

use serde_json::Value;

use crate::error::Error;
use crate::name::DomainName;
use crate::redact::Detail;

use super::api::{Condition, RecordSet, Written};
use super::client::AzureDns;

impl AzureDns {
    /// The record set of `name` and `type_name` (the API's spelling), or `None`; a zone the
    /// resource group does not hold is `Error::ZoneNotFound`.
    pub(super) async fn read_record_set(
        &self,
        zone: &DomainName,
        name: &DomainName,
        type_name: &str,
    ) -> Result<Option<RecordSet>, Error> {
        if let Some(set) = self.api.record_set(zone, name, type_name).await? {
            return Ok(Some(set));
        }
        if self.api.zone_exists(zone).await? {
            Ok(None)
        } else {
            Err(Error::zone_not_found(zone.clone()))
        }
    }

    /// Writes the record set with `records` (the record objects of its type). `prior` is the
    /// record set as read (`None`: there was none); `ttl` `None` keeps the TTL `prior` has.
    pub(super) async fn write_record_set(
        &self,
        zone: &DomainName,
        name: &DomainName,
        type_name: &str,
        prior: Option<&RecordSet>,
        records: Vec<Value>,
        ttl: Option<u32>,
    ) -> Result<(), Error> {
        if let Some(e) = prior.and_then(RecordSet::unwritable) {
            return Err(e);
        }
        let condition = match prior {
            None => Condition::Absent,
            Some(prior) => Condition::Etag(etag_of(prior)?),
        };
        let body = RecordSet::body(prior, type_name, records, ttl, self.ttl)?;
        let refusal = match self
            .api
            .put(zone, name, type_name, &body, &condition)
            .await?
        {
            Written::Done | Written::NotFound => return Ok(()),
            Written::Refused(e) => e,
        };
        let now = self.read_record_set(zone, name, type_name).await?;
        match (prior, now) {
            (None, None) => Err(refusal),
            (None, Some(_)) => Err(conflict(
                "a record set of this name and type was created between the read and the write",
            )),
            (Some(_), None) => Err(conflict(
                "the record set was removed between the read and the write",
            )),
            (Some(prior), Some(now)) if now.etag != prior.etag => Err(conflict(
                "the record set changed between the read and the write",
            )),
            (Some(_), Some(_)) => Err(refusal),
        }
    }

    /// Deletes the record set if it is still `prior`.
    pub(super) async fn delete_record_set(
        &self,
        zone: &DomainName,
        name: &DomainName,
        type_name: &str,
        prior: &RecordSet,
    ) -> Result<(), Error> {
        let etag = etag_of(prior)?;
        let refusal = match self.api.delete(zone, name, type_name, etag).await? {
            Written::Done => return Ok(()),
            Written::NotFound => None,
            Written::Refused(e) => Some(e),
        };
        match self.read_record_set(zone, name, type_name).await? {
            None => Ok(()),
            Some(now) if now.etag != prior.etag => Err(conflict(
                "the record set changed between the read and the delete",
            )),
            Some(_) => Err(refusal.unwrap_or_else(|| {
                conflict(
                    "the record set was found again after its delete was answered \"not \
                     found\"",
                )
            })),
        }
    }
}

/// The etag of a record set as read; a conditional write is impossible without one.
fn etag_of(set: &RecordSet) -> Result<&str, Error> {
    set.etag
        .as_deref()
        .filter(|etag| !etag.is_empty())
        .ok_or(Error::Protocol {
            detail: Detail::constant(
                "the provider returned a record set without an etag; it is not written without \
                 the condition",
            ),
        })
}

fn conflict(text: &'static str) -> Error {
    Error::Conflict {
        detail: Detail::constant(text),
    }
}
