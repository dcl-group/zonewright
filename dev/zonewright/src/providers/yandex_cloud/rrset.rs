//! The record set primitives both layers build on: read one record set by name and type under
//! the zone cache, and interpret the answer to a strict write. `txt.rs` (the TXT value layer) and
//! `records.rs` (the record layer) call these with the API's type name; the rules for each answer
//! live here once.
//!
//! - read: `getRecordSet` with the name relative to the zone and the type, under the zone-ID
//!   cache. A `404` with a freshly resolved zone ID is "no record set"; with a cached ID the zone
//!   is first confirmed with `DnsZone.get`, since the same status answers a missing zone.
//! - after a write: which status or operation error a failed condition of the strict call
//!   produces is not documented. Every refusal is therefore followed by a new read: a set that
//!   differs from the one the write was conditional on (or a zone that is now known under
//!   another ID) is `Error::Conflict`, which both layers answer by running the operation once
//!   more; a delete whose set is gone now is a success; otherwise the refusal is the error.

use serde_json::Value;

use crate::error::Error;
use crate::http::{Attempt, ZoneId};
use crate::name::DomainName;
use crate::redact::Detail;

use super::api::{Found, Written};
use super::client::YandexCloud;

/// A record set as read: the JSON object the API returned, kept whole so that a deletion repeats
/// it exactly, fields this crate does not model included (design section 11.3).
///
/// Two snapshots are equal when they describe the same record set: the same members, whatever
/// their order, and the same other fields.
#[derive(Clone, Debug)]
pub(crate) struct RecordSet(pub(super) Value);

impl PartialEq for RecordSet {
    fn eq(&self, other: &RecordSet) -> bool {
        normalized(&self.0) == normalized(&other.0)
    }
}

/// `set` with its `data` sorted, for comparison.
fn normalized(set: &Value) -> Value {
    let mut set = set.clone();
    if let Some(Value::Array(data)) = set.get_mut("data") {
        data.sort_by_key(Value::to_string);
    }
    set
}

/// The record set `getRecordSet` returned is the one asked for: its `name` denotes `name` and its
/// `type` is `rtype`. A name without the trailing dot that ends with the zone's name could be
/// spelled either way and is accepted when either reading gives `name`.
// Source: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/getRecordSet (the answer is a
// `RecordSet` with `name` and `type`).
fn answers(zone: &DomainName, name: &DomainName, rtype: &str, set: &Value) -> bool {
    let Some(text) = set.get("name").and_then(Value::as_str) else {
        return false;
    };
    let same_type = set
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|stated| stated.eq_ignore_ascii_case(rtype));
    let same_name = match super::records::owner_name(zone, text) {
        Some(owner) => owner == *name,
        None => {
            !text.ends_with('.')
                && (DomainName::parse(text).ok().as_ref() == Some(name)
                    || DomainName::from_relative(text, zone).ok().as_ref() == Some(name))
        }
    };
    same_type && same_name
}

impl YandexCloud {
    /// The record set of `name` and type `rtype` (the API's spelling), with the zone identifier
    /// the read ended with.
    pub(super) async fn read_set(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
    ) -> Result<(String, Option<Value>), Error> {
        let (zone_id, set) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| self.read_set_in(zone, name, rtype, id),
            )
            .await?;
        Ok((zone_id.id, set))
    }

    /// The read phase under the zone cache: the record set in the zone `id`, or `Stale` when the
    /// zone is not known under that identifier.
    async fn read_set_in(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        id: ZoneId,
    ) -> Result<Attempt<Option<Value>>, Error> {
        match self
            .api
            .record_set(&id.id, relative(zone, name)?, rtype)
            .await?
        {
            Found::Set(set) if answers(zone, name, rtype, &set) => Ok(Attempt::Done(Some(set))),
            Found::Set(_) => Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider answered with a record set of another name or type",
                ),
            }),
            // Resolved during this call: the zone exists, so the record set does not.
            Found::NotFound if id.fresh => Ok(Attempt::Done(None)),
            // Cached: the same status answers a missing zone. Confirm the zone first.
            Found::NotFound => match self.api.zone(&id.id).await? {
                Some(found) if found.zone_name().as_ref() == Some(zone) => Ok(Attempt::Done(None)),
                _ => Ok(Attempt::Stale),
            },
        }
    }

    /// After a write was answered: done, or the refusal interpreted against a new read of the
    /// record set of `name` and `rtype`. `prior` is the set the write was conditional on
    /// (`None`: its absence); `delete` is true for a write that only deletes.
    #[allow(clippy::too_many_arguments)] // Reason: the operation's key plus the write's answer.
    pub(super) async fn settle(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        zone_id: &str,
        prior: Option<&RecordSet>,
        written: Written,
        delete: bool,
    ) -> Result<(), Error> {
        let (error, not_found) = match written {
            Written::Done => return Ok(()),
            Written::Refused { error, not_found } => (error, not_found),
        };
        if not_found {
            // The zone identifier may have gone stale; the new read resolves it afresh.
            self.forget_zone(zone);
        }
        let (now_zone, now) = self.read_set(zone, name, rtype).await?;
        if delete && now.is_none() {
            // The record set, and with it every value, is gone.
            return Ok(());
        }
        let current = now.map(RecordSet);
        if now_zone != zone_id || current.as_ref() != prior {
            return Err(Error::Conflict {
                detail: Detail::constant(
                    "the record set changed between the read and the write, and the provider \
                     refused the write",
                ),
            });
        }
        Err(error)
    }
}

/// The name relative to the zone as the API takes it; `@` for the zone apex.
// Source: lego yandexcloud.go:136 and :211-214 (the sub-domain relative to the zone). The apex
// is `@` in the provider's console ("Matches zone name (@)",
// https://yandex.cloud/en/docs/dns/operations/resource-record-create). Assumption (not
// documented): the API reads `@` the same way. If it does not, a read at the apex finds nothing
// and a create is refused by the strict call when a set exists, so nothing is overwritten.
pub(super) fn relative<'a>(zone: &DomainName, name: &'a DomainName) -> Result<&'a str, Error> {
    match name.relative_to(zone) {
        Some("") => Ok("@"),
        Some(relative) => Ok(relative),
        None => Err(Error::name_outside_zone(name.clone(), zone.clone())),
    }
}

/// The TTL of a record set: a string (proto3 JSON int64) or a number; absent is zero, the
/// default value proto3 JSON omits.
pub(super) fn ttl_of(set: &Value) -> Option<u32> {
    match set.get("ttl") {
        None => Some(0),
        Some(Value::String(text)) => text.parse().ok(),
        Some(Value::Number(number)) => number.as_u64().and_then(|n| u32::try_from(n).ok()),
        Some(_) => None,
    }
}

/// The data elements of a record set as the API returned them. A set without its `data` list or
/// with an element that is not a string is an answer the client cannot interpret.
pub(super) fn data_of(set: &Value) -> Result<Vec<&str>, Error> {
    let shape = || Error::Protocol {
        detail: Detail::constant("the provider's record set is not in the expected form"),
    };
    set.get("data")
        .and_then(Value::as_array)
        .ok_or_else(shape)?
        .iter()
        .map(|element| element.as_str().ok_or_else(shape))
        .collect()
}
