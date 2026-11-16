//! The rrset primitives both layers build on: read one rrset by name and type under the zone
//! cache, build the rrsets a change carries, and interpret the answer to a change. `txt.rs` (the
//! TXT value layer) and `records.rs` (the record layer) call these with the API's type name; the
//! rules for each answer live here once.
//!
//! - read: `resourceRecordSets.list` with the name (absolute, with the trailing dot) and the
//!   type, under the zone-ID cache. A missing rrset is an empty list; a `404` is the managed zone,
//!   which is then looked up again.
//! - write: one `changes.create`. A write over an existing rrset carries it, exactly as read, in
//!   `deletions` and the new rrset in `additions`; a write of a new rrset carries the addition
//!   only, which the API refuses when an rrset of that name and type exists (`alreadyExists`); a
//!   delete carries the deletion only.
//! - after a refused change: which status a failed deletion match (`preconditionFailed`)
//!   produces is not documented, so every refusal is followed by a new read: an rrset that
//!   differs from the one the change was conditional on (or a zone now known under another ID)
//!   is `Error::Conflict`, which both layers answer by running the operation once more; a delete
//!   whose rrset is gone now is a success; otherwise the refusal is the error.
//!
//! # Rrsets that are not plain records
//!
//! "A valid `ResourceRecordSet` contains only `rrdata` (for static resolution) or a
//! `routing_policy` (for dynamic resolution)"
//! (<https://www.googleapis.com/discovery/v1/apis/dns/v1/rest>, `ResourceRecordSet.routingPolicy`).
//! An rrset with a `routingPolicy` is not plain records: its `rrdatas` are not what is served. An
//! rrset with `signatureRrdatas` (RRSIG data, RFC 4034 section 3.2, same schema) carries
//! signatures that a rewritten rrset would no longer match. Neither is read or changed as an
//! rrset: the read fails with `Error::Rejected` before any write, and a listing reports it as
//! skipped. The second is an assumption, conservative: whether the API returns
//! `signatureRrdatas` for the rrsets of a zone it signs itself is not documented.

use serde_json::{Map, Value};

use crate::error::Error;
use crate::http::{Attempt, ZoneId};
use crate::name::DomainName;
use crate::redact::Detail;

use super::api::Written;
use super::client::GoogleCloud;

/// An rrset as read: the JSON object the API returned, kept whole so that a deletion repeats it
/// exactly, members this crate does not model included.
///
/// Two snapshots are equal when they are the same JSON: the API's deletion has to "match
/// existing data exactly", so an rrset whose values were merely reordered is a change too.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Snapshot(pub(super) Value);

/// The rrset is plain records: no `routingPolicy`, no `signatureRrdatas` (module
/// documentation).
pub(super) fn is_plain(set: &Value) -> bool {
    let routed = set.get("routingPolicy").is_some_and(|v| !v.is_null());
    let signed = set
        .get("signatureRrdatas")
        .and_then(Value::as_array)
        .is_some_and(|signatures| !signatures.is_empty());
    !routed && !signed
}

/// The refusal of a name and type held by an rrset that is not plain records. The client
/// decides it itself, so it carries no provider code.
pub(super) fn not_plain() -> Error {
    Error::Rejected {
        status: None,
        detail: Detail::constant(
            "the rrset has a routing policy or DNSSEC signatures; it is not read or changed as \
             an rrset",
        ),
        code: None,
    }
}

/// The owner name of an rrset: its `name`, a fully qualified domain name. `None` when it is
/// missing or not a valid name.
// Source: https://www.googleapis.com/discovery/v1/apis/dns/v1/rest (`ResourceRecordSet.name`:
// "For example, www.example.com."; `resourceRecordSets.list` `name`: "a fully qualified domain
// name").
pub(super) fn owner_of(set: &Value) -> Option<DomainName> {
    set.get("name")
        .and_then(Value::as_str)
        .and_then(|name| DomainName::parse(name).ok())
}

/// The rrset's type as the API spells it.
pub(super) fn type_of(set: &Value) -> Option<&str> {
    set.get("type").and_then(Value::as_str)
}

/// The TTL of an rrset, a number of seconds; `None` when absent or not a number in range.
// Source: Discovery document, `ResourceRecordSet.ttl` (an integer).
pub(super) fn ttl_of(set: &Value) -> Option<u32> {
    set.get("ttl")
        .and_then(Value::as_u64)
        .and_then(|ttl| u32::try_from(ttl).ok())
}

/// The `rrdatas` of a plain rrset as the API returned them. An rrset without the list, or with
/// an element that is not a string, is an answer the client cannot interpret.
pub(super) fn rrdatas_of(set: &Value) -> Result<Vec<&str>, Error> {
    let shape = || Error::Protocol {
        detail: Detail::constant("the provider's rrset is not in the expected form"),
    };
    set.get("rrdatas")
        .and_then(Value::as_array)
        .ok_or_else(shape)?
        .iter()
        .map(|element| element.as_str().ok_or_else(shape))
        .collect()
}

/// A new rrset: the absolute name with the trailing dot, the type, the TTL and the data.
// Source: Discovery document, `ResourceRecordSet` (`name`, `type`, `ttl`, `rrdatas`).
pub(super) fn new_rrset(name: &DomainName, rtype: &str, ttl: u32, rrdatas: Vec<Value>) -> Value {
    let mut set = Map::new();
    set.insert("name".into(), Value::String(name.as_str().to_owned()));
    set.insert("type".into(), Value::String(rtype.to_owned()));
    set.insert("ttl".into(), Value::from(ttl));
    set.insert("rrdatas".into(), Value::Array(rrdatas));
    Value::Object(set)
}

/// The rrset that replaces `prior`: every member of `prior` as read (name, type, TTL, `kind`
/// and any member the client does not know), with `rrdatas` replaced and, when `ttl` is given,
/// the TTL. Nothing the model does not carry is dropped.
pub(super) fn replaced(prior: &Snapshot, rrdatas: Vec<Value>, ttl: Option<u32>) -> Value {
    let mut set = match &prior.0 {
        Value::Object(map) => map.clone(),
        _ => Map::new(),
    };
    if let Some(ttl) = ttl {
        set.insert("ttl".into(), Value::from(ttl));
    }
    set.insert("rrdatas".into(), Value::Array(rrdatas));
    Value::Object(set)
}

impl GoogleCloud {
    /// The plain rrset of `name` and type `rtype` (the API's spelling), with the managed zone
    /// identifier the read ended with. An rrset that is not plain records is `Error::Rejected`.
    pub(super) async fn read_set(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
    ) -> Result<(String, Option<Value>), Error> {
        let (zone_id, set) = self.read_any(zone, name, rtype).await?;
        if set.as_ref().is_some_and(|set| !is_plain(set)) {
            return Err(not_plain());
        }
        Ok((zone_id, set))
    }

    /// The rrset of `name` and `rtype`, plain or not, with the managed zone identifier.
    async fn read_any(
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
                |id| self.read_set_in(name, rtype, id),
            )
            .await?;
        Ok((zone_id.id, set))
    }

    /// The read phase under the zone cache: the rrset in managed zone `id`, or `Stale` when the
    /// zone is not known under that identifier. The listing was asked for one name and type: an
    /// rrset of another name or type in the answer, or two rrsets, is an answer the client
    /// cannot interpret.
    async fn read_set_in(
        &self,
        name: &DomainName,
        rtype: &str,
        id: ZoneId,
    ) -> Result<Attempt<Option<Value>>, Error> {
        let Some(sets) = self
            .api
            .rrsets(&id.id, Some((name.as_str(), rtype)))
            .await?
        else {
            return Ok(Attempt::Stale);
        };
        let answers = |set: &Value| {
            owner_of(set).as_ref() == Some(name)
                && type_of(set).is_some_and(|stated| stated.eq_ignore_ascii_case(rtype))
        };
        if !sets.iter().all(answers) {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider answered with an rrset of another name or type",
                ),
            });
        }
        let mut sets = sets.into_iter();
        match (sets.next(), sets.next()) {
            (first, None) => Ok(Attempt::Done(first)),
            (_, Some(_)) => Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider answered with two rrsets of one name and type",
                ),
            }),
        }
    }

    /// After a change was answered: done, or the refusal interpreted against a new read of the
    /// rrset of `name` and `rtype`. `prior` is the rrset the change was conditional on (`None`:
    /// its absence); `delete` is true for a change that only deletes.
    #[allow(clippy::too_many_arguments)] // Reason: the operation's key plus the change's answer.
    pub(super) async fn settle(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        zone_id: &str,
        prior: Option<&Snapshot>,
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
        let (now_zone, now) = self.read_any(zone, name, rtype).await?;
        if delete && now.is_none() {
            // The rrset, and with it every value, is gone.
            return Ok(());
        }
        let current = now.map(Snapshot);
        if now_zone != zone_id || current.as_ref() != prior {
            return Err(Error::Conflict {
                detail: Detail::constant(
                    "the rrset changed between the read and the write, and the provider refused \
                     the change",
                ),
            });
        }
        Err(error)
    }
}
