//! TXT value operations: the `WholeSet` shape of the value layer over the strict record set
//! call.
//!
//! The record set is the native unit, addressed by name and type, and it is replaced through
//! `updateRecordSets`, whose deletions must match the record set at the provider exactly. Every
//! write therefore carries the old set as the client read it and the provider refuses the write
//! if the set changed in between: `ValueGuarantee::Conditional` (design sections 3.4 and 3.5).
//! The value layer takes the per-name lock, reads, computes the new member list and calls
//! [`WholeSet::write`] or [`WholeSet::delete`]; this file maps those onto the API:
//!
//! - read: `getRecordSet` with the name relative to the zone and type `TXT`, under the zone-ID
//!   cache. A `404` with a freshly resolved zone ID is "no record set"; with a cached ID the zone
//!   is first confirmed with `DnsZone.get`, since the same status answers a missing zone;
//! - write without a prior set: `additions` only, with the configured or requested TTL;
//! - write over a prior set: `deletions` with the JSON object read, unchanged (design section
//!   11.3), and `additions` with the same name, TTL and description and the new data;
//! - delete: `deletions` only. A record set cannot hold no data (documented `data` range 1 to
//!   100), so the last value is removed by deleting the set.
//!
//! Which status or operation error a failed condition produces is not documented. Every refusal
//! of a write is therefore followed by a new read: a set that differs from the one the write was
//! conditional on (or a zone that is now known under another ID) is `Error::Conflict`, which the
//! value layer answers by running the operation once more; a delete whose set is gone now is a
//! success; otherwise the refusal is the error. A write sent once and answered with an unknown
//! outcome (a 5xx, a timeout, an operation still running) is `Error::Transient`.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Raw`. Plain values, the only
//! ones the capabilities accept, are written unquoted, as the TXT-level version proven against
//! the live API did and as lego does (`Data: []string{value}`, yandexcloud.go:224-238).

use serde_json::{Map, Value};

use crate::error::Error;
use crate::http::{Attempt, ZoneId};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{Ttl, TxtDialect};
use crate::redact::Detail;
use crate::values::{Member, SetRead, SetState, TxtBase, TxtRecord, TxtSet, WholeSet, WriteTtl};

use super::api::{Found, Written};
use super::client::YandexCloud;

/// How TXT data is read.
const READ: TxtDialect = TxtDialect::Auto;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Raw;

/// The record type as the API spells it.
const TXT: &str = "TXT";

/// Most data elements of one record set.
// Source: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/updateRecordSets (`data[]`: "The
// number of elements must be in the range 1-100").
const MAX_DATA: usize = 100;

/// A record set as read: the JSON object the API returned, kept whole so that a deletion repeats
/// it exactly, fields this crate does not model included (design section 11.3).
///
/// Two snapshots are equal when they describe the same record set: the same members, whatever
/// their order, and the same other fields.
#[derive(Clone, Debug)]
pub(crate) struct RecordSet(Value);

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

impl TxtBase for YandexCloud {
    fn provider(&self) -> ProviderId {
        ProviderId::YandexCloud
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl WholeSet for YandexCloud {
    /// The data element as the API returned it.
    type Handle = String;
    type Snapshot = RecordSet;
    /// The zone identifier the read used.
    type Context = String;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> SetRead<String, RecordSet, String> {
        let (zone_id, set) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| self.read_txt(zone, name, id),
            )
            .await?;
        Ok(SetState {
            context: zone_id.id,
            set: set.map(txt_set).transpose()?,
        })
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        zone_id: &String,
        prior: Option<&RecordSet>,
        members: &[Member<'_, String>],
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let data = data(members)?;
        let (deletions, addition) = match prior {
            None => (Vec::new(), self.new_set(zone, name, data, ttl)?),
            Some(prior) => (vec![prior.0.clone()], replaced(prior, data)),
        };
        let written = self
            .api
            .update_record_sets(zone_id, &deletions, &[addition])
            .await?;
        self.settle(zone, name, zone_id, prior, written, false)
            .await
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        zone_id: &String,
        prior: &RecordSet,
    ) -> Result<(), Error> {
        let written = self
            .api
            .update_record_sets(zone_id, std::slice::from_ref(&prior.0), &[])
            .await?;
        self.settle(zone, name, zone_id, Some(prior), written, true)
            .await
    }
}

impl YandexCloud {
    /// The read phase under the zone cache: the TXT record set of `name` in the zone `id`, or
    /// `Stale` when the zone is not known under that identifier.
    async fn read_txt(
        &self,
        zone: &DomainName,
        name: &DomainName,
        id: ZoneId,
    ) -> Result<Attempt<Option<Value>>, Error> {
        match self
            .api
            .record_set(&id.id, relative(zone, name)?, TXT)
            .await?
        {
            Found::Set(set) => Ok(Attempt::Done(Some(set))),
            // Resolved during this call: the zone exists, so the record set does not.
            Found::NotFound if id.fresh => Ok(Attempt::Done(None)),
            // Cached: the same status answers a missing zone. Confirm the zone first.
            Found::NotFound => match self.api.zone(&id.id).await? {
                Some(found) if found.zone_name().as_ref() == Some(zone) => Ok(Attempt::Done(None)),
                _ => Ok(Attempt::Stale),
            },
        }
    }

    /// After a write was answered: done, or the refusal interpreted against a new read.
    async fn settle(
        &self,
        zone: &DomainName,
        name: &DomainName,
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
        let now = self.read(zone, name).await?;
        if delete && now.set.is_none() {
            // The record set, and with it the value, is gone.
            return Ok(());
        }
        let current = now.set.as_ref().map(|set| &set.snapshot);
        if now.context != zone_id || current != prior {
            return Err(Error::Conflict {
                detail: Detail::constant(
                    "the TXT record set changed between the read and the write, and the provider \
                     refused the write",
                ),
            });
        }
        Err(error)
    }

    /// A new record set: the name relative to the zone, the caller's or the configured TTL.
    /// The API carries the TTL as a string (an int64 in proto3 JSON).
    fn new_set(
        &self,
        zone: &DomainName,
        name: &DomainName,
        data: Vec<Value>,
        ttl: WriteTtl,
    ) -> Result<Value, Error> {
        let ttl = match ttl {
            WriteTtl::New(Some(ttl)) | WriteTtl::Existing(Some(ttl)) => ttl.as_secs(),
            WriteTtl::New(None) | WriteTtl::Existing(None) => self.ttl,
        };
        let mut set = Map::new();
        set.insert(
            "name".into(),
            Value::String(relative(zone, name)?.to_owned()),
        );
        set.insert("type".into(), Value::String(TXT.to_owned()));
        set.insert("ttl".into(), Value::String(ttl.to_string()));
        set.insert("data".into(), Value::Array(data));
        Ok(Value::Object(set))
    }
}

/// The name relative to the zone as the API takes it; `@` for the zone apex.
// Source: lego yandexcloud.go:136 and :211-214 (the sub-domain relative to the zone). The apex
// is `@` in the provider's console ("Matches zone name (@)",
// https://yandex.cloud/en/docs/dns/operations/resource-record-create). Assumption (not
// documented): the API reads `@` the same way. If it does not, a read at the apex finds nothing
// and a create is refused by the strict call when a set exists, so nothing is overwritten.
fn relative<'a>(zone: &DomainName, name: &'a DomainName) -> Result<&'a str, Error> {
    match name.relative_to(zone) {
        Some("") => Ok("@"),
        Some(relative) => Ok(relative),
        None => Err(Error::name_outside_zone(name.clone(), zone.clone())),
    }
}

/// The value layer's view of a record set. A set without its `data` list or with a data element
/// that is not a string is an answer the client cannot interpret.
fn txt_set(set: Value) -> Result<TxtSet<String, RecordSet>, Error> {
    let shape = || Error::Protocol {
        detail: Detail::constant("the provider's record set is not in the expected form"),
    };
    let ttl = ttl_of(&set).and_then(|secs| Ttl::from_secs(secs).ok());
    let data = set
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(shape)?;
    let mut records = Vec::with_capacity(data.len());
    for element in data {
        let text = element.as_str().ok_or_else(shape)?;
        records.push(TxtRecord {
            value: READ.read(text),
            ttl,
            handle: text.to_owned(),
        });
    }
    Ok(TxtSet {
        records,
        ttl,
        snapshot: RecordSet(set),
    })
}

/// The TTL of a record set: a string (proto3 JSON int64) or a number; absent is zero, the
/// default value proto3 JSON omits.
fn ttl_of(set: &Value) -> Option<u32> {
    match set.get("ttl") {
        None => Some(0),
        Some(Value::String(text)) => text.parse().ok(),
        Some(Value::Number(number)) => number.as_u64().and_then(|n| u32::try_from(n).ok()),
        Some(_) => None,
    }
}

/// The data to write: the elements kept, unchanged, then the value added.
fn data(members: &[Member<'_, String>]) -> Result<Vec<Value>, Error> {
    let mut data = Vec::with_capacity(members.len());
    for member in members {
        let text = match member {
            Member::Kept(record) => record.handle.clone(),
            Member::Added(value) => WRITE.write(value).ok_or(Error::InvalidInput {
                detail: Detail::constant("the TXT value cannot be written in this dialect"),
            })?,
        };
        data.push(Value::String(text));
    }
    if data.len() > MAX_DATA {
        return Err(Error::InvalidInput {
            detail: Detail::constant("a Yandex Cloud record set holds at most 100 values"),
        });
    }
    Ok(data)
}

/// The record set that replaces `prior`: its name, type, TTL and description as read, with
/// `data`. An existing record set keeps its TTL (design section 3.6).
// Source: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/updateRecordSets (`RecordSet`:
// `name`, `type`, `ttl`, `data[]`, `description`).
fn replaced(prior: &RecordSet, data: Vec<Value>) -> Value {
    let mut set = Map::new();
    for key in ["name", "type", "ttl", "description"] {
        if let Some(value) = prior.0.get(key) {
            set.insert(key.to_owned(), value.clone());
        }
    }
    set.insert("data".into(), Value::Array(data));
    Value::Object(set)
}
