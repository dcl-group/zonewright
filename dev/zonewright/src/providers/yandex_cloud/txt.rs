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
//! Which status or operation error a failed condition produces is not documented; a refusal is
//! interpreted against a new read (`rrset.rs`), and a changed set is `Error::Conflict`, which the
//! value layer answers by running the operation once more. A write sent once and answered with an
//! unknown outcome (a 5xx, a timeout, an operation still running) is `Error::Transient`.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Raw`. Plain values, the only
//! ones the capabilities accept, are written unquoted, as the TXT-level version proven against
//! the live API did and as lego does (`Data: []string{value}`, yandexcloud.go:224-238).

use serde_json::{Map, Value};

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{Ttl, TxtDialect};
use crate::redact::Detail;
use crate::values::{Member, SetRead, SetState, TxtBase, TxtRecord, TxtSet, WholeSet, WriteTtl};

use super::client::YandexCloud;
use super::rrset::{RecordSet, data_of, relative, ttl_of};

/// How TXT data is read.
const READ: TxtDialect = TxtDialect::Auto;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Raw;

/// The record type as the API spells it.
const TXT: &str = "TXT";

/// Most data elements of one record set.
// Source: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/updateRecordSets (`data[]`: "The
// number of elements must be in the range 1-100").
pub(super) const MAX_DATA: usize = 100;

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
        let (zone_id, set) = self.read_set(zone, name, TXT).await?;
        Ok(SetState {
            context: zone_id,
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
        self.settle(zone, name, TXT, zone_id, prior, written, false)
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
        self.settle(zone, name, TXT, zone_id, Some(prior), written, true)
            .await
    }
}

impl YandexCloud {
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

/// The value layer's view of a record set. A set without its `data` list or with a data element
/// that is not a string is an answer the client cannot interpret.
fn txt_set(set: Value) -> Result<TxtSet<String, RecordSet>, Error> {
    let ttl = ttl_of(&set).and_then(|secs| Ttl::from_secs(secs).ok());
    let records = data_of(&set)?
        .into_iter()
        .map(|text| TxtRecord {
            value: READ.read(text),
            ttl,
            handle: text.to_owned(),
        })
        .collect();
    Ok(TxtSet {
        records,
        ttl,
        snapshot: RecordSet(set),
    })
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
