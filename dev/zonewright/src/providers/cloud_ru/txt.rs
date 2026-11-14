//! TXT value operations: the `WholeSet` shape of the value layer over the record API.
//!
//! The service keeps one record per name and type, holding every value of that name and type
//! (the provider's limitations page), and replaces the values whole by `PATCH`, without a
//! condition the provider checks. Hence `ValueGuarantee::ReadThenWrite`, with the extra read the
//! design assigns to this provider ([`WholeSet::reread_before_write`], design section 3.5): the
//! value layer reads, computes the new value list, reads again and refuses with
//! `Error::Conflict` if the record changed, and only then calls [`WholeSet::write`] or
//! [`WholeSet::delete`]. This file maps those onto the record primitives of `rrset.rs`:
//!
//! - read: the TXT record whose owner name is exactly the requested one;
//! - write without a prior record: a create in the zone the read used, with the configured or
//!   requested TTL;
//! - write over a prior record: an update with the full value list, and the TTL, description,
//!   tags and GSLB data as read;
//! - delete: for the last value. Whether a record can be written with no values is not
//!   documented, so the last value is removed by deleting the record.
//!
//! Wildcard owner names are refused (`Error::InvalidInput`) before any request: TXT values at a
//! wildcard name are not offered by the value operations.
//!
//! A TXT record with GSLB links answers from its links, not from its values: it is not an rrset
//! (design section 3.4, `records.rs`) and is never modified. An add or a remove at its name
//! fails with `Error::Rejected` after the read, before any write, whatever the values hold.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Raw`. Plain values, the only
//! ones the capabilities accept, are spelled the same in either.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{Ttl, TxtDialect};
use crate::redact::Detail;
use crate::values::{Member, SetRead, SetState, TxtBase, TxtRecord, TxtSet, WholeSet, WriteTtl};

use super::api::{Record, TXT};
use super::client::CloudRu;

/// How TXT values are read.
const READ: TxtDialect = TxtDialect::Auto;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Raw;

impl TxtBase for CloudRu {
    fn provider(&self) -> ProviderId {
        ProviderId::CloudRu
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl WholeSet for CloudRu {
    /// A value as the API spells it, written back unchanged.
    type Handle = String;
    type Snapshot = Record;
    /// The zone identifier the read used.
    type Context = String;

    async fn read(&self, zone: &DomainName, name: &DomainName) -> SetRead<String, Record, String> {
        if name.is_wildcard() {
            return Err(Error::InvalidInput {
                detail: Detail::constant(
                    "wildcard names are not supported by the TXT value operations of this \
                     provider",
                ),
            });
        }
        let (zone_id, record) = self.read_record(zone, name, TXT).await?;
        if record.as_ref().is_some_and(Record::is_gslb) {
            return Err(super::records::not_plain());
        }
        Ok(SetState {
            context: zone_id,
            set: record.map(txt_set),
        })
    }

    fn reread_before_write(&self) -> bool {
        true
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        zone_id: &String,
        prior: Option<&Record>,
        members: &[Member<'_, String>],
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let values = values(members)?;
        match prior {
            None => {
                let ttl = u64::from(self.new_ttl(ttl));
                self.create_record(zone, name, TXT, zone_id, &values, ttl)
                    .await
            }
            // An existing record keeps its TTL (design section 3.6).
            Some(prior) => self.update_record(zone, prior, &values, prior.ttl).await,
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        _zone_id: &String,
        prior: &Record,
    ) -> Result<(), Error> {
        self.delete_record(zone, name, TXT, prior).await
    }
}

impl CloudRu {
    /// The TTL of a new record: the caller's, else the configured one.
    fn new_ttl(&self, ttl: WriteTtl) -> u32 {
        match ttl {
            WriteTtl::New(Some(ttl)) | WriteTtl::Existing(Some(ttl)) => ttl.as_secs(),
            WriteTtl::New(None) | WriteTtl::Existing(None) => self.ttl,
        }
    }
}

/// The value layer's view of a record.
fn txt_set(record: Record) -> TxtSet<String, Record> {
    let ttl = u32::try_from(record.ttl)
        .ok()
        .and_then(|secs| Ttl::from_secs(secs).ok());
    let records = record
        .values
        .iter()
        .map(|value| TxtRecord {
            value: READ.read(value),
            ttl,
            handle: value.clone(),
        })
        .collect();
    TxtSet {
        records,
        ttl,
        snapshot: record,
    }
}

/// The values to write: those kept, unchanged, then the value added.
fn values(members: &[Member<'_, String>]) -> Result<Vec<String>, Error> {
    members
        .iter()
        .map(|member| match member {
            Member::Kept(record) => Ok(record.handle.clone()),
            Member::Added(value) => WRITE.write(value).ok_or(Error::InvalidInput {
                detail: Detail::constant("the TXT value cannot be written in this dialect"),
            }),
        })
        .collect()
}
