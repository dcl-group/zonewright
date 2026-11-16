//! TXT value operations: the `PerRecord` shape of the value layer over the record API.
//!
//! Every TXT value is a record of its own with an identifier, so a request names only our
//! record and a foreign value cannot be part of it (`ValueGuarantee::PerValue`). The value
//! layer takes the per-name lock, reads and decides; this file maps its calls onto the API:
//!
//! - read: `GET …/record?fieldType=TXT&subDomain=`, then each record by identifier, an exact
//!   name and type match on the client's side (see `records.rs`);
//! - create: `POST …/record`, sent once, with `subDomain` (left out for the apex), the value and
//!   the TTL the value layer chose (the rrset's as read when the name has TXT records, else the
//!   caller's or the configured one);
//! - delete: `DELETE …/record/{id}`. An answer `404` counts as done only after a new read finds
//!   no record with the value.
//!
//! The change is published by the refresh the client sends at the end of the operation
//! (`client.rs`). TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Raw`, the rule
//! `records.rs` states once for both layers.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{RecordType, RrsetTtl, Txt};
use crate::redact::Detail;
use crate::values::{PerRecord, PerRecordRead, TxtBase, TxtRecord, WriteTtl};

use super::api::{NewRecord, TXT, Written};
use super::client::Ovh;
use super::records::{Handle, TXT_READ, TXT_WRITE, outside_zone, ttl_of};

impl TxtBase for Ovh {
    fn provider(&self) -> ProviderId {
        ProviderId::Ovh
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl PerRecord for Ovh {
    /// The record as read.
    type Handle = Handle;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> Result<PerRecordRead<Handle>, Error> {
        let records = self.records_at(zone, name, RecordType::TXT).await?;
        Ok(PerRecordRead::Records(
            records
                .iter()
                .map(|record| TxtRecord {
                    value: TXT_READ.read(&record.target),
                    ttl: ttl_of(record),
                    handle: Handle::of(record),
                })
                .collect(),
        ))
    }

    async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let target = TXT_WRITE.write(value).ok_or(Error::InvalidInput {
            detail: Detail::constant("the TXT value cannot be written in this dialect"),
            code: None,
        })?;
        let ttl = match ttl {
            WriteTtl::New(Some(RrsetTtl::Explicit(ttl)))
            | WriteTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => ttl.as_secs(),
            // Every record the client writes states its TTL (`provider_default_ttl` is
            // `Absent`): the configured TTL stands for a set without one.
            WriteTtl::New(None | Some(RrsetTtl::ProviderDefault))
            | WriteTtl::Existing(None | Some(RrsetTtl::ProviderDefault)) => self.ttl,
        };
        let relative = name
            .relative_to(zone)
            .ok_or_else(|| outside_zone(name, zone))?;
        let record = NewRecord {
            field_type: TXT,
            sub_domain: (!relative.is_empty()).then_some(relative),
            target: &target,
            ttl,
        };
        self.api.create_record(zone, &record).await
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        record: &TxtRecord<Handle>,
    ) -> Result<(), Error> {
        match self.api.delete_record(zone, record.handle.id).await? {
            Written::Done => Ok(()),
            Written::NotFound(_) => {
                // The record is gone, or the zone is and was created again. Only a new read
                // tells them apart.
                let PerRecordRead::Records(now) = PerRecord::read(self, zone, name).await? else {
                    return Ok(());
                };
                let still_there = now.iter().any(|r| r.value == record.value);
                if still_there && record.value.is_some() {
                    Err(Error::Conflict {
                        detail: Detail::constant(
                            "the value was found again after its delete was answered \
                             \"not found\"; the zone changed between the read and the delete",
                        ),
                    })
                } else {
                    Ok(())
                }
            }
        }
    }
}
