//! TXT value operations: the `PerRecord` shape of the value layer over the record API.
//!
//! Every TXT value is a record of its own with an identifier, so a request names only our
//! record and a foreign value cannot be part of it (`ValueGuarantee::PerValue`). The value
//! layer takes the per-name lock, reads and decides; this file maps its calls onto the API:
//!
//! - read: `GET …/records?type=TXT`, every page, an exact name and type match on the client's
//!   side (see `records.rs` for why the `name` filter is not used). A TXT record at the name that
//!   is limited to some regions makes the read fail, as the record layer's does: the name does
//!   not have one set of values;
//! - create: `POST …/records`, sent once, with the name relative to the zone, the value and the
//!   TTL the value layer chose (the rrset's as read when the name has TXT records, else the
//!   caller's or the configured one);
//! - delete: `DELETE …/records/{id}`. An answer "not found" says that the record, or the whole
//!   zone with it, is gone; a zone deleted and created again could hold the value under a new
//!   identifier, so it counts as done only after a new read finds no record with the value. A
//!   system record (`system_record`, "not modifiable") is never deleted.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Raw`, the rule `records.rs`
//! states once for both layers.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{RecordType, RrsetTtl, Txt};
use crate::redact::Detail;
use crate::values::{PerRecord, PerRecordRead, TxtBase, TxtRecord, WriteTtl};

use super::api::{NewRecord, TXT, Written, relative_name};
use super::client::Dnsimple;
use super::records::{Handle, TXT_READ, TXT_WRITE, not_plain, outside_zone, system_record};

impl TxtBase for Dnsimple {
    fn provider(&self) -> ProviderId {
        ProviderId::Dnsimple
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl PerRecord for Dnsimple {
    /// The record's identifier and whether it is a system record.
    type Handle = Handle;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> Result<PerRecordRead<Handle>, Error> {
        let records = self.records_at(zone, name, RecordType::TXT).await?;
        if records.iter().any(|record| !record.is_global()) {
            return Err(not_plain());
        }
        Ok(PerRecordRead::Records(
            records
                .into_iter()
                .map(|record| TxtRecord {
                    value: TXT_READ.read(&record.content),
                    ttl: RrsetTtl::from_secs(record.ttl).ok(),
                    handle: Handle::of(&record),
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
        let content = TXT_WRITE.write(value).ok_or(Error::InvalidInput {
            detail: Detail::constant("the TXT value cannot be written in this dialect"),
            code: None,
        })?;
        let ttl = match ttl {
            WriteTtl::New(Some(RrsetTtl::Explicit(ttl)))
            | WriteTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => ttl.as_secs(),
            // Every record states its TTL (`provider_default_ttl` is `Absent`): the configured
            // TTL stands for a set without one.
            WriteTtl::New(None | Some(RrsetTtl::ProviderDefault))
            | WriteTtl::Existing(None | Some(RrsetTtl::ProviderDefault)) => self.ttl,
        };
        let record = NewRecord {
            name: relative_name(name, zone).ok_or_else(|| outside_zone(name, zone))?,
            rtype: TXT,
            content: &content,
            ttl,
            priority: None,
        };
        match self.api.create_record(zone, &record).await? {
            Written::Done => Ok(()),
            // The zone does not exist (any more): nothing was written.
            Written::NotFound => Err(Error::zone_not_found(zone.clone())),
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        record: &TxtRecord<Handle>,
    ) -> Result<(), Error> {
        if record.handle.system {
            return Err(system_record());
        }
        match self.api.delete_record(zone, record.handle.id).await? {
            Written::Done => Ok(()),
            Written::NotFound => {
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
