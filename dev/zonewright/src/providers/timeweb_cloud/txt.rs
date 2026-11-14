//! TXT value operations: the `PerRecord` shape of the value layer over the record API.
//!
//! Every TXT value is a record of its own with an identifier, so a request names only our
//! record and a foreign value cannot be part of it (`ValueGuarantee::PerValue`). The value
//! layer takes the per-name lock, reads and decides; this file maps its calls onto the API:
//!
//! - read: `GET …/dns-records`, every page, the whole zone (the API has no filter), then the
//!   records of type TXT at exactly the requested name, selected on the client's side;
//! - create: `POST …/dns-records`, sent once, with the full name in `subdomain`, the value and
//!   the TTL the value layer chose (the rrset's as read when the name has TXT records, else the
//!   caller's, else the configured one, else none, so that the provider decides). The answer's
//!   identifier is remembered in the `Context`;
//! - delete: `DELETE …/dns-records/{id}`. An answer "not found" says that the record, or the
//!   whole domain with it, is gone; a domain deleted and created again could hold the value
//!   under a new identifier, so it counts as done only after a new read finds no record with the
//!   value.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Raw`. lego sent the value
//! itself in `value`, unquoted (providers/dns/timewebcloud/timewebcloud.go line 115 at commit
//! `c40c0a2a45`, the last one on the v1 endpoints). Plain values, the only ones the
//! capabilities accept, need no escape.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{Ttl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::values::{PerRecord, PerRecordRead, TxtBase, TxtRecord, WriteTtl};

use super::api::{Created, Deleted, NewRecord, Record, TXT, stated_names};
use super::client::TimewebCloud;

/// How TXT data is read.
const READ: TxtDialect = TxtDialect::Auto;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Raw;

impl TxtBase for TimewebCloud {
    fn provider(&self) -> ProviderId {
        ProviderId::TimewebCloud
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl PerRecord for TimewebCloud {
    /// The record's identifier; the listing's schema allows a record without one, which can be
    /// read but not deleted.
    type Handle = Option<u64>;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> Result<PerRecordRead<Option<u64>>, Error> {
        let records = self
            .api
            .records(zone)
            .await?
            .into_iter()
            .filter(|record| is_txt_at(record, zone, name))
            .map(|record| TxtRecord {
                value: record.value().and_then(|text| READ.read(text)),
                ttl: record.ttl().and_then(|secs| Ttl::from_secs(secs).ok()),
                handle: record.id(),
            })
            .collect();
        Ok(PerRecordRead::Records(records))
    }

    async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let data = WRITE.write(value).ok_or(Error::InvalidInput {
            detail: Detail::constant("the TXT value cannot be written in this dialect"),
        })?;
        let ttl = match ttl {
            WriteTtl::New(Some(ttl)) | WriteTtl::Existing(Some(ttl)) => Some(ttl.as_secs()),
            WriteTtl::New(None) => self.ttl,
            // The set's TTL was not reported: send none, so that the provider decides.
            WriteTtl::Existing(None) => None,
        };
        let record = NewRecord {
            rtype: TXT,
            value: &data,
            subdomain: name.without_dot(),
            ttl,
        };
        match self.api.create_record(zone, &record).await? {
            Created::Done(id) => {
                if let Some(id) = id {
                    self.ctx.timeweb_cloud().remember(
                        self.api.endpoint_key(),
                        zone,
                        name,
                        value.as_bytes(),
                        id,
                    );
                }
                Ok(())
            }
            // The domain does not exist (any more): nothing was written.
            Created::NotFound => Err(Error::zone_not_found(zone.clone())),
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        record: &TxtRecord<Option<u64>>,
    ) -> Result<(), Error> {
        let Some(id) = record.handle else {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider lists the record without an identifier, so it cannot be deleted",
                ),
            });
        };
        if let Deleted::NotFound = self.api.delete_record(zone, id).await? {
            // The record is gone, or the domain is and was created again. Only a new read tells
            // them apart.
            let PerRecordRead::Records(now) = self.read(zone, name).await? else {
                return Ok(());
            };
            let still_there = record.value.is_some() && now.iter().any(|r| r.value == record.value);
            if still_there {
                return Err(Error::Conflict {
                    detail: Detail::constant(
                        "the value was found again after its delete was answered \
                         \"not found\"; the domain changed between the read and the delete",
                    ),
                });
            }
        }
        self.ctx
            .timeweb_cloud()
            .forget(self.api.endpoint_key(), zone, id);
        Ok(())
    }
}

/// Whether a listed record is a TXT record at exactly `name`.
pub(super) fn is_txt_at(record: &Record, zone: &DomainName, name: &DomainName) -> bool {
    record.rtype == TXT && stated_names(record.subdomain(), zone).contains(name)
}

/// Whether a listed record is a TXT record at exactly `name` that holds `value`.
pub(super) fn holds(record: &Record, zone: &DomainName, name: &DomainName, value: &Txt) -> bool {
    is_txt_at(record, zone, name)
        && record.value().and_then(|text| READ.read(text)).as_ref() == Some(value)
}
