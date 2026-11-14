//! TXT value operations: the `PerRecord` shape of the value layer over the record API.
//!
//! Every TXT value is a record of its own with an identifier, so a request names only our
//! record and a foreign value cannot be part of it (`ValueGuarantee::PerValue`). The value
//! layer takes the per-name lock, reads and decides; this file maps its calls onto the API. All
//! three calls are addressed to the owner name itself (the zone, or the full name below it):
//!
//! - read: `GET /v1/domains/{name}/dns-records`, every page, then the records of type TXT at
//!   exactly the requested name, selected on the client's side. The listing of a subdomain
//!   holds all its records, so every record at the name is seen and no identifier needs to be
//!   remembered between operations. A listing of a name below the zone that states a record
//!   without a name is refused (`Error::Protocol`), since such a record could be at the name or
//!   at the zone itself;
//! - create: `POST /v2/domains/{name}/dns-records`, sent once, with the value and the TTL the
//!   value layer chose (the rrset's as read when the name has TXT records, else the caller's,
//!   else the configured one, else none, so that the provider decides). No subdomain is created
//!   first, as lego does not create one (see the API module); if the provider insists, the
//!   create is refused and nothing is written;
//! - delete: `DELETE /v2/domains/{name}/dns-records/{id}`. An answer "not found" says that the
//!   record, or the whole domain with it, is gone; a domain deleted and created again could hold
//!   the value under a new identifier, so it counts as done only after a new read finds no record
//!   with the value.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Raw`. The create's `value` is
//! described as the record's text, and lego sends the value itself, unquoted
//! (providers/dns/timewebcloud/timewebcloud.go line 115 at commit `012a2c1e01`). Plain values,
//! the only ones the capabilities accept, need no escape.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{Ttl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::values::{PerRecord, PerRecordRead, TxtBase, TxtRecord, WriteTtl};

use super::api::{Created, Deleted, NewRecord, Record, TXT, check_named, stated_names};
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
        let listed = self.api.records(zone, name).await?;
        check_named(&listed, name == zone)?;
        let records = listed
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
            priority: None,
            ttl,
        };
        match self.api.create_record(name, &record).await? {
            Created::Done => Ok(()),
            // Nothing was written. Either the domain does not exist (any more), or the provider
            // does not take the name as a subdomain of it; only a lookup tells them apart.
            Created::NotFound(refusal) => Err(if self.api.zone_exists(zone).await? {
                refusal
            } else {
                Error::zone_not_found(zone.clone())
            }),
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
        if let Deleted::NotFound = self.api.delete_record(name, id).await? {
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
        Ok(())
    }
}

/// Whether a listed record is a TXT record at exactly `name`.
fn is_txt_at(record: &Record, zone: &DomainName, name: &DomainName) -> bool {
    record.rtype == TXT && stated_names(record.subdomain(), zone).contains(name)
}
