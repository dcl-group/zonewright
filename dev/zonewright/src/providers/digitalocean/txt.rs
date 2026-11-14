//! TXT value operations: the `PerRecord` shape of the value layer over the record API.
//!
//! Every TXT value is a record of its own with an identifier, so a request names only our
//! record and a foreign value cannot be part of it (`ValueGuarantee::PerValue`). The value
//! layer takes the per-name lock, reads and decides; this file maps its calls onto the API:
//!
//! - read: `GET …/records?type=TXT&name=…`, every page, an exact name match on the client's
//!   side, under no cached identifier: the domain's name is the key in every path;
//! - create: `POST …/records`, sent once, with the zone-file name, the value and the TTL the
//!   value layer chose (the rrset's as read when the name has TXT records, else the caller's or
//!   the configured one);
//! - delete: `DELETE …/records/{id}`. An answer "not found" says that the record, or the whole
//!   domain with it, is gone; a domain deleted and created again could hold the value under a
//!   new identifier, so it counts as done only after a new read finds no record with the value.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Raw`. lego sends the value
//! itself in `data`, unquoted (providers/dns/digitalocean/digitalocean.go line 129). Plain
//! values, the only ones the capabilities accept, need no escape.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{RrsetTtl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::values::{PerRecord, PerRecordRead, TxtBase, TxtRecord, WriteTtl};

use super::api::{Extra, NewRecord, TXT, Written, normalize_name};
use super::client::DigitalOcean;

/// How TXT data is read.
const READ: TxtDialect = TxtDialect::Auto;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Raw;

impl TxtBase for DigitalOcean {
    fn provider(&self) -> ProviderId {
        ProviderId::DigitalOcean
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl PerRecord for DigitalOcean {
    /// The record's identifier.
    type Handle = u64;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> Result<PerRecordRead<u64>, Error> {
        let records = self
            .api
            .records(zone, name, TXT)
            .await?
            .into_iter()
            .filter(|record| {
                record.rtype == TXT
                    && record
                        .name
                        .as_deref()
                        .and_then(|stated| normalize_name(stated, zone))
                        .as_ref()
                        == Some(name)
            })
            .map(|record| TxtRecord {
                value: record.data.as_deref().and_then(|data| READ.read(data)),
                ttl: record.ttl.and_then(|secs| RrsetTtl::from_secs(secs).ok()),
                handle: record.id,
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
            WriteTtl::New(Some(RrsetTtl::Explicit(ttl)))
            | WriteTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => Some(ttl.as_secs()),
            WriteTtl::New(None | Some(RrsetTtl::ProviderDefault)) => Some(self.ttl),
            // The set's TTL was not reported: send none, so that the provider decides.
            WriteTtl::Existing(None | Some(RrsetTtl::ProviderDefault)) => None,
        };
        let record = NewRecord {
            rtype: TXT,
            name: name.as_str(),
            data: &data,
            ttl,
            extra: Extra::default(),
        };
        match self.api.create_record(zone, &record).await? {
            Written::Done => Ok(()),
            // The domain does not exist (any more): nothing was written.
            Written::NotFound => Err(Error::zone_not_found(zone.clone())),
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        record: &TxtRecord<u64>,
    ) -> Result<(), Error> {
        match self.api.delete_record(zone, record.handle).await? {
            Written::Done => Ok(()),
            Written::NotFound => {
                // The record is gone, or the domain is and was created again. Only a new read
                // tells them apart.
                let PerRecordRead::Records(now) = self.read(zone, name).await? else {
                    return Ok(());
                };
                let still_there = now.iter().any(|r| r.value == record.value);
                if still_there && record.value.is_some() {
                    Err(Error::Conflict {
                        detail: Detail::constant(
                            "the value was found again after its delete was answered \
                             \"not found\"; the domain changed between the read and the delete",
                        ),
                    })
                } else {
                    Ok(())
                }
            }
        }
    }
}
