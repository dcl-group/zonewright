//! TXT value operations: the `PerRecord` shape of the value layer over the record API.
//!
//! Every TXT value is a record of its own with an identifier, so a request names only our
//! record and a foreign value cannot be part of it (`ValueGuarantee::PerValue`). The value
//! layer takes the per-name lock, reads and decides; this file maps its calls onto the API:
//!
//! - read: `GET /dns/retrieve/{domain}`, an exact name and type match on the client's side;
//! - create: `POST /dns/create/{domain}`, sent once, with the name relative to the domain, the
//!   value and the TTL the value layer chose (the rrset's as read when the name has TXT records,
//!   else the caller's or the configured one). A refusal `DUPLICATE_RECORD` is confirmed by a new
//!   read: when the value is there now, another writer created it after the read, and the result
//!   is `Error::Conflict`, which a repeat turns into `AlreadyPresent`;
//! - delete: `POST /dns/delete/{domain}/{id}`. An answer `INVALID_RECORD_ID` says that the record
//!   is gone, or that the domain is and was created again; it counts as done only after a new
//!   read finds no record with the value.
//!
//! `deleteByNameType` would delete every TXT value at the name, foreign ones included, and is
//! never used.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Raw`, the rule `records.rs`
//! follows too. lego sends the value itself in `content` (providers/dns/porkbun/porkbun.go line
//! 129). Plain values, the only ones the capabilities accept, need no escape.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{RecordType, Txt};
use crate::redact::Detail;
use crate::values::{PerRecord, PerRecordRead, TxtBase, TxtRecord, WriteTtl};

use super::api::{Created, NewRecord, TXT, Written};
use super::client::Porkbun;
use super::records::{TXT_READ, TXT_WRITE, create_ttl, relative};

impl TxtBase for Porkbun {
    fn provider(&self) -> ProviderId {
        ProviderId::Porkbun
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl PerRecord for Porkbun {
    /// The record's identifier, when the listing states one.
    type Handle = Option<u64>;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> Result<PerRecordRead<Option<u64>>, Error> {
        let (records, _) = self.records_at(zone, name, RecordType::TXT).await?;
        let records = records
            .iter()
            .map(|record| TxtRecord {
                value: record
                    .content
                    .as_deref()
                    .and_then(|text| TXT_READ.read(text)),
                ttl: record.ttl(),
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
        let content = TXT_WRITE.write(value).ok_or(Error::InvalidInput {
            detail: Detail::constant("the TXT value cannot be written in this dialect"),
            code: None,
        })?;
        let record = NewRecord {
            name: relative(name, zone)?,
            rtype: TXT,
            content: &content,
            // A TTL the read did not state is the configured one, as in `records.rs`.
            ttl: create_ttl(
                match ttl {
                    WriteTtl::New(ttl) | WriteTtl::Existing(ttl) => ttl,
                },
                self.ttl,
            ),
            prio: None,
        };
        match self.api.create(zone, &record).await? {
            Created::Done => Ok(()),
            Created::Duplicate(refusal) => {
                let PerRecordRead::Records(now) =
                    <Self as PerRecord>::read(self, zone, name).await?
                else {
                    return Err(refusal);
                };
                if now.iter().any(|r| r.value.as_ref() == Some(value)) {
                    Err(Error::Conflict {
                        detail: Detail::constant(
                            "the value was created by another writer after the read",
                        ),
                    })
                } else {
                    Err(refusal)
                }
            }
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        record: &TxtRecord<Option<u64>>,
    ) -> Result<(), Error> {
        let id = record.handle.ok_or(Error::Protocol {
            detail: Detail::constant("the provider lists the record without an identifier"),
        })?;
        match self.api.delete(zone, id).await? {
            Written::Done => Ok(()),
            Written::Gone => {
                // The record is gone, or the domain is and was created again. Only a new read
                // tells them apart.
                let PerRecordRead::Records(now) =
                    <Self as PerRecord>::read(self, zone, name).await?
                else {
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
