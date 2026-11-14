//! TXT value operations: the `PerRecord` shape of the value layer over the record API.
//!
//! Every TXT value is a record of its own, with an identifier. Adding creates one record and
//! removing deletes the records that hold the value, by identifier, so a request never names a
//! foreign value: `ValueGuarantee::PerValue`. The value layer takes the per-name lock, reads,
//! decides and calls [`PerRecord::create`] or [`PerRecord::delete`]; this file maps those onto
//! the API:
//!
//! - read: `GET …/dns_records?type=TXT&name=`, exact name match, under the zone-ID cache;
//! - create: `POST …/dns_records`, sent once; a refusal is followed by a new read, and our
//!   value found there is `Error::Conflict` (created by another writer meanwhile);
//! - delete: `DELETE …/dns_records/{id}`, by the identifier just read. A `404` is success only
//!   when a new read, under a freshly looked-up zone, no longer finds the value: the answer can
//!   also mean that the zone identifier went stale while the record is still published.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Presentation`. The API
//! documents TXT content as quoted character strings, and plain values, the only ones the
//! capabilities accept, need no escape.
//!
//! TTL: the API stores a TTL on every record, `1` meaning automatic, which reads as no TTL
//! (design section 3.6). A record added to an existing set gets the smallest TTL read; when
//! none was reported, the set is automatic and the record is created with `1`.

use crate::error::Error;
use crate::http::{Attempt, ZoneId};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{Txt, TxtDialect};
use crate::redact::Detail;
use crate::values::{PerRecord, PerRecordRead, TxtBase, TxtRecord, WriteTtl};

use super::api::{NewRecord, TXT, Written};
use super::client::Cloudflare;
use super::config::TTL_AUTOMATIC;
use super::records::read_ttl;

/// How TXT content is read.
const READ: TxtDialect = TxtDialect::Auto;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Presentation;

impl TxtBase for Cloudflare {
    fn provider(&self) -> ProviderId {
        ProviderId::Cloudflare
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl PerRecord for Cloudflare {
    /// The record's identifier.
    type Handle = String;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> Result<PerRecordRead<String>, Error> {
        let (_, records) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| self.read_txt(zone, name, id),
            )
            .await?;
        Ok(PerRecordRead::Records(records))
    }

    async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let content = WRITE.write(value).ok_or(Error::InvalidInput {
            detail: Detail::constant("the TXT value cannot be written in this dialect"),
        })?;
        let zone_id = self.write_zone_id(zone).await?;
        let record = NewRecord {
            rtype: TXT,
            name: name.without_dot(),
            content: Some(&content),
            priority: None,
            data: None,
            ttl: self.new_ttl(ttl),
            proxied: None,
            private_routing: None,
            settings: None,
        };
        match self.api.create_record(&zone_id, &record).await? {
            Written::Done => Ok(()),
            Written::NotFound => {
                self.forget_zone(zone);
                Err(vanished())
            }
            // The API documents no refusal for a record that exists already, so a refused
            // create is followed by a new read (design section 3.5): our value found there now
            // was created by another writer after this operation's read, nothing was written,
            // and the repeat of the operation reports it present. Otherwise, or when the read
            // fails, the refusal is the error.
            Written::Refused(
                e @ Error::Rejected {
                    status: Some(400..=499),
                    ..
                },
            ) => match self.read(zone, name).await {
                Ok(PerRecordRead::Records(records))
                    if records.iter().any(|r| r.value.as_ref() == Some(value)) =>
                {
                    Err(Error::Conflict {
                        detail: Detail::constant(
                            "the TXT value was created by another writer between the read \
                                 and the write",
                        ),
                    })
                }
                _ => Err(e),
            },
            Written::Refused(e) => Err(e),
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        record: &TxtRecord<String>,
    ) -> Result<(), Error> {
        let zone_id = self.write_zone_id(zone).await?;
        match self.api.delete_record(&zone_id, &record.handle).await? {
            Written::Done => Ok(()),
            // The record is gone, or the zone identifier is (a zone recreated with the record
            // in it). Only a new read under a freshly looked-up zone tells them apart.
            Written::NotFound => {
                self.forget_zone(zone);
                let PerRecordRead::Records(records) = self.read(zone, name).await? else {
                    return Err(vanished());
                };
                match &record.value {
                    Some(value) if records.iter().any(|r| r.value.as_ref() == Some(value)) => {
                        Err(Error::Conflict {
                            detail: Detail::constant(
                                "the TXT value was found again after its delete was answered \
                                 \"not found\"; the zone changed between the read and the delete",
                            ),
                        })
                    }
                    _ => Ok(()),
                }
            }
            Written::Refused(e) => Err(e),
        }
    }
}

impl Cloudflare {
    /// The read phase under the zone cache: the TXT records of `name` in the zone `id`, or
    /// `Stale` when the zone identifier may be stale (see `records.rs`, `fetch`).
    async fn read_txt(
        &self,
        zone: &DomainName,
        name: &DomainName,
        id: ZoneId,
    ) -> Result<Attempt<Vec<TxtRecord<String>>>, Error> {
        Ok(match self.fetch(zone, id, Some(name), Some(TXT)).await? {
            Attempt::Done(records) => Attempt::Done(
                records
                    .into_iter()
                    .map(|r| TxtRecord {
                        // A record without content holds no value this client can match.
                        value: r.content.as_deref().and_then(|c| READ.read(c)),
                        ttl: read_ttl(&r),
                        handle: r.id,
                    })
                    .collect(),
            ),
            Attempt::Stale => Attempt::Stale,
        })
    }

    /// The TTL of a new record: the caller's, else the configured one for a new rrset; the TTL
    /// of the existing set, or automatic when it reports none.
    fn new_ttl(&self, ttl: WriteTtl) -> u32 {
        match ttl {
            WriteTtl::New(Some(ttl)) | WriteTtl::Existing(Some(ttl)) => ttl.as_secs(),
            WriteTtl::New(None) => self.ttl,
            WriteTtl::Existing(None) => TTL_AUTOMATIC,
        }
    }
}

/// A write addressed a zone that no longer exists: it changed after the read, and nothing was
/// written.
fn vanished() -> Error {
    Error::Conflict {
        detail: Detail::constant("the zone was removed between the read and the write"),
    }
}
