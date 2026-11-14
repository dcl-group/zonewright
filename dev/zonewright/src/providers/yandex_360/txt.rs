//! TXT value operations: the `PerRecord` shape of the value layer over the record API.
//!
//! Every TXT value is a record of its own with an identifier, so a request names only our
//! record and a foreign value cannot be part of it (`ValueGuarantee::PerValue`). The value
//! layer takes the per-name lock, reads and decides; this file maps its calls onto the API:
//!
//! - read: `GET …/dns`, every page (the listing has no filter), an exact name and type match
//!   on the client's side, under no cached identifier: the domain's name is the key in every
//!   path;
//! - create: `POST …/dns`, sent once, with the name relative to the zone, the value and the
//!   TTL the value layer chose (the rrset's as read when the name has TXT records, else the
//!   caller's or the configured one; the API requires a TTL, so the configured one stands in
//!   when the API reported none);
//! - delete: `DELETE …/dns/{recordId}`. An answer "not found" says that the record, or the
//!   whole domain with it, is gone; a domain deleted and created again could hold the value
//!   under a new identifier, so it counts as done only after a new read finds no record with
//!   the value.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Raw`. lego sends the value
//! itself in `text`, unquoted (providers/dns/yandex360/yandex360.go lines 127 to 132). Plain
//! values, the only ones the capabilities accept, need no escape.
//!
//! The zone's own name is not written: the documentation does not say how the API spells the
//! name of the apex in a create, and lego never writes there (`dns01.ExtractSubDomain`,
//! challenge/dns01/domain.go lines 15 to 17, refuses a name equal to the zone, and
//! providers/dns/yandex360/yandex360.go lines 120 to 123 stop on that error). An add at the apex
//! is refused with `Error::InvalidInput` before any request (design section 3.1, check 4); a
//! value found there can still be removed, by its identifier.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{Ttl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::values::{PerRecord, PerRecordRead, TxtBase, TxtRecord, WriteTtl};

use super::api::{NewRecord, TXT, Written, names_match};
use super::client::Yandex360;

/// How TXT data is read.
const READ: TxtDialect = TxtDialect::Auto;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Raw;

impl TxtBase for Yandex360 {
    fn provider(&self) -> ProviderId {
        ProviderId::Yandex360
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl PerRecord for Yandex360 {
    /// The record's identifier.
    type Handle = u64;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> Result<PerRecordRead<u64>, Error> {
        let records = self
            .api
            .records(zone)
            .await?
            .into_iter()
            .filter(|record| {
                record.rtype.eq_ignore_ascii_case(TXT) && names_match(&record.name, zone, name)
            })
            .map(|record| TxtRecord {
                value: record.text.as_deref().and_then(|text| READ.read(text)),
                ttl: record.ttl.and_then(|secs| Ttl::from_secs(secs).ok()),
                handle: record.record_id,
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
        let relative = match name.relative_to(zone) {
            Some(relative) if !relative.is_empty() => relative,
            // Refused before any request by `add_txt_value`; kept here so that no path can
            // send an invented name.
            Some(_) => return Err(apex_not_written()),
            None => return Err(Error::name_outside_zone(name.clone(), zone.clone())),
        };
        let text = WRITE.write(value).ok_or(Error::InvalidInput {
            detail: Detail::constant("the TXT value cannot be written in this dialect"),
        })?;
        let ttl = match ttl {
            WriteTtl::New(Some(ttl)) | WriteTtl::Existing(Some(ttl)) => ttl.as_secs(),
            // The API requires a TTL: with none reported, the configured one is sent.
            WriteTtl::New(None) | WriteTtl::Existing(None) => self.ttl,
        };
        let record = NewRecord {
            rtype: TXT,
            name: relative,
            text: &text,
            ttl,
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

/// The refusal of an add at the zone's own name.
pub(super) fn apex_not_written() -> Error {
    Error::InvalidInput {
        detail: Detail::constant(
            "the provider's documentation does not say how to write the name of the zone \
             itself; only names below it are written",
        ),
    }
}
