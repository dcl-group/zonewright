//! TXT value operations: the `PerRecord` shape of the value layer over the TXT record API.
//!
//! Every TXT value is a record of its own, with an identifier. Adding creates one record and
//! removing deletes the records that hold the value, by identifier, so a request never names a
//! foreign value: `ValueGuarantee::PerValue`. The value layer takes the per-name lock, reads,
//! decides and calls [`PerRecord::create`] or [`PerRecord::delete`]; this file maps those onto
//! the API:
//!
//! - read: `GET …/{zone}/txt/`, every TXT record of the zone, filtered here by exact name,
//!   under the zone-ID cache. A `404` is "records not found" in the documentation, and also what
//!   a zone that does not exist gets: under a freshly looked-up identifier it is an empty
//!   listing, under a cached one it may be a stale identifier, so the zone is looked up again
//!   and the read repeated once (design section 3.8);
//! - create: `POST …/{zone}/txt/`, sent once; a refusal is followed by a new read, and our
//!   value found there is `Error::Conflict` (created by another writer meanwhile);
//! - delete: `DELETE …/{zone}/txt/{record}`, by the identifier just read. A `404` is success
//!   only when a new read, under a freshly looked-up zone, no longer finds the value: the answer
//!   can also mean that the zone identifier went stale while the record is still published.
//!
//! Names are relative to the zone, `@` for the apex (lego sends the relative name; the
//! OpenAPI's example of `name` is `@`). A listed name is read the zone-file way: `@` or empty
//! is the apex, a name ending in a dot is absolute, anything else is relative.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Raw`. lego writes the value
//! unquoted and compares the listed content with it as it is (vkcloud.go:216, 222-226); plain
//! values, the only ones the capabilities accept, need no escape in any dialect.
//!
//! TTL: the API stores a TTL on every record and requires one on a create. A record added to an
//! existing set gets the smallest TTL read (design section 3.6); when none was reported, the
//! configured one.

use crate::error::Error;
use crate::http::{Attempt, ZoneId};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{Ttl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::values::{PerRecord, PerRecordRead, TxtBase, TxtRecord, WriteTtl};

use super::api::{self, NewTxt, Written};
use super::client::VkCloud;

/// How TXT content is read.
const READ: TxtDialect = TxtDialect::Auto;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Raw;

/// The name of the apex in a write.
// Source: the OpenAPI, the example of `name` ("@").
const APEX: &str = "@";

impl TxtBase for VkCloud {
    fn provider(&self) -> ProviderId {
        ProviderId::VkCloud
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl PerRecord for VkCloud {
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
        let relative = relative_name(zone, name)?;
        let zone_id = self.write_zone_id(zone).await?;
        let record = NewTxt {
            name: relative,
            content: &content,
            ttl: self.new_ttl(ttl),
        };
        match self.api.create_txt(&zone_id, &record).await? {
            Written::Done => Ok(()),
            Written::NotFound => {
                self.forget_zone(zone);
                Err(vanished())
            }
            // The documented 409 covers a duplicate among other things, and other refusals
            // are not documented further, so a refused create is followed by a new read
            // (design section 3.5): our value found there now was created by another writer
            // after this operation's read, nothing was written, and the repeat of the
            // operation reports it present. Otherwise, or when the read fails, the refusal is
            // the error.
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
        match self.api.delete_txt(&zone_id, &record.handle).await? {
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

impl VkCloud {
    /// The read phase under the zone cache: the TXT records of `name` in the zone `id`. A `404`
    /// is an empty listing under a freshly looked-up identifier and `Stale` under a cached one.
    async fn read_txt(
        &self,
        zone: &DomainName,
        name: &DomainName,
        id: ZoneId,
    ) -> Result<Attempt<Vec<TxtRecord<String>>>, Error> {
        match self.api.txt_records(&id.id).await? {
            Some(records) => Ok(Attempt::Done(
                records
                    .into_iter()
                    .filter(|r| is_name(&r.name, zone, name))
                    .map(txt_record)
                    .collect(),
            )),
            None if id.fresh => Ok(Attempt::Done(Vec::new())),
            None => Ok(Attempt::Stale),
        }
    }

    /// The TTL of a new record: the caller's, else the configured one for a new rrset; the
    /// smallest TTL of the existing set, else the configured one.
    fn new_ttl(&self, ttl: WriteTtl) -> u32 {
        match ttl {
            WriteTtl::New(Some(ttl)) | WriteTtl::Existing(Some(ttl)) => ttl.as_secs(),
            WriteTtl::New(None) | WriteTtl::Existing(None) => self.ttl,
        }
    }
}

/// The value layer's view of a listed record.
fn txt_record(record: api::TxtRecord) -> TxtRecord<String> {
    TxtRecord {
        value: READ.read(&record.content),
        ttl: record.ttl.and_then(|ttl| Ttl::from_secs(ttl).ok()),
        handle: record.uuid,
    }
}

/// Whether the listed name `listed` is `name`, read relative to `zone`.
fn is_name(listed: &str, zone: &DomainName, name: &DomainName) -> bool {
    DomainName::from_relative(listed.trim(), zone).is_ok_and(|listed| &listed == name)
}

/// The name of a write: relative to the zone, `@` for the apex.
fn relative_name<'a>(zone: &DomainName, name: &'a DomainName) -> Result<&'a str, Error> {
    match name.relative_to(zone) {
        Some("") => Ok(APEX),
        Some(relative) => Ok(relative),
        None => Err(Error::name_outside_zone(name.clone(), zone.clone())),
    }
}

/// A write addressed a zone that no longer exists: it changed after the read, and nothing was
/// written.
fn vanished() -> Error {
    Error::Conflict {
        detail: Detail::constant("the zone was removed between the read and the write"),
    }
}

#[cfg(test)]
mod tests {
    use super::{is_name, relative_name};
    use crate::name::DomainName;

    fn dn(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    #[test]
    fn listed_names_are_relative_to_the_zone() {
        let zone = dn("example.org");
        let name = dn("_acme-challenge.www.example.org");
        assert!(is_name("_acme-challenge.www", &zone, &name));
        assert!(is_name("_ACME-challenge.WWW", &zone, &name));
        assert!(is_name("_acme-challenge.www.example.org.", &zone, &name));
        // Without the trailing dot a name is relative: this one is below the zone's name again.
        assert!(!is_name("_acme-challenge.www.example.org", &zone, &name));
        assert!(!is_name("_acme-challenge", &zone, &name));
        assert!(!is_name("x._acme-challenge.www", &zone, &name));
        assert!(!is_name("not a name", &zone, &name));
        assert!(is_name("@", &zone, &zone));
        assert!(is_name("", &zone, &zone));
        assert!(!is_name("@", &zone, &name));
    }

    #[test]
    fn written_names_are_relative_and_the_apex_is_at() {
        let zone = dn("example.org");
        assert_eq!(
            relative_name(&zone, &dn("_acme-challenge.www.example.org")).unwrap(),
            "_acme-challenge.www"
        );
        assert_eq!(relative_name(&zone, &zone).unwrap(), "@");
        assert!(relative_name(&zone, &dn("example.net")).is_err());
    }
}
