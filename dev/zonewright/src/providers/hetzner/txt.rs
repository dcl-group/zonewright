//! TXT value operations: the `ValueCalls` shape of the value layer over the rrset actions.
//!
//! The API's unit is the rrset, and it changes it by value: `add_records` appends the values it
//! is given (creating the rrset when there is none) and `remove_records` removes the values it
//! is given (deleting the rrset when nothing is left). A request therefore names only our value
//! and a foreign value cannot be part of it (`ValueGuarantee::PerValue`). The value layer takes
//! the per-name lock, reads and decides; this file maps its calls onto the API:
//!
//! - read: `GET …/rrsets/{rr_name}/TXT` under the zone-ID cache. The `404` answer cannot tell a
//!   missing rrset from a missing zone: under an identifier resolved in this call it means the
//!   rrset is absent; under a cached one the zone is looked up again and the read repeated;
//! - add: `add_records` with the value in zone-file text (quoted), sent once, then the action is
//!   waited for. The TTL is the one the value layer chose: the rrset's as read when it exists
//!   (the API refuses another one), else the caller's or the configured one;
//! - remove: `remove_records` with the texts the API returned for the records that hold our
//!   value, sent once, then the action is waited for. An answer "not found" says that the rrset,
//!   or the zone with it, is gone; the zone may have been deleted and created again with the
//!   value in it, so it counts as done only after a new read under a freshly looked-up zone no
//!   longer finds the value.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Presentation`. The DNS
//! documentation says that a TXT value "has to be quoted", and lego writes `strconv.Quote` of the
//! value (hetznerv1.go:125). Plain values, the only ones the capabilities accept, need no escape.

use crate::error::Error;
use crate::http::{Attempt, ZoneId};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{Ttl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::values::{TxtBase, TxtRecord, ValueCalls, WriteTtl};

use super::api::MAX_RECORDS_PER_CALL;
use super::client::Hetzner;

/// How TXT data is read.
const READ: TxtDialect = TxtDialect::Auto;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Presentation;

impl TxtBase for Hetzner {
    fn provider(&self) -> ProviderId {
        ProviderId::Hetzner
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl ValueCalls for Hetzner {
    /// The value exactly as the API returned it.
    type Handle = String;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> Result<Vec<TxtRecord<String>>, Error> {
        let rr = rr_name(zone, name)?;
        let (_, records) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| self.read_txt(&rr, id),
            )
            .await?;
        Ok(records)
    }

    async fn add(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let rr = rr_name(zone, name)?;
        let text = WRITE.write(value).ok_or(Error::InvalidInput {
            detail: Detail::constant("the TXT value cannot be written in this dialect"),
        })?;
        let ttl = match ttl {
            WriteTtl::New(Some(ttl)) | WriteTtl::Existing(Some(ttl)) => Some(ttl.as_secs()),
            WriteTtl::New(None) => Some(self.ttl),
            // The set's TTL was not reported: it has none and the zone's default applies. Send
            // none, so that the provider keeps it.
            WriteTtl::Existing(None) => None,
        };
        let zone_id = self.write_zone_id(zone).await?;
        match self.api.add_records(&zone_id, &rr, &text, ttl).await? {
            Some(action) => self.api.wait(&self.poller, action).await,
            None => {
                self.forget_zone(zone);
                Err(vanished())
            }
        }
    }

    async fn remove(
        &self,
        zone: &DomainName,
        name: &DomainName,
        records: &[&TxtRecord<String>],
    ) -> Result<(), Error> {
        let rr = rr_name(zone, name)?;
        // The values as the API returned them: it identifies a record by its value.
        let values: Vec<&str> = records.iter().map(|r| r.handle.as_str()).collect();
        if values.len() > MAX_RECORDS_PER_CALL {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the rrset holds more copies of the value than one request can remove",
                ),
            });
        }
        let zone_id = self.write_zone_id(zone).await?;
        match self.api.remove_records(&zone_id, &rr, &values).await? {
            Some(action) => self.api.wait(&self.poller, action).await,
            // The rrset is gone, or the zone identifier is (a zone recreated with the value in
            // it). Only a new read under a freshly looked-up zone tells them apart.
            None => {
                self.forget_zone(zone);
                let now = self.read(zone, name).await?;
                let still_there = records.iter().any(|ours| {
                    ours.value.is_some() && now.iter().any(|record| record.value == ours.value)
                });
                if still_there {
                    Err(Error::Conflict {
                        detail: Detail::constant(
                            "the TXT value was found again after its removal was answered \
                             \"not found\"; the zone changed between the read and the write",
                        ),
                    })
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl Hetzner {
    /// The read phase under the zone cache: the TXT values of the rrset `rr` in the zone `id`,
    /// or `Stale` when the API does not know the rrset under a cached identifier.
    async fn read_txt(
        &self,
        rr: &str,
        id: ZoneId,
    ) -> Result<Attempt<Vec<TxtRecord<String>>>, Error> {
        match self.api.rrset(&id.id, rr).await? {
            Some(set) => {
                // A TTL outside the crate's range is outside the documented one (60 to
                // 2147483647) too. Read as "no TTL" it would make the add send none and could
                // change the rrset's TTL (design section 3.6), so it is an answer the client
                // cannot use.
                let ttl = match set.ttl {
                    None => None,
                    Some(secs) => Some(Ttl::from_secs(secs).map_err(|_| Error::Protocol {
                        detail: Detail::constant("the provider's rrset has an unusable TTL"),
                    })?),
                };
                Ok(Attempt::Done(
                    set.records
                        .into_iter()
                        .map(|record| TxtRecord {
                            value: READ.read(&record.value),
                            ttl,
                            handle: record.value,
                        })
                        .collect(),
                ))
            }
            // The zone was resolved in this call: it exists, so the rrset does not.
            None if id.fresh => Ok(Attempt::Done(Vec::new())),
            // A cached identifier: the zone may have been deleted and created again.
            None => Ok(Attempt::Stale),
        }
    }
}

/// The owner name relative to the zone, `@` for the apex.
// Source: the reference, Zone RRSets, `rr_name`: "must not end with a dot or the Zone name ...
// For the Zone apex, use `@`".
fn rr_name(zone: &DomainName, name: &DomainName) -> Result<String, Error> {
    match name.relative_to(zone) {
        None => Err(Error::name_outside_zone(name.clone(), zone.clone())),
        Some("") => Ok("@".to_owned()),
        Some(relative) => Ok(relative.to_owned()),
    }
}

/// A write addressed a zone or rrset that no longer exists: it changed after the read, and
/// nothing was written.
fn vanished() -> Error {
    Error::Conflict {
        detail: Detail::constant("the zone was removed between the read and the write"),
    }
}
