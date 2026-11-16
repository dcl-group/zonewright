//! TXT value operations: the `ValueCalls` shape of the value layer over the rrset API.
//!
//! The API changes an rrset by value: `PATCH …/records/{name}/{type}` with `add_rrset_values` or
//! `remove_rrset_values` ("Add or remove some values of a Resource Record set (RRset)", the
//! LiveDNS API reference). A request therefore names only our value, and a foreign value cannot
//! be part of it (`ValueGuarantee::PerValue`). The value layer takes the per-name lock, reads and
//! decides; this file maps its calls onto the API:
//!
//! - read: `GET …/records/{name}/TXT` (`rrset.rs`);
//! - add to a name without a TXT rrset: a create (`POST`) with the value and the requested or
//!   configured TTL. The documentation says what a create of an existing rrset is answered with
//!   (`409`, or `200` when the values are the same): another writer created the rrset after the
//!   read, nothing was overwritten, and the result is `Error::Conflict`;
//! - add to an existing rrset: `PATCH` with `add_rrset_values` and no `rrset_ttl`, so the rrset
//!   keeps its TTL (design section 3.6). The documented answer is `200` with the rrset; a `204`
//!   ("no longer exists") after an add is an answer the client cannot interpret
//!   (`Error::Protocol`), and a `404` means the rrset went away after the read
//!   (`Error::Conflict`);
//! - remove: `PATCH` with `remove_rrset_values` holding the texts the API returned for the
//!   records that hold our value. Removing the last value leaves no rrset ("the resource record
//!   set no longer exists at the end of the operation", answer `204`), so no `DELETE` is ever
//!   sent by these operations: a value another writer added after the read survives. A `404`
//!   counts as done only after a new read no longer finds the value.
//!
//! lego reads the TXT rrset and writes it back whole with `PUT` (`AddTXTRecord`), and its cleanup
//! deletes the whole TXT rrset at the name, values of other writers included; this client does
//! neither (hard rule 2).
//!
//! What the `PATCH` does in the cases the client does not create is not documented: a value to
//! add that is present, a value to remove that is absent, a missing rrset. The client sends a
//! value to add only after a read that did not show it and a value to remove only after a read
//! that did, so these cases arise only when another writer changed the rrset in between; the live
//! test `gandi_live_assumptions` exercises the documented cases.
//!
//! TXT dialect: read and written by the rules of `content.rs`, which the record level follows
//! too. Only plain values are accepted (`Capabilities::txt_plain_only`); each is written as one
//! quoted string.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{RrsetTtl, Txt};
use crate::redact::Detail;
use crate::values::{TxtBase, TxtRecord, ValueCalls, WriteTtl};

use super::api::{Patched, TXT};
use super::client::Gandi;
use super::content;
use super::rrset::{rr_name, vanished};

impl TxtBase for Gandi {
    fn provider(&self) -> ProviderId {
        ProviderId::Gandi
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl ValueCalls for Gandi {
    /// The value exactly as the API returned it.
    type Handle = String;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> Result<Vec<TxtRecord<String>>, Error> {
        let rr = rr_name(zone, name)?;
        let Some(rrset) = self.read_rrset(zone, &rr, TXT).await? else {
            return Ok(Vec::new());
        };
        let ttl = rrset.ttl.and_then(|ttl| RrsetTtl::from_secs(ttl).ok());
        Ok(rrset
            .values
            .into_iter()
            .map(|text| TxtRecord {
                value: content::read_txt(&text),
                ttl,
                handle: text,
            })
            .collect())
    }

    async fn add(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let rr = rr_name(zone, name)?;
        let text = content::write_txt(value).ok_or(Error::InvalidInput {
            detail: Detail::constant("the TXT value cannot be written in this dialect"),
            code: None,
        })?;
        let values = [text];
        match ttl {
            WriteTtl::New(requested) => {
                // The provider has no default TTL a write can ask for (the capabilities refuse
                // it before any request); the setting stands in for anything but a number.
                let ttl = match requested {
                    Some(RrsetTtl::Explicit(ttl)) => ttl.as_secs(),
                    None | Some(RrsetTtl::ProviderDefault) => self.ttl,
                };
                self.create_rrset(zone, &rr, TXT, &values, ttl).await
            }
            WriteTtl::Existing(_) => match self.api.patch(zone, &rr, TXT, &values, &[]).await? {
                Patched::Present => Ok(()),
                Patched::Gone => Err(Error::Protocol {
                    detail: Detail::constant(
                        "the provider reported no rrset after a value was added to it",
                    ),
                }),
                Patched::NotFound => Err(vanished()),
                Patched::Refused(e) => Err(e),
            },
        }
    }

    async fn remove(
        &self,
        zone: &DomainName,
        name: &DomainName,
        records: &[&TxtRecord<String>],
    ) -> Result<(), Error> {
        let rr = rr_name(zone, name)?;
        // The values as the API returned them, each once.
        let mut values: Vec<String> = Vec::new();
        for record in records {
            if !values.contains(&record.handle) {
                values.push(record.handle.clone());
            }
        }
        match self.api.patch(zone, &rr, TXT, &[], &values).await? {
            Patched::Present | Patched::Gone => Ok(()),
            Patched::Refused(e) => Err(e),
            // The rrset, or the domain, is gone; it may have been created again with the value
            // in it. Only a new read tells.
            Patched::NotFound => {
                let now = self.read(zone, name).await?;
                let still_there = records.iter().any(|ours| {
                    ours.value.is_some() && now.iter().any(|record| record.value == ours.value)
                });
                if still_there {
                    Err(Error::Conflict {
                        detail: Detail::constant(
                            "the TXT value was found again after its removal was answered \
                             \"not found\"; the rrset changed between the read and the write",
                        ),
                    })
                } else {
                    Ok(())
                }
            }
        }
    }
}
