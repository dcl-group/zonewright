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
//! - add to an existing rrset: `PATCH` with `add_rrset_values` and, when the read stated one,
//!   `rrset_ttl` with the rrset's TTL as read. The reference does not say what a change without
//!   `rrset_ttl` does to the TTL (kept, or set to a default); sending the TTL read keeps it under
//!   either reading (design section 3.6), and is the form of the reference's only example. The
//!   documented answer is `200` with the rrset; a `204` ("no longer exists") after an add is an
//!   answer the client cannot interpret (`Error::Protocol`), and a `404` means the rrset went
//!   away after the read (`Error::Conflict`);
//! - remove: `PATCH` with `remove_rrset_values` holding the texts the API returned for the
//!   records that hold our value, and the TTL as read. Removing the last value leaves no rrset
//!   ("the resource record set no longer exists at the end of the operation", answer `204`), so
//!   no `DELETE` is ever sent by these operations: a value another writer added after the read
//!   survives. A `404` counts as done only after a new read no longer finds the value.
//!
//! A `200` is a success only when the rrset it states holds the value added, or no longer holds
//! the value removed (compared as decoded values, since the API may respell them); an answer
//! without the values is confirmed by a new read. Otherwise the result is `Error::Protocol`: the
//! client never reports a change it cannot see.
//!
//! lego reads the TXT rrset and writes it back whole with `PUT` (`AddTXTRecord`), and its cleanup
//! deletes the whole TXT rrset at the name, values of other writers included; this client does
//! neither (hard rule 2).
//!
//! What the `PATCH` does in the cases the client does not create is not documented: a value to
//! add that is present, a value to remove that is absent, a missing rrset. The client sends a
//! value to add only after a read that did not show it and a value to remove only after a read
//! that did, so these cases arise only when another writer changed the rrset in between; then a
//! refusal is returned as the provider's refusal, and an answer the client can check is checked
//! as above. The live test `gandi_live_assumptions` exercises the documented cases.
//!
//! TXT dialect: read and written by the rules of `content.rs`, which the record level follows
//! too. A value is accepted exactly when `content::write_txt` can write it (one quoted string of
//! 1 to 255 printable ASCII octets without `"` or `\`; spaces inside are allowed, as in the
//! reference's own TXT example), checked before any request (`TxtBase::check_value`).

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

    /// The value must be one the client can write: the record level's rule (`content.rs`).
    fn check_value(&self, value: &Txt) -> Result<(), Error> {
        match content::write_txt(value) {
            Some(_) => Ok(()),
            None => Err(unwritable()),
        }
    }
}

fn unwritable() -> Error {
    Error::InvalidInput {
        detail: Detail::constant(
            "the provider's encoding of this TXT value is not established: 1 to 255 printable \
             ASCII characters without quotes or backslashes",
        ),
        code: None,
    }
}

/// The TTL to send with a value-level change: the rrset's as read, when the read stated one.
fn ttl_as_read(ttl: Option<RrsetTtl>) -> Option<u32> {
    ttl.and_then(RrsetTtl::explicit).map(|ttl| ttl.as_secs())
}

fn unseen(what: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(what),
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
        let text = content::write_txt(value).ok_or_else(unwritable)?;
        let values = [text];
        let existing = match ttl {
            WriteTtl::New(requested) => {
                // The provider has no default TTL a write can ask for (the capabilities refuse
                // it before any request); the setting stands in for anything but a number.
                let ttl = match requested {
                    Some(RrsetTtl::Explicit(ttl)) => ttl.as_secs(),
                    None | Some(RrsetTtl::ProviderDefault) => self.ttl,
                };
                return self.create_rrset(zone, &rr, TXT, &values, ttl).await;
            }
            WriteTtl::Existing(existing) => existing,
        };
        let stated = match self
            .api
            .patch(zone, &rr, TXT, &values, &[], ttl_as_read(existing))
            .await?
        {
            Patched::Present(stated) => stated,
            Patched::Gone => {
                return Err(unseen(
                    "the provider reported no rrset after a value was added to it",
                ));
            }
            Patched::NotFound => return Err(vanished()),
            Patched::Refused(e) => return Err(e),
        };
        let holds = match stated {
            Some(now) => now
                .iter()
                .any(|t| content::read_txt(t).as_ref() == Some(value)),
            None => self
                .read(zone, name)
                .await?
                .iter()
                .any(|record| record.value.as_ref() == Some(value)),
        };
        if holds {
            Ok(())
        } else {
            Err(unseen(
                "the provider accepted the value but the rrset does not hold it",
            ))
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
        let ttl = ttl_as_read(records.first().and_then(|record| record.ttl));
        // A record still holds our value: one of the texts sent, or the same value respelled.
        let ours = |text: &str| {
            values.iter().any(|sent| sent == text)
                || records
                    .iter()
                    .any(|r| r.value.is_some() && content::read_txt(text) == r.value)
        };
        match self.api.patch(zone, &rr, TXT, &[], &values, ttl).await? {
            Patched::Gone => Ok(()),
            Patched::Present(Some(now)) => {
                if now.iter().any(|text| ours(text)) {
                    Err(unseen(
                        "the provider accepted the removal but the rrset still holds the value",
                    ))
                } else {
                    Ok(())
                }
            }
            Patched::Refused(e) => Err(e),
            // An answer without the values, or the rrset (or the domain) gone: the rrset may
            // have been created again with the value in it. Only a new read tells.
            answer @ (Patched::Present(None) | Patched::NotFound) => {
                let now = self.read(zone, name).await?;
                if now.iter().any(|record| ours(&record.handle)) {
                    Err(match answer {
                        Patched::NotFound => Error::Conflict {
                            detail: Detail::constant(
                                "the TXT value was found again after its removal was answered \
                                 \"not found\"; the rrset changed between the read and the write",
                            ),
                        },
                        _ => unseen(
                            "the provider accepted the removal but the rrset still holds the value",
                        ),
                    })
                } else {
                    Ok(())
                }
            }
        }
    }
}
