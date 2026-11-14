//! TXT value operations: the `WholeSet` shape of the value layer over atomic change batches.
//!
//! The rrset is the native unit, changed by a change batch that Route 53 applies as a whole or
//! not at all. Every write is conditional on the set as read (design sections 3.4 and 3.5,
//! `ValueGuarantee::Conditional`):
//!
//! - no prior set: `CREATE`, which the API refuses when the rrset exists by then;
//! - over a prior set: `DELETE` of the old set exactly as read (TTL and values) plus `CREATE` of
//!   the new one with the old TTL, in one batch; the `DELETE` fails when the set changed;
//! - the last value: `DELETE` of the old set exactly as read.
//!
//! A batch refused with `InvalidChangeBatch` is followed by a new read: a set that differs from
//! the one read now means the rrset changed in between, and the answer is `Error::Conflict`,
//! which makes the value layer run the operation once more (design section 3.5); a set that is
//! still as read means the batch was refused for another reason, which is the error. A `404`
//! means the hosted zone is gone (a recreated zone): nothing was written; the zone is looked up
//! again by the repeat.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Presentation`. Values are
//! quoted strings of at most 255 characters each. The API writes bytes outside printable ASCII
//! as `\ooo` octal escapes, unlike the decimal `\DDD` of zone files, so a value with any
//! backslash is not decoded: it is a foreign value kept as it is and never equal to a value of
//! this client (plain values contain no backslash).
// Source: Developer Guide, "Supported DNS record types", TXT
// (https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#TXTFormat):
// strings "enclosed in double quotation marks", "A single string can include up to 255
// characters", "specify the characters by using escape codes in the format \three-digit octal
// code", "To include a quotation mark ... put a backslash"; lego writes `"` + value + `"`.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{Ttl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::values::{Member, SetRead, SetState, TxtBase, TxtRecord, TxtSet, WholeSet, WriteTtl};

use super::api::{Action, Change, Rrset, Submitted};
use super::client::Route53;

/// How TXT values are read.
const READ: TxtDialect = TxtDialect::Auto;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Presentation;

/// Most records of one rrset.
// Source: Quotas, "Records in a record set: 400 per record set".
const MAX_RECORDS: usize = 400;

/// Most characters of all values of one change batch.
// Source: Quotas, "The sum of the number of characters (including spaces) in all Value elements
// in a request cannot exceed 32,000 characters".
const MAX_BATCH_CHARS: usize = 32_000;

/// Longest value.
// Source: API reference, `ResourceRecord.Value`: "Maximum length of 4000".
const MAX_VALUE_CHARS: usize = 4000;

impl TxtBase for Route53 {
    fn provider(&self) -> ProviderId {
        ProviderId::Route53
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl WholeSet for Route53 {
    type Handle = String;
    type Snapshot = Rrset;
    /// The hosted zone ID the read used.
    type Context = String;

    async fn read(&self, zone: &DomainName, name: &DomainName) -> SetRead<String, Rrset, String> {
        let (zone_id, rrset) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| async move { self.api.txt_rrset(&id.id, name).await },
            )
            .await?;
        Ok(SetState {
            context: zone_id.id,
            set: rrset.map(txt_set),
        })
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        zone_id: &String,
        prior: Option<&Rrset>,
        members: &[Member<'_, String>],
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let values = values(members)?;
        let outcome = match prior {
            None => {
                let create = Change {
                    action: Action::Create,
                    name,
                    ttl: u64::from(self.new_ttl(ttl)),
                    values: &values,
                };
                check_batch(&[&values])?;
                self.api.change(zone_id, &[create]).await?
            }
            Some(prior) => {
                check_batch(&[&prior.values, &values])?;
                let delete = Change {
                    action: Action::Delete,
                    name,
                    ttl: prior.ttl,
                    values: &prior.values,
                };
                // An existing rrset keeps its TTL (design section 3.6).
                let create = Change {
                    action: Action::Create,
                    name,
                    ttl: prior.ttl,
                    values: &values,
                };
                self.api.change(zone_id, &[delete, create]).await?
            }
        };
        self.settle(zone, name, prior, outcome, false).await
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        zone_id: &String,
        prior: &Rrset,
    ) -> Result<(), Error> {
        check_batch(&[&prior.values])?;
        let delete = Change {
            action: Action::Delete,
            name,
            ttl: prior.ttl,
            values: &prior.values,
        };
        let outcome = self.api.change(zone_id, &[delete]).await?;
        self.settle(zone, name, Some(prior), outcome, true).await
    }
}

impl Route53 {
    /// Interprets the answer to a batch built from the set `prior` as read.
    async fn settle(
        &self,
        zone: &DomainName,
        name: &DomainName,
        prior: Option<&Rrset>,
        outcome: Submitted,
        deleting: bool,
    ) -> Result<(), Error> {
        match outcome {
            Submitted::Done => Ok(()),
            // The zone is gone, or was recreated under a new ID with the rrset in it. Nothing
            // was written. A delete is complete only if a read under the zone looked up afresh
            // finds no rrset (design section 3.5).
            Submitted::ZoneMissing => {
                self.forget_zone(zone);
                if deleting {
                    match self.read(zone, name).await?.set {
                        None => Ok(()),
                        Some(_) => Err(changed(
                            "the hosted zone was replaced between the read and the delete; the \
                             TXT rrset is still there",
                        )),
                    }
                } else {
                    Err(changed(
                        "the hosted zone was removed or replaced between the read and the write",
                    ))
                }
            }
            Submitted::Invalid(refusal) => {
                let now = self.read(zone, name).await?.set.map(|set| set.snapshot);
                if now.as_ref() == prior {
                    Err(refusal)
                } else {
                    Err(changed(
                        "the TXT rrset changed between the read and the write",
                    ))
                }
            }
        }
    }

    /// The TTL of a new rrset: the caller's, else the configured one.
    fn new_ttl(&self, ttl: WriteTtl) -> u32 {
        match ttl {
            WriteTtl::New(Some(ttl)) | WriteTtl::Existing(Some(ttl)) => ttl.as_secs(),
            WriteTtl::New(None) | WriteTtl::Existing(None) => self.ttl,
        }
    }
}

/// The value layer's view of an rrset.
fn txt_set(rrset: Rrset) -> TxtSet<String, Rrset> {
    let ttl = u32::try_from(rrset.ttl)
        .ok()
        .and_then(|secs| Ttl::from_secs(secs).ok());
    let records = rrset
        .values
        .iter()
        .map(|value| TxtRecord {
            value: decode(value),
            ttl,
            handle: value.clone(),
        })
        .collect();
    TxtSet {
        records,
        ttl,
        snapshot: rrset,
    }
}

/// The value of a record, or `None` for text this client does not decode (see the module
/// documentation): kept as it is and never equal to a value.
fn decode(text: &str) -> Option<Txt> {
    if text.contains('\\') {
        None
    } else {
        READ.read(text)
    }
}

/// The values to write: those kept, exactly as read, then the value added.
fn values(members: &[Member<'_, String>]) -> Result<Vec<String>, Error> {
    let mut values = Vec::with_capacity(members.len());
    for member in members {
        values.push(match member {
            Member::Kept(record) => record.handle.clone(),
            Member::Added(value) => WRITE.write(value).ok_or(Error::InvalidInput {
                detail: Detail::constant("the TXT value cannot be written in this dialect"),
            })?,
        });
    }
    if values.len() > MAX_RECORDS {
        return Err(Error::InvalidInput {
            detail: Detail::constant("a Route 53 rrset holds at most 400 records"),
        });
    }
    if values.iter().any(|v| v.chars().count() > MAX_VALUE_CHARS) {
        return Err(Error::InvalidInput {
            detail: Detail::constant("a Route 53 record value holds at most 4000 characters"),
        });
    }
    Ok(values)
}

/// The size limits of one change batch, checked before it is sent.
// Source: Quotas: at most 1,000 `ResourceRecord` elements and 32,000 characters in all `Value`
// elements of a request.
fn check_batch(sets: &[&Vec<String>]) -> Result<(), Error> {
    let records: usize = sets.iter().map(|s| s.len()).sum();
    let chars: usize = sets
        .iter()
        .flat_map(|s| s.iter())
        .map(|v| v.chars().count())
        .sum();
    if records > 1000 || chars > MAX_BATCH_CHARS {
        return Err(Error::InvalidInput {
            detail: Detail::constant(
                "the change exceeds the size limits of a Route 53 change batch",
            ),
        });
    }
    Ok(())
}

/// The rrset or the zone changed between the read and the write; nothing was written.
fn changed(text: &'static str) -> Error {
    Error::Conflict {
        detail: Detail::constant(text),
    }
}
