//! Record-level operations: the `WholeSet` shape of the record layer (`crate::rrsets`) over
//! atomic change batches, and the listing of a zone. The mapping between `Value` text and
//! `RecordData` is in `content.rs`.
//!
//! # Writes
//!
//! The native unit is the resource record set, changed by a change batch that Route 53 applies
//! as a whole or not at all, hence `Preconditions::Atomic` and `atomic_rrset_write`. Every
//! write is conditional on the set as the operation read it (design section 3.4):
//!
//! - no set was read: `CREATE`, which the API refuses when a set exists by then;
//! - a set was read: `DELETE` of that set exactly as read (TTL and every value, as the API
//!   returned them) plus `CREATE` of the new set, in one batch; the `DELETE` fails when the set
//!   changed in between;
//! - delete: `DELETE` of the set exactly as read.
//!
//! So `Expect::Matches` is the `DELETE` of the expected set (the record layer has compared it
//! with the set read, and the `DELETE` repeats what was read), `Expect::Absent` is a bare
//! `CREATE`, and `Expect::Any` is the same read followed by `DELETE`-as-read plus `CREATE`.
//! `UPSERT` is not used, also not for `Expect::Any`: design section 3.4 makes every write of a
//! conditional-write provider conditional, not only one under `Matches`; the read is needed in
//! any case (for `Unchanged`, the TTL policy of section 3.6 and writing members back exactly as
//! read), and an `UPSERT` would overwrite a set another writer created or changed after that
//! read, which `DELETE` plus `CREATE` turns into a refusal and one fresh attempt.
//!
//! A batch refused with `InvalidChangeBatch` is followed by a new read: a set that differs from
//! the one read means it changed in between, and the answer is `Error::Conflict`, which makes
//! the record layer run the operation once more from the read, and return `Conflict` if that is
//! refused as well; a set still as read means the batch was refused for another reason, which is
//! the error. A `404` means the hosted zone is gone or was recreated: nothing was written; a
//! delete is complete only when a read under the zone looked up afresh finds no set (design
//! section 3.5).
//!
//! # Sets that are not plain records
//!
//! An alias (`AliasTarget`), a set with a routing policy other than simple (`SetIdentifier`,
//! `Weight`, `Region`, `Failover`, `GeoLocation`, `GeoProximityLocation`, `MultiValueAnswer`,
//! `CidrRoutingConfig`), one bound to a health check (`HealthCheckId`) or created by a traffic
//! policy (`TrafficPolicyInstanceId`) cannot be an `RrSet`: several such sets can share one name
//! and type, and their attributes have no place in the model. Decision (conservative, design
//! sections 3.4 and 11.2): a listing reports each name and type holding one in `skipped` with
//! `SkipReason::NotPlainRecords`; `get_rrset`, `set_rrset` and `delete_rrset` at that name and
//! type fail with `Error::Rejected` (status `None`) after their read and before any write, so
//! that no one of several policy sets is presented as "the" rrset and none is changed. The TXT
//! value operations meet the same rule through the same predicate.
//!
//! # Names
//!
//! Owner names are sent as the crate's canonical text, which holds only `a-z`, `0-9`, `-`, `_`
//! and a leading `*` label. Names returned by the API have their octal escapes decoded (a
//! wildcard is returned as `\052`).
//!
//! SOA is read-only and the apex NS set is refused by the record layer before any request.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::provider::{SkipReason, ZoneListing};
use crate::record::{RecordData, RecordType, RrsetTtl};
use crate::redact::Detail;
use crate::rrsets::{self, Current, Found, Listing, Member, RrsetBase, SetTtl, Stored, WholeSet};

use super::api::{self, Action, Change, Lookup, Rrset, Submitted};
use super::client::Route53;
use super::content;
use super::txt::{MAX_RECORDS, MAX_VALUE_CHARS, check_batch};

impl RrsetBase for Route53 {
    fn provider(&self) -> ProviderId {
        ProviderId::Route53
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }

    // Source: Quotas, "Records in a record set: 400 per record set".
    fn max_records(&self) -> Option<usize> {
        Some(MAX_RECORDS)
    }

    fn can_send(&self, rtype: RecordType, data: &RecordData) -> bool {
        content::encode(rtype, data).is_some()
    }
}

/// The record layer's view of a plain rrset the API returned.
fn found(rtype: RecordType, rrset: Rrset) -> Found<String, Rrset> {
    let records = rrset
        .values
        .iter()
        .map(|value| Stored {
            data: content::read(rtype, value),
            enabled: true,
            ttl: None,
            handle: value.clone(),
        })
        .collect();
    Found {
        records,
        ttl: ttl(rrset.ttl),
        snapshot: rrset,
    }
}

fn ttl(secs: u64) -> Option<RrsetTtl> {
    u32::try_from(secs)
        .ok()
        .and_then(|secs| RrsetTtl::from_secs(secs).ok())
}

impl WholeSet for Route53 {
    type Handle = String;
    type Snapshot = Rrset;
    /// The hosted zone ID the read used.
    type Context = String;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Current<String, Rrset, String>, Error> {
        let type_name = rtype.to_string();
        let (zone_id, lookup) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| {
                    let type_name = &type_name;
                    async move { self.api.rrset_at(&id.id, name, type_name).await }
                },
            )
            .await?;
        let found = match lookup {
            Lookup::Absent => None,
            Lookup::Plain(rrset) => Some(found(rtype, rrset)),
            Lookup::NotPlain => return Err(api::not_plain()),
        };
        Ok(Current {
            context: zone_id.id,
            found,
        })
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        zone_id: &String,
        prior: Option<&Rrset>,
        members: &[Member<'_, String>],
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let type_name = rtype.to_string();
        let values = values(rtype, members)?;
        let ttl = match (ttl, prior) {
            (SetTtl::Requested(RrsetTtl::Explicit(ttl)), _) => u64::from(ttl.as_secs()),
            // An existing rrset keeps its TTL exactly as read (design section 3.6).
            (SetTtl::Existing(_), Some(prior)) => prior.ttl,
            (
                SetTtl::Existing(_)
                | SetTtl::Default
                | SetTtl::Requested(RrsetTtl::ProviderDefault),
                _,
            ) => u64::from(self.ttl),
        };
        let create = Change {
            action: Action::Create,
            name,
            rtype: &type_name,
            ttl,
            values: &values,
        };
        let outcome = match prior {
            None => {
                check_batch(&[&values])?;
                self.api.change(zone_id, &[create]).await?
            }
            Some(prior) => {
                check_batch(&[&prior.values, &values])?;
                let delete = Change {
                    action: Action::Delete,
                    name,
                    rtype: &type_name,
                    ttl: prior.ttl,
                    values: &prior.values,
                };
                self.api.change(zone_id, &[delete, create]).await?
            }
        };
        self.settle_set(zone, name, rtype, prior, outcome, false)
            .await
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        zone_id: &String,
        prior: &Rrset,
    ) -> Result<(), Error> {
        let type_name = rtype.to_string();
        check_batch(&[&prior.values])?;
        let delete = Change {
            action: Action::Delete,
            name,
            rtype: &type_name,
            ttl: prior.ttl,
            values: &prior.values,
        };
        let outcome = self.api.change(zone_id, &[delete]).await?;
        self.settle_set(zone, name, rtype, Some(prior), outcome, true)
            .await
    }
}

/// The values of a set to write: the records kept, exactly as read, then the new values in the
/// API's text form.
fn values(rtype: RecordType, members: &[Member<'_, String>]) -> Result<Vec<String>, Error> {
    let mut values = Vec::with_capacity(members.len());
    for member in members {
        values.push(match member {
            Member::Kept(record) | Member::Enabled(record) => record.handle.clone(),
            Member::Added(data) => content::encode(rtype, data).ok_or(Error::InvalidInput {
                detail: Detail::constant(
                    "the provider's encoding of this record data is not established",
                ),
                code: None,
            })?,
        });
    }
    if values.len() > MAX_RECORDS {
        return Err(Error::InvalidInput {
            detail: Detail::constant("a Route 53 rrset holds at most 400 records"),
            code: None,
        });
    }
    if values.iter().any(|v| v.chars().count() > MAX_VALUE_CHARS) {
        return Err(Error::InvalidInput {
            detail: Detail::constant("a Route 53 record value holds at most 4000 characters"),
            code: None,
        });
    }
    Ok(values)
}

impl Route53 {
    /// Interprets the answer to a batch built from the set `prior` as read (see the module
    /// documentation).
    async fn settle_set(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        prior: Option<&Rrset>,
        outcome: Submitted,
        deleting: bool,
    ) -> Result<(), Error> {
        match outcome {
            Submitted::Done => Ok(()),
            Submitted::ZoneMissing => {
                self.forget_zone(zone);
                if deleting {
                    match self.read(zone, name, rtype).await?.found {
                        None => Ok(()),
                        Some(_) => Err(changed(
                            "the hosted zone was replaced between the read and the delete; the \
                             rrset is still there",
                        )),
                    }
                } else {
                    Err(changed(
                        "the hosted zone was removed or replaced between the read and the write",
                    ))
                }
            }
            Submitted::Invalid(refusal) => {
                let now = self
                    .read(zone, name, rtype)
                    .await?
                    .found
                    .map(|found| found.snapshot);
                if now.as_ref() == prior {
                    Err(refusal)
                } else {
                    Err(changed("the rrset changed between the read and the write"))
                }
            }
        }
    }

    /// `list_rrsets`: every rrset of the zone, all pages, under the zone-ID cache.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let (_, all) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| async move { self.api.all_rrsets(&id.id).await },
            )
            .await?;
        let mut listing = Listing::new(zone);
        let mut last_skipped: Option<(Option<DomainName>, String)> = None;
        for set in all {
            let Some(rrset) = set.plain else {
                // One entry per name and type, however many policy sets share them.
                let key = (set.name.clone(), set.rtype.clone());
                if last_skipped.as_ref() != Some(&key) {
                    match set.name.filter(|name| name.is_within(zone)) {
                        Some(name) => {
                            listing.skip(name, &set.rtype, SkipReason::NotPlainRecords);
                        }
                        None => listing.skip(zone.clone(), &set.rtype, SkipReason::UnsupportedName),
                    }
                    last_skipped = Some(key);
                }
                continue;
            };
            last_skipped = None;
            // A type name that maps to no record type is skipped by the listing, whatever the
            // records hold; the values are then never parsed.
            let records: Vec<RecordData> = match set.rtype.parse::<RecordType>() {
                Ok(rtype) => rrset
                    .values
                    .iter()
                    .map(|value| content::read(rtype, value))
                    .collect(),
                Err(_) => rrset
                    .values
                    .iter()
                    .map(|value| RecordData::non_canonical(value))
                    .collect(),
            };
            listing.push(set.name, &set.rtype, ttl(rrset.ttl), records);
        }
        listing.finish(ProviderId::Route53)
    }
}

/// The rrset or the zone changed between the read and the write; nothing was written.
fn changed(text: &'static str) -> Error {
    Error::Conflict {
        detail: Detail::constant(text),
    }
}
