//! TXT value operations: the `WholeSet` shape of the value layer over the rrset API.
//!
//! The rrset is the native unit and is replaced whole, without a condition the provider checks
//! (no ETag, no If-Match), hence `ValueGuarantee::ReadThenWrite`. The value layer takes the
//! per-name lock, reads, computes the new member list and calls [`WholeSet::write`] or
//! [`WholeSet::delete`]; this file maps those onto the API:
//!
//! - read: `GET …/rrset?name=&rrset_types=TXT`, exact name match, under the zone-ID cache;
//! - write without a prior set: `POST …/rrset` in the zone the read used, with the configured
//!   or requested TTL. What the API answers to a create of a name and type that exists is not
//!   documented, so any refusal is followed by a new read: an rrset found there now is
//!   `Error::Conflict` (someone created it after our read; nothing was overwritten), otherwise
//!   the refusal is the error;
//! - write over a prior set: `PATCH …/rrset/{id}` with the full record list, and the TTL, the
//!   comment and the managing resource as read;
//! - delete: `DELETE …/rrset/{id}`, sent once. An rrset cannot be written with no records
//!   (documented `records` range 1 to 100), so the last value is removed by deleting the rrset.
//!   A `404` to it is success only when a new read finds no rrset; the zone may have been
//!   recreated with the rrset in it, and then the value is still published.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Presentation`. The API
//! carries TXT content quoted (lego writes `fmt.Sprintf("%q", value)`; the provider's examples
//! quote TXT), and plain values, the only ones the capabilities accept, need no escape.
//!
//! Disabled records (design section 3.4): a disabled record is not published, so it never counts
//! as holding a value (its decoded value is `None`) and is written back as it was; a value being
//! added that a disabled record already holds is enabled rather than duplicated. A removal
//! therefore leaves a disabled record with the value in place.

use crate::error::Error;
use crate::http::{Attempt, ZoneId};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{Ttl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::values::{Member, SetRead, SetState, TxtBase, TxtRecord, TxtSet, WholeSet, WriteTtl};

use super::api::{NewRrset, Record, Rrset, RrsetUpdate, TXT, Written};
use super::client::SelectelV2;

/// How TXT content is read.
const READ: TxtDialect = TxtDialect::Auto;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Presentation;

/// Most records of one rrset.
// Source: the OpenAPI, `RRSetCreateForm` and `RRSetUpdateForm` (`records`: 1 to 100 items).
const MAX_RECORDS: usize = 100;

impl TxtBase for SelectelV2 {
    fn provider(&self) -> ProviderId {
        ProviderId::SelectelV2
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl WholeSet for SelectelV2 {
    type Handle = Record;
    type Snapshot = Rrset;
    /// The zone identifier the read used.
    type Context = String;

    async fn read(&self, zone: &DomainName, name: &DomainName) -> SetRead<Record, Rrset, String> {
        let (zone_id, rrset) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| self.read_txt(zone, name, id),
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
        members: &[Member<'_, Record>],
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let records = records(members)?;
        match prior {
            None => self.create(zone, name, zone_id, &records, ttl).await,
            Some(prior) => {
                let update = RrsetUpdate {
                    // An existing rrset keeps its TTL (design section 3.6).
                    ttl: prior.ttl,
                    records: &records,
                    comment: prior.comment.as_deref(),
                };
                let managed_by = prior.managed_by.as_deref();
                match self
                    .api
                    .update_rrset(zone_id, &prior.id, managed_by, &update)
                    .await?
                {
                    Written::Done => Ok(()),
                    Written::NotFound => {
                        self.forget_zone(zone);
                        Err(vanished())
                    }
                    Written::Refused(e) => Err(e),
                }
            }
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        zone_id: &String,
        prior: &Rrset,
    ) -> Result<(), Error> {
        match self.api.delete_rrset(zone_id, &prior.id).await? {
            Written::Done => Ok(()),
            // The rrset is gone, or the zone identifier is (a zone recreated with the rrset in
            // it). Only a new read under a freshly looked-up zone tells them apart.
            Written::NotFound => {
                self.forget_zone(zone);
                match self.read(zone, name).await?.set {
                    None => Ok(()),
                    Some(_) => Err(Error::Conflict {
                        detail: Detail::constant(
                            "the TXT rrset was found again after its delete was answered \
                             \"not found\"; the zone changed between the read and the delete",
                        ),
                    }),
                }
            }
            Written::Refused(e) => Err(e),
        }
    }
}

impl SelectelV2 {
    /// Creates the rrset in the zone the read used. Names are sent in Unicode form, absolute
    /// (design section 11.3).
    async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        zone_id: &str,
        records: &[Record],
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let unicode = name.to_unicode();
        let rrset = NewRrset {
            name: &unicode,
            rtype: TXT,
            ttl: self.new_ttl(ttl),
            records,
        };
        let refusal = match self.api.create_rrset(zone_id, &rrset).await? {
            Written::Done => return Ok(()),
            Written::NotFound => {
                self.forget_zone(zone);
                vanished()
            }
            Written::Refused(e) => e,
        };
        // The answer to a duplicate create is not documented: read again. An rrset there now
        // was created by someone else after our read, and nothing of it was overwritten.
        match self.read(zone, name).await?.set {
            Some(_) => Err(Error::Conflict {
                detail: Detail::constant(
                    "an rrset of this name and type was created between the read and the write",
                ),
            }),
            None => Err(refusal),
        }
    }

    /// The read phase under the zone cache: the TXT rrset of `name` in the zone `id`, or
    /// `Stale` when the API does not know the zone (`404`).
    async fn read_txt(
        &self,
        zone: &DomainName,
        name: &DomainName,
        id: ZoneId,
    ) -> Result<Attempt<Option<Rrset>>, Error> {
        let unicode = name.to_unicode();
        let filter = unicode.strip_suffix('.').unwrap_or(&unicode);
        match self.api.rrsets(zone, &id.id, filter, TXT).await {
            Ok(rrsets) => Ok(Attempt::Done(rrsets.into_iter().find(|r| {
                r.rtype == TXT && DomainName::parse(&r.name).as_ref() == Ok(name)
            }))),
            Err(Error::ZoneNotFound { .. }) => Ok(Attempt::Stale),
            Err(e) => Err(e),
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
fn txt_set(rrset: Rrset) -> TxtSet<Record, Rrset> {
    let ttl = Ttl::from_secs(rrset.ttl).ok();
    let records = rrset
        .records
        .iter()
        .map(|record| TxtRecord {
            value: decode(record),
            ttl,
            handle: record.clone(),
        })
        .collect();
    TxtSet {
        records,
        ttl,
        snapshot: rrset,
    }
}

/// The published value of a record: `None` for a disabled record and for content the dialect
/// cannot decode, which are kept as they are and never equal a value.
fn decode(record: &Record) -> Option<Txt> {
    if record.disabled {
        None
    } else {
        READ.read(&record.content)
    }
}

/// The records to write: those kept, unchanged, then the value added, unless a disabled record
/// holds it already, which is enabled instead.
fn records(members: &[Member<'_, Record>]) -> Result<Vec<Record>, Error> {
    let mut records: Vec<Record> = members
        .iter()
        .filter_map(|member| match member {
            Member::Kept(record) => Some(record.handle.clone()),
            Member::Added(_) => None,
        })
        .collect();
    for member in members {
        let Member::Added(value) = member else {
            continue;
        };
        let disabled_copy = records
            .iter_mut()
            .find(|r| r.disabled && READ.read(&r.content).as_ref() == Some(*value));
        match disabled_copy {
            Some(record) => record.disabled = false,
            None => records.push(Record {
                content: WRITE.write(value).ok_or(Error::InvalidInput {
                    detail: Detail::constant("the TXT value cannot be written in this dialect"),
                })?,
                disabled: false,
            }),
        }
    }
    if records.len() > MAX_RECORDS {
        return Err(Error::InvalidInput {
            detail: Detail::constant("a Selectel rrset holds at most 100 records"),
        });
    }
    Ok(records)
}

/// A write addressed a zone or an rrset that no longer exists: it changed after the read, and
/// nothing was written.
fn vanished() -> Error {
    Error::Conflict {
        detail: Detail::constant(
            "the zone or the rrset was removed between the read and the write",
        ),
    }
}
