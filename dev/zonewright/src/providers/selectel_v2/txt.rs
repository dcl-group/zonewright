//! TXT value operations: the `WholeSet` shape of the value layer over the rrset API.
//!
//! The rrset is the native unit and is replaced whole, without a condition the provider checks
//! (no ETag, no If-Match), hence `ValueGuarantee::ReadThenWrite`. The value layer takes the
//! per-name lock, reads, computes the new member list and calls [`WholeSet::write`] or
//! [`WholeSet::delete`]; this file maps those onto the API:
//!
//! - read: `GET …/rrset?name=&rrset_types=TXT`, exact name match, under the zone-ID cache;
//! - write without a prior set: `POST …/rrset` with the configured or requested TTL;
//! - write over a prior set: `PATCH …/rrset/{id}` with the full record list, the TTL and the
//!   comment as read;
//! - delete: `DELETE …/rrset/{id}`. An rrset cannot be written with no records (documented
//!   `records` range 1 to 100), so the last value is removed by deleting the rrset.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Presentation`. The API
//! carries TXT content quoted (lego writes `fmt.Sprintf("%q", value)`; the provider's examples
//! quote TXT), and plain values, the only ones the capabilities accept, need no escape.
//!
//! Disabled records: a disabled record is not published, so it never counts as holding a value
//! (its decoded value is `None`), it is written back as it was, and a value being added that a
//! disabled record already holds is enabled instead of duplicated (design section 3.4; the
//! earlier implementation did the same).

use crate::error::Error;
use crate::http::{Attempt, ZoneId};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{Ttl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::values::{Member, SetRead, TxtBase, TxtRecord, TxtSet, WholeSet, WriteTtl};

use super::api::{NewRrset, Record, Rrset, RrsetUpdate, TXT, Written};
use super::client::SelectelV2;

/// How TXT content is read.
const READ: TxtDialect = TxtDialect::Auto;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Presentation;

/// Most records of one rrset.
// Source: DNS v2 documentation (`records`: 1 to 100 items).
const MAX_RECORDS: usize = 100;

/// The TXT rrset as read: what the write and the delete address. `pub(crate)`: it is the
/// `Snapshot` of a crate-wide trait.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    /// The zone identifier the read used.
    zone_id: String,
    /// The rrset as the API returned it.
    rrset: Rrset,
}

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
    type Snapshot = Snapshot;

    async fn read(&self, zone: &DomainName, name: &DomainName) -> SetRead<Record, Snapshot> {
        let (zone_id, rrset) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| self.read_txt(zone, name, id),
            )
            .await?;
        Ok(rrset.map(|rrset| txt_set(zone_id.id, rrset)))
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        prior: Option<&Snapshot>,
        members: &[Member<'_, Record>],
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let records = records(members)?;
        let written = match prior {
            None => {
                let zone_id = self.zone_id(zone).await?;
                // Names are sent in Unicode form, absolute (design section 11.3).
                let unicode = name.to_unicode();
                let rrset = NewRrset {
                    name: &unicode,
                    rtype: TXT,
                    ttl: self.new_ttl(ttl),
                    records: &records,
                };
                self.api.create_rrset(&zone_id, &rrset).await?
            }
            Some(prior) => {
                let update = RrsetUpdate {
                    // An existing rrset keeps its TTL (design section 3.6).
                    ttl: prior.rrset.ttl,
                    records: &records,
                    comment: prior.rrset.comment.as_deref(),
                };
                self.api
                    .update_rrset(&prior.zone_id, &prior.rrset.id, &update)
                    .await?
            }
        };
        match written {
            Written::Done => Ok(()),
            Written::NotFound => {
                self.forget_zone(zone);
                Err(vanished())
            }
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        _name: &DomainName,
        prior: &Snapshot,
    ) -> Result<(), Error> {
        match self
            .api
            .delete_rrset(&prior.zone_id, &prior.rrset.id)
            .await?
        {
            Written::Done => Ok(()),
            // The rrset is gone: by an earlier attempt or by someone else (design section 3.5).
            // The zone identifier may be what is gone, so it is looked up again next time.
            Written::NotFound => {
                self.forget_zone(zone);
                Ok(())
            }
        }
    }
}

impl SelectelV2 {
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
fn txt_set(zone_id: String, rrset: Rrset) -> TxtSet<Record, Snapshot> {
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
        snapshot: Snapshot { zone_id, rrset },
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
