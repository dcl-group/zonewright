//! TXT value operations: the `WholeSet` shape of the value layer over the rrset API.
//!
//! The rrset is the native unit and is replaced whole, without a condition the provider checks
//! (no ETag, no If-Match), hence `ValueGuarantee::ReadThenWrite`. The value layer takes the
//! per-name lock, reads, computes the new member list and calls [`WholeSet::write`] or
//! [`WholeSet::delete`]; this file maps those onto the rrset primitives of `rrset.rs`, which the
//! record layer shares:
//!
//! - read: the TXT rrset of the name;
//! - write without a prior set: a create with the configured or requested TTL;
//! - write over a prior set: an update with the full record list, the TTL as read, and the
//!   comment and the managing resource as read;
//! - delete: an rrset cannot be written with no records (documented `records` range 1 to 100), so
//!   the last value is removed by deleting the rrset.
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
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{RrsetTtl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::values::{Member, SetRead, SetState, TxtBase, TxtRecord, TxtSet, WholeSet, WriteTtl};

use super::api::{Record, Rrset, TXT};
use super::client::SelectelV2;
use super::records::{MAX_RECORDS, TXT_READ};

/// How TXT content is read: the rule the record level reads TXT content with.
const READ: TxtDialect = TXT_READ;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Presentation;

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
        let (zone_id, rrset) = self.read_rrset(zone, name, TXT).await?;
        Ok(SetState {
            context: zone_id,
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
            None => {
                let ttl = self.new_ttl(ttl);
                self.create_rrset(zone, name, TXT, zone_id, &records, ttl)
                    .await
            }
            // An existing rrset keeps its TTL (design section 3.6).
            Some(prior) => {
                self.update_rrset(zone, zone_id, prior, &records, prior.ttl)
                    .await
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
        self.delete_rrset_checked(zone, name, TXT, zone_id, prior)
            .await
    }
}

impl SelectelV2 {
    /// The TTL of a new rrset: the caller's, else the configured one.
    fn new_ttl(&self, ttl: WriteTtl) -> u32 {
        match ttl {
            WriteTtl::New(Some(RrsetTtl::Explicit(ttl)))
            | WriteTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => ttl.as_secs(),
            // No default TTL of its own: the layer never passes it, and the setting stands in.
            WriteTtl::New(None | Some(RrsetTtl::ProviderDefault))
            | WriteTtl::Existing(None | Some(RrsetTtl::ProviderDefault)) => self.ttl,
        }
    }
}

/// The value layer's view of an rrset.
fn txt_set(rrset: Rrset) -> TxtSet<Record, Rrset> {
    let ttl = RrsetTtl::from_secs(rrset.ttl).ok();
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
