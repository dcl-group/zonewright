//! Record-level operations: the `WholeSet` shape of the record layer (`crate::rrsets`) over the
//! record primitives of `rrset.rs`, and the listing of a zone. The mapping between the API's
//! value text and `RecordData` is in `content.rs`.
//!
//! The native unit is one record per name and type holding the list of values ("В зоне можно
//! создать только одну запись с заданным сочетанием имени домена или поддомена и ее типа. При
//! этом у записей может быть несколько значений",
//! <https://cloud.ru/docs/evolution-dns/ug/topics/overview__limitations>), created by one `POST`
//! and replaced whole by one `PATCH` without a condition the provider checks: hence
//! `Preconditions::ReadThenWrite` and `atomic_rrset_write`. The record layer does the checks,
//! takes the per-name lock, reads, evaluates the expectation and computes the member list.
//!
//! # The read again before every write
//!
//! The design gives this provider a second read immediately before every write, which turns a
//! change seen since the first read into `Error::Conflict` (design section 3.5, "re-read
//! first"). Both layers have a hook for it: here [`WholeSet::reread_before_write`], with
//! [`WholeSet::same_snapshot`] comparing the two reads as `api::Record` defines it. The refusals
//! that need the read (a read-only record, a wildcard NS record) are made in
//! [`WholeSet::check_write`], which the layer calls before the second read, so that a refused
//! write sends nothing after the first read. The layer does not repeat a `Conflict` from a
//! read-then-write client, so the caller's repeat starts with a fresh read.
//!
//! # What the model does not carry
//!
//! - The description, the tags and GSLB data without links travel back unchanged on every
//!   update (`rrset.rs`); a new record gets none of them.
//! - A read-only record (`readOnly`) is read like any other and refuses every write with
//!   `Error::Rejected` after the read, before any write request (design section 11.3). The SOA
//!   and the apex NS records are created with the zone and cannot be edited ("кроме
//!   автоматически созданных SOA и NS-записей",
//!   <https://cloud.ru/docs/evolution-dns/ug/topics/guides__edit-record>): SOA is outside
//!   `record_types` (the API's type list has no `soa`, and the page's SOA value form is not
//!   presentation format) and the record layer refuses writes to the apex NS set before any
//!   request.
//! - A record with GSLB links answers from its links, not from a list of values: it is not an
//!   rrset. A listing reports it in `skipped` with `SkipReason::NotPlainRecords`; `get_rrset`,
//!   `set_rrset` and `delete_rrset` at its name and type fail with `Error::Rejected` after their
//!   read and before any write (design section 3.4).
//! - The wildcard flag is part of the owner name (`rrset.rs`). An NS record cannot be a wildcard
//!   ("Опция Wildcard недоступна для NS-записей",
//!   <https://cloud.ru/docs/evolution-dns/ug/topics/guides__add-record>): such a write is
//!   `Error::InvalidInput` before any write request.

use crate::error::Error;
use crate::http::Attempt;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::provider::{SkipReason, ZoneListing};
use crate::record::{RecordData, RecordType, RrsetTtl};
use crate::redact::Detail;
use crate::rrsets::{
    self, Current, Found, Listing, Member, Neighbors, RrsetBase, SetTtl, Stored, WholeChange,
    WholeSet,
};

use super::api::Record;
use super::client::CloudRu;
use super::content;
use super::rrset::{listed_owner, writable};

impl RrsetBase for CloudRu {
    fn provider(&self) -> ProviderId {
        ProviderId::CloudRu
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }

    fn can_send(&self, rtype: RecordType, data: &RecordData) -> bool {
        content::encode(rtype, data).is_some()
    }
}

/// The API's spelling of a type the capabilities accept. Every type in `record_types` has one;
/// another one is an error rather than a panic.
fn api_type(rtype: RecordType) -> Result<&'static str, Error> {
    content::api_type(rtype).ok_or(Error::UnsupportedRecordType {
        provider: ProviderId::CloudRu,
        rtype,
    })
}

/// The TTL a record reports, if it is a valid one.
fn ttl_of(record: &Record) -> Option<RrsetTtl> {
    u32::try_from(record.ttl)
        .ok()
        .and_then(|secs| RrsetTtl::from_secs(secs).ok())
}

/// The record layer's view of a record the API returned.
fn found(rtype: RecordType, record: Record) -> Found<String, Record> {
    let records = record
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
        ttl: ttl_of(&record),
        snapshot: record,
    }
}

/// A record with GSLB links at the name and type (see the module documentation). The TXT value
/// operations refuse such a record in the same way (`txt.rs`).
pub(super) fn not_plain() -> Error {
    Error::Rejected {
        status: None,
        detail: Detail::constant(
            "the record balances between GSLB links; it is not read or changed as an rrset",
        ),
        code: None,
    }
}

impl WholeSet for CloudRu {
    /// A value as the API spells it, written back unchanged.
    type Handle = String;
    type Snapshot = Record;
    /// The zone identifier the read used, and what else the read found at the name.
    type Context = (String, Neighbors);

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Current<String, Record, (String, Neighbors)>, Error> {
        let (zone_id, record, others) = self.read_name(zone, name, api_type(rtype)?).await?;
        if record.as_ref().is_some_and(Record::is_gslb) {
            return Err(not_plain());
        }
        Ok(Current {
            context: (zone_id, Neighbors::of(rtype, others)),
            found: record.map(|record| found(rtype, record)),
        })
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        (zone_id, _): &(String, Neighbors),
        prior: Option<&Record>,
        members: &[Member<'_, String>],
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let api = api_type(rtype)?;
        let values = members
            .iter()
            .map(|member| match member {
                Member::Kept(record) | Member::Enabled(record) => Ok(record.handle.clone()),
                Member::Added(data) => content::encode(rtype, data).ok_or(Error::InvalidInput {
                    detail: Detail::constant(
                        "the provider's encoding of this record data is not established",
                    ),
                    code: None,
                }),
            })
            .collect::<Result<Vec<String>, Error>>()?;
        let ttl = match ttl {
            SetTtl::Requested(RrsetTtl::Explicit(ttl))
            | SetTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => u64::from(ttl.as_secs()),
            // A TTL outside the model's range travels back as read.
            SetTtl::Existing(None | Some(RrsetTtl::ProviderDefault)) => {
                prior.map_or(u64::from(self.ttl), |prior| prior.ttl)
            }
            SetTtl::Default | SetTtl::Requested(RrsetTtl::ProviderDefault) => u64::from(self.ttl),
        };
        match prior {
            None => {
                self.create_record(zone, name, api, zone_id, &values, ttl)
                    .await
            }
            Some(prior) => self.update_record(zone, prior, &values, ttl).await,
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &(String, Neighbors),
        prior: &Record,
    ) -> Result<(), Error> {
        self.delete_record(zone, name, api_type(rtype)?, prior)
            .await
    }

    /// A read-only record, a wildcard NS record and a value without an established encoding are
    /// refused before the second read, so that nothing at all is sent after the first one.
    fn check_write(
        &self,
        _zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &(String, Neighbors),
        change: &WholeChange<'_, String, Record>,
    ) -> Result<(), Error> {
        let (prior, members) = match change {
            WholeChange::Write { prior, members } => (*prior, *members),
            WholeChange::Delete { prior } => (Some(*prior), &[][..]),
        };
        if matches!(change, WholeChange::Write { .. })
            && rtype == RecordType::NS
            && name.is_wildcard()
        {
            return Err(Error::InvalidInput {
                detail: Detail::constant("the provider does not offer wildcard NS records"),
                code: None,
            });
        }
        // `can_send` has accepted every added value; checked here once more so that the write
        // itself cannot fail on an encoding after the second read.
        let unsendable = members.iter().any(|member| match member {
            Member::Added(data) => content::encode(rtype, data).is_none(),
            Member::Kept(_) | Member::Enabled(_) => false,
        });
        if unsendable {
            return Err(Error::InvalidInput {
                detail: Detail::constant(
                    "the provider's encoding of this record data is not established",
                ),
                code: None,
            });
        }
        prior.map_or(Ok(()), writable)
    }

    fn reread_before_write(&self) -> bool {
        true
    }

    fn same_snapshot(&self, first: &Record, again: &Record) -> bool {
        first == again
    }

    fn holds_cname(
        &self,
        _rtype: RecordType,
        (_, neighbors): &(String, Neighbors),
    ) -> Option<bool> {
        neighbors.holds_cname()
    }

    fn holds_other_data(
        &self,
        _rtype: RecordType,
        (_, neighbors): &(String, Neighbors),
    ) -> Option<bool> {
        neighbors.holds_other_data()
    }
}

impl CloudRu {
    /// `list_rrsets`: every record of the zone, all pages, under the zone-ID cache.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let (zone_id, all) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| async move {
                    match self.api.records(zone, &id.id).await {
                        Ok(all) => Ok(Attempt::Done(all)),
                        Err(Error::ZoneNotFound { .. }) => Ok(Attempt::Stale),
                        Err(e) => Err(e),
                    }
                },
            )
            .await?;
        let mut listing = Listing::new(zone);
        for item in all {
            let record: Record = serde_json::from_value(item).map_err(|_| Error::Protocol {
                detail: Detail::constant("the provider's record is not in the expected form"),
            })?;
            if record.public_zone_id.as_deref() != Some(zone_id.id.as_str()) {
                return Err(Error::Protocol {
                    detail: Detail::constant(
                        "the provider's record listing holds a record of another zone",
                    ),
                });
            }
            let type_name = record.rtype.as_deref().unwrap_or_default();
            // `None` for an owner that is not a valid name inside the zone and for an ambiguous
            // spelling (`rrset.rs`): skipped by the listing as `UnsupportedName`, never placed
            // at a guessed name.
            let name = listed_owner(
                zone,
                record.name.as_deref().unwrap_or_default(),
                record.wildcard,
            );
            if record.is_gslb() {
                let name = name.unwrap_or_else(|| zone.clone());
                listing.skip(name, type_name, SkipReason::NotPlainRecords);
                continue;
            }
            // A type name that maps to no record type is skipped by the listing, whatever the
            // values hold; the values are then never parsed.
            let records = match type_name.parse::<RecordType>() {
                Ok(rtype) => record
                    .values
                    .iter()
                    .map(|value| content::read(rtype, value))
                    .collect(),
                Err(_) => record
                    .values
                    .iter()
                    .map(|value| RecordData::non_canonical(value))
                    .collect(),
            };
            listing.push(name, type_name, ttl_of(&record), records);
        }
        listing.finish(ProviderId::CloudRu)
    }
}
