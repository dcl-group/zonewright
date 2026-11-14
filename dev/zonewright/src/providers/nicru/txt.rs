//! TXT value operations: the `PerRecord` shape of the value layer over the record API, inside
//! the zone protocol that staged changes require.
//!
//! Every TXT value is a record of its own, with an identifier. Adding stages one record and
//! removing stages the deletion of the records that hold the value, by identifier, so a request
//! never names a foreign value: `ValueGuarantee::PerValue`. A staged change is published only by
//! a commit, and a commit publishes every staged change of the zone, whoever made it. The client
//! therefore follows design section 11.3:
//!
//! - (a) a lock per zone, held in the [`Context`](crate::Context) for the whole read, edit and
//!   commit, taken after the per-name lock (design section 3.3);
//! - (b) a zone that has staged changes this process did not make is refused with
//!   `Error::Rejected`, and nothing is committed;
//! - (c) the zone is marked "has our staged changes" in the context before an edit is sent, and
//!   the mark is cleared after a successful commit; a zone with staged changes and the mark is
//!   committed before the operation goes on, which finishes an earlier operation that failed or
//!   was dropped between its edit and its commit (or rolled back, when the mark was left by a
//!   record-level operation that did not finish, see `records.rs`). A zone found without staged changes has its
//!   mark cleared too: nothing of ours can be pending there, and a stale mark must not later
//!   make a foreign edit look like ours;
//! - (d) the commit is tried up to three times; if all fail, `Error::Transient`.
//!
//! The value layer takes the per-name lock and then calls [`PerRecord::read`] and the writes of
//! one operation on an [`Op`], which exists for that one operation: it takes the zone lock in
//! its read and holds it until the operation ends, so the read, the edits and the commits of the
//! operation are one critical section in the zone.
//!
//! - read: `GET /zones` (staged changes of the zone, its service; leftovers of this process
//!   settled by `Nicru::settle_leftovers`), then `GET …/records`, exact name match;
//! - create: mark, `PUT …/records` (sent once), commit;
//! - delete: mark, `DELETE …/records/{id}` (sent once), commit;
//! - a failed edit clears the mark at once when it was certainly refused, and otherwise lists
//!   the zone again: no staged changes clears the mark, staged changes are this edit and are
//!   committed (`Nicru::settle_failed_edit`).
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Raw`, write `Raw`. The API carries each
//! character string as the text of a `string` element; only plain values are written.
//!
//! TTL: the API stores a TTL on every record; one without `<ttl>` has the zone's default and
//! reads as the provider's default. A record added to an existing set gets the smallest
//! explicit TTL read; when the set has none, none is sent and the zone's default applies. A new
//! set asked to have the provider's default is staged without `<ttl>` as well.

use std::sync::{Mutex, PoisonError};

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::{NameGuard, NameLocks};
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{Txt, TxtDialect};
use crate::redact::Detail;
use crate::values::{PerRecord, PerRecordRead, TxtBase, TxtRecord, WriteTtl};

use super::api::TXT;
use super::client::Nicru;
use super::records::{api_ttl, read_ttl};

/// How TXT text is read.
const READ: TxtDialect = TxtDialect::Raw;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Raw;

/// Why a zone with foreign staged changes is refused.
pub(super) const FOREIGN_CHANGES: &str = "the zone has staged changes that this client did not \
     make; a commit would publish them, so nothing is changed until they are committed or rolled \
     back";

/// One TXT value operation: the client, the zone lock once the read has taken it, and the
/// zone's service as the read found it.
pub(super) struct Op<'a> {
    client: &'a Nicru,
    zone_guard: Mutex<Option<NameGuard>>,
    service: Mutex<Option<String>>,
}

impl<'a> Op<'a> {
    /// A new operation of `client`.
    pub(super) fn new(client: &'a Nicru) -> Op<'a> {
        Op {
            client,
            zone_guard: Mutex::new(None),
            service: Mutex::new(None),
        }
    }

    /// Takes the zone lock unless this operation holds it already.
    async fn lock_zone(&self, zone: &DomainName) {
        if self.holds_zone() {
            return;
        }
        let guard = self.client.state().zone_locks.lock(zone).await;
        *self
            .zone_guard
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(guard);
    }

    fn holds_zone(&self) -> bool {
        self.zone_guard
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// The zone's service, as this operation's read found it.
    fn service(&self) -> Result<String, Error> {
        self.service
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or(Error::Protocol {
                detail: Detail::constant("a write was attempted before the zone was read"),
            })
    }
}

impl TxtBase for Op<'_> {
    fn provider(&self) -> ProviderId {
        ProviderId::Nicru
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.client.locks
    }
}

impl PerRecord for Op<'_> {
    /// The record's identifier.
    type Handle = String;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> Result<PerRecordRead<String>, Error> {
        self.lock_zone(zone).await;
        let target = self.client.resolve_zone(zone).await?;
        // Refuses foreign staged changes, and finishes (commits) or discards (rolls back) our
        // own from an earlier operation that failed or was dropped before its end (design
        // section 11.3, points b and c).
        self.client.settle_leftovers(zone, &target).await?;
        *self.service.lock().unwrap_or_else(PoisonError::into_inner) = Some(target.service.clone());
        let records = self
            .client
            .api
            .records(&target.service, zone)
            .await?
            .records
            .into_iter()
            .filter(|rr| rr.rtype.eq_ignore_ascii_case(TXT) && rr.owner.as_ref() == Some(name))
            .map(|rr| TxtRecord {
                value: rr.txt.as_deref().and_then(|text| READ.read(text)),
                ttl: read_ttl(rr.ttl),
                handle: rr.id,
            })
            .collect();
        Ok(PerRecordRead::Records(records))
    }

    async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let text = WRITE.write(value).ok_or(Error::InvalidInput {
            detail: Detail::constant("the TXT value cannot be written in this dialect"),
        })?;
        let owner = match name.relative_to(zone) {
            Some("") => "@",
            Some(relative) => relative,
            None => return Err(Error::name_outside_zone(name.clone(), zone.clone())),
        };
        let ttl = api_ttl(ttl.resolve(self.client.ttl));
        let service = self.service()?;
        // Recorded before the edit is sent (design section 3.2), so that an edit whose answer
        // is lost is recognized as ours.
        self.client.mark(zone);
        match self
            .client
            .api
            .add_txt(&service, zone, owner, &text, ttl)
            .await
        {
            Ok(()) => self.client.commit_own(zone, &service).await,
            Err(failed) => {
                // Even when the staging turns out to have happened and is committed now, the
                // operation reports the edit's error: the repeat reads the zone and reports
                // what is there.
                self.client
                    .settle_failed_edit(zone, &service, failed.refused)
                    .await?;
                Err(failed.error)
            }
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        _name: &DomainName,
        record: &TxtRecord<String>,
    ) -> Result<(), Error> {
        let service = self.service()?;
        self.client.mark(zone);
        match self
            .client
            .api
            .delete_record(&service, zone, &record.handle)
            .await
        {
            Ok(()) => self.client.commit_own(zone, &service).await,
            Err(failed) => {
                // Even when the deletion turns out to have been staged and is committed now,
                // the operation reports the edit's error; its repeat reads the zone.
                self.client
                    .settle_failed_edit(zone, &service, failed.refused)
                    .await?;
                Err(failed.error)
            }
        }
    }
}
