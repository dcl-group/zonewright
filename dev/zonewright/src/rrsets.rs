//! The record-level layer (design sections 3.1 to 3.4 and 3.6).
//!
//! `get_rrset`, `set_rrset` and `delete_rrset` are implemented once, here, over two private
//! traits that match the native shapes of provider APIs; `list_rrsets` gets a builder that turns
//! what a provider reported into a [`ZoneListing`]:
//!
//! - [`WholeSet`]: an rrset written whole in one request. Without a condition the provider checks
//!   (`Preconditions::ReadThenWrite`: Selectel v2, Cloud.ru), or with one (`Preconditions::Atomic`:
//!   the Yandex Cloud strict update, a Route 53 change batch, RFC 2136 prerequisites). The layer
//!   tells them apart by the capabilities: after an [`Error::Conflict`] from an atomic provider it
//!   runs the operation once more from the read, and a second conflict is the result.
//! - [`PerRecord`]: individual records with identifiers (Cloudflare, DigitalOcean); replacing an
//!   rrset is several requests.
//!
//! A client supplies the reads and writes of its API. The checks before any request, the
//! per-name lock, the evaluation of [`Expect`], the "nothing to do" outcomes, the TTL policy, the
//! handling of disabled records and of non-canonical data, and the order of the requests of a
//! per-record replacement are this module's.
//!
//! # Order of a per-record replacement
//!
//! The layer computes every request of a replacement from one read, as a list of [`Step`]s,
//! hands the whole list to [`PerRecord::check_plan`] (which may refuse it before anything is
//! sent), and then sends the steps in the list's order. The order is fixed: within each group
//! below, records that were read go in the order of the read, and new values in the order of
//! [`RrSet::records`] of the requested set (which is sorted).
//!
//! For every type except the singletons (CNAME, SOA, DNAME, ALIAS, ANAME) the groups are, in this
//! order: enabling of disabled records that hold a requested value, TTL changes of records that
//! stay, creates of the missing values, and only then deletes of the surplus records. So the name
//! never loses all its values: the intermediate states are "old values plus some new ones" and
//! "all new values plus some old ones", never fewer published records than either end. If a
//! request fails part-way the error is returned with the rrset holding such a mixture; repeating
//! the call reads the mixture and sends only the remaining difference.
//!
//! A singleton type never has two published records, not even for one request: the surplus
//! records are deleted first. When exactly one value is to be created and the API can change a
//! record in place ([`PerRecord::updates_in_place`]), the last surplus record is kept and changed
//! to the new value instead of being deleted. Otherwise the order is deletes, enables, TTL
//! changes, creates, and a failure between the deletes and the create leaves the name without the
//! record until the call is repeated.
//!
//! # A CNAME and other data at one name
//!
//! A CNAME owner has no other data (RFC 1034 section 3.6.2; RRSIG and NSEC are the exceptions
//! of RFC 4035 section 2.5). The layer reads one name and type, so it learns what else is at the
//! name only from the client: [`PerRecord::holds_cname`] and [`PerRecord::holds_other_data`] (and
//! the same methods of [`WholeSet`]) answer from what the operation's read already returned, and
//! answer `None` (the default) when that read does not tell. When the answer is known, a
//! `set_rrset` of a CNAME at a name with other data, or of another type at a name with a CNAME,
//! is `Error::InvalidInput` after the read and before any write. When it is not known, the write
//! is sent and a refusal by the provider is mapped as any other refusal. No request is made only
//! to find out.
//!
//! # Rules a client keeps when it implements a trait
//!
//! - A read is complete or it fails, and returns every record of the name and type, disabled ones
//!   included ([`Stored::enabled`] false). Values go through
//!   [`RecordData::from_provider`]: text the parser refuses is non-canonical data, never dropped.
//! - The handle (and for a whole set, the snapshot) carries whatever the client needs to write a
//!   record back exactly as the provider returned it, attributes the model does not carry (a
//!   comment, a managing resource) included, or to delete it by identifier.
//! - A delete answered "not found" is not done on the strength of that answer alone, since the
//!   answer can also mean that the zone, or the zone identifier the client used, changed after
//!   the read while the value is still published (design sections 3.5 and 3.8). The client drops
//!   a cached zone identifier and reads again: when the new read no longer finds the deleted
//!   record's value (per-record) or the rrset (whole set), the delete is done; otherwise the
//!   result is [`Error::Conflict`].
//! - Only a conditional write that the provider refused because the rrset changed returns
//!   [`Error::Conflict`] from an atomic provider. A read-then-write client may return it for a
//!   change it detected itself (an rrset created by someone else after the read); the layer does
//!   not repeat it then.
//! - Writes that carry no condition are sent once (design section 5.3).
//!
//! # Plugging a provider in
//!
//! ```text
//! impl RrsetBase for MyClient { provider, capabilities, locks, max_records?, can_send? }
//! impl WholeSet for MyClient {
//!     type Handle = ApiRecord; type Snapshot = ApiRrset; type Context = ZoneId;
//!     async fn read(&self, zone, name, rtype) -> Result<Current<..>, Error>   // GET by name+type
//!     async fn write(&self, zone, name, rtype, ctx, prior, members, ttl)      // POST or PATCH
//!     async fn delete(&self, zone, name, rtype, ctx, prior)                   // DELETE
//!     // optional: check_write, reread_before_write + same_snapshot,
//!     //           holds_cname, holds_other_data
//! }
//! impl Provider for MyClient {
//!     async fn get_rrset(..)    { rrsets::get_whole_set(self, zone, name, rtype).await }
//!     async fn set_rrset(..)    { rrsets::set_whole_set(self, zone, rrset, expect).await }
//!     async fn delete_rrset(..) { rrsets::delete_whole_set(self, zone, name, rtype, expect).await }
//!     async fn list_rrsets(..)  { rrsets::check_list(self, zone)?; let mut b = Listing::new(zone);
//!                                 for item in api_listing { b.push(name, type, ttl, records) }
//!                                 b.finish(self.provider()) }
//! }
//! ```

// A provider uses one of the two shapes. In a build without `all-providers` the other shape can be
// unused; with all providers both are used, and nothing here may be dead (design section 9.2).
#![cfg_attr(not(feature = "all-providers"), allow(dead_code))]

use std::future::Future;

use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::{Capabilities, Preconditions};
use crate::name::DomainName;
use crate::provider::{DeleteOutcome, Expect, SetOutcome, SkipReason, SkippedRrset, ZoneListing};
use crate::record::{RecordData, RecordType, RrSet, Ttl, singleton};
use crate::redact::Detail;

// ---- Shared types --------------------------------------------------------------------------------

/// What every shape provides.
pub(crate) trait RrsetBase: Send + Sync {
    /// The provider, for `Error::Unsupported` and `Error::UnsupportedRecordType`.
    fn provider(&self) -> ProviderId;

    /// The capabilities that decide which operations and types are offered and which TTLs are
    /// accepted.
    fn capabilities(&self) -> &Capabilities;

    /// The per-name locks of the client's `Context`.
    fn locks(&self) -> &NameLocks;

    /// Most records one rrset holds at the provider, disabled ones included. `None`: no
    /// documented limit. A requested set over it is `Error::InvalidInput` before any request; a
    /// write that would exceed it with the disabled records kept is refused after the read.
    fn max_records(&self) -> Option<usize> {
        None
    }

    /// The client can send `data` as a new record of type `rtype`: its encoding of the value is
    /// established. Asked after the read and only for values the provider does not hold already
    /// (those are written back exactly as read, without encoding). False is
    /// `Error::InvalidInput` and nothing is written.
    fn can_send(&self, rtype: RecordType, data: &RecordData) -> bool {
        let _ = (rtype, data);
        true
    }
}

/// One record as the provider returned it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Stored<H> {
    /// The value, through [`RecordData::from_provider`].
    pub(crate) data: RecordData,
    /// False for a record the provider keeps but does not publish (a disabled record). It is
    /// not part of the rrset as read, is never deleted by the layer, and is enabled when a write
    /// asks for its value.
    pub(crate) enabled: bool,
    /// The record's TTL where the API stores one per record (`TtlSupport::PerRecord`); a
    /// whole-set client may leave it `None` and report the TTL in [`Found::ttl`].
    pub(crate) ttl: Option<Ttl>,
    /// What the client needs to write the record back unchanged or delete it.
    pub(crate) handle: H,
}

/// The TTL a write is to carry (design section 3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetTtl {
    /// The caller asked for this TTL.
    Requested(Ttl),
    /// The caller gave none and the rrset exists: its TTL as read. `None`: the provider reported
    /// none; the client sends none, so the provider keeps what it has.
    Existing(Option<Ttl>),
    /// The caller gave none and the rrset is new: the client's configured default (which may
    /// be "let the provider choose").
    Default,
}

// ---- Whole-set shape -----------------------------------------------------------------------------

/// An rrset as a [`WholeSet`] read found it.
#[derive(Clone, Debug)]
pub(crate) struct Found<H, S> {
    /// Every record, disabled ones included. Empty only if the provider keeps an rrset without
    /// records, which then reads as absent.
    pub(crate) records: Vec<Stored<H>>,
    /// The rrset's TTL, if the provider reports one. Where the API stores a TTL per record
    /// (`TtlSupport::PerRecord`), the smallest of them; the records then carry their own in
    /// [`Stored::ttl`], and a requested TTL counts as already set only when every record that
    /// states one has it.
    pub(crate) ttl: Option<Ttl>,
    /// The rrset as the client read it: what a write sends back for attributes the model does
    /// not carry, and what a conditional write sends as its condition.
    pub(crate) snapshot: S,
}

/// What a [`WholeSet`] read returned.
#[derive(Clone, Debug)]
pub(crate) struct Current<H, S, C> {
    /// What the read learned that every write needs, such as the zone identifier it used.
    pub(crate) context: C,
    /// The rrset at the provider, or `None` when there is none.
    pub(crate) found: Option<Found<H, S>>,
}

/// One member of a whole set to be written, in the order the client sends them: the records read
/// in the provider's order, then the new values in the order of the requested set.
#[derive(Debug)]
pub(crate) enum Member<'a, H> {
    /// A record that was read, written back exactly as the provider returned it (a disabled one
    /// stays disabled).
    Kept(&'a Stored<H>),
    /// A disabled record that holds a requested value, written back enabled and otherwise
    /// unchanged.
    Enabled(&'a Stored<H>),
    /// A value the provider does not hold, encoded by the client. Always canonical, and
    /// [`RrsetBase::can_send`] accepted it.
    Added(&'a RecordData),
}

/// What a [`WholeSet`] operation is about to send, as [`WholeSet::check_write`] sees it.
#[derive(Debug)]
pub(crate) enum WholeChange<'a, H, S> {
    /// [`WholeSet::write`] with these arguments.
    Write {
        /// The rrset as read; `None`: the write creates it.
        prior: Option<&'a S>,
        /// The members of the rrset after the write.
        members: &'a [Member<'a, H>],
    },
    /// [`WholeSet::delete`] of the rrset as read.
    Delete {
        /// The rrset as read.
        prior: &'a S,
    },
}

/// The answer of [`WholeSet::read`].
pub(crate) type WholeRead<B> = Result<
    Current<<B as WholeSet>::Handle, <B as WholeSet>::Snapshot, <B as WholeSet>::Context>,
    Error,
>;

/// An rrset written whole in one request.
pub(crate) trait WholeSet: RrsetBase {
    /// Identifies one record as the provider spells it.
    type Handle: Send + Sync;
    /// The rrset as read.
    type Snapshot: Send + Sync;
    /// What the read hands to every write ([`Current::context`]).
    type Context: Send + Sync;

    /// The rrset of `name` and `rtype`, or `None`, with the read's context.
    fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> impl Future<Output = WholeRead<Self>> + Send;

    /// Writes the rrset with exactly `members`. `prior` is the rrset as read (`None`: there was
    /// none, the write creates it); an atomic client makes the write conditional on it, also on
    /// its absence.
    #[allow(clippy::too_many_arguments)] // Reason: the operation's key plus the read's results.
    fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        context: &Self::Context,
        prior: Option<&Self::Snapshot>,
        members: &[Member<'_, Self::Handle>],
        ttl: SetTtl,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Deletes the rrset; an atomic client makes the delete conditional on `prior`. A "not
    /// found" answer is done only when a new read finds no rrset (module documentation).
    fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        context: &Self::Context,
        prior: &Self::Snapshot,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Called after the read and the layer's own checks, before any further request, with what
    /// is about to be sent. An error ends the operation with nothing more sent, not even the
    /// read of [`WholeSet::reread_before_write`]. For refusals that need the read (a read-only
    /// rrset, a combination the API does not offer). The default accepts everything.
    fn check_write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        context: &Self::Context,
        change: &WholeChange<'_, Self::Handle, Self::Snapshot>,
    ) -> Result<(), Error> {
        let _ = (zone, name, rtype, context, change);
        Ok(())
    }

    /// Read the rrset again immediately before each write or delete, after
    /// [`WholeSet::check_write`]: when [`WholeSet::same_snapshot`] says it changed since the
    /// first read (or it appeared or vanished), the result is `Error::Conflict` and nothing is
    /// written (design section 3.5, "re-read first"). The layer does not repeat that `Conflict`
    /// for a read-then-write provider; the caller's repeat starts with a fresh read. Default:
    /// no second read.
    fn reread_before_write(&self) -> bool {
        false
    }

    /// The rrset read first and the rrset read again are the same: nothing a write would carry
    /// differs. Asked only when [`WholeSet::reread_before_write`] is true; a client that turns
    /// that on implements this. The default answers "changed", so that a missing implementation
    /// can only refuse a write, never let one through.
    fn same_snapshot(&self, first: &Self::Snapshot, again: &Self::Snapshot) -> bool {
        let _ = (first, again);
        false
    }

    /// The read that produced `context` found a published CNAME at the name, the operation
    /// being about `rtype`, another type. `None` (the default): the read does not tell. See
    /// the module documentation, "A CNAME and other data at one name".
    fn holds_cname(&self, rtype: RecordType, context: &Self::Context) -> Option<bool> {
        let _ = (rtype, context);
        None
    }

    /// The read that produced `context` found published data at the name of a type other than
    /// CNAME, `rtype`, RRSIG and NSEC. `None` (the default): the read does not tell.
    fn holds_other_data(&self, rtype: RecordType, context: &Self::Context) -> Option<bool> {
        let _ = (rtype, context);
        None
    }
}

// ---- Per-record shape ----------------------------------------------------------------------------

/// What a [`PerRecord`] read returned.
#[derive(Clone, Debug)]
pub(crate) struct RecordsRead<H, C> {
    /// What the read learned that every write needs.
    pub(crate) context: C,
    /// Every record of the name and type, disabled ones included; empty when there is none.
    pub(crate) records: Vec<Stored<H>>,
}

/// A change to one existing record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecordUpdate<'a> {
    /// Enable the record (it was disabled).
    pub(crate) enable: bool,
    /// The new TTL; `None` keeps the record's own.
    pub(crate) ttl: Option<Ttl>,
    /// New content, for the in-place replacement of a singleton; `None` keeps the content.
    pub(crate) data: Option<&'a RecordData>,
}

/// One request of a per-record write, as computed from the read (module documentation, "Order
/// of a per-record replacement").
#[derive(Debug)]
pub(crate) enum Step<'a, H> {
    /// [`PerRecord::update`] of `record` with `update`.
    Update {
        /// The record as read.
        record: &'a Stored<H>,
        /// The change.
        update: RecordUpdate<'a>,
    },
    /// [`PerRecord::create`] of `data` with `ttl`.
    Create {
        /// The new value.
        data: &'a RecordData,
        /// The TTL the record gets.
        ttl: SetTtl,
    },
    /// [`PerRecord::delete`] of the record as read.
    Delete(&'a Stored<H>),
}

/// Individual records with identifiers.
pub(crate) trait PerRecord: RrsetBase {
    /// Identifies one record (its identifier and whatever else a write back needs).
    type Handle: Send + Sync;
    /// What the read hands to every write.
    type Context: Send + Sync;

    /// Every record of `name` and `rtype`.
    fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> impl Future<Output = Result<RecordsRead<Self::Handle, Self::Context>, Error>> + Send;

    /// Creates one record. Always canonical data that [`RrsetBase::can_send`] accepted.
    fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        context: &Self::Context,
        data: &RecordData,
        ttl: SetTtl,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Changes one record, keeping every attribute `update` does not name.
    fn update(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        context: &Self::Context,
        record: &Stored<Self::Handle>,
        update: &RecordUpdate<'_>,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Deletes one record by identifier. A "not found" answer is done only when a new read no
    /// longer finds the record's value; when it does, the zone changed after the read and the
    /// result is `Error::Conflict` (module documentation).
    fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        context: &Self::Context,
        record: &Stored<Self::Handle>,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// The API can change the content of a record in place, so a singleton is replaced by one
    /// update instead of a delete followed by a create.
    fn updates_in_place(&self) -> bool {
        true
    }

    /// Called with every request of a `set_rrset` or a `delete_rrset`, in the order they will
    /// be sent, after the read and the layer's own checks and before the first write. An error
    /// ends the operation with nothing written, so a request the API is known to refuse (a TTL
    /// change of a record whose TTL cannot be changed, a combination of attributes) does not
    /// fail after earlier requests of the same plan were applied. The default accepts every
    /// plan.
    fn check_plan(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        context: &Self::Context,
        steps: &[Step<'_, Self::Handle>],
    ) -> Result<(), Error> {
        let _ = (zone, name, rtype, context, steps);
        Ok(())
    }

    /// The read that produced `context` found a published CNAME at the name, the operation
    /// being about `rtype`, another type. `None` (the default): the read does not tell. See
    /// the module documentation, "A CNAME and other data at one name".
    fn holds_cname(&self, rtype: RecordType, context: &Self::Context) -> Option<bool> {
        let _ = (rtype, context);
        None
    }

    /// The read that produced `context` found published data at the name of a type other than
    /// CNAME, `rtype`, RRSIG and NSEC. `None` (the default): the read does not tell.
    fn holds_other_data(&self, rtype: RecordType, context: &Self::Context) -> Option<bool> {
        let _ = (rtype, context);
        None
    }
}

// ---- Checks before any request (design section 3.1) ----------------------------------------------

/// How many times an operation runs at a provider with atomic preconditions: once, and once more
/// after the provider refused the write because the rrset changed (design section 3.4).
const ATOMIC_ATTEMPTS: usize = 2;

fn invalid(text: &'static str) -> Error {
    Error::InvalidInput {
        detail: Detail::constant(text),
    }
}

fn precondition_failed(text: &'static str) -> Error {
    Error::PreconditionFailed {
        detail: Detail::constant(text),
    }
}

/// Checks 1 to 3 of design section 3.1 for an operation on one name and type. A query or meta
/// type is `InvalidInput` (design section 2.2) whatever the capabilities say, so the type check of
/// step 1 leaves it to step 2. SOA is never writable (design section 3.4), whatever a provider's
/// type set says.
fn check_target<B: RrsetBase>(
    backend: &B,
    operation: Operation,
    zone: &DomainName,
    name: &DomainName,
    rtype: RecordType,
) -> Result<(), Error> {
    let caps = backend.capabilities();
    if !caps.supports(operation) {
        return Err(Error::unsupported(backend.provider(), operation));
    }
    if !rtype.is_meta() {
        let accepted = match operation {
            Operation::GetRrset => caps.can_read(rtype),
            _ => caps.can_write(rtype) && rtype != RecordType::SOA,
        };
        if !accepted {
            return Err(Error::unsupported_record_type(backend.provider(), rtype));
        }
    }
    check_zone(zone)?;
    if rtype.is_meta() {
        return Err(invalid(
            "query and meta record types cannot be read or written",
        ));
    }
    if !name.is_within(zone) {
        return Err(Error::name_outside_zone(name.clone(), zone.clone()));
    }
    Ok(())
}

fn check_zone(zone: &DomainName) -> Result<(), Error> {
    if zone.is_root() || zone.is_wildcard() {
        return Err(invalid("the zone must not be the root or a wildcard name"));
    }
    Ok(())
}

/// Check 4 shared by writes: the apex NS set belongs to the provider (design section 3.4), and
/// an `Expect::Matches` set must be about the operation's name and type.
fn check_write(
    zone: &DomainName,
    name: &DomainName,
    rtype: RecordType,
    expect: Expect<'_>,
) -> Result<(), Error> {
    if rtype == RecordType::NS && name == zone {
        return Err(invalid("the NS rrset at the zone apex is not writable"));
    }
    if let Expect::Matches(prev) = expect
        && (prev.name() != name || prev.rtype() != rtype)
    {
        return Err(invalid(
            "the expected rrset has another name or type than the operation",
        ));
    }
    Ok(())
}

fn check_set<B: RrsetBase>(
    backend: &B,
    zone: &DomainName,
    rrset: &RrSet,
    expect: Expect<'_>,
) -> Result<(), Error> {
    let (name, rtype) = (rrset.name(), rrset.rtype());
    check_target(backend, Operation::SetRrset, zone, name, rtype)?;
    check_write(zone, name, rtype, expect)?;
    if let Some(ttl) = rrset.ttl()
        && !backend.capabilities().ttl.accepts(ttl.as_secs())
    {
        return Err(invalid("the TTL is outside the range the provider accepts"));
    }
    if backend
        .max_records()
        .is_some_and(|max| rrset.records().len() > max)
    {
        return Err(invalid(
            "the rrset has more records than the provider accepts",
        ));
    }
    Ok(())
}

fn check_delete<B: RrsetBase>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    rtype: RecordType,
    expect: Expect<'_>,
) -> Result<(), Error> {
    check_target(backend, Operation::DeleteRrset, zone, name, rtype)?;
    if matches!(expect, Expect::Absent) {
        return Err(invalid("Expect::Absent has no meaning for a delete"));
    }
    check_write(zone, name, rtype, expect)
}

/// The checks of `list_rrsets` (design section 3.1, steps 1 and 2).
pub(crate) fn check_list<B: RrsetBase>(backend: &B, zone: &DomainName) -> Result<(), Error> {
    if !backend.capabilities().supports(Operation::ListRrsets) {
        return Err(Error::unsupported(
            backend.provider(),
            Operation::ListRrsets,
        ));
    }
    check_zone(zone)
}

// ---- Evaluation ----------------------------------------------------------------------------------

/// The published rrset: the enabled records, with `ttl`. `None` when no record is enabled. A set
/// the model cannot hold (two records of a singleton type) is `Error::Protocol`.
pub(crate) fn published<H>(
    name: &DomainName,
    rtype: RecordType,
    ttl: Option<Ttl>,
    records: &[Stored<H>],
) -> Result<Option<RrSet>, Error> {
    let data: Vec<RecordData> = records
        .iter()
        .filter(|record| record.enabled)
        .map(|record| record.data.clone())
        .collect();
    if data.is_empty() {
        return Ok(None);
    }
    RrSet::new(name.clone(), rtype, ttl, data)
        .map(Some)
        .map_err(|_| Error::Protocol {
            detail: Detail::constant("the provider returned an rrset the record model cannot hold"),
        })
}

/// The smallest TTL among the enabled records (design section 3.6, `TtlSupport::PerRecord`).
fn smallest_ttl<H>(records: &[Stored<H>]) -> Option<Ttl> {
    Listing::smallest_ttl(
        records
            .iter()
            .filter(|record| record.enabled)
            .map(|record| record.ttl),
    )
}

/// Step 2 of `set_rrset` (design section 3.4), also used by `delete_rrset`.
fn evaluate(expect: Expect<'_>, current: Option<&RrSet>) -> Result<(), Error> {
    match (expect, current) {
        (Expect::Absent, Some(_)) => Err(precondition_failed(
            "the rrset exists, and the operation expected none",
        )),
        (Expect::Matches(_), None) => Err(precondition_failed(
            "the rrset does not exist, and the operation expected it to",
        )),
        (Expect::Matches(prev), Some(current)) => {
            if !prev.same_records(current) {
                Err(precondition_failed(
                    "the records of the rrset differ from the expected ones",
                ))
            } else if prev.ttl().is_some() && prev.ttl() != current.ttl() {
                Err(precondition_failed(
                    "the TTL of the rrset differs from the expected one",
                ))
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

/// Step 3: the rrset is already as requested (members, and the TTL when one is requested).
///
/// A requested TTL must be the rrset's TTL as read and also the TTL of every enabled record
/// that states one of its own: where the API stores a TTL per record the rrset reports the
/// smallest (design section 3.6), so the rrset's TTL alone can match while another record
/// differs. `per_record`: a record that states no TTL does not have the requested one (an
/// individual record without a TTL is one whose TTL the provider chooses); otherwise such a
/// record takes the rrset's TTL.
fn unchanged<H>(
    current: Option<&RrSet>,
    wanted: &RrSet,
    records: &[Stored<H>],
    per_record: bool,
) -> bool {
    current.is_some_and(|current| {
        current.same_records(wanted)
            && wanted.ttl().is_none_or(|ttl| {
                current.ttl() == Some(ttl)
                    && records
                        .iter()
                        .filter(|record| record.enabled)
                        .all(|record| record.ttl.map_or(!per_record, |own| own == ttl))
            })
    })
}

/// The CNAME rule of RFC 1034 section 3.6.2, where the client can tell what else is at the name
/// (module documentation).
fn check_coexistence(
    rtype: RecordType,
    holds_cname: Option<bool>,
    holds_other_data: Option<bool>,
) -> Result<(), Error> {
    if rtype == RecordType::CNAME && holds_other_data == Some(true) {
        return Err(invalid(
            "a CNAME cannot be written at a name that holds data of other types",
        ));
    }
    // RRSIG (46) and NSEC (47) may share a name with a CNAME (RFC 4035 section 2.5).
    let beside_cname = matches!(rtype.code(), Some(46 | 47));
    if rtype != RecordType::CNAME && !beside_cname && holds_cname == Some(true) {
        return Err(invalid(
            "the name holds a CNAME, which cannot share its name with other data",
        ));
    }
    Ok(())
}

/// A requested value the provider does not hold: it must be canonical (design section 4.9) and
/// one the client can send.
fn check_new<B: RrsetBase>(backend: &B, rtype: RecordType, data: &RecordData) -> Result<(), Error> {
    if !data.is_canonical() {
        return Err(invalid(
            "non-canonical record data can only be written to an rrset that holds a record with \
             exactly that text",
        ));
    }
    if !backend.can_send(rtype, data) {
        return Err(invalid(
            "the provider's encoding of this record data is not established",
        ));
    }
    Ok(())
}

fn too_many() -> Error {
    invalid("the rrset would hold more records than the provider accepts")
}

/// Runs `once` again after an `Error::Conflict` when the provider checks preconditions
/// atomically (design section 3.4).
fn repeat_after_conflict<B: RrsetBase>(backend: &B, attempt: usize) -> bool {
    backend.capabilities().preconditions == Preconditions::Atomic && attempt < ATOMIC_ATTEMPTS
}

// ---- Whole-set operations ------------------------------------------------------------------------

/// `get_rrset` for a [`WholeSet`] provider. Takes no lock.
pub(crate) async fn get_whole_set<B: WholeSet>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    rtype: RecordType,
) -> Result<Option<RrSet>, Error> {
    check_target(backend, Operation::GetRrset, zone, name, rtype)?;
    match backend.read(zone, name, rtype).await?.found {
        Some(found) => published(name, rtype, found.ttl, &found.records),
        None => Ok(None),
    }
}

/// `set_rrset` for a [`WholeSet`] provider.
pub(crate) async fn set_whole_set<B: WholeSet>(
    backend: &B,
    zone: &DomainName,
    rrset: &RrSet,
    expect: Expect<'_>,
) -> Result<SetOutcome, Error> {
    check_set(backend, zone, rrset, expect)?;
    let _guard = backend.locks().lock(rrset.name()).await;
    let mut attempt = 1;
    loop {
        match set_whole_set_once(backend, zone, rrset, expect).await {
            Err(Error::Conflict { .. }) if repeat_after_conflict(backend, attempt) => attempt += 1,
            result => return result,
        }
    }
}

/// The member list that makes the published set equal `wanted`: every record read, in order
/// (enabled records with a wanted value kept, other enabled records left out, disabled records
/// kept disabled unless they hold a wanted value no enabled record holds, which enables the
/// first of them), then the wanted values the provider does not hold.
fn whole_set_members<'a, B: RrsetBase, H>(
    backend: &B,
    rtype: RecordType,
    records: &'a [Stored<H>],
    wanted: &'a RrSet,
) -> Result<Vec<Member<'a, H>>, Error> {
    let mut covered = vec![false; wanted.records().len()];
    let position = |data: &RecordData| wanted.records().iter().position(|w| w == data);
    for record in records.iter().filter(|r| r.enabled) {
        if let Some(slot) = position(&record.data).and_then(|i| covered.get_mut(i)) {
            *slot = true;
        }
    }
    let mut members = Vec::with_capacity(records.len() + wanted.records().len());
    for record in records {
        let index = position(&record.data);
        if record.enabled {
            if index.is_some() {
                members.push(Member::Kept(record));
            }
            continue;
        }
        match index.and_then(|i| covered.get_mut(i)) {
            Some(slot) if !*slot => {
                *slot = true;
                members.push(Member::Enabled(record));
            }
            _ => members.push(Member::Kept(record)),
        }
    }
    for (data, done) in wanted.records().iter().zip(&covered) {
        if !done {
            check_new(backend, rtype, data)?;
            members.push(Member::Added(data));
        }
    }
    if backend.max_records().is_some_and(|max| members.len() > max) {
        return Err(too_many());
    }
    Ok(members)
}

async fn set_whole_set_once<B: WholeSet>(
    backend: &B,
    zone: &DomainName,
    wanted: &RrSet,
    expect: Expect<'_>,
) -> Result<SetOutcome, Error> {
    let (name, rtype) = (wanted.name(), wanted.rtype());
    let current = backend.read(zone, name, rtype).await?;
    let found = current.found.as_ref();
    let published = match found {
        Some(found) => published(name, rtype, found.ttl, &found.records)?,
        None => None,
    };
    evaluate(expect, published.as_ref())?;
    let records = found.map_or(&[][..], |found| found.records.as_slice());
    if unchanged(published.as_ref(), wanted, records, false) {
        return Ok(SetOutcome::Unchanged);
    }
    let context = &current.context;
    check_coexistence(
        rtype,
        backend.holds_cname(rtype, context),
        backend.holds_other_data(rtype, context),
    )?;
    let members = whole_set_members(backend, rtype, records, wanted)?;
    let ttl = match (wanted.ttl(), found) {
        (Some(ttl), _) => SetTtl::Requested(ttl),
        (None, Some(found)) => SetTtl::Existing(found.ttl),
        (None, None) => SetTtl::Default,
    };
    let prior = found.map(|found| &found.snapshot);
    let change = WholeChange::Write {
        prior,
        members: &members,
    };
    backend.check_write(zone, name, rtype, context, &change)?;
    reread_unchanged(backend, zone, name, rtype, prior).await?;
    backend
        .write(zone, name, rtype, context, prior, &members, ttl)
        .await?;
    Ok(if published.is_some() {
        SetOutcome::Replaced
    } else {
        SetOutcome::Created
    })
}

/// `delete_rrset` for a [`WholeSet`] provider. Disabled records are not published values and
/// stay: when there are any, the rrset is written with them alone instead of being deleted.
pub(crate) async fn delete_whole_set<B: WholeSet>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    rtype: RecordType,
    expect: Expect<'_>,
) -> Result<DeleteOutcome, Error> {
    check_delete(backend, zone, name, rtype, expect)?;
    let _guard = backend.locks().lock(name).await;
    let mut attempt = 1;
    loop {
        match delete_whole_set_once(backend, zone, name, rtype, expect).await {
            Err(Error::Conflict { .. }) if repeat_after_conflict(backend, attempt) => attempt += 1,
            result => return result,
        }
    }
}

async fn delete_whole_set_once<B: WholeSet>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    rtype: RecordType,
    expect: Expect<'_>,
) -> Result<DeleteOutcome, Error> {
    let current = backend.read(zone, name, rtype).await?;
    let Some(found) = current.found.as_ref() else {
        evaluate(expect, None)?;
        return Ok(DeleteOutcome::NotPresent);
    };
    let published = published(name, rtype, found.ttl, &found.records)?;
    evaluate(expect, published.as_ref())?;
    if published.is_none() {
        return Ok(DeleteOutcome::NotPresent);
    }
    let context = &current.context;
    let prior = &found.snapshot;
    let disabled: Vec<Member<'_, B::Handle>> = found
        .records
        .iter()
        .filter(|record| !record.enabled)
        .map(Member::Kept)
        .collect();
    let ttl = SetTtl::Existing(found.ttl);
    let change = if disabled.is_empty() {
        WholeChange::Delete { prior }
    } else {
        WholeChange::Write {
            prior: Some(prior),
            members: &disabled,
        }
    };
    backend.check_write(zone, name, rtype, context, &change)?;
    reread_unchanged(backend, zone, name, rtype, Some(prior)).await?;
    if disabled.is_empty() {
        backend.delete(zone, name, rtype, context, prior).await?;
    } else {
        backend
            .write(zone, name, rtype, context, Some(prior), &disabled, ttl)
            .await?;
    }
    Ok(DeleteOutcome::Deleted)
}

/// For [`WholeSet::reread_before_write`]: reads again and fails with `Error::Conflict` unless
/// the rrset is as it was (`prior`; `None`: there was none).
async fn reread_unchanged<B: WholeSet>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    rtype: RecordType,
    prior: Option<&B::Snapshot>,
) -> Result<(), Error> {
    if !backend.reread_before_write() {
        return Ok(());
    }
    let again = backend.read(zone, name, rtype).await?;
    let same = match (prior, again.found.as_ref()) {
        (None, None) => true,
        (Some(prior), Some(found)) => backend.same_snapshot(prior, &found.snapshot),
        _ => false,
    };
    if same {
        Ok(())
    } else {
        Err(Error::Conflict {
            detail: Detail::constant("the rrset changed between the read and the write"),
        })
    }
}

// ---- Per-record operations -----------------------------------------------------------------------

/// `get_rrset` for a [`PerRecord`] provider. Takes no lock. The TTL is the smallest of the
/// enabled records.
pub(crate) async fn get_per_record<B: PerRecord>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    rtype: RecordType,
) -> Result<Option<RrSet>, Error> {
    check_target(backend, Operation::GetRrset, zone, name, rtype)?;
    let read = backend.read(zone, name, rtype).await?;
    published(name, rtype, smallest_ttl(&read.records), &read.records)
}

/// `set_rrset` for a [`PerRecord`] provider (see the module documentation for the order of the
/// requests).
pub(crate) async fn set_per_record<B: PerRecord>(
    backend: &B,
    zone: &DomainName,
    rrset: &RrSet,
    expect: Expect<'_>,
) -> Result<SetOutcome, Error> {
    check_set(backend, zone, rrset, expect)?;
    let _guard = backend.locks().lock(rrset.name()).await;
    let mut attempt = 1;
    loop {
        match set_per_record_once(backend, zone, rrset, expect).await {
            Err(Error::Conflict { .. }) if repeat_after_conflict(backend, attempt) => attempt += 1,
            result => return result,
        }
    }
}

/// The requests of a per-record replacement, computed from one read.
struct Plan<'a, H> {
    /// Disabled records with a wanted value: enabled (with the target TTL if one applies).
    enable: Vec<&'a Stored<H>>,
    /// Enabled records that stay but need the requested TTL.
    retune: Vec<&'a Stored<H>>,
    /// Wanted values the provider does not hold.
    create: Vec<&'a RecordData>,
    /// Enabled records whose value is not wanted.
    delete: Vec<&'a Stored<H>>,
}

fn per_record_plan<'a, B: RrsetBase, H>(
    backend: &B,
    rtype: RecordType,
    records: &'a [Stored<H>],
    wanted: &'a RrSet,
) -> Result<Plan<'a, H>, Error> {
    let mut covered = vec![false; wanted.records().len()];
    let position = |data: &RecordData| wanted.records().iter().position(|w| w == data);
    let mut plan = Plan {
        enable: Vec::new(),
        retune: Vec::new(),
        create: Vec::new(),
        delete: Vec::new(),
    };
    for record in records.iter().filter(|r| r.enabled) {
        match position(&record.data) {
            Some(index) => {
                if let Some(slot) = covered.get_mut(index) {
                    *slot = true;
                }
                if let Some(ttl) = wanted.ttl()
                    && record.ttl != Some(ttl)
                {
                    plan.retune.push(record);
                }
            }
            None => plan.delete.push(record),
        }
    }
    for record in records.iter().filter(|r| !r.enabled) {
        if let Some(slot) = position(&record.data).and_then(|i| covered.get_mut(i))
            && !*slot
        {
            *slot = true;
            plan.enable.push(record);
        }
    }
    for (data, done) in wanted.records().iter().zip(&covered) {
        if !done {
            check_new(backend, rtype, data)?;
            plan.create.push(data);
        }
    }
    let after = records.len() + plan.create.len();
    if backend.max_records().is_some_and(|max| after > max) {
        return Err(too_many());
    }
    Ok(plan)
}

async fn set_per_record_once<B: PerRecord>(
    backend: &B,
    zone: &DomainName,
    wanted: &RrSet,
    expect: Expect<'_>,
) -> Result<SetOutcome, Error> {
    let (name, rtype) = (wanted.name(), wanted.rtype());
    let read = backend.read(zone, name, rtype).await?;
    let context = &read.context;
    let current_ttl = smallest_ttl(&read.records);
    let published = published(name, rtype, current_ttl, &read.records)?;
    evaluate(expect, published.as_ref())?;
    if unchanged(published.as_ref(), wanted, &read.records, true) {
        return Ok(SetOutcome::Unchanged);
    }
    check_coexistence(
        rtype,
        backend.holds_cname(rtype, context),
        backend.holds_other_data(rtype, context),
    )?;
    let plan = per_record_plan(backend, rtype, &read.records, wanted)?;
    let ttl = match wanted.ttl() {
        Some(ttl) => SetTtl::Requested(ttl),
        None if published.is_some() => SetTtl::Existing(current_ttl),
        None => SetTtl::Default,
    };
    let steps = plan.steps(rtype, wanted.ttl(), ttl, backend.updates_in_place());
    backend.check_plan(zone, name, rtype, context, &steps)?;
    send_steps(backend, zone, name, rtype, context, &steps).await?;
    Ok(if published.is_some() {
        SetOutcome::Replaced
    } else {
        SetOutcome::Created
    })
}

impl<'a, H> Plan<'a, H> {
    /// The requests of the plan in the order they are sent (module documentation). `requested`
    /// is the caller's TTL, `ttl` what a new record gets.
    fn steps(
        self,
        rtype: RecordType,
        requested: Option<Ttl>,
        ttl: SetTtl,
        in_place: bool,
    ) -> Vec<Step<'a, H>> {
        // A record that is enabled gets the TTL a new record would get, so that it matches the
        // rest of the set.
        let enable_ttl = match ttl {
            SetTtl::Requested(ttl) => Some(ttl),
            SetTtl::Existing(ttl) => ttl,
            SetTtl::Default => None,
        };
        let enable = |record| Step::Update {
            record,
            update: RecordUpdate {
                enable: true,
                ttl: enable_ttl,
                data: None,
            },
        };
        let retune = |record| Step::Update {
            record,
            update: RecordUpdate {
                enable: false,
                ttl: requested,
                data: None,
            },
        };
        let create = |data| Step::Create { data, ttl };
        let Plan {
            enable: enabled,
            retune: retuned,
            create: created,
            delete: mut deleted,
        } = self;
        let mut steps =
            Vec::with_capacity(enabled.len() + retuned.len() + created.len() + deleted.len());
        if !singleton(rtype) {
            // Deletes last: the name never loses all its values.
            steps.extend(enabled.into_iter().map(enable));
            steps.extend(retuned.into_iter().map(retune));
            steps.extend(created.into_iter().map(create));
            steps.extend(deleted.into_iter().map(Step::Delete));
            return steps;
        }
        // A singleton: never two published records, so the surplus goes first; the last of it
        // is changed in place to the one new value where the API can.
        let in_place_target = match (in_place, enabled.is_empty(), created.as_slice()) {
            (true, true, [new]) => deleted.pop().map(|old| (old, *new)),
            _ => None,
        };
        steps.extend(deleted.into_iter().map(Step::Delete));
        if let Some((old, new)) = in_place_target {
            steps.push(Step::Update {
                record: old,
                update: RecordUpdate {
                    enable: false,
                    ttl: requested,
                    data: Some(new),
                },
            });
            steps.extend(retuned.into_iter().map(retune));
            return steps;
        }
        steps.extend(enabled.into_iter().map(enable));
        steps.extend(retuned.into_iter().map(retune));
        steps.extend(created.into_iter().map(create));
        steps
    }
}

/// Sends `steps` in order; the first error ends the sequence.
async fn send_steps<B: PerRecord>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    rtype: RecordType,
    context: &B::Context,
    steps: &[Step<'_, B::Handle>],
) -> Result<(), Error> {
    for step in steps {
        match step {
            Step::Update { record, update } => {
                backend
                    .update(zone, name, rtype, context, record, update)
                    .await?;
            }
            Step::Create { data, ttl } => {
                backend
                    .create(zone, name, rtype, context, data, *ttl)
                    .await?;
            }
            Step::Delete(record) => backend.delete(zone, name, rtype, context, record).await?,
        }
    }
    Ok(())
}

/// `delete_rrset` for a [`PerRecord`] provider: every enabled record by identifier. Disabled
/// records are not published values and stay.
pub(crate) async fn delete_per_record<B: PerRecord>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    rtype: RecordType,
    expect: Expect<'_>,
) -> Result<DeleteOutcome, Error> {
    check_delete(backend, zone, name, rtype, expect)?;
    let _guard = backend.locks().lock(name).await;
    let read = backend.read(zone, name, rtype).await?;
    let published = published(name, rtype, smallest_ttl(&read.records), &read.records)?;
    evaluate(expect, published.as_ref())?;
    if published.is_none() {
        return Ok(DeleteOutcome::NotPresent);
    }
    let steps: Vec<Step<'_, B::Handle>> = read
        .records
        .iter()
        .filter(|record| record.enabled)
        .map(Step::Delete)
        .collect();
    backend.check_plan(zone, name, rtype, &read.context, &steps)?;
    send_steps(backend, zone, name, rtype, &read.context, &steps).await?;
    Ok(DeleteOutcome::Deleted)
}

// ---- Listings ------------------------------------------------------------------------------------

/// Builds the [`ZoneListing`] of `list_rrsets` from what the provider reported (design section
/// 3.4): every rrset of every type, also outside `record_types`; what the model cannot hold goes
/// to `skipped`, never silently away.
#[derive(Debug)]
pub(crate) struct Listing<'z> {
    zone: &'z DomainName,
    rrsets: Vec<RrSet>,
    skipped: Vec<SkippedRrset>,
}

impl<'z> Listing<'z> {
    /// An empty listing of `zone`.
    pub(crate) fn new(zone: &'z DomainName) -> Listing<'z> {
        Listing {
            zone,
            rrsets: Vec::new(),
            skipped: Vec::new(),
        }
    }

    /// The TTL of an rrset whose records state their own (design section 3.6,
    /// `TtlSupport::PerRecord`): the smallest of `ttls`, one per enabled record, ignoring
    /// records that state none. `None` when no record states one. For the `ttl` of
    /// [`Listing::push`] where the API stores a TTL per record.
    pub(crate) fn smallest_ttl(ttls: impl IntoIterator<Item = Option<Ttl>>) -> Option<Ttl> {
        ttls.into_iter().flatten().min()
    }

    /// One rrset as the provider reported it. `name` is the owner name, `None` when the
    /// provider's spelling is not a valid `DomainName`; `records` are its enabled records only
    /// (an rrset whose records are all disabled is not part of the listing); `ttl` is the
    /// rrset's TTL ([`Listing::smallest_ttl`] where the records state their own).
    ///
    /// A name that is not a valid `DomainName`, or not within the zone, is skipped as
    /// `UnsupportedName` under the zone's name, since `SkippedRrset::name` must be a valid name.
    /// A type name that maps to no `RecordType` is `UnknownType`; a query or meta type, or a set
    /// the model cannot hold (two records of a singleton type), is `NotPlainRecords`.
    pub(crate) fn push(
        &mut self,
        name: Option<DomainName>,
        type_name: &str,
        ttl: Option<Ttl>,
        records: Vec<RecordData>,
    ) {
        if records.is_empty() {
            return;
        }
        let name = match name {
            Some(name) if name.is_within(self.zone) => name,
            _ => {
                self.skip(self.zone.clone(), type_name, SkipReason::UnsupportedName);
                return;
            }
        };
        let rtype: RecordType = match type_name.parse() {
            Ok(rtype) => rtype,
            Err(_) => return self.skip(name, type_name, SkipReason::UnknownType),
        };
        if rtype.is_meta() {
            return self.skip(name, type_name, SkipReason::NotPlainRecords);
        }
        match RrSet::new(name.clone(), rtype, ttl, records) {
            Ok(set) => self.rrsets.push(set),
            Err(_) => self.skip(name, type_name, SkipReason::NotPlainRecords),
        }
    }

    /// Records an rrset that cannot be an `RrSet`, for a reason the caller determined (a
    /// provider-specific record kind, an alias to a provider resource).
    pub(crate) fn skip(&mut self, name: DomainName, type_name: &str, reason: SkipReason) {
        self.skipped
            .push(SkippedRrset::new(name, type_name, reason));
    }

    /// The listing, sorted by name and type. Two rrsets of one name and type are a listing the
    /// client cannot interpret (`Error::Protocol`). Logs one `WARN` event with the number of
    /// skipped sets when there are any.
    pub(crate) fn finish(self, provider: ProviderId) -> Result<ZoneListing, Error> {
        let listing = ZoneListing::new(self.rrsets, self.skipped);
        let duplicate = listing
            .rrsets
            .windows(2)
            .any(|pair| matches!(pair, [a, b] if a.name() == b.name() && a.rtype() == b.rtype()));
        if duplicate {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider's listing holds two rrsets of the same name and type",
                ),
            });
        }
        if !listing.skipped.is_empty() {
            tracing::warn!(
                target: "zonewright::rrsets",
                provider = provider.as_str(),
                skipped = listing.skipped.len(),
                "the listing holds rrsets the record model cannot represent"
            );
        }
        Ok(listing)
    }
}

#[cfg(test)]
mod tests {
    //! The layer against in-memory providers of the three shapes it is designed for: an rrset
    //! written whole without a condition (Selectel v2, Cloud.ru), the same with an atomic
    //! condition (Yandex Cloud, Route 53, RFC 2136), and individual records (Cloudflare,
    //! DigitalOcean); including changes by another writer between the read and the write.

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::{
        Current, Found, Listing, Member, PerRecord, RecordUpdate, RecordsRead, RrsetBase, SetTtl,
        Step, Stored, WholeChange, WholeRead, WholeSet,
    };
    use crate::error::{Error, ErrorKind};
    use crate::id::ProviderId;
    use crate::locks::NameLocks;
    use crate::meta::{Capabilities, Preconditions, TtlSupport, TypeSet, ValueGuarantee};
    use crate::name::DomainName;
    use crate::provider::{DeleteOutcome, Expect, SetOutcome, SkipReason};
    use crate::record::{RecordData, RecordType, RrSet, Ttl};

    /// The TTL the fake gives a new rrset when the client sends none.
    const DEFAULT_TTL: u32 = 300;

    const TYPES: &[RecordType] = &[
        RecordType::A,
        RecordType::TXT,
        RecordType::CNAME,
        RecordType::NS,
        RecordType::MX,
        RecordType::SOA,
    ];

    fn caps(preconditions: Preconditions, atomic_write: bool) -> Capabilities {
        Capabilities {
            list_zones: false,
            list_rrsets: true,
            get_rrset: true,
            set_rrset: true,
            delete_rrset: true,
            add_txt_value: false,
            remove_txt_value: false,
            record_types: TypeSet::Listed(TYPES),
            read_only_types: &[RecordType::SOA],
            txt_plain_only: true,
            txt_values: ValueGuarantee::NotOffered,
            preconditions,
            atomic_rrset_write: atomic_write,
            ttl: TtlSupport::PerRrset {
                min: 60,
                max: 86_400,
            },
            provider_default_ttl: false,
            asynchronous: false,
        }
    }

    fn dn(name: &str) -> DomainName {
        DomainName::parse(name).unwrap()
    }

    fn zone() -> DomainName {
        dn("example.org")
    }

    fn name() -> DomainName {
        dn("www.example.org")
    }

    /// Text starting with `!` stands for provider text the parser refuses.
    fn data(rtype: RecordType, text: &str) -> RecordData {
        RecordData::parse(rtype, text).unwrap_or_else(|_| RecordData::non_canonical(text))
    }

    fn set(rtype: RecordType, ttl: Option<u32>, texts: &[&str]) -> RrSet {
        RrSet::new(
            name(),
            rtype,
            ttl.map(|t| Ttl::from_secs(t).unwrap()),
            texts.iter().map(|t| data(rtype, t)),
        )
        .unwrap()
    }

    fn a(ttl: Option<u32>, texts: &[&str]) -> RrSet {
        set(RecordType::A, ttl, texts)
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Rec {
        id: u64,
        text: String,
        enabled: bool,
        ttl: u32,
    }

    #[derive(Default)]
    struct Store {
        sets: HashMap<(DomainName, RecordType), Vec<Rec>>,
        next_id: u64,
        log: Vec<String>,
        /// Values another writer adds right before the next write requests, one per request.
        foreign_before_write: Vec<String>,
        /// The write request with this number (1-based, counted from now) fails.
        fail_write: Option<usize>,
        writes: usize,
        write_delay: Duration,
        /// Reads so far, and a value another writer adds right after the read with this number.
        reads: usize,
        foreign_after_read: Option<(usize, String)>,
        /// The whole-set fake reads again before every write.
        reread: bool,
        /// The fakes answer the coexistence hooks from the store; otherwise they do not tell.
        coexistence: bool,
        /// The plan hooks refuse any plan that creates a value.
        refuse_creates: bool,
    }

    impl Store {
        fn insert(&mut self, rtype: RecordType, text: &str, enabled: bool, ttl: u32) -> u64 {
            self.next_id += 1;
            let id = self.next_id;
            self.sets.entry((name(), rtype)).or_default().push(Rec {
                id,
                text: text.to_owned(),
                enabled,
                ttl,
            });
            id
        }

        fn recs(&self, rtype: RecordType) -> Vec<Rec> {
            self.sets.get(&(name(), rtype)).cloned().unwrap_or_default()
        }

        fn texts(&self, rtype: RecordType) -> Vec<(String, bool, u32)> {
            let mut texts: Vec<_> = self
                .recs(rtype)
                .into_iter()
                .map(|r| (r.text, r.enabled, r.ttl))
                .collect();
            texts.sort();
            texts
        }

        fn before_write(&mut self, rtype: RecordType) -> Result<(), Error> {
            if !self.foreign_before_write.is_empty() {
                let text = self.foreign_before_write.remove(0);
                self.insert(rtype, &text, true, 600);
            }
            self.writes += 1;
            if self.fail_write == Some(self.writes) {
                self.log.push("write-failed".into());
                return Err(Error::transient("injected failure"));
            }
            Ok(())
        }

        fn tidy(&mut self, rtype: RecordType) {
            if self.sets.get(&(name(), rtype)).is_some_and(Vec::is_empty) {
                self.sets.remove(&(name(), rtype));
            }
        }

        /// Counts a read and lets another writer act right after it.
        fn after_read(&mut self, rtype: RecordType) {
            self.reads += 1;
            if let Some((at, text)) = self.foreign_after_read.clone()
                && at == self.reads
            {
                self.insert(rtype, &text, true, 600);
            }
        }

        /// The coexistence hooks: whether the name holds published data of another type
        /// than `rtype` that is (`cname`) or is not a CNAME.
        fn holds(&self, rtype: RecordType, cname: bool) -> Option<bool> {
            self.coexistence.then(|| {
                self.sets.iter().any(|((owner, t), recs)| {
                    *owner == name()
                        && *t != rtype
                        && (*t == RecordType::CNAME) == cname
                        && recs.iter().any(|r| r.enabled)
                })
            })
        }

        fn refusal(&mut self) -> Error {
            self.log.push("plan-refused".into());
            Error::rejected(None, "the plan creates a value")
        }

        fn writes_logged(&self) -> Vec<&str> {
            self.log
                .iter()
                .map(String::as_str)
                .filter(|op| *op != "read")
                .collect()
        }
    }

    type Shared = Arc<Mutex<Store>>;

    async fn delay(store: &Shared) {
        let delay = store.lock().unwrap().write_delay;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    fn stored(rtype: RecordType, rec: &Rec) -> Stored<Rec> {
        Stored {
            data: data(rtype, &rec.text),
            enabled: rec.enabled,
            ttl: Some(Ttl::from_secs(rec.ttl).unwrap()),
            handle: rec.clone(),
        }
    }

    fn ttl_secs(ttl: SetTtl) -> u32 {
        match ttl {
            SetTtl::Requested(t) | SetTtl::Existing(Some(t)) => t.as_secs(),
            SetTtl::Existing(None) | SetTtl::Default => DEFAULT_TTL,
        }
    }

    struct Base {
        store: Shared,
        locks: NameLocks,
        caps: Capabilities,
        max: Option<usize>,
    }

    impl RrsetBase for Base {
        fn provider(&self) -> ProviderId {
            ProviderId::SelectelV2
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        fn locks(&self) -> &NameLocks {
            &self.locks
        }
        fn max_records(&self) -> Option<usize> {
            self.max
        }
        /// A value with a backslash stands for one the client cannot encode.
        fn can_send(&self, _rtype: RecordType, data: &RecordData) -> bool {
            !data.as_str().contains('\\')
        }
    }

    macro_rules! base {
        ($t:ty) => {
            impl RrsetBase for $t {
                fn provider(&self) -> ProviderId {
                    self.0.provider()
                }
                fn capabilities(&self) -> &Capabilities {
                    self.0.capabilities()
                }
                fn locks(&self) -> &NameLocks {
                    self.0.locks()
                }
                fn max_records(&self) -> Option<usize> {
                    self.0.max_records()
                }
                fn can_send(&self, rtype: RecordType, data: &RecordData) -> bool {
                    self.0.can_send(rtype, data)
                }
            }
        };
    }

    /// An rrset written whole; the write is conditional on the set as read when the
    /// capabilities say `Atomic`.
    struct WholeFake(Base);
    base!(WholeFake);

    impl WholeSet for WholeFake {
        type Handle = Rec;
        type Snapshot = Vec<Rec>;
        type Context = ();

        async fn read(
            &self,
            _zone: &DomainName,
            name: &DomainName,
            rtype: RecordType,
        ) -> WholeRead<Self> {
            let mut store = self.0.store.lock().unwrap();
            store.log.push("read".into());
            let recs = store.sets.get(&(name.clone(), rtype)).cloned();
            store.after_read(rtype);
            Ok(Current {
                context: (),
                found: recs.map(|recs| Found {
                    records: recs.iter().map(|r| stored(rtype, r)).collect(),
                    ttl: recs.first().map(|r| Ttl::from_secs(r.ttl).unwrap()),
                    snapshot: recs,
                }),
            })
        }

        fn check_write(
            &self,
            _zone: &DomainName,
            _name: &DomainName,
            _rtype: RecordType,
            _context: &(),
            change: &WholeChange<'_, Rec, Vec<Rec>>,
        ) -> Result<(), Error> {
            let mut store = self.0.store.lock().unwrap();
            let creates = match change {
                WholeChange::Write { members, .. } => {
                    members.iter().any(|m| matches!(m, Member::Added(_)))
                }
                WholeChange::Delete { .. } => false,
            };
            if store.refuse_creates && creates {
                return Err(store.refusal());
            }
            Ok(())
        }

        fn reread_before_write(&self) -> bool {
            self.0.store.lock().unwrap().reread
        }

        fn same_snapshot(&self, first: &Vec<Rec>, again: &Vec<Rec>) -> bool {
            first == again
        }

        fn holds_cname(&self, rtype: RecordType, _context: &()) -> Option<bool> {
            self.0.store.lock().unwrap().holds(rtype, true)
        }

        fn holds_other_data(&self, rtype: RecordType, _context: &()) -> Option<bool> {
            self.0.store.lock().unwrap().holds(rtype, false)
        }

        async fn write(
            &self,
            _zone: &DomainName,
            name: &DomainName,
            rtype: RecordType,
            _context: &(),
            prior: Option<&Vec<Rec>>,
            members: &[Member<'_, Rec>],
            ttl: SetTtl,
        ) -> Result<(), Error> {
            delay(&self.0.store).await;
            let mut store = self.0.store.lock().unwrap();
            store.before_write(rtype)?;
            let key = (name.clone(), rtype);
            if self.0.caps.preconditions == Preconditions::Atomic && store.sets.get(&key) != prior {
                store.log.push("write-refused".into());
                return Err(Error::conflict("the rrset changed"));
            }
            store.log.push("write".into());
            let ttl = ttl_secs(ttl);
            let mut recs = Vec::new();
            for member in members {
                let rec = match member {
                    Member::Kept(r) => r.handle.clone(),
                    Member::Enabled(r) => Rec {
                        enabled: true,
                        ..r.handle.clone()
                    },
                    Member::Added(d) => {
                        store.next_id += 1;
                        Rec {
                            id: store.next_id,
                            text: d.as_str().to_owned(),
                            enabled: true,
                            ttl,
                        }
                    }
                };
                recs.push(Rec { ttl, ..rec });
            }
            store.sets.insert(key, recs);
            Ok(())
        }

        async fn delete(
            &self,
            _zone: &DomainName,
            name: &DomainName,
            rtype: RecordType,
            _context: &(),
            prior: &Vec<Rec>,
        ) -> Result<(), Error> {
            delay(&self.0.store).await;
            let mut store = self.0.store.lock().unwrap();
            store.before_write(rtype)?;
            let key = (name.clone(), rtype);
            if self.0.caps.preconditions == Preconditions::Atomic
                && store.sets.get(&key) != Some(prior)
            {
                store.log.push("delete-refused".into());
                return Err(Error::conflict("the rrset changed"));
            }
            store.log.push("delete".into());
            store.sets.remove(&key);
            Ok(())
        }
    }

    /// Individual records with identifiers.
    struct RecordFake(Base, bool);
    base!(RecordFake);

    impl PerRecord for RecordFake {
        type Handle = Rec;
        type Context = ();

        async fn read(
            &self,
            _zone: &DomainName,
            _name: &DomainName,
            rtype: RecordType,
        ) -> Result<RecordsRead<Rec, ()>, Error> {
            let mut store = self.0.store.lock().unwrap();
            store.log.push("read".into());
            let records = store.recs(rtype).iter().map(|r| stored(rtype, r)).collect();
            store.after_read(rtype);
            Ok(RecordsRead {
                context: (),
                records,
            })
        }

        async fn create(
            &self,
            _zone: &DomainName,
            _name: &DomainName,
            rtype: RecordType,
            _context: &(),
            data: &RecordData,
            ttl: SetTtl,
        ) -> Result<(), Error> {
            delay(&self.0.store).await;
            let mut store = self.0.store.lock().unwrap();
            store.before_write(rtype)?;
            store.log.push(format!("create {}", data.as_str()));
            store.insert(rtype, data.as_str(), true, ttl_secs(ttl));
            Ok(())
        }

        async fn update(
            &self,
            _zone: &DomainName,
            _name: &DomainName,
            rtype: RecordType,
            _context: &(),
            record: &Stored<Rec>,
            update: &RecordUpdate<'_>,
        ) -> Result<(), Error> {
            delay(&self.0.store).await;
            let mut store = self.0.store.lock().unwrap();
            store.before_write(rtype)?;
            store.log.push(format!("update {}", record.handle.text));
            if let Some(rec) = store
                .sets
                .get_mut(&(name(), rtype))
                .and_then(|recs| recs.iter_mut().find(|r| r.id == record.handle.id))
            {
                rec.enabled |= update.enable;
                if let Some(ttl) = update.ttl {
                    rec.ttl = ttl.as_secs();
                }
                if let Some(data) = update.data {
                    rec.text = data.as_str().to_owned();
                }
            }
            Ok(())
        }

        async fn delete(
            &self,
            _zone: &DomainName,
            _name: &DomainName,
            rtype: RecordType,
            _context: &(),
            record: &Stored<Rec>,
        ) -> Result<(), Error> {
            delay(&self.0.store).await;
            let mut store = self.0.store.lock().unwrap();
            store.before_write(rtype)?;
            store.log.push(format!("delete {}", record.handle.text));
            if let Some(recs) = store.sets.get_mut(&(name(), rtype)) {
                recs.retain(|r| r.id != record.handle.id);
            }
            store.tidy(rtype);
            Ok(())
        }

        fn updates_in_place(&self) -> bool {
            self.1
        }

        fn check_plan(
            &self,
            _zone: &DomainName,
            _name: &DomainName,
            _rtype: RecordType,
            _context: &(),
            steps: &[Step<'_, Rec>],
        ) -> Result<(), Error> {
            let mut store = self.0.store.lock().unwrap();
            let creates = steps.iter().any(|s| matches!(s, Step::Create { .. }));
            if store.refuse_creates && creates {
                return Err(store.refusal());
            }
            Ok(())
        }

        fn holds_cname(&self, rtype: RecordType, _context: &()) -> Option<bool> {
            self.0.store.lock().unwrap().holds(rtype, true)
        }

        fn holds_other_data(&self, rtype: RecordType, _context: &()) -> Option<bool> {
            self.0.store.lock().unwrap().holds(rtype, false)
        }
    }

    fn base(caps: Capabilities) -> Base {
        Base {
            store: Shared::default(),
            locks: NameLocks::new(),
            caps,
            max: Some(5),
        }
    }

    fn rtw() -> WholeFake {
        WholeFake(base(caps(Preconditions::ReadThenWrite, true)))
    }

    fn atomic() -> WholeFake {
        WholeFake(base(caps(Preconditions::Atomic, true)))
    }

    fn per_record(in_place: bool) -> RecordFake {
        RecordFake(base(caps(Preconditions::ReadThenWrite, false)), in_place)
    }

    fn store(base: &Base) -> std::sync::MutexGuard<'_, Store> {
        base.store.lock().unwrap()
    }

    /// The three shapes behind one interface, so that a property is asserted for all of them.
    enum Shape {
        Rtw(WholeFake),
        Atomic(WholeFake),
        Records(RecordFake),
    }

    impl Shape {
        fn all() -> Vec<Shape> {
            vec![
                Shape::Rtw(rtw()),
                Shape::Atomic(atomic()),
                Shape::Records(per_record(true)),
            ]
        }

        fn base(&self) -> &Base {
            match self {
                Shape::Rtw(f) | Shape::Atomic(f) => &f.0,
                Shape::Records(f) => &f.0,
            }
        }

        fn label(&self) -> &'static str {
            match self {
                Shape::Rtw(_) => "read-then-write",
                Shape::Atomic(_) => "atomic",
                Shape::Records(_) => "per-record",
            }
        }

        async fn get(&self, rtype: RecordType) -> Result<Option<RrSet>, Error> {
            match self {
                Shape::Rtw(f) | Shape::Atomic(f) => {
                    super::get_whole_set(f, &zone(), &name(), rtype).await
                }
                Shape::Records(f) => super::get_per_record(f, &zone(), &name(), rtype).await,
            }
        }

        async fn set(&self, rrset: &RrSet, expect: Expect<'_>) -> Result<SetOutcome, Error> {
            match self {
                Shape::Rtw(f) | Shape::Atomic(f) => {
                    super::set_whole_set(f, &zone(), rrset, expect).await
                }
                Shape::Records(f) => super::set_per_record(f, &zone(), rrset, expect).await,
            }
        }

        async fn set_at(
            &self,
            zone: &DomainName,
            rrset: &RrSet,
            expect: Expect<'_>,
        ) -> Result<SetOutcome, Error> {
            match self {
                Shape::Rtw(f) | Shape::Atomic(f) => {
                    super::set_whole_set(f, zone, rrset, expect).await
                }
                Shape::Records(f) => super::set_per_record(f, zone, rrset, expect).await,
            }
        }

        async fn delete(
            &self,
            name: &DomainName,
            rtype: RecordType,
            expect: Expect<'_>,
        ) -> Result<DeleteOutcome, Error> {
            match self {
                Shape::Rtw(f) | Shape::Atomic(f) => {
                    super::delete_whole_set(f, &zone(), name, rtype, expect).await
                }
                Shape::Records(f) => {
                    super::delete_per_record(f, &zone(), name, rtype, expect).await
                }
            }
        }

        fn requests(&self) -> usize {
            store(self.base()).log.len()
        }

        fn writes(&self) -> Vec<String> {
            store(self.base())
                .writes_logged()
                .into_iter()
                .map(str::to_owned)
                .collect()
        }

        fn insert(&self, rtype: RecordType, text: &str, enabled: bool, ttl: u32) {
            store(self.base()).insert(rtype, text, enabled, ttl);
        }

        fn texts(&self, rtype: RecordType) -> Vec<(String, bool, u32)> {
            store(self.base()).texts(rtype)
        }
    }

    fn kind<T: std::fmt::Debug>(result: Result<T, Error>) -> ErrorKind {
        result.unwrap_err().kind()
    }

    // ---- Checks before any request -----------------------------------------------------------

    #[tokio::test]
    async fn refusals_send_nothing() {
        for shape in Shape::all() {
            let label = shape.label();
            let txt = set(RecordType::TXT, None, &["\"v\""]);
            // A type outside the list, and a read-only type for writes.
            let aaaa = RrSet::new(
                name(),
                RecordType::AAAA,
                None,
                [RecordData::parse(RecordType::AAAA, "2001:db8::1").unwrap()],
            )
            .unwrap();
            assert_eq!(
                kind(shape.set(&aaaa, Expect::Any).await),
                ErrorKind::UnsupportedRecordType,
                "{label}"
            );
            assert_eq!(
                kind(shape.get(RecordType::AAAA).await),
                ErrorKind::UnsupportedRecordType
            );
            let soa = set(
                RecordType::SOA,
                None,
                &["ns1.example.org. admin.example.org. 1 7200 3600 1209600 300"],
            );
            assert_eq!(
                kind(shape.set(&soa, Expect::Any).await),
                ErrorKind::UnsupportedRecordType
            );
            assert_eq!(
                kind(shape.delete(&name(), RecordType::SOA, Expect::Any).await),
                ErrorKind::UnsupportedRecordType
            );
            // A meta type is invalid, whatever the type list says.
            assert_eq!(
                kind(shape.get(RecordType::from_code(255)).await),
                ErrorKind::InvalidInput
            );
            // The root and a wildcard are not zones.
            assert_eq!(
                kind(shape.set_at(&DomainName::root(), &txt, Expect::Any).await),
                ErrorKind::InvalidInput
            );
            assert_eq!(
                kind(shape.set_at(&dn("*.example.org"), &txt, Expect::Any).await),
                ErrorKind::InvalidInput
            );
            // Outside the zone, by labels.
            assert_eq!(
                kind(shape.set_at(&dn("ww.example.org"), &txt, Expect::Any).await),
                ErrorKind::NameOutsideZone
            );
            // The apex NS set.
            let apex_ns = RrSet::new(
                zone(),
                RecordType::NS,
                None,
                [RecordData::parse(RecordType::NS, "ns1.example.net.").unwrap()],
            )
            .unwrap();
            assert_eq!(
                kind(shape.set(&apex_ns, Expect::Any).await),
                ErrorKind::InvalidInput
            );
            assert_eq!(
                kind(shape.delete(&zone(), RecordType::NS, Expect::Any).await),
                ErrorKind::InvalidInput
            );
            // TTL bounds, inclusive.
            assert_eq!(
                kind(shape.set(&a(Some(59), &["192.0.2.1"]), Expect::Any).await),
                ErrorKind::InvalidInput
            );
            assert_eq!(
                kind(
                    shape
                        .set(&a(Some(86_401), &["192.0.2.1"]), Expect::Any)
                        .await
                ),
                ErrorKind::InvalidInput
            );
            // More records than the provider holds.
            let six = a(
                None,
                &[
                    "192.0.2.1",
                    "192.0.2.2",
                    "192.0.2.3",
                    "192.0.2.4",
                    "192.0.2.5",
                    "192.0.2.6",
                ],
            );
            assert_eq!(
                kind(shape.set(&six, Expect::Any).await),
                ErrorKind::InvalidInput
            );
            // An expectation about another name or type.
            let other = a(None, &["192.0.2.1"]);
            assert_eq!(
                kind(shape.set(&txt, Expect::Matches(&other)).await),
                ErrorKind::InvalidInput
            );
            assert_eq!(
                kind(
                    shape
                        .delete(&name(), RecordType::TXT, Expect::Matches(&other))
                        .await
                ),
                ErrorKind::InvalidInput
            );
            assert_eq!(
                kind(shape.delete(&name(), RecordType::A, Expect::Absent).await),
                ErrorKind::InvalidInput
            );
            assert_eq!(shape.requests(), 0, "{label}: a refusal made a request");
            // The bounds themselves are accepted.
            assert_eq!(
                shape
                    .set(&a(Some(60), &["192.0.2.1"]), Expect::Any)
                    .await
                    .unwrap(),
                SetOutcome::Created
            );
            assert_eq!(
                shape
                    .set(&a(Some(86_400), &["192.0.2.1"]), Expect::Any)
                    .await
                    .unwrap(),
                SetOutcome::Replaced
            );
        }
    }

    #[tokio::test]
    async fn unsupported_operations_send_nothing() {
        let mut caps = caps(Preconditions::ReadThenWrite, true);
        caps.set_rrset = false;
        caps.delete_rrset = false;
        caps.get_rrset = false;
        caps.list_rrsets = false;
        let fake = WholeFake(base(caps));
        let e = super::set_whole_set(&fake, &zone(), &a(None, &["192.0.2.1"]), Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported);
        let e = super::get_whole_set(&fake, &zone(), &name(), RecordType::A)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported);
        let e = super::delete_whole_set(&fake, &zone(), &name(), RecordType::A, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported);
        let e = super::check_list(&fake, &zone()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported);
        assert!(store(&fake.0).log.is_empty());
    }

    // ---- Outcomes and the TTL policy ---------------------------------------------------------

    #[tokio::test]
    async fn outcomes_and_ttl_policy() {
        for shape in Shape::all() {
            let label = shape.label();
            // A new set with no TTL gets the client's default.
            assert_eq!(
                shape
                    .set(&a(None, &["192.0.2.1"]), Expect::Absent)
                    .await
                    .unwrap(),
                SetOutcome::Created,
                "{label}"
            );
            assert_eq!(
                shape.texts(RecordType::A),
                [("192.0.2.1".to_owned(), true, DEFAULT_TTL)]
            );
            // Equal members, no TTL requested: nothing is written.
            let before = shape.writes().len();
            assert_eq!(
                shape
                    .set(&a(None, &["192.0.2.1"]), Expect::Any)
                    .await
                    .unwrap(),
                SetOutcome::Unchanged
            );
            // The same TTL as stored: unchanged too.
            assert_eq!(
                shape
                    .set(&a(Some(DEFAULT_TTL), &["192.0.2.1"]), Expect::Any)
                    .await
                    .unwrap(),
                SetOutcome::Unchanged
            );
            assert_eq!(
                shape.writes().len(),
                before,
                "{label}: an unchanged set wrote"
            );
            // A new member, no TTL: the existing TTL is kept.
            assert_eq!(
                shape
                    .set(&a(None, &["192.0.2.1", "192.0.2.2"]), Expect::Any)
                    .await
                    .unwrap(),
                SetOutcome::Replaced
            );
            assert_eq!(
                shape.texts(RecordType::A),
                [
                    ("192.0.2.1".to_owned(), true, DEFAULT_TTL),
                    ("192.0.2.2".to_owned(), true, DEFAULT_TTL)
                ],
                "{label}"
            );
            // Only the TTL changes: applied to every record.
            assert_eq!(
                shape
                    .set(&a(Some(900), &["192.0.2.1", "192.0.2.2"]), Expect::Any)
                    .await
                    .unwrap(),
                SetOutcome::Replaced
            );
            assert_eq!(
                shape.texts(RecordType::A),
                [
                    ("192.0.2.1".to_owned(), true, 900),
                    ("192.0.2.2".to_owned(), true, 900)
                ],
                "{label}"
            );
            assert_eq!(
                shape.get(RecordType::A).await.unwrap(),
                Some(a(Some(900), &["192.0.2.1", "192.0.2.2"]))
            );
            // Replace with a disjoint set.
            assert_eq!(
                shape
                    .set(&a(None, &["192.0.2.9"]), Expect::Any)
                    .await
                    .unwrap(),
                SetOutcome::Replaced
            );
            assert_eq!(
                shape.texts(RecordType::A),
                [("192.0.2.9".to_owned(), true, 900)],
                "{label}"
            );
            // Delete, then delete again.
            assert_eq!(
                shape
                    .delete(&name(), RecordType::A, Expect::Any)
                    .await
                    .unwrap(),
                DeleteOutcome::Deleted
            );
            let before = shape.writes().len();
            assert_eq!(
                shape
                    .delete(&name(), RecordType::A, Expect::Any)
                    .await
                    .unwrap(),
                DeleteOutcome::NotPresent
            );
            assert_eq!(shape.writes().len(), before);
            assert_eq!(shape.get(RecordType::A).await.unwrap(), None);
        }
    }

    // ---- Expectations ------------------------------------------------------------------------

    #[tokio::test]
    async fn failed_expectations_write_nothing() {
        for shape in Shape::all() {
            let label = shape.label();
            shape.insert(RecordType::A, "192.0.2.1", true, 600);
            let wanted = a(None, &["192.0.2.7"]);
            let cases = [
                Expect::Absent,
                Expect::Matches(&a(None, &["192.0.2.2"])),
                Expect::Matches(&a(None, &["192.0.2.1", "192.0.2.2"])),
                Expect::Matches(&a(Some(300), &["192.0.2.1"])),
            ];
            for expect in cases {
                let e = shape.set(&wanted, expect).await.unwrap_err();
                assert_eq!(
                    e.kind(),
                    ErrorKind::PreconditionFailed,
                    "{label} {expect:?}"
                );
                assert!(!e.is_retryable());
            }
            for expect in [
                Expect::Matches(&a(None, &["192.0.2.2"])),
                Expect::Matches(&a(Some(300), &["192.0.2.1"])),
            ] {
                let e = shape
                    .delete(&name(), RecordType::A, expect)
                    .await
                    .unwrap_err();
                assert_eq!(
                    e.kind(),
                    ErrorKind::PreconditionFailed,
                    "{label} {expect:?}"
                );
            }
            // Expectations on a missing rrset.
            let txt = set(RecordType::TXT, None, &["\"v\""]);
            assert_eq!(
                kind(shape.set(&txt, Expect::Matches(&txt)).await),
                ErrorKind::PreconditionFailed
            );
            assert_eq!(
                kind(
                    shape
                        .delete(&name(), RecordType::TXT, Expect::Matches(&txt))
                        .await
                ),
                ErrorKind::PreconditionFailed
            );
            assert!(shape.writes().is_empty(), "{label}: {:?}", shape.writes());
            assert_eq!(
                shape.texts(RecordType::A),
                [("192.0.2.1".to_owned(), true, 600)]
            );

            // The expectation holds: with the TTL, and without one (any TTL).
            assert_eq!(
                shape
                    .set(&wanted, Expect::Matches(&a(Some(600), &["192.0.2.1"])))
                    .await
                    .unwrap(),
                SetOutcome::Replaced,
                "{label}"
            );
            assert_eq!(
                shape
                    .delete(
                        &name(),
                        RecordType::A,
                        Expect::Matches(&a(None, &["192.0.2.7"]))
                    )
                    .await
                    .unwrap(),
                DeleteOutcome::Deleted
            );
            assert_eq!(
                shape.set(&wanted, Expect::Absent).await.unwrap(),
                SetOutcome::Created
            );
        }
    }

    // ---- Disabled records and non-canonical data ---------------------------------------------

    #[tokio::test]
    async fn disabled_records_are_enabled_or_kept() {
        for shape in Shape::all() {
            let label = shape.label();
            shape.insert(RecordType::A, "192.0.2.1", true, 600);
            shape.insert(RecordType::A, "192.0.2.2", false, 600);
            shape.insert(RecordType::A, "192.0.2.3", false, 600);
            // Disabled records are not part of the rrset as read.
            assert_eq!(
                shape.get(RecordType::A).await.unwrap(),
                Some(a(Some(600), &["192.0.2.1"]))
            );
            // A requested value held by a disabled record enables it; the other stays.
            assert_eq!(
                shape
                    .set(&a(None, &["192.0.2.1", "192.0.2.2"]), Expect::Any)
                    .await
                    .unwrap(),
                SetOutcome::Replaced
            );
            assert_eq!(
                shape.texts(RecordType::A),
                [
                    ("192.0.2.1".to_owned(), true, 600),
                    ("192.0.2.2".to_owned(), true, 600),
                    ("192.0.2.3".to_owned(), false, 600)
                ],
                "{label}"
            );
            // A delete removes the published values and leaves the disabled record.
            assert_eq!(
                shape
                    .delete(&name(), RecordType::A, Expect::Any)
                    .await
                    .unwrap(),
                DeleteOutcome::Deleted
            );
            assert_eq!(
                shape.texts(RecordType::A),
                [("192.0.2.3".to_owned(), false, 600)],
                "{label}"
            );
            // Only a disabled record: absent as published; a set creates the published set.
            assert_eq!(shape.get(RecordType::A).await.unwrap(), None);
            assert_eq!(
                shape
                    .delete(&name(), RecordType::A, Expect::Any)
                    .await
                    .unwrap(),
                DeleteOutcome::NotPresent
            );
            assert_eq!(
                shape
                    .set(&a(None, &["192.0.2.3"]), Expect::Absent)
                    .await
                    .unwrap(),
                SetOutcome::Created
            );
            assert_eq!(
                shape.texts(RecordType::A),
                [("192.0.2.3".to_owned(), true, 600)],
                "{label}"
            );
        }
    }

    #[tokio::test]
    async fn non_canonical_data_is_written_back_never_introduced() {
        for shape in Shape::all() {
            let label = shape.label();
            shape.insert(RecordType::A, "!odd", true, 600);
            let listed = shape.get(RecordType::A).await.unwrap().unwrap();
            assert!(!listed.records()[0].is_canonical());
            // Written back with a member added: the odd record is left as it is.
            let mut members = listed.records().to_vec();
            members.push(data(RecordType::A, "192.0.2.1"));
            let wanted = RrSet::new(name(), RecordType::A, None, members).unwrap();
            assert_eq!(
                shape.set(&wanted, Expect::Matches(&listed)).await.unwrap(),
                SetOutcome::Replaced,
                "{label}"
            );
            assert_eq!(
                shape.texts(RecordType::A),
                [
                    ("!odd".to_owned(), true, 600),
                    ("192.0.2.1".to_owned(), true, 600)
                ]
            );
            // Non-canonical data the provider does not hold cannot be introduced.
            let before = shape.writes().len();
            let foreign = RrSet::new(
                name(),
                RecordType::A,
                None,
                [
                    data(RecordType::A, "192.0.2.1"),
                    data(RecordType::A, "!other"),
                ],
            )
            .unwrap();
            assert_eq!(
                kind(shape.set(&foreign, Expect::Any).await),
                ErrorKind::InvalidInput,
                "{label}"
            );
            assert_eq!(shape.writes().len(), before);
        }
    }

    #[tokio::test]
    async fn values_the_client_cannot_send_are_refused_unless_present() {
        for shape in Shape::all() {
            let label = shape.label();
            let escaped = "\"a\\\"b\"";
            let wanted = set(RecordType::TXT, None, &[escaped]);
            assert_eq!(
                kind(shape.set(&wanted, Expect::Any).await),
                ErrorKind::InvalidInput,
                "{label}"
            );
            assert!(shape.writes().is_empty());
            // Present at the provider: kept as read, and another value can join it.
            shape.insert(RecordType::TXT, escaped, true, 600);
            let both = set(RecordType::TXT, None, &[escaped, "\"plain\""]);
            assert_eq!(
                shape.set(&both, Expect::Any).await.unwrap(),
                SetOutcome::Replaced,
                "{label}"
            );
        }
    }

    #[tokio::test]
    async fn disabled_records_count_toward_the_provider_limit() {
        for shape in Shape::all() {
            let label = shape.label();
            for i in 1..=4 {
                shape.insert(RecordType::A, &format!("192.0.2.{i}"), false, 600);
            }
            let wanted = a(None, &["192.0.2.10", "192.0.2.11"]);
            assert_eq!(
                kind(shape.set(&wanted, Expect::Any).await),
                ErrorKind::InvalidInput,
                "{label}"
            );
            assert!(shape.writes().is_empty(), "{label}");
        }
    }

    // ---- Interleavings -----------------------------------------------------------------------

    /// Read-then-write: a change by another writer between the read and the write is
    /// overwritten and not detected; that is what `Preconditions::ReadThenWrite` states.
    #[tokio::test]
    async fn read_then_write_overwrites_a_concurrent_change() {
        let fake = rtw();
        store(&fake.0).insert(RecordType::A, "192.0.2.1", true, 600);
        store(&fake.0).foreign_before_write = vec!["192.0.2.66".into()];
        let outcome = super::set_whole_set(&fake, &zone(), &a(None, &["192.0.2.2"]), Expect::Any)
            .await
            .unwrap();
        assert_eq!(outcome, SetOutcome::Replaced);
        assert_eq!(
            store(&fake.0).texts(RecordType::A),
            [("192.0.2.2".to_owned(), true, 600)]
        );
        assert_eq!(store(&fake.0).writes_logged(), ["write"]);
    }

    /// Atomic: the refused write is repeated once from the read, which evaluates the
    /// expectation against the new state.
    #[tokio::test]
    async fn atomic_conflict_runs_again_from_the_read() {
        // Any: the second run writes over the new state.
        let fake = atomic();
        store(&fake.0).insert(RecordType::A, "192.0.2.1", true, 600);
        store(&fake.0).foreign_before_write = vec!["192.0.2.66".into()];
        let outcome = super::set_whole_set(&fake, &zone(), &a(None, &["192.0.2.2"]), Expect::Any)
            .await
            .unwrap();
        assert_eq!(outcome, SetOutcome::Replaced);
        assert_eq!(
            store(&fake.0).log,
            ["read", "write-refused", "read", "write"]
        );

        // Matches the old state: the second run fails the expectation, nothing is written.
        let fake = atomic();
        store(&fake.0).insert(RecordType::A, "192.0.2.1", true, 600);
        store(&fake.0).foreign_before_write = vec!["192.0.2.66".into()];
        let old = a(None, &["192.0.2.1"]);
        let e = super::set_whole_set(
            &fake,
            &zone(),
            &a(None, &["192.0.2.2"]),
            Expect::Matches(&old),
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
        assert_eq!(
            store(&fake.0).texts(RecordType::A),
            [
                ("192.0.2.1".to_owned(), true, 600),
                ("192.0.2.66".to_owned(), true, 600)
            ]
        );

        // Absent, and someone creates the rrset in between.
        let fake = atomic();
        store(&fake.0).foreign_before_write = vec!["192.0.2.66".into()];
        let e = super::set_whole_set(&fake, &zone(), &a(None, &["192.0.2.2"]), Expect::Absent)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");

        // Refused twice: `Conflict`, retryable, and ours was never written.
        let fake = atomic();
        store(&fake.0).insert(RecordType::A, "192.0.2.1", true, 600);
        store(&fake.0).foreign_before_write = vec!["192.0.2.66".into(), "192.0.2.67".into()];
        let e = super::set_whole_set(&fake, &zone(), &a(None, &["192.0.2.2"]), Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
        assert!(e.is_retryable());
        assert!(
            !store(&fake.0)
                .texts(RecordType::A)
                .iter()
                .any(|(t, ..)| t == "192.0.2.2")
        );

        // A delete is conditional too.
        let fake = atomic();
        store(&fake.0).insert(RecordType::A, "192.0.2.1", true, 600);
        store(&fake.0).foreign_before_write = vec!["192.0.2.66".into()];
        let e = super::delete_whole_set(
            &fake,
            &zone(),
            &name(),
            RecordType::A,
            Expect::Matches(&a(None, &["192.0.2.1"])),
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
        assert_eq!(store(&fake.0).texts(RecordType::A).len(), 2);
    }

    /// A read-then-write provider does not repeat a write after `Conflict`.
    #[tokio::test]
    async fn read_then_write_does_not_repeat_a_conflict() {
        struct Conflicting(WholeFake);
        base!(Conflicting);
        impl WholeSet for Conflicting {
            type Handle = Rec;
            type Snapshot = Vec<Rec>;
            type Context = ();
            async fn read(
                &self,
                zone: &DomainName,
                name: &DomainName,
                rtype: RecordType,
            ) -> WholeRead<Self> {
                self.0.read(zone, name, rtype).await
            }
            async fn write(
                &self,
                _zone: &DomainName,
                _name: &DomainName,
                _rtype: RecordType,
                _context: &(),
                _prior: Option<&Vec<Rec>>,
                _members: &[Member<'_, Rec>],
                _ttl: SetTtl,
            ) -> Result<(), Error> {
                store(&self.0.0).log.push("write-refused".into());
                Err(Error::conflict("created by someone else"))
            }
            async fn delete(
                &self,
                _zone: &DomainName,
                _name: &DomainName,
                _rtype: RecordType,
                _context: &(),
                _prior: &Vec<Rec>,
            ) -> Result<(), Error> {
                Ok(())
            }
        }
        let fake = Conflicting(rtw());
        let e = super::set_whole_set(&fake, &zone(), &a(None, &["192.0.2.2"]), Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Conflict);
        assert_eq!(store(&fake.0.0).log, ["read", "write-refused"]);
    }

    /// Per-record: creates before deletes, so the name never loses all its values; a failure
    /// part-way leaves a mixture, and the repeat completes the change.
    #[tokio::test]
    async fn per_record_creates_before_it_deletes_and_resumes() {
        let fake = per_record(true);
        store(&fake.0).insert(RecordType::A, "192.0.2.1", true, 600);
        store(&fake.0).insert(RecordType::A, "192.0.2.2", true, 600);
        let wanted = a(None, &["192.0.2.2", "192.0.2.3", "192.0.2.4"]);
        super::set_per_record(&fake, &zone(), &wanted, Expect::Any)
            .await
            .unwrap();
        assert_eq!(
            store(&fake.0).writes_logged(),
            ["create 192.0.2.3", "create 192.0.2.4", "delete 192.0.2.1"]
        );

        // The second create fails: the error is returned, the old value is still there.
        let fake = per_record(true);
        store(&fake.0).insert(RecordType::A, "192.0.2.1", true, 600);
        store(&fake.0).fail_write = Some(2);
        let wanted = a(None, &["192.0.2.3", "192.0.2.4"]);
        let e = super::set_per_record(&fake, &zone(), &wanted, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Transient);
        assert_eq!(
            store(&fake.0).texts(RecordType::A),
            [
                ("192.0.2.1".to_owned(), true, 600),
                ("192.0.2.3".to_owned(), true, 600)
            ]
        );
        // The repeat reads the mixture and sends only the rest; the record already created is
        // not touched.
        store(&fake.0).log.clear();
        assert_eq!(
            super::set_per_record(&fake, &zone(), &wanted, Expect::Any)
                .await
                .unwrap(),
            SetOutcome::Replaced
        );
        assert_eq!(
            store(&fake.0).writes_logged(),
            ["create 192.0.2.4", "delete 192.0.2.1"]
        );
        assert_eq!(
            super::set_per_record(&fake, &zone(), &wanted, Expect::Any)
                .await
                .unwrap(),
            SetOutcome::Unchanged
        );

        // A failing delete after the creates: the new values are published, the old one too.
        let fake = per_record(true);
        store(&fake.0).insert(RecordType::A, "192.0.2.1", true, 600);
        store(&fake.0).fail_write = Some(2);
        let wanted = a(None, &["192.0.2.3"]);
        assert!(
            super::set_per_record(&fake, &zone(), &wanted, Expect::Any)
                .await
                .is_err()
        );
        assert_eq!(
            store(&fake.0).writes_logged(),
            ["create 192.0.2.3", "write-failed"]
        );
        assert_eq!(
            store(&fake.0).texts(RecordType::A),
            [
                ("192.0.2.1".to_owned(), true, 600),
                ("192.0.2.3".to_owned(), true, 600)
            ]
        );
    }

    #[tokio::test]
    async fn per_record_singletons() {
        let cname = |target: &str| set(RecordType::CNAME, None, &[target]);
        // In place: one update, never two records of a singleton type at once.
        let fake = per_record(true);
        store(&fake.0).insert(RecordType::CNAME, "a.example.net.", true, 600);
        super::set_per_record(&fake, &zone(), &cname("b.example.net."), Expect::Any)
            .await
            .unwrap();
        assert_eq!(store(&fake.0).writes_logged(), ["update a.example.net."]);
        assert_eq!(
            store(&fake.0).texts(RecordType::CNAME),
            [("b.example.net.".to_owned(), true, 600)]
        );
        // Without in-place updates: delete, then create.
        let fake = per_record(false);
        store(&fake.0).insert(RecordType::CNAME, "a.example.net.", true, 600);
        super::set_per_record(&fake, &zone(), &cname("b.example.net."), Expect::Any)
            .await
            .unwrap();
        assert_eq!(
            store(&fake.0).writes_logged(),
            ["delete a.example.net.", "create b.example.net."]
        );
        assert_eq!(
            store(&fake.0).texts(RecordType::CNAME),
            [("b.example.net.".to_owned(), true, 600)]
        );
    }

    #[tokio::test]
    async fn per_record_ttl_change_and_delete_by_identifier() {
        let fake = per_record(true);
        store(&fake.0).insert(RecordType::A, "192.0.2.1", true, 600);
        store(&fake.0).insert(RecordType::A, "192.0.2.2", true, 300);
        store(&fake.0).insert(RecordType::A, "192.0.2.3", false, 300);
        // The smallest TTL is reported.
        assert_eq!(
            super::get_per_record(&fake, &zone(), &name(), RecordType::A)
                .await
                .unwrap(),
            Some(a(Some(300), &["192.0.2.1", "192.0.2.2"]))
        );
        // A record added without a TTL gets the set's TTL as read.
        super::set_per_record(
            &fake,
            &zone(),
            &a(None, &["192.0.2.1", "192.0.2.2", "192.0.2.4"]),
            Expect::Any,
        )
        .await
        .unwrap();
        assert!(
            store(&fake.0)
                .texts(RecordType::A)
                .contains(&("192.0.2.4".to_owned(), true, 300))
        );
        store(&fake.0).log.clear();
        // A TTL change touches every record that needs it.
        super::set_per_record(
            &fake,
            &zone(),
            &a(Some(300), &["192.0.2.1", "192.0.2.2", "192.0.2.4"]),
            Expect::Any,
        )
        .await
        .unwrap();
        assert_eq!(store(&fake.0).writes_logged(), ["update 192.0.2.1"]);
        store(&fake.0).log.clear();
        super::delete_per_record(&fake, &zone(), &name(), RecordType::A, Expect::Any)
            .await
            .unwrap();
        assert_eq!(
            store(&fake.0).writes_logged(),
            ["delete 192.0.2.1", "delete 192.0.2.2", "delete 192.0.2.4"]
        );
        assert_eq!(
            store(&fake.0).texts(RecordType::A),
            [("192.0.2.3".to_owned(), false, 300)]
        );
    }

    /// Two operations on one name sharing the locks never interleave: the second reads after
    /// the first wrote, so the second's expectation sees the first's result.
    #[tokio::test]
    async fn operations_on_one_name_are_serialized() {
        for shape in Shape::all() {
            let label = shape.label();
            store(shape.base()).write_delay = Duration::from_millis(100);
            let first = a(None, &["192.0.2.1"]);
            let second = a(None, &["192.0.2.2"]);
            let (r1, r2) = tokio::join!(
                shape.set(&first, Expect::Absent),
                shape.set(&second, Expect::Absent),
            );
            let mut kinds = [r1.map_err(|e| e.kind()), r2.map_err(|e| e.kind())];
            kinds.sort_by_key(|r| format!("{r:?}"));
            assert_eq!(
                kinds,
                [Err(ErrorKind::PreconditionFailed), Ok(SetOutcome::Created)],
                "{label}"
            );
            let log = store(shape.base()).log.clone();
            let first_write = log.iter().position(|op| op != "read").unwrap();
            assert_eq!(
                log.iter().filter(|op| *op == "read").count(),
                2,
                "{label}: {log:?}"
            );
            assert!(
                log.iter().skip(first_write).any(|op| op == "read"),
                "{label}: the second read did not wait for the first write: {log:?}"
            );
        }
    }

    /// A singleton never has two published records, not even for one request: duplicates of
    /// the old value, and a disabled record that holds the new one, are dealt with by deleting
    /// the surplus first.
    #[tokio::test]
    async fn per_record_singletons_are_never_duplicated() {
        let cname = |target: &str| set(RecordType::CNAME, None, &[target]);
        let b = || ("b.example.net.".to_owned(), true, 600);

        // Two records with the old value, in place: one is deleted, the other changed.
        let fake = per_record(true);
        store(&fake.0).insert(RecordType::CNAME, "a.example.net.", true, 600);
        store(&fake.0).insert(RecordType::CNAME, "a.example.net.", true, 600);
        super::set_per_record(&fake, &zone(), &cname("b.example.net."), Expect::Any)
            .await
            .unwrap();
        assert_eq!(
            store(&fake.0).writes_logged(),
            ["delete a.example.net.", "update a.example.net."]
        );
        assert_eq!(store(&fake.0).texts(RecordType::CNAME), [b()]);

        // The same without in-place updates: both deleted, then the create.
        let fake = per_record(false);
        store(&fake.0).insert(RecordType::CNAME, "a.example.net.", true, 600);
        store(&fake.0).insert(RecordType::CNAME, "a.example.net.", true, 600);
        super::set_per_record(&fake, &zone(), &cname("b.example.net."), Expect::Any)
            .await
            .unwrap();
        assert_eq!(
            store(&fake.0).writes_logged(),
            [
                "delete a.example.net.",
                "delete a.example.net.",
                "create b.example.net."
            ]
        );
        assert_eq!(store(&fake.0).texts(RecordType::CNAME), [b()]);

        // The new value is held by a disabled record: the old record goes before it is enabled.
        let fake = per_record(true);
        store(&fake.0).insert(RecordType::CNAME, "a.example.net.", true, 600);
        store(&fake.0).insert(RecordType::CNAME, "b.example.net.", false, 600);
        super::set_per_record(&fake, &zone(), &cname("b.example.net."), Expect::Any)
            .await
            .unwrap();
        assert_eq!(
            store(&fake.0).writes_logged(),
            ["delete a.example.net.", "update b.example.net."]
        );
        assert_eq!(store(&fake.0).texts(RecordType::CNAME), [b()]);
    }

    /// An in-place change of a singleton carries a requested TTL.
    #[tokio::test]
    async fn per_record_in_place_update_carries_the_requested_ttl() {
        let fake = per_record(true);
        store(&fake.0).insert(RecordType::CNAME, "a.example.net.", true, 600);
        let wanted = set(RecordType::CNAME, Some(900), &["b.example.net."]);
        super::set_per_record(&fake, &zone(), &wanted, Expect::Any)
            .await
            .unwrap();
        assert_eq!(store(&fake.0).writes_logged(), ["update a.example.net."]);
        assert_eq!(
            store(&fake.0).texts(RecordType::CNAME),
            [("b.example.net.".to_owned(), true, 900)]
        );
    }

    /// Where the client can tell what else is at the name, a CNAME next to other data is
    /// refused after the read and before any write, in both directions; where it cannot, the
    /// write is sent and the provider's answer decides.
    #[tokio::test]
    async fn cname_next_to_other_data_is_refused_where_the_client_can_tell() {
        let cname = set(RecordType::CNAME, None, &["a.example.net."]);
        for shape in Shape::all() {
            let label = shape.label();
            store(shape.base()).coexistence = true;
            shape.insert(RecordType::A, "192.0.2.1", true, 600);
            let e = shape.set(&cname, Expect::Any).await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidInput, "{label}: {e:?}");
            assert!(shape.writes().is_empty(), "{label}: {:?}", shape.writes());
            // A disabled record is not published data.
            store(shape.base()).sets.clear();
            shape.insert(RecordType::A, "192.0.2.1", false, 600);
            assert_eq!(
                shape.set(&cname, Expect::Any).await.unwrap(),
                SetOutcome::Created,
                "{label}"
            );
            // The other direction: a name with a CNAME takes no other type.
            let before = shape.writes().len();
            let e = shape
                .set(&set(RecordType::TXT, None, &["\"v\""]), Expect::Any)
                .await
                .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidInput, "{label}: {e:?}");
            assert_eq!(shape.writes().len(), before, "{label}");
            // Replacing the CNAME itself is not affected.
            assert_eq!(
                shape
                    .set(
                        &set(RecordType::CNAME, None, &["b.example.net."]),
                        Expect::Any
                    )
                    .await
                    .unwrap(),
                SetOutcome::Replaced,
                "{label}"
            );
        }
        // The client does not tell: the write is sent.
        for shape in Shape::all() {
            shape.insert(RecordType::A, "192.0.2.1", true, 600);
            assert_eq!(
                shape.set(&cname, Expect::Any).await.unwrap(),
                SetOutcome::Created,
                "{}",
                shape.label()
            );
        }
    }

    /// The whole plan reaches the client before the first write: a refusal leaves everything
    /// as it was, including TTL changes that would have come before the refused create.
    #[tokio::test]
    async fn per_record_plan_is_checked_before_any_write() {
        let fake = per_record(true);
        store(&fake.0).insert(RecordType::A, "192.0.2.1", true, 600);
        store(&fake.0).refuse_creates = true;
        let e = super::set_per_record(
            &fake,
            &zone(),
            &a(Some(300), &["192.0.2.1", "192.0.2.2"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected);
        assert_eq!(store(&fake.0).writes_logged(), ["plan-refused"]);
        assert_eq!(
            store(&fake.0).texts(RecordType::A),
            [("192.0.2.1".to_owned(), true, 600)]
        );
        // A plan without creates passes.
        super::set_per_record(&fake, &zone(), &a(Some(300), &["192.0.2.1"]), Expect::Any)
            .await
            .unwrap();
        assert_eq!(
            store(&fake.0).texts(RecordType::A),
            [("192.0.2.1".to_owned(), true, 300)]
        );

        // The whole-set counterpart is asked before the second read.
        let fake = rtw();
        store(&fake.0).reread = true;
        store(&fake.0).refuse_creates = true;
        store(&fake.0).insert(RecordType::A, "192.0.2.1", true, 600);
        let e = super::set_whole_set(
            &fake,
            &zone(),
            &a(None, &["192.0.2.1", "192.0.2.2"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected);
        assert_eq!(store(&fake.0).log, ["read", "plan-refused"]);
    }

    /// The order of the requests: enables, TTL changes, creates, deletes; records in the order
    /// of the read, new values in the order of the requested set (sorted).
    #[tokio::test]
    async fn per_record_requests_have_a_fixed_order() {
        let mut fake = per_record(true);
        fake.0.max = None;
        store(&fake.0).insert(RecordType::A, "192.0.2.1", true, 600);
        store(&fake.0).insert(RecordType::A, "192.0.2.2", true, 300);
        store(&fake.0).insert(RecordType::A, "192.0.2.3", false, 600);
        store(&fake.0).insert(RecordType::A, "192.0.2.4", true, 600);
        let wanted = a(
            Some(900),
            &[
                "192.0.2.6",
                "192.0.2.2",
                "192.0.2.5",
                "192.0.2.1",
                "192.0.2.3",
            ],
        );
        super::set_per_record(&fake, &zone(), &wanted, Expect::Any)
            .await
            .unwrap();
        assert_eq!(
            store(&fake.0).writes_logged(),
            [
                "update 192.0.2.3",
                "update 192.0.2.1",
                "update 192.0.2.2",
                "create 192.0.2.5",
                "create 192.0.2.6",
                "delete 192.0.2.4"
            ]
        );
        assert!(
            store(&fake.0)
                .texts(RecordType::A)
                .iter()
                .all(|(_, enabled, ttl)| *enabled && *ttl == 900)
        );
    }

    /// A whole-set read whose records state their own TTLs: a requested TTL equal to the
    /// rrset's (the smallest) is not "unchanged" while another record differs.
    #[tokio::test]
    async fn whole_set_with_per_record_ttls_writes_a_differing_ttl() {
        for fake in [rtw(), atomic()] {
            store(&fake.0).insert(RecordType::A, "192.0.2.1", true, 300);
            store(&fake.0).insert(RecordType::A, "192.0.2.2", true, 600);
            let wanted = a(Some(300), &["192.0.2.1", "192.0.2.2"]);
            assert_eq!(
                super::set_whole_set(&fake, &zone(), &wanted, Expect::Any)
                    .await
                    .unwrap(),
                SetOutcome::Replaced
            );
            assert_eq!(
                store(&fake.0).texts(RecordType::A),
                [
                    ("192.0.2.1".to_owned(), true, 300),
                    ("192.0.2.2".to_owned(), true, 300)
                ]
            );
            assert_eq!(
                super::set_whole_set(&fake, &zone(), &wanted, Expect::Any)
                    .await
                    .unwrap(),
                SetOutcome::Unchanged
            );
        }
    }

    /// `Expect::Matches` with a TTL against records that disagree on their TTLs compares with
    /// the smallest, the TTL the rrset reads with.
    #[tokio::test]
    async fn per_record_expectation_with_a_ttl_uses_the_smallest() {
        let fake = per_record(true);
        store(&fake.0).insert(RecordType::A, "192.0.2.1", true, 600);
        store(&fake.0).insert(RecordType::A, "192.0.2.2", true, 300);
        let both = ["192.0.2.1", "192.0.2.2"];
        let wanted = a(None, &["192.0.2.1"]);
        let e = super::set_per_record(
            &fake,
            &zone(),
            &wanted,
            Expect::Matches(&a(Some(600), &both)),
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed);
        let e = super::delete_per_record(
            &fake,
            &zone(),
            &name(),
            RecordType::A,
            Expect::Matches(&a(Some(600), &both)),
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed);
        assert!(store(&fake.0).writes_logged().is_empty());
        assert_eq!(
            super::set_per_record(
                &fake,
                &zone(),
                &wanted,
                Expect::Matches(&a(Some(300), &both))
            )
            .await
            .unwrap(),
            SetOutcome::Replaced
        );
        assert_eq!(store(&fake.0).writes_logged(), ["delete 192.0.2.2"]);
    }

    /// With `reread_before_write`, a change between the read and the second read is
    /// `Conflict` for a create, an update and a delete, nothing is written, and the
    /// read-then-write layer does not repeat it; the caller's repeat succeeds.
    #[tokio::test]
    async fn reread_before_write_turns_a_change_into_conflict() {
        let reread = |existing: &[&str]| {
            let fake = rtw();
            store(&fake.0).reread = true;
            for text in existing {
                store(&fake.0).insert(RecordType::A, text, true, 600);
            }
            store(&fake.0).foreign_after_read = Some((1, "192.0.2.66".into()));
            fake
        };
        let wanted = a(None, &["192.0.2.2"]);
        for existing in [&[][..], &["192.0.2.1"][..]] {
            let fake = reread(existing);
            let e = super::set_whole_set(&fake, &zone(), &wanted, Expect::Any)
                .await
                .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Conflict, "{existing:?}: {e:?}");
            assert!(e.is_retryable());
            assert_eq!(store(&fake.0).log, ["read", "read"], "{existing:?}");
            store(&fake.0).log.clear();
            assert_ne!(
                super::set_whole_set(&fake, &zone(), &wanted, Expect::Any)
                    .await
                    .unwrap(),
                SetOutcome::Unchanged
            );
            assert_eq!(
                store(&fake.0).log,
                ["read", "read", "write"],
                "{existing:?}"
            );
            assert_eq!(
                store(&fake.0).texts(RecordType::A),
                [("192.0.2.2".to_owned(), true, 600)]
            );
        }
        let fake = reread(&["192.0.2.1"]);
        let e = super::delete_whole_set(&fake, &zone(), &name(), RecordType::A, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
        assert_eq!(store(&fake.0).texts(RecordType::A).len(), 2);
        assert_eq!(
            super::delete_whole_set(&fake, &zone(), &name(), RecordType::A, Expect::Any)
                .await
                .unwrap(),
            DeleteOutcome::Deleted
        );
        assert!(store(&fake.0).texts(RecordType::A).is_empty());
    }

    #[test]
    fn smallest_ttl_ignores_records_without_one() {
        let ttl = |s| Some(Ttl::from_secs(s).unwrap());
        assert_eq!(
            Listing::smallest_ttl([None, ttl(600), None, ttl(300)]),
            ttl(300)
        );
        assert_eq!(Listing::smallest_ttl([None, None]), None);
        assert_eq!(Listing::smallest_ttl([]), None);
    }

    // ---- Listings ----------------------------------------------------------------------------

    #[test]
    fn listing_reports_what_it_cannot_hold() {
        let zone = zone();
        let mut listing = Listing::new(&zone);
        let txt = |t: &str| data(RecordType::TXT, t);
        listing.push(
            Some(dn("b.example.org")),
            "A",
            None,
            vec![data(RecordType::A, "192.0.2.1")],
        );
        listing.push(Some(dn("a.example.org")), "TXT", None, vec![txt("\"x\"")]);
        listing.push(
            Some(dn("a.example.org")),
            "A",
            None,
            vec![data(RecordType::A, "!odd")],
        );
        // Only disabled records: not part of the listing.
        listing.push(Some(dn("c.example.org")), "A", None, Vec::new());
        listing.push(
            Some(dn("d.example.org")),
            "WEIRD",
            None,
            vec![RecordData::non_canonical("x")],
        );
        listing.push(None, "A", None, vec![data(RecordType::A, "192.0.2.1")]);
        listing.push(
            Some(dn("example.net")),
            "A",
            None,
            vec![data(RecordType::A, "192.0.2.1")],
        );
        listing.push(
            Some(dn("e.example.org")),
            "ANY",
            None,
            vec![RecordData::non_canonical("x")],
        );
        listing.push(
            Some(dn("f.example.org")),
            "CNAME",
            None,
            vec![
                data(RecordType::CNAME, "a.example.net."),
                data(RecordType::CNAME, "b.example.net."),
            ],
        );
        let listing = listing.finish(ProviderId::SelectelV2).unwrap();
        let sets: Vec<(String, RecordType)> = listing
            .rrsets
            .iter()
            .map(|s| (s.name().to_string(), s.rtype()))
            .collect();
        assert_eq!(
            sets,
            [
                ("a.example.org.".to_owned(), RecordType::A),
                ("a.example.org.".to_owned(), RecordType::TXT),
                ("b.example.org.".to_owned(), RecordType::A),
            ]
        );
        assert!(!listing.rrsets[0].records()[0].is_canonical());
        let skipped: Vec<(String, &str, SkipReason)> = listing
            .skipped
            .iter()
            .map(|s| (s.name.to_string(), s.type_name.as_str(), s.reason))
            .collect();
        assert_eq!(
            skipped,
            [
                (
                    "d.example.org.".to_owned(),
                    "WEIRD",
                    SkipReason::UnknownType
                ),
                ("example.org.".to_owned(), "A", SkipReason::UnsupportedName),
                ("example.org.".to_owned(), "A", SkipReason::UnsupportedName),
                (
                    "e.example.org.".to_owned(),
                    "ANY",
                    SkipReason::NotPlainRecords
                ),
                (
                    "f.example.org.".to_owned(),
                    "CNAME",
                    SkipReason::NotPlainRecords
                ),
            ]
        );
    }

    #[test]
    fn a_listing_with_two_sets_of_one_name_and_type_is_protocol() {
        let zone = zone();
        let mut listing = Listing::new(&zone);
        for text in ["192.0.2.1", "192.0.2.2"] {
            listing.push(Some(name()), "A", None, vec![data(RecordType::A, text)]);
        }
        let e = listing.finish(ProviderId::SelectelV2).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol);
    }

    /// A read the model cannot hold fails the operation instead of writing over it.
    #[tokio::test]
    async fn a_set_the_model_cannot_hold_is_protocol() {
        for shape in Shape::all() {
            shape.insert(RecordType::CNAME, "a.example.net.", true, 600);
            shape.insert(RecordType::CNAME, "b.example.net.", true, 600);
            assert_eq!(
                kind(shape.get(RecordType::CNAME).await),
                ErrorKind::Protocol
            );
            let wanted = set(RecordType::CNAME, None, &["c.example.net."]);
            assert_eq!(
                kind(shape.set(&wanted, Expect::Any).await),
                ErrorKind::Protocol
            );
            assert!(shape.writes().is_empty());
        }
    }
}
