//! The generic TXT value layer (design section 3.5).
//!
//! `add_txt_value` and `remove_txt_value` are implemented once, here, over three private traits
//! that match the three native shapes of provider APIs:
//!
//! - [`PerRecord`]: individual records with identifiers (Cloudflare, DigitalOcean, nic.ru,
//!   reg.ru, Timeweb Cloud, VK Cloud, Yandex 360) and the single-RR changes of RFC 2136;
//! - [`ValueCalls`]: an rrset with value-level add and remove calls (Hetzner);
//! - [`WholeSet`]: an rrset replaced whole, with a conditional write (Route 53, Yandex Cloud),
//!   without one (Selectel v2, Beget), or without one but re-read before the write (Cloud.ru).
//!
//! A client supplies the reads and writes of its API; the checks before any request, the per-name
//! lock, the outcome computation, the TTL policy and the foreign-value rules are this module's.
//!
//! Rules the client keeps when it implements a trait:
//!
//! - A read is complete or it fails. A read that was truncated or had an unexpected shape is an
//!   error, never a shorter list (a whole set is never written after an incomplete read).
//! - Every TXT record at the name is returned, including those whose text the client's dialect
//!   cannot decode: they have `value == None`, never equal any value, and are written back as they
//!   were.
//! - The handle carries whatever the client needs to write a record back exactly as the provider
//!   returned it (same text, same attributes) or to delete it by identifier.
//! - A delete answered "not found" is not done on the strength of that answer alone, since the
//!   answer can also mean that the zone identifier the client used went stale, or that the domain
//!   was deleted and created again, while the value is still published (design sections 3.5 and
//!   3.8). The client drops a cached zone identifier and reads again: when the new read no longer
//!   finds the deleted record's value (per-record) or the rrset (whole set), the delete is done;
//!   otherwise the result is [`Error::Conflict`].
//! - A conditional write that the provider refused because the rrset changed returns
//!   [`Error::Conflict`]; apart from the delete above, nothing else does.
//!
//! acme-dns does not use this layer: it has no read (design section 11.3).

// Design section 9.2: each client uses one of the three shapes, so builds without
// `all-providers` allow the unused ones; the build with all providers does not, so that code no
// provider uses is found.
#![cfg_attr(not(feature = "all-providers"), allow(dead_code))]

use std::future::Future;

use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::{Capabilities, TtlSupport, ValueGuarantee};
use crate::name::DomainName;
use crate::provider::{AddOutcome, RemoveOutcome};
use crate::record::{RrsetTtl, Txt};
use crate::redact::Detail;

/// One TXT record as the provider returned it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TxtRecord<H> {
    /// The value decoded with the client's reading rule; `None` when the text could not be
    /// decoded. Such a record is a foreign value that is never equal to ours.
    pub(crate) value: Option<Txt>,
    /// The record's TTL: a number, `ProviderDefault` for a record without a TTL of its own, or
    /// `None` when the read does not tell.
    pub(crate) ttl: Option<RrsetTtl>,
    /// What the client needs to delete the record or write it back unchanged.
    pub(crate) handle: H,
}

/// The TTL a write is to carry (design section 3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteTtl {
    /// The rrset is created: the caller's TTL (a number or the provider's default), or with
    /// `None` the client's `ttl` setting (which may be the provider's default).
    New(Option<RrsetTtl>),
    /// The value joins, or the set rewrites, an existing rrset: its TTL as read. `None`: the
    /// read did not state one; what the client sends then is its own documented choice.
    Existing(Option<RrsetTtl>),
}

impl WriteTtl {
    /// The TTL the write carries, `setting` standing for the client's `ttl` setting: a number,
    /// the provider's default, or `None` for an existing rrset whose TTL the read did not state.
    pub(crate) fn resolve(self, setting: RrsetTtl) -> Option<RrsetTtl> {
        match self {
            WriteTtl::New(ttl) => Some(ttl.unwrap_or(setting)),
            WriteTtl::Existing(ttl) => ttl,
        }
    }
}

/// The answer of a [`PerRecord`] read.
#[derive(Clone, Debug)]
pub(crate) enum PerRecordRead<H> {
    /// Every TXT record at the name; empty when there is none.
    Records(Vec<TxtRecord<H>>),
    /// The provider refused to be read (an RFC 2136 server that allows updates but refuses
    /// queries). The layer then sends the idempotent change blind and reports `Accepted`.
    Unavailable,
}

/// A whole TXT rrset as read from a [`WholeSet`] provider.
#[derive(Clone, Debug)]
pub(crate) struct TxtSet<H, S> {
    /// The records; never empty (a missing rrset is `None`).
    pub(crate) records: Vec<TxtRecord<H>>,
    /// The rrset's TTL: a number, `ProviderDefault`, or `None` when the read does not tell.
    pub(crate) ttl: Option<RrsetTtl>,
    /// The old set as the client read it: what a conditional write sends as its condition, and
    /// what a re-read is compared with.
    pub(crate) snapshot: S,
}

/// What a [`WholeSet`] read found.
#[derive(Clone, Debug)]
pub(crate) struct SetState<H, S, C> {
    /// What the read learned that the write needs whatever it found, such as the zone
    /// identifier it used. A create has nothing else to go by.
    pub(crate) context: C,
    /// The set, or `None` when there is no TXT rrset at the name.
    pub(crate) set: Option<TxtSet<H, S>>,
}

/// The answer of a [`WholeSet`] read.
pub(crate) type SetRead<H, S, C> = Result<SetState<H, S, C>, Error>;

/// One member of a whole set to be written.
#[derive(Debug)]
pub(crate) enum Member<'a, H> {
    /// A record that was read, written back exactly as the provider returned it.
    Kept(&'a TxtRecord<H>),
    /// The value being added, encoded with the client's writing rule.
    Added(&'a Txt),
}

/// What every shape provides.
pub(crate) trait TxtBase: Send + Sync {
    /// The provider, for `Error::Unsupported`.
    fn provider(&self) -> ProviderId;

    /// The capabilities that decide which operations are offered and what they accept.
    fn capabilities(&self) -> &Capabilities;

    /// The per-name locks of the client's `Context`.
    fn locks(&self) -> &NameLocks;

    /// Client-specific checks of a value made before any request (design section 3.1, check 4),
    /// beyond `txt_plain_only`.
    fn check_value(&self, value: &Txt) -> Result<(), Error> {
        let _ = value;
        Ok(())
    }
}

/// Individual records with identifiers.
pub(crate) trait PerRecord: TxtBase {
    /// Identifies one record (an ID, or for RFC 2136 the record itself).
    type Handle: Send + Sync;

    /// Every TXT record at `name`.
    fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> impl Future<Output = Result<PerRecordRead<Self::Handle>, Error>> + Send;

    /// Creates one record holding `value`.
    fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: WriteTtl,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Deletes one record. A "not found" answer is done only when a new read no longer finds
    /// the record's value; when it does, the result is `Error::Conflict` (module documentation).
    fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        record: &TxtRecord<Self::Handle>,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Deletes the records holding `value` without having read them. Called only after `read`
    /// returned [`PerRecordRead::Unavailable`]; a client that never does keeps this default.
    fn delete_blind(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        let _ = (zone, name, value);
        async {
            Err(Error::Protocol {
                detail: Detail::constant("the client cannot remove a value without reading"),
            })
        }
    }
}

/// An rrset with value-level add and remove calls.
pub(crate) trait ValueCalls: TxtBase {
    /// Identifies one value as the provider spells it.
    type Handle: Send + Sync;

    /// Every TXT value at `name`.
    fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> impl Future<Output = Result<Vec<TxtRecord<Self::Handle>>, Error>> + Send;

    /// Asks the provider to add `value`, creating the rrset if needed.
    fn add(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: WriteTtl,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Asks the provider to remove exactly these values, spelled as it returned them.
    fn remove(
        &self,
        zone: &DomainName,
        name: &DomainName,
        records: &[&TxtRecord<Self::Handle>],
    ) -> impl Future<Output = Result<(), Error>> + Send;
}

/// An rrset replaced whole.
///
/// The guarantee against outside writers comes from `capabilities().txt_values`:
/// `Conditional` makes the layer repeat the operation once after a [`Error::Conflict`];
/// `ReadThenWrite` does not. [`WholeSet::reread_before_write`] adds a second read immediately
/// before every write, which turns a change seen in between into `Error::Conflict`.
pub(crate) trait WholeSet: TxtBase {
    /// Identifies one record as the provider spells it.
    type Handle: Send + Sync;
    /// The old set as read.
    type Snapshot: PartialEq + Send + Sync;
    /// What the read hands to the write and the delete in every case ([`SetState::context`]).
    type Context: Send + Sync;

    /// The TXT rrset at `name`, or `None`, with the read's context.
    fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> impl Future<Output = SetRead<Self::Handle, Self::Snapshot, Self::Context>> + Send;

    /// Writes the rrset with exactly `members`. `context` is the read's; `prior` is the set as
    /// read (`None`: it did not exist); a conditional client makes the write depend on it.
    fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        context: &Self::Context,
        prior: Option<&Self::Snapshot>,
        members: &[Member<'_, Self::Handle>],
        ttl: WriteTtl,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Deletes the rrset; a conditional client makes the delete depend on `prior`.
    fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        context: &Self::Context,
        prior: &Self::Snapshot,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Read the set again immediately before each write and refuse with `Error::Conflict` if it
    /// changed (Cloud.ru).
    fn reread_before_write(&self) -> bool {
        false
    }
}

/// How many times a conditional whole-set operation runs: once, and once more after the
/// provider refused the write because the rrset changed (design section 3.4).
const CONDITIONAL_ATTEMPTS: usize = 2;

fn conflict() -> Error {
    Error::Conflict {
        detail: Detail::constant("the TXT rrset changed between the read and the write"),
    }
}

/// The checks of design section 3.1, in order, before any request.
fn precheck<B: TxtBase>(
    backend: &B,
    operation: Operation,
    zone: &DomainName,
    name: &DomainName,
    value: &Txt,
    ttl: Option<RrsetTtl>,
) -> Result<(), Error> {
    let caps = backend.capabilities();
    if !caps.supports(operation) {
        return Err(Error::unsupported(backend.provider(), operation));
    }
    if zone.is_root() || zone.is_wildcard() {
        return Err(Error::InvalidInput {
            detail: Detail::constant("the zone must not be the root or a wildcard name"),
            code: None,
        });
    }
    if !name.is_within(zone) {
        return Err(Error::name_outside_zone(name.clone(), zone.clone()));
    }
    if let Some(ttl) = ttl
        && !caps.accepts_ttl(ttl)
    {
        return Err(Error::InvalidInput {
            detail: Detail::constant(ttl_refusal(caps, ttl)),
            code: None,
        });
    }
    if caps.txt_plain_only && !value.is_plain() {
        return Err(Error::InvalidInput {
            detail: Detail::constant(
                "the provider accepts only plain TXT values: 1 to 255 printable ASCII characters \
                 without spaces, quotes or backslashes",
            ),
            code: None,
        });
    }
    backend.check_value(value)
}

/// The text of the refusal of a requested TTL that `caps` does not accept (design section 3.6).
/// Shared with the record-level layer, which is compiled with a subset of the providers that
/// compile this module.
pub(crate) fn ttl_refusal(caps: &Capabilities, ttl: RrsetTtl) -> &'static str {
    match ttl {
        RrsetTtl::ProviderDefault => {
            "the provider has no default TTL of its own: the TTL must be a number"
        }
        _ if caps.ttl == TtlSupport::NotSettable => {
            "the provider chooses the TTL; a requested TTL cannot be honored"
        }
        _ => "the TTL is outside the range the provider accepts",
    }
}

fn holds<H>(record: &TxtRecord<H>, value: &Txt) -> bool {
    record.value.as_ref() == Some(value)
}

/// The TTL an existing per-record set is reported with: the smallest explicit one read, else
/// the provider's default when a record has it (design section 3.6).
fn smallest_ttl<H>(records: &[TxtRecord<H>]) -> Option<RrsetTtl> {
    RrsetTtl::of_records(records.iter().map(|record| record.ttl))
}

/// `add_txt_value` for a [`PerRecord`] provider.
pub(crate) async fn add_per_record<B: PerRecord>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    value: &Txt,
    ttl: Option<RrsetTtl>,
) -> Result<AddOutcome, Error> {
    precheck(backend, Operation::AddTxtValue, zone, name, value, ttl)?;
    let _guard = backend.locks().lock(name).await;
    match backend.read(zone, name).await? {
        PerRecordRead::Unavailable => {
            backend
                .create(zone, name, value, WriteTtl::New(ttl))
                .await?;
            Ok(AddOutcome::Accepted)
        }
        PerRecordRead::Records(records) => {
            if records.iter().any(|record| holds(record, value)) {
                return Ok(AddOutcome::AlreadyPresent);
            }
            if records.is_empty() {
                backend
                    .create(zone, name, value, WriteTtl::New(ttl))
                    .await?;
                Ok(AddOutcome::Created)
            } else {
                let ttl = WriteTtl::Existing(smallest_ttl(&records));
                backend.create(zone, name, value, ttl).await?;
                Ok(AddOutcome::Appended)
            }
        }
    }
}

/// `remove_txt_value` for a [`PerRecord`] provider.
pub(crate) async fn remove_per_record<B: PerRecord>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    value: &Txt,
) -> Result<RemoveOutcome, Error> {
    precheck(backend, Operation::RemoveTxtValue, zone, name, value, None)?;
    let _guard = backend.locks().lock(name).await;
    match backend.read(zone, name).await? {
        PerRecordRead::Unavailable => {
            backend.delete_blind(zone, name, value).await?;
            Ok(RemoveOutcome::Accepted)
        }
        PerRecordRead::Records(records) => {
            let ours: Vec<&TxtRecord<B::Handle>> = records
                .iter()
                .filter(|record| holds(record, value))
                .collect();
            if ours.is_empty() {
                return Ok(RemoveOutcome::NotPresent);
            }
            for record in &ours {
                backend.delete(zone, name, record).await?;
            }
            Ok(if ours.len() == records.len() {
                RemoveOutcome::RrsetDeleted
            } else {
                RemoveOutcome::Removed
            })
        }
    }
}

/// `add_txt_value` for a [`ValueCalls`] provider.
pub(crate) async fn add_value_calls<B: ValueCalls>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    value: &Txt,
    ttl: Option<RrsetTtl>,
) -> Result<AddOutcome, Error> {
    precheck(backend, Operation::AddTxtValue, zone, name, value, ttl)?;
    let _guard = backend.locks().lock(name).await;
    let records = backend.read(zone, name).await?;
    if records.iter().any(|record| holds(record, value)) {
        return Ok(AddOutcome::AlreadyPresent);
    }
    if records.is_empty() {
        backend.add(zone, name, value, WriteTtl::New(ttl)).await?;
        Ok(AddOutcome::Created)
    } else {
        let ttl = WriteTtl::Existing(smallest_ttl(&records));
        backend.add(zone, name, value, ttl).await?;
        Ok(AddOutcome::Appended)
    }
}

/// `remove_txt_value` for a [`ValueCalls`] provider.
pub(crate) async fn remove_value_calls<B: ValueCalls>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    value: &Txt,
) -> Result<RemoveOutcome, Error> {
    precheck(backend, Operation::RemoveTxtValue, zone, name, value, None)?;
    let _guard = backend.locks().lock(name).await;
    let records = backend.read(zone, name).await?;
    let ours: Vec<&TxtRecord<B::Handle>> = records
        .iter()
        .filter(|record| holds(record, value))
        .collect();
    if ours.is_empty() {
        return Ok(RemoveOutcome::NotPresent);
    }
    backend.remove(zone, name, &ours).await?;
    Ok(if ours.len() == records.len() {
        RemoveOutcome::RrsetDeleted
    } else {
        RemoveOutcome::Removed
    })
}

/// `add_txt_value` for a [`WholeSet`] provider.
pub(crate) async fn add_whole_set<B: WholeSet>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    value: &Txt,
    ttl: Option<RrsetTtl>,
) -> Result<AddOutcome, Error> {
    precheck(backend, Operation::AddTxtValue, zone, name, value, ttl)?;
    let _guard = backend.locks().lock(name).await;
    let mut attempt = 1;
    loop {
        match add_whole_set_once(backend, zone, name, value, ttl).await {
            Err(Error::Conflict { .. }) if repeat_after_conflict(backend, attempt) => attempt += 1,
            result => return result,
        }
    }
}

/// `remove_txt_value` for a [`WholeSet`] provider.
pub(crate) async fn remove_whole_set<B: WholeSet>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    value: &Txt,
) -> Result<RemoveOutcome, Error> {
    precheck(backend, Operation::RemoveTxtValue, zone, name, value, None)?;
    let _guard = backend.locks().lock(name).await;
    let mut attempt = 1;
    loop {
        match remove_whole_set_once(backend, zone, name, value).await {
            Err(Error::Conflict { .. }) if repeat_after_conflict(backend, attempt) => attempt += 1,
            result => return result,
        }
    }
}

fn repeat_after_conflict<B: WholeSet>(backend: &B, attempt: usize) -> bool {
    backend.capabilities().txt_values == ValueGuarantee::Conditional
        && attempt < CONDITIONAL_ATTEMPTS
}

/// A set read is never empty; an empty one is an unexpected shape, and nothing is written after
/// it.
fn non_empty<H, S>(set: Option<TxtSet<H, S>>) -> Result<Option<TxtSet<H, S>>, Error> {
    match set {
        Some(set) if set.records.is_empty() => Err(Error::Protocol {
            detail: Detail::constant("the provider returned a TXT rrset without records"),
        }),
        other => Ok(other),
    }
}

/// For [`WholeSet::reread_before_write`]: reads again and fails with `Conflict` unless the set is
/// as it was.
async fn reread_unchanged<B: WholeSet>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    prior: Option<&B::Snapshot>,
) -> Result<(), Error> {
    if !backend.reread_before_write() {
        return Ok(());
    }
    let again = non_empty(backend.read(zone, name).await?.set)?;
    if again.as_ref().map(|set| &set.snapshot) == prior {
        Ok(())
    } else {
        Err(conflict())
    }
}

async fn add_whole_set_once<B: WholeSet>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    value: &Txt,
    ttl: Option<RrsetTtl>,
) -> Result<AddOutcome, Error> {
    let state = backend.read(zone, name).await?;
    let context = &state.context;
    match non_empty(state.set)? {
        None => {
            reread_unchanged(backend, zone, name, None).await?;
            let members = [Member::Added(value)];
            backend
                .write(zone, name, context, None, &members, WriteTtl::New(ttl))
                .await?;
            Ok(AddOutcome::Created)
        }
        Some(set) => {
            if set.records.iter().any(|record| holds(record, value)) {
                return Ok(AddOutcome::AlreadyPresent);
            }
            let members: Vec<Member<'_, B::Handle>> = set
                .records
                .iter()
                .map(Member::Kept)
                .chain(std::iter::once(Member::Added(value)))
                .collect();
            reread_unchanged(backend, zone, name, Some(&set.snapshot)).await?;
            backend
                .write(
                    zone,
                    name,
                    context,
                    Some(&set.snapshot),
                    &members,
                    WriteTtl::Existing(set.ttl),
                )
                .await?;
            Ok(AddOutcome::Appended)
        }
    }
}

async fn remove_whole_set_once<B: WholeSet>(
    backend: &B,
    zone: &DomainName,
    name: &DomainName,
    value: &Txt,
) -> Result<RemoveOutcome, Error> {
    let state = backend.read(zone, name).await?;
    let context = &state.context;
    let Some(set) = non_empty(state.set)? else {
        return Ok(RemoveOutcome::NotPresent);
    };
    if !set.records.iter().any(|record| holds(record, value)) {
        return Ok(RemoveOutcome::NotPresent);
    }
    let rest: Vec<Member<'_, B::Handle>> = set
        .records
        .iter()
        .filter(|record| !holds(record, value))
        .map(Member::Kept)
        .collect();
    reread_unchanged(backend, zone, name, Some(&set.snapshot)).await?;
    if rest.is_empty() {
        backend.delete(zone, name, context, &set.snapshot).await?;
        Ok(RemoveOutcome::RrsetDeleted)
    } else {
        backend
            .write(
                zone,
                name,
                context,
                Some(&set.snapshot),
                &rest,
                WriteTtl::Existing(set.ttl),
            )
            .await?;
        Ok(RemoveOutcome::Removed)
    }
}

#[cfg(test)]
mod tests {
    //! The layer against in-memory providers of each native shape (design section 12.3).

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::{
        Member, PerRecord, PerRecordRead, SetRead, SetState, TxtBase, TxtRecord, TxtSet,
        ValueCalls, WholeSet, WriteTtl,
    };
    use crate::error::{Error, ErrorKind};
    use crate::id::ProviderId;
    use crate::locks::NameLocks;
    use crate::meta::{
        Capabilities, Preconditions, ProviderDefaultTtl, TtlSupport, TypeSet, ValueGuarantee,
    };
    use crate::name::DomainName;
    use crate::provider::{AddOutcome, RemoveOutcome};
    use crate::record::{RrsetTtl, Txt};

    /// The TTL the fake provider gives a new rrset when the client sends none.
    const DEFAULT_TTL: u32 = 300;

    /// The fake's spelling of "no TTL of its own: the provider's default" in a stored record.
    const PD: u32 = u32::MAX;

    /// A stored TTL as the layer sees it.
    fn rrset_ttl(secs: u32) -> RrsetTtl {
        if secs == PD {
            RrsetTtl::ProviderDefault
        } else {
            RrsetTtl::from_secs(secs).unwrap()
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Rec {
        id: u64,
        text: String,
        ttl: u32,
    }

    #[derive(Default)]
    struct Store {
        sets: HashMap<DomainName, Vec<Rec>>,
        next_id: u64,
        log: Vec<&'static str>,
        reads: usize,
        /// Foreign values inserted by "another process" right before the next writes, one per
        /// write request.
        foreign_before_write: Vec<String>,
        /// A foreign value inserted right before the read with this number (1-based).
        foreign_on_read: Option<(usize, String)>,
        fail_next_write: bool,
        write_delay: Duration,
        unreadable: bool,
    }

    impl Store {
        fn insert(&mut self, name: &DomainName, text: &str, ttl: u32) -> u64 {
            self.next_id += 1;
            let id = self.next_id;
            self.sets.entry(name.clone()).or_default().push(Rec {
                id,
                text: text.to_owned(),
                ttl,
            });
            id
        }

        fn records(&self, name: &DomainName) -> Vec<Rec> {
            self.sets.get(name).cloned().unwrap_or_default()
        }

        fn texts(&self, name: &DomainName) -> Vec<String> {
            let mut texts: Vec<String> = self.records(name).into_iter().map(|r| r.text).collect();
            texts.sort();
            texts
        }

        fn read(&mut self, name: &DomainName) -> Vec<Rec> {
            self.reads += 1;
            self.log.push("read");
            if let Some((at, text)) = self.foreign_on_read.take() {
                if at == self.reads {
                    self.insert(name, &text, 600);
                } else {
                    self.foreign_on_read = Some((at, text));
                }
            }
            self.records(name)
        }

        /// What happens at the provider before any write is applied: a concurrent foreign
        /// change, then an injected failure.
        fn before_write(&mut self, name: &DomainName) -> Result<(), Error> {
            if !self.foreign_before_write.is_empty() {
                let text = self.foreign_before_write.remove(0);
                self.insert(name, &text, 600);
            }
            if std::mem::take(&mut self.fail_next_write) {
                self.log.push("write-failed");
                return Err(Error::transient("injected failure"));
            }
            Ok(())
        }

        fn tidy(&mut self, name: &DomainName) {
            if self.sets.get(name).is_some_and(Vec::is_empty) {
                self.sets.remove(name);
            }
        }
    }

    type Shared = Arc<Mutex<Store>>;

    fn decode(text: &str) -> Option<Txt> {
        // Text starting with "!" stands for a value the client's dialect cannot decode.
        if text.starts_with('!') {
            None
        } else {
            Txt::new(text.as_bytes()).ok()
        }
    }

    fn encode(value: &Txt) -> String {
        value.as_str().unwrap().to_owned()
    }

    fn ttl_secs(ttl: WriteTtl) -> u32 {
        match ttl.resolve(RrsetTtl::from_secs(DEFAULT_TTL).unwrap()) {
            Some(RrsetTtl::Explicit(ttl)) => ttl.as_secs(),
            Some(RrsetTtl::ProviderDefault) => PD,
            _ => DEFAULT_TTL,
        }
    }

    fn txt_record<H>(rec: &Rec, handle: H) -> TxtRecord<H> {
        TxtRecord {
            value: decode(&rec.text),
            ttl: Some(rrset_ttl(rec.ttl)),
            handle,
        }
    }

    async fn delay(store: &Shared) {
        let delay = store.lock().unwrap().write_delay;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    struct Fake {
        store: Shared,
        locks: NameLocks,
        caps: Capabilities,
    }

    impl TxtBase for Fake {
        fn provider(&self) -> ProviderId {
            ProviderId::Hetzner
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        fn locks(&self) -> &NameLocks {
            &self.locks
        }
    }

    macro_rules! base {
        ($t:ty) => {
            impl TxtBase for $t {
                fn provider(&self) -> ProviderId {
                    self.0.provider()
                }
                fn capabilities(&self) -> &Capabilities {
                    self.0.capabilities()
                }
                fn locks(&self) -> &NameLocks {
                    self.0.locks()
                }
            }
        };
    }

    /// Individual records with identifiers.
    struct PerRecordFake(Fake);
    base!(PerRecordFake);

    impl PerRecord for PerRecordFake {
        type Handle = u64;

        async fn read(
            &self,
            _zone: &DomainName,
            name: &DomainName,
        ) -> Result<PerRecordRead<u64>, Error> {
            let mut store = self.0.store.lock().unwrap();
            if store.unreadable {
                store.log.push("read-refused");
                return Ok(PerRecordRead::Unavailable);
            }
            let recs = store.read(name);
            Ok(PerRecordRead::Records(
                recs.iter().map(|r| txt_record(r, r.id)).collect(),
            ))
        }

        async fn create(
            &self,
            _zone: &DomainName,
            name: &DomainName,
            value: &Txt,
            ttl: WriteTtl,
        ) -> Result<(), Error> {
            delay(&self.0.store).await;
            let mut store = self.0.store.lock().unwrap();
            store.before_write(name)?;
            store.log.push("create");
            store.insert(name, &encode(value), ttl_secs(ttl));
            Ok(())
        }

        async fn delete(
            &self,
            _zone: &DomainName,
            name: &DomainName,
            record: &TxtRecord<u64>,
        ) -> Result<(), Error> {
            delay(&self.0.store).await;
            let mut store = self.0.store.lock().unwrap();
            store.before_write(name)?;
            store.log.push("delete");
            if let Some(set) = store.sets.get_mut(name) {
                set.retain(|r| r.id != record.handle);
            }
            store.tidy(name);
            Ok(())
        }

        async fn delete_blind(
            &self,
            _zone: &DomainName,
            name: &DomainName,
            value: &Txt,
        ) -> Result<(), Error> {
            let mut store = self.0.store.lock().unwrap();
            store.before_write(name)?;
            store.log.push("delete");
            let text = encode(value);
            if let Some(set) = store.sets.get_mut(name) {
                set.retain(|r| r.text != text);
            }
            store.tidy(name);
            Ok(())
        }
    }

    /// An rrset with value-level add and remove calls.
    struct ValueFake(Fake);
    base!(ValueFake);

    impl ValueCalls for ValueFake {
        type Handle = String;

        async fn read(
            &self,
            _zone: &DomainName,
            name: &DomainName,
        ) -> Result<Vec<TxtRecord<String>>, Error> {
            let recs = self.0.store.lock().unwrap().read(name);
            Ok(recs.iter().map(|r| txt_record(r, r.text.clone())).collect())
        }

        async fn add(
            &self,
            _zone: &DomainName,
            name: &DomainName,
            value: &Txt,
            ttl: WriteTtl,
        ) -> Result<(), Error> {
            delay(&self.0.store).await;
            let mut store = self.0.store.lock().unwrap();
            store.before_write(name)?;
            store.log.push("add");
            store.insert(name, &encode(value), ttl_secs(ttl));
            Ok(())
        }

        async fn remove(
            &self,
            _zone: &DomainName,
            name: &DomainName,
            records: &[&TxtRecord<String>],
        ) -> Result<(), Error> {
            delay(&self.0.store).await;
            let mut store = self.0.store.lock().unwrap();
            store.before_write(name)?;
            store.log.push("remove");
            if let Some(set) = store.sets.get_mut(name) {
                set.retain(|r| !records.iter().any(|x| x.handle == r.text));
            }
            store.tidy(name);
            Ok(())
        }
    }

    /// An rrset replaced whole; conditional when the capabilities say so.
    struct WholeFake(Fake, bool);
    base!(WholeFake);

    impl WholeFake {
        fn conditional(&self) -> bool {
            self.0.caps.txt_values == ValueGuarantee::Conditional
        }
    }

    impl WholeSet for WholeFake {
        type Handle = Rec;
        type Snapshot = Vec<Rec>;
        type Context = ();

        async fn read(&self, _zone: &DomainName, name: &DomainName) -> SetRead<Rec, Vec<Rec>, ()> {
            let recs = self.0.store.lock().unwrap().read(name);
            let set = recs.first().map(|first| TxtSet {
                records: recs.iter().map(|r| txt_record(r, r.clone())).collect(),
                ttl: Some(rrset_ttl(first.ttl)),
                snapshot: recs.clone(),
            });
            Ok(SetState { context: (), set })
        }

        async fn write(
            &self,
            _zone: &DomainName,
            name: &DomainName,
            _context: &(),
            prior: Option<&Vec<Rec>>,
            members: &[Member<'_, Rec>],
            ttl: WriteTtl,
        ) -> Result<(), Error> {
            delay(&self.0.store).await;
            let mut store = self.0.store.lock().unwrap();
            store.before_write(name)?;
            if self.conditional() && store.records(name) != prior.cloned().unwrap_or_default() {
                store.log.push("write-refused");
                return Err(Error::conflict("the rrset changed"));
            }
            store.log.push("write");
            let ttl = ttl_secs(ttl);
            let mut set = Vec::new();
            for member in members {
                match member {
                    Member::Kept(record) => set.push(record.handle.clone()),
                    Member::Added(value) => {
                        store.next_id += 1;
                        set.push(Rec {
                            id: store.next_id,
                            text: encode(value),
                            ttl,
                        });
                    }
                }
            }
            store.sets.insert(name.clone(), set);
            Ok(())
        }

        async fn delete(
            &self,
            _zone: &DomainName,
            name: &DomainName,
            _context: &(),
            prior: &Vec<Rec>,
        ) -> Result<(), Error> {
            delay(&self.0.store).await;
            let mut store = self.0.store.lock().unwrap();
            store.before_write(name)?;
            if self.conditional() && &store.records(name) != prior {
                store.log.push("delete-refused");
                return Err(Error::conflict("the rrset changed"));
            }
            store.log.push("delete");
            store.sets.remove(name);
            Ok(())
        }

        fn reread_before_write(&self) -> bool {
            self.1
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Shape {
        PerRecord,
        ValueCalls,
        WholeSet,
        WholeSetConditional,
        WholeSetReread,
    }

    const SHAPES: [Shape; 5] = [
        Shape::PerRecord,
        Shape::ValueCalls,
        Shape::WholeSet,
        Shape::WholeSetConditional,
        Shape::WholeSetReread,
    ];

    fn caps(shape: Shape) -> Capabilities {
        Capabilities {
            list_zones: false,
            list_rrsets: false,
            get_rrset: false,
            set_rrset: false,
            delete_rrset: false,
            add_txt_value: true,
            remove_txt_value: true,
            record_types: TypeSet::Listed(&[]),
            read_only_types: &[],
            txt_plain_only: false,
            txt_values: match shape {
                Shape::PerRecord | Shape::ValueCalls => ValueGuarantee::PerValue,
                Shape::WholeSetConditional => ValueGuarantee::Conditional,
                Shape::WholeSet | Shape::WholeSetReread => ValueGuarantee::ReadThenWrite,
            },
            preconditions: Preconditions::ReadThenWrite,
            atomic_rrset_write: false,
            ttl: TtlSupport::PerRrset {
                min: 30,
                max: 86_400,
            },
            provider_default_ttl: ProviderDefaultTtl::Absent,
            asynchronous: false,
        }
    }

    enum Client {
        PerRecord(PerRecordFake),
        ValueCalls(ValueFake),
        WholeSet(WholeFake),
    }

    impl Client {
        fn with(shape: Shape, store: &Shared, locks: &NameLocks, caps: Capabilities) -> Client {
            let fake = Fake {
                store: Arc::clone(store),
                locks: locks.clone(),
                caps,
            };
            match shape {
                Shape::PerRecord => Client::PerRecord(PerRecordFake(fake)),
                Shape::ValueCalls => Client::ValueCalls(ValueFake(fake)),
                Shape::WholeSet | Shape::WholeSetConditional => {
                    Client::WholeSet(WholeFake(fake, false))
                }
                Shape::WholeSetReread => Client::WholeSet(WholeFake(fake, true)),
            }
        }

        fn new(shape: Shape, store: &Shared, locks: &NameLocks) -> Client {
            Client::with(shape, store, locks, caps(shape))
        }

        async fn add(
            &self,
            zone: &DomainName,
            name: &DomainName,
            value: &Txt,
            ttl: Option<RrsetTtl>,
        ) -> Result<AddOutcome, Error> {
            match self {
                Client::PerRecord(b) => super::add_per_record(b, zone, name, value, ttl).await,
                Client::ValueCalls(b) => super::add_value_calls(b, zone, name, value, ttl).await,
                Client::WholeSet(b) => super::add_whole_set(b, zone, name, value, ttl).await,
            }
        }

        async fn remove(
            &self,
            zone: &DomainName,
            name: &DomainName,
            value: &Txt,
        ) -> Result<RemoveOutcome, Error> {
            match self {
                Client::PerRecord(b) => super::remove_per_record(b, zone, name, value).await,
                Client::ValueCalls(b) => super::remove_value_calls(b, zone, name, value).await,
                Client::WholeSet(b) => super::remove_whole_set(b, zone, name, value).await,
            }
        }
    }

    struct Env {
        store: Shared,
        locks: NameLocks,
        client: Client,
        zone: DomainName,
        name: DomainName,
    }

    impl Env {
        fn new(shape: Shape) -> Env {
            Env::with_caps(shape, caps(shape))
        }

        fn with_caps(shape: Shape, caps: Capabilities) -> Env {
            let store = Shared::default();
            let locks = NameLocks::new();
            let client = Client::with(shape, &store, &locks, caps);
            Env {
                store,
                locks,
                client,
                zone: dn("example.org"),
                name: dn("_acme-challenge.example.org"),
            }
        }

        fn seed(&self, text: &str, ttl: u32) -> u64 {
            self.store.lock().unwrap().insert(&self.name, text, ttl)
        }

        fn records(&self) -> Vec<Rec> {
            self.store.lock().unwrap().records(&self.name)
        }

        fn texts(&self) -> Vec<String> {
            self.store.lock().unwrap().texts(&self.name)
        }

        fn take_log(&self) -> Vec<&'static str> {
            std::mem::take(&mut self.store.lock().unwrap().log)
        }

        async fn add(&self, value: &Txt, ttl: Option<RrsetTtl>) -> Result<AddOutcome, Error> {
            self.client.add(&self.zone, &self.name, value, ttl).await
        }

        async fn remove(&self, value: &Txt) -> Result<RemoveOutcome, Error> {
            self.client.remove(&self.zone, &self.name, value).await
        }
    }

    fn dn(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    fn txt(s: &str) -> Txt {
        Txt::new(s.as_bytes()).unwrap()
    }

    fn ttl(secs: u32) -> Option<RrsetTtl> {
        Some(RrsetTtl::from_secs(secs).unwrap())
    }

    fn is_write(entry: &&str) -> bool {
        !matches!(*entry, "read" | "read-refused")
    }

    #[tokio::test]
    async fn add_is_idempotent() {
        for shape in SHAPES {
            let env = Env::new(shape);
            assert_eq!(
                env.add(&txt("one"), None).await.unwrap(),
                AddOutcome::Created,
                "{shape:?}"
            );
            assert_eq!(
                env.add(&txt("two"), None).await.unwrap(),
                AddOutcome::Appended,
                "{shape:?}"
            );
            env.take_log();
            assert_eq!(
                env.add(&txt("two"), None).await.unwrap(),
                AddOutcome::AlreadyPresent,
                "{shape:?}"
            );
            assert!(!env.take_log().iter().any(is_write), "{shape:?}");
            assert_eq!(env.texts(), ["one", "two"], "{shape:?}");
            assert_eq!(env.locks.len(), 0);
        }
    }

    #[tokio::test]
    async fn never_removes_foreign_value() {
        for shape in SHAPES {
            let env = Env::new(shape);
            let foreign = env.seed("foreign", 600);
            let before = env.records();
            env.take_log();
            assert_eq!(
                env.remove(&txt("ours")).await.unwrap(),
                RemoveOutcome::NotPresent,
                "{shape:?}"
            );
            assert!(!env.take_log().iter().any(is_write), "{shape:?}");
            assert_eq!(env.records(), before, "{shape:?}");

            assert_eq!(
                env.add(&txt("ours"), None).await.unwrap(),
                AddOutcome::Appended,
                "{shape:?}"
            );
            assert_eq!(
                env.remove(&txt("ours")).await.unwrap(),
                RemoveOutcome::Removed,
                "{shape:?}"
            );
            let after = env.records();
            assert_eq!(after.len(), 1, "{shape:?}");
            assert_eq!(
                after[0],
                Rec {
                    id: foreign,
                    text: "foreign".into(),
                    ttl: 600
                },
                "{shape:?}"
            );
        }
    }

    #[tokio::test]
    async fn remove_last_value_deletes_rrset_and_is_idempotent() {
        for shape in SHAPES {
            let env = Env::new(shape);
            assert_eq!(
                env.add(&txt("ours"), None).await.unwrap(),
                AddOutcome::Created
            );
            assert_eq!(
                env.remove(&txt("ours")).await.unwrap(),
                RemoveOutcome::RrsetDeleted,
                "{shape:?}"
            );
            assert!(env.records().is_empty(), "{shape:?}");
            env.take_log();
            assert_eq!(
                env.remove(&txt("ours")).await.unwrap(),
                RemoveOutcome::NotPresent,
                "{shape:?}"
            );
            assert!(!env.take_log().iter().any(is_write), "{shape:?}");
        }
    }

    #[tokio::test]
    async fn duplicates_of_our_value_are_all_removed() {
        for shape in SHAPES {
            let env = Env::new(shape);
            env.seed("ours", 60);
            env.seed("foreign", 60);
            env.seed("ours", 60);
            assert_eq!(
                env.remove(&txt("ours")).await.unwrap(),
                RemoveOutcome::Removed,
                "{shape:?}"
            );
            assert_eq!(env.texts(), ["foreign"], "{shape:?}");

            let env = Env::new(shape);
            env.seed("ours", 60);
            env.seed("ours", 60);
            assert_eq!(
                env.remove(&txt("ours")).await.unwrap(),
                RemoveOutcome::RrsetDeleted,
                "{shape:?}"
            );
            assert!(env.records().is_empty(), "{shape:?}");
        }
    }

    #[tokio::test]
    async fn undecodable_foreign_value_is_kept_and_never_matches() {
        for shape in SHAPES {
            let env = Env::new(shape);
            let opaque = env.seed("!opaque", 600);
            assert_eq!(
                env.add(&txt("ours"), None).await.unwrap(),
                AddOutcome::Appended,
                "{shape:?}"
            );
            assert_eq!(
                env.remove(&txt("ours")).await.unwrap(),
                RemoveOutcome::Removed,
                "{shape:?}"
            );
            // A value spelled like the opaque text is still not the opaque record.
            assert_eq!(
                env.remove(&txt("!opaque")).await.unwrap(),
                RemoveOutcome::NotPresent,
                "{shape:?}"
            );
            assert_eq!(
                env.add(&txt("!opaque"), None).await.unwrap(),
                AddOutcome::Appended,
                "{shape:?}"
            );
            let records = env.records();
            assert!(
                records.contains(&Rec {
                    id: opaque,
                    text: "!opaque".into(),
                    ttl: 600
                }),
                "{shape:?}"
            );
        }
    }

    #[tokio::test]
    async fn non_plain_values_follow_the_capability() {
        for shape in SHAPES {
            let env = Env::new(shape);
            let value = txt("v=spf1 \"quoted\" -all");
            assert_eq!(
                env.add(&value, None).await.unwrap(),
                AddOutcome::Created,
                "{shape:?}"
            );
            assert_eq!(
                env.remove(&value).await.unwrap(),
                RemoveOutcome::RrsetDeleted,
                "{shape:?}"
            );

            let env = Env::with_caps(
                shape,
                Capabilities {
                    txt_plain_only: true,
                    ..caps(shape)
                },
            );
            for value in [txt("a b"), txt(""), txt("x\"y"), txt(&"a".repeat(256))] {
                let err = env.add(&value, None).await.unwrap_err();
                assert_eq!(err.kind(), ErrorKind::InvalidInput, "{shape:?}");
                let err = env.remove(&value).await.unwrap_err();
                assert_eq!(err.kind(), ErrorKind::InvalidInput, "{shape:?}");
            }
            assert!(env.take_log().is_empty(), "{shape:?}");
        }
    }

    #[tokio::test]
    async fn new_rrset_gets_the_requested_or_default_ttl() {
        for shape in SHAPES {
            let env = Env::new(shape);
            env.add(&txt("a"), ttl(120)).await.unwrap();
            assert_eq!(env.records()[0].ttl, 120, "{shape:?}");

            let env = Env::new(shape);
            env.add(&txt("a"), None).await.unwrap();
            assert_eq!(env.records()[0].ttl, DEFAULT_TTL, "{shape:?}");
        }
    }

    #[tokio::test]
    async fn existing_rrset_keeps_its_ttl() {
        for shape in SHAPES {
            let env = Env::new(shape);
            env.seed("foreign", 600);
            env.add(&txt("ours"), ttl(120)).await.unwrap();
            assert!(env.records().iter().all(|r| r.ttl == 600), "{shape:?}");
            env.remove(&txt("ours")).await.unwrap();
            assert_eq!(env.records()[0].ttl, 600, "{shape:?}");
        }
        // Per-record APIs: a record added to an existing set gets the smallest TTL read.
        for shape in [Shape::PerRecord, Shape::ValueCalls] {
            let env = Env::new(shape);
            env.seed("a", 900);
            env.seed("b", 600);
            env.add(&txt("ours"), ttl(120)).await.unwrap();
            let ours = env
                .records()
                .into_iter()
                .find(|r| r.text == "ours")
                .unwrap();
            assert_eq!(ours.ttl, 600, "{shape:?}");
        }
    }

    #[tokio::test]
    async fn provider_default_ttl_for_a_new_rrset() {
        let default = Some(RrsetTtl::ProviderDefault);
        for shape in SHAPES {
            // Refused before any call where the provider has no default of its own.
            let env = Env::new(shape);
            let err = env.add(&txt("a"), default).await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidInput, "{shape:?}");
            assert!(err.to_string().contains("default TTL"), "{shape:?}");
            assert!(env.take_log().is_empty(), "{shape:?}");

            for level in [
                ProviderDefaultTtl::ForNewRecords,
                ProviderDefaultTtl::Requestable,
            ] {
                let with_default = Capabilities {
                    provider_default_ttl: level,
                    ..caps(shape)
                };
                // A new rrset gets the provider's default, not a number.
                let env = Env::with_caps(shape, with_default);
                env.add(&txt("a"), default).await.unwrap();
                assert_eq!(env.records()[0].ttl, PD, "{shape:?}");
                // A value added to it keeps the default, whatever is asked for.
                env.add(&txt("b"), ttl(120)).await.unwrap();
                env.add(&txt("c"), None).await.unwrap();
                assert!(env.records().iter().all(|r| r.ttl == PD), "{shape:?}");
                // An existing rrset with a number keeps it when the default is asked for.
                let env = Env::with_caps(shape, with_default);
                env.seed("foreign", 600);
                env.add(&txt("ours"), default).await.unwrap();
                assert!(env.records().iter().all(|r| r.ttl == 600), "{shape:?}");
            }
        }
    }

    #[tokio::test]
    async fn name_outside_zone_is_refused_before_any_call() {
        for shape in SHAPES {
            let env = Env::new(shape);
            for name in ["a.example.net", "badexample.org", "example.com", "org"] {
                let name = dn(name);
                let err = env
                    .client
                    .add(&env.zone, &name, &txt("v"), None)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(err, Error::NameOutsideZone { .. }),
                    "{shape:?} {name}: {err:?}"
                );
                let err = env
                    .client
                    .remove(&env.zone, &name, &txt("v"))
                    .await
                    .unwrap_err();
                assert!(
                    matches!(err, Error::NameOutsideZone { .. }),
                    "{shape:?} {name}"
                );
            }
            // A sibling zone.
            let sibling = dn("other.example.org");
            let name = dn("_acme-challenge.example.org");
            let err = env
                .client
                .add(&sibling, &name, &txt("v"), None)
                .await
                .unwrap_err();
            assert!(matches!(err, Error::NameOutsideZone { .. }), "{shape:?}");
            assert!(env.take_log().is_empty(), "{shape:?}");
            assert_eq!(env.locks.len(), 0);
        }
    }

    #[tokio::test]
    async fn root_or_wildcard_zone_is_invalid_input() {
        for shape in SHAPES {
            let env = Env::new(shape);
            for zone in [DomainName::root(), dn("*.example.org")] {
                let name = dn("x.example.org");
                let err = env
                    .client
                    .add(&zone, &name, &txt("v"), None)
                    .await
                    .unwrap_err();
                assert_eq!(err.kind(), ErrorKind::InvalidInput, "{shape:?}");
                let err = env
                    .client
                    .remove(&zone, &name, &txt("v"))
                    .await
                    .unwrap_err();
                assert_eq!(err.kind(), ErrorKind::InvalidInput, "{shape:?}");
            }
            assert!(env.take_log().is_empty(), "{shape:?}");
        }
    }

    #[tokio::test]
    async fn ttl_outside_the_range_is_invalid_input() {
        for shape in SHAPES {
            let env = Env::new(shape);
            for secs in [0, 29, 86_401] {
                let err = env.add(&txt("v"), ttl(secs)).await.unwrap_err();
                assert_eq!(err.kind(), ErrorKind::InvalidInput, "{shape:?}");
            }
            let env = Env::with_caps(
                shape,
                Capabilities {
                    ttl: TtlSupport::NotSettable,
                    ..caps(shape)
                },
            );
            let err = env.add(&txt("v"), ttl(60)).await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidInput, "{shape:?}");
            assert!(
                err.to_string()
                    .contains("the provider chooses the TTL; a requested TTL cannot be honored"),
                "{shape:?}: {err}"
            );
            assert!(env.take_log().is_empty(), "{shape:?}");
            assert_eq!(env.add(&txt("v"), None).await.unwrap(), AddOutcome::Created);
        }
    }

    #[tokio::test]
    async fn unsupported_operation_makes_no_call() {
        for shape in SHAPES {
            let env = Env::with_caps(
                shape,
                Capabilities {
                    add_txt_value: false,
                    remove_txt_value: false,
                    ..caps(shape)
                },
            );
            let err = env.add(&txt("v"), None).await.unwrap_err();
            assert!(matches!(err, Error::Unsupported { .. }), "{shape:?}");
            let err = env.remove(&txt("v")).await.unwrap_err();
            assert!(matches!(err, Error::Unsupported { .. }), "{shape:?}");
            // Unsupported comes before every other check.
            let err = env
                .client
                .add(
                    &DomainName::root(),
                    &dn("a.example.net"),
                    &txt("a b"),
                    ttl(1),
                )
                .await
                .unwrap_err();
            assert!(matches!(err, Error::Unsupported { .. }), "{shape:?}");
            assert!(env.take_log().is_empty(), "{shape:?}");
        }
    }

    #[tokio::test]
    async fn failure_between_read_and_write_changes_nothing_and_a_repeat_converges() {
        for shape in SHAPES {
            let env = Env::new(shape);
            env.seed("foreign", 600);
            env.store.lock().unwrap().fail_next_write = true;
            let err = env.add(&txt("ours"), None).await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Transient, "{shape:?}");
            assert_eq!(env.texts(), ["foreign"], "{shape:?}");
            assert_eq!(
                env.add(&txt("ours"), None).await.unwrap(),
                AddOutcome::Appended
            );

            env.store.lock().unwrap().fail_next_write = true;
            let err = env.remove(&txt("ours")).await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Transient, "{shape:?}");
            assert_eq!(env.texts(), ["foreign", "ours"], "{shape:?}");
            assert_eq!(
                env.remove(&txt("ours")).await.unwrap(),
                RemoveOutcome::Removed
            );
            assert_eq!(env.texts(), ["foreign"], "{shape:?}");
            assert_eq!(env.locks.len(), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_adds_sharing_locks_are_serialized() {
        for shape in SHAPES {
            let store = Shared::default();
            store.lock().unwrap().write_delay = Duration::from_millis(50);
            let locks = NameLocks::new();
            let first = Client::new(shape, &store, &locks);
            let second = Client::new(shape, &store, &locks);
            let zone = dn("example.org");
            let name = dn("_acme-challenge.example.org");
            let (va, vb) = (txt("a"), txt("b"));
            let (a, b) = tokio::join!(
                first.add(&zone, &name, &va, None),
                second.add(&zone, &name, &vb, None)
            );
            let mut outcomes = [a.unwrap(), b.unwrap()];
            outcomes.sort_by_key(|o| format!("{o:?}"));
            assert_eq!(
                outcomes,
                [AddOutcome::Appended, AddOutcome::Created],
                "{shape:?}"
            );
            assert_eq!(store.lock().unwrap().texts(&name), ["a", "b"], "{shape:?}");
        }
    }

    /// Control for the test above: without shared locks, an unconditional whole-set write loses
    /// a value. This is what the lock prevents inside one process, and what `ReadThenWrite`
    /// states for writers outside it.
    #[tokio::test(start_paused = true)]
    async fn without_shared_locks_unconditional_whole_set_loses_a_value() {
        let store = Shared::default();
        store.lock().unwrap().write_delay = Duration::from_millis(50);
        let first = Client::new(Shape::WholeSet, &store, &NameLocks::new());
        let second = Client::new(Shape::WholeSet, &store, &NameLocks::new());
        let zone = dn("example.org");
        let name = dn("_acme-challenge.example.org");
        let (va, vb) = (txt("a"), txt("b"));
        let (a, b) = tokio::join!(
            first.add(&zone, &name, &va, None),
            second.add(&zone, &name, &vb, None)
        );
        a.unwrap();
        b.unwrap();
        assert_eq!(store.lock().unwrap().texts(&name).len(), 1);
    }

    #[tokio::test]
    async fn conditional_write_repeats_once_after_a_concurrent_change() {
        let env = Env::new(Shape::WholeSetConditional);
        env.store.lock().unwrap().foreign_before_write = vec!["foreign".into()];
        assert_eq!(
            env.add(&txt("ours"), None).await.unwrap(),
            AddOutcome::Appended
        );
        assert_eq!(env.texts(), ["foreign", "ours"]);
        assert_eq!(env.take_log(), ["read", "write-refused", "read", "write"]);

        env.store.lock().unwrap().foreign_before_write = vec!["late".into()];
        assert_eq!(
            env.remove(&txt("ours")).await.unwrap(),
            RemoveOutcome::Removed
        );
        assert_eq!(env.texts(), ["foreign", "late"]);
    }

    #[tokio::test]
    async fn conditional_write_refused_twice_is_conflict_and_loses_nothing() {
        let env = Env::new(Shape::WholeSetConditional);
        env.store.lock().unwrap().foreign_before_write = vec!["f1".into(), "f2".into()];
        let err = env.add(&txt("ours"), None).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Conflict);
        assert!(err.is_retryable());
        assert_eq!(env.texts(), ["f1", "f2"]);
        assert_eq!(
            env.take_log(),
            ["read", "write-refused", "read", "write-refused"]
        );

        // Removing a sole value: the conditional delete is refused, the foreign value survives.
        let env = Env::new(Shape::WholeSetConditional);
        env.seed("ours", 60);
        env.store.lock().unwrap().foreign_before_write = vec!["f1".into(), "f2".into()];
        let err = env.remove(&txt("ours")).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Conflict);
        assert_eq!(env.texts(), ["f1", "f2", "ours"]);
    }

    /// Documents `ValueGuarantee::ReadThenWrite`: a value another process adds between the read
    /// and an unconditional write is lost.
    #[tokio::test]
    async fn unconditional_write_overwrites_a_concurrent_outside_change() {
        let env = Env::new(Shape::WholeSet);
        env.store.lock().unwrap().foreign_before_write = vec!["foreign".into()];
        assert_eq!(
            env.add(&txt("ours"), None).await.unwrap(),
            AddOutcome::Created
        );
        assert_eq!(env.texts(), ["ours"]);
    }

    #[tokio::test]
    async fn reread_detects_a_change_and_writes_nothing() {
        let env = Env::new(Shape::WholeSetReread);
        env.seed("existing", 60);
        env.store.lock().unwrap().foreign_on_read = Some((2, "foreign".into()));
        let err = env.add(&txt("ours"), None).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Conflict);
        assert_eq!(env.texts(), ["existing", "foreign"]);
        assert_eq!(env.take_log(), ["read", "read"]);

        // A sole value is re-read immediately before the delete.
        let env = Env::new(Shape::WholeSetReread);
        env.seed("ours", 60);
        env.store.lock().unwrap().foreign_on_read = Some((2, "foreign".into()));
        let err = env.remove(&txt("ours")).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Conflict);
        assert_eq!(env.texts(), ["foreign", "ours"]);

        // A rrset that appears between the reads of a create.
        let env = Env::new(Shape::WholeSetReread);
        env.store.lock().unwrap().foreign_on_read = Some((2, "foreign".into()));
        let err = env.add(&txt("ours"), None).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Conflict);
        assert_eq!(env.texts(), ["foreign"]);
    }

    #[tokio::test]
    async fn unreadable_provider_writes_blind_and_reports_accepted() {
        let env = Env::new(Shape::PerRecord);
        env.seed("foreign", 600);
        env.store.lock().unwrap().unreadable = true;
        assert_eq!(
            env.add(&txt("ours"), ttl(120)).await.unwrap(),
            AddOutcome::Accepted
        );
        let ours = env
            .records()
            .into_iter()
            .find(|r| r.text == "ours")
            .unwrap();
        assert_eq!(ours.ttl, 120);
        assert_eq!(
            env.remove(&txt("ours")).await.unwrap(),
            RemoveOutcome::Accepted
        );
        assert_eq!(env.texts(), ["foreign"]);
        assert_eq!(
            env.remove(&txt("ours")).await.unwrap(),
            RemoveOutcome::Accepted
        );
        assert_eq!(env.texts(), ["foreign"]);
    }

    #[tokio::test]
    async fn empty_set_from_a_whole_set_read_is_protocol_and_writes_nothing() {
        struct EmptySet(Fake);
        base!(EmptySet);
        impl WholeSet for EmptySet {
            type Handle = ();
            type Snapshot = ();
            type Context = ();
            async fn read(&self, _zone: &DomainName, _name: &DomainName) -> SetRead<(), (), ()> {
                Ok(SetState {
                    context: (),
                    set: Some(TxtSet {
                        records: Vec::new(),
                        ttl: None,
                        snapshot: (),
                    }),
                })
            }
            async fn write(
                &self,
                _zone: &DomainName,
                _name: &DomainName,
                _context: &(),
                _prior: Option<&()>,
                _members: &[Member<'_, ()>],
                _ttl: WriteTtl,
            ) -> Result<(), Error> {
                panic!("written after an unexpected read");
            }
            async fn delete(
                &self,
                _zone: &DomainName,
                _name: &DomainName,
                _context: &(),
                _prior: &(),
            ) -> Result<(), Error> {
                panic!("deleted after an unexpected read");
            }
        }
        let backend = EmptySet(Fake {
            store: Shared::default(),
            locks: NameLocks::new(),
            caps: caps(Shape::WholeSet),
        });
        let zone = dn("example.org");
        let err = super::add_whole_set(&backend, &zone, &zone, &txt("v"), None)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Protocol);
        let err = super::remove_whole_set(&backend, &zone, &zone, &txt("v"))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Protocol);
    }
}
