//! Record-level operations: the `PerRecord` shape of the record layer (`crate::rrsets`) over the
//! record API, inside the zone protocol that staged changes require; the listing of a zone; and
//! the mapping between the API's record elements and `RecordData`.
//!
//! # Staged changes
//!
//! Every edit (`PUT …/records` with one record, `DELETE …/records/{id}`) is staged, and nothing is
//! published until a commit, which publishes every staged change of the zone at once (Docs 4.3.1,
//! 4.5.1, 4.5.3). The record layer decides which records to create and which to delete and calls
//! [`PerRecord::create`] and [`PerRecord::delete`] on a [`RecordOp`], which exists for one
//! operation and keeps the protocol of the TXT value operations (design section 11.3):
//!
//! - its read takes the zone lock (after the name lock the layer holds) and keeps it until the
//!   operation has ended, commit included; a zone with staged changes this process did not make
//!   is `Error::Rejected`; staged changes of this process left by an earlier operation are
//!   committed or rolled back first, as their mark says;
//! - before its first edit the zone is marked "staged changes of this process, to be rolled
//!   back": an operation that fails or is dropped part-way leaves a mark that makes the next
//!   operation discard its edits, never publish them;
//! - after the layer has returned with every edit staged ([`RecordOp::finish`]) the mark becomes
//!   "to be committed" and the zone is committed once for the whole operation (up to three
//!   attempts). The published rrset thus goes from the old set to the new one in one step: a
//!   replacement is never published half-applied. `atomic_rrset_write` stays false all the
//!   same, since it says whether a replacement is one request;
//! - after the layer has returned an error with edits possibly staged, the zone is listed again
//!   and rolled back (Docs 4.2) if it has staged changes; an edit that was certainly refused
//!   stages nothing and only clears the mark.
//!
//! The commit and the rollback happen after the record layer has released the name lock, which
//! `crate::rrsets` holds only inside its functions, but while the zone lock is still held: every
//! operation of this client in the zone, on any name, waits for that lock, so operations on one
//! name stay serialized.
//!
//! The API has no edit call, so a TTL change of a record that stays is staged as a new record
//! with the same value and the new TTL (none for the zone's default, which a record without
//! `<ttl>` takes, Docs 4.6) followed by the deletion of the old one (for a CNAME or
//! DNAME the deletion first, so that two records of the type are never staged at once), and a
//! CNAME or DNAME is replaced by a deletion and a creation (`updates_in_place` false); both are
//! published by the one commit.
//!
//! # Reads
//!
//! `get_rrset` and `list_rrsets` take the zone lock too, so they never see this process's edits
//! between staging and commit, and they first settle staged changes this process left behind
//! (commit or rollback, as their mark says), as a write does. The documentation says neither
//! that the record listing shows the published records nor that it shows the staged ones
//! ("resource records which are already created in the zone file", Docs 4.5.2). A zone with
//! other staged changes, by `GET /zones` or by the `has-changes` attribute of the record listing
//! itself, is therefore not read: `Error::Rejected`.
//! The same check makes a write refuse a zone in which a foreign edit was staged between its zone
//! lookup and its record listing.
//!
//! # Elements per type
//!
//! Source of every row: Docs 4.6 and the type's subsection (`api::SHAPES`); "Docs" is the
//! provider's request description cited in `api.rs`, opened for this client on 2026-11-14 in the
//! Internet Archive copy.
//!
//! | Type  | Element and fields → canonical text                                   | Written |
//! | ----- | --------------------------------------------------------------------- | ------- |
//! | A     | `<a>IP</a>` (4.6.2)                                                   | yes     |
//! | AAAA  | `<aaaa>ipv6</aaaa>` (4.6.3)                                           | yes     |
//! | CNAME | `<cname><name>` (4.6.4) (1)                                           | yes     |
//! | NS    | `<ns><name>` (4.6.5) (1)                                              | yes (2) |
//! | MX    | `<mx><preference>`, `<exchange><name>` → `pref exchange` (4.6.6) (1)  | yes     |
//! | SRV   | `<srv>` `priority`, `weight`, `port`, `<target><name>` (4.6.7) (1)    | yes     |
//! | PTR   | `<ptr><name>` (4.6.8) (1)                                             | yes     |
//! | TXT   | `<txt>(<string>text</string>)+` (4.6.9) (3)                           | yes     |
//! | DNAME | `<dname><name>` (4.6.10) (1)                                          | yes     |
//! | SOA   | `<soa>` `mname/name`, `rname/name` and five numbers (4.6.1) (1)       | no      |
//! | HINFO, NAPTR, RP | 4.6.11 to 4.6.13                                           | no (4)  |
//!
//! (1) Domain names. Every example of the documentation writes them absolute with the trailing
//! dot (4.5.1, 4.5.2 and each subsection), and 4.6.8 says the PTR host name is "absolute host
//! name (with the dot at the end of the name)". They are written so. A name read without the
//! trailing dot is not interpreted (the document does not say whether it is relative to the
//! zone); its record is carried as non-canonical data. A name whose canonical text needs a
//! backslash escape is not written: no source shows how the API takes one. The root (`.`) is
//! written as `<name>.</name>`, as the NAPTR example of 4.6.12 shows it.
//! (2) Not at the zone apex (design section 3.4; refused by the record layer).
//! (3) TXT dialect `Raw` on read and write, as for the TXT value operations: the example of 4.6.9
//! carries `Location this machine: City` in a `string` element for the record
//! `IN TXT "Location this machine: City"`, so a string is the text itself, spaces included, and a
//! record holds one or more strings of "up to 255 bytes". A value is written as strings of at
//! most 255 bytes, cut where neither side of a cut is a space (whether the API keeps a space at
//! the edge of a string is not established), and only when it is printable ASCII without `"` and
//! `\` and does not start or end with a space: how the API treats quotes, backslashes and other
//! bytes is not established.
//! (4) The crate has no canonical text for these types (design section 4.7); a listing carries
//! them as non-canonical data and they are not among `record_types`.
//!
//! Owner names are written relative to the zone, `@` for the apex, as the TXT value operations
//! do (lego fixtures and Docs 4.5.1), in Punycode. A TTL is written in seconds; one read in BIND
//! form (Docs 4.6) is converted. The API documents no disabled records, comments or other
//! attributes the model does not carry.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::{NameGuard, NameLocks};
use crate::meta::Capabilities;
use crate::name::{DomainName, TargetName};
use crate::provider::{SkipReason, ZoneListing};
use crate::record::{Mx, RecordData, RecordType, RrsetTtl, Srv, Ttl, Txt, TxtDialect, singleton};
use crate::redact::Detail;
use crate::rrsets::{
    self, Listing, Neighbors, PerRecord, RecordUpdate, RecordsRead, RrsetBase, SetTtl, Stored,
};

use super::Pending;
use super::api::{Content, EditError, Rr, Shape, TXT, Zone, shape};
use super::client::{Nicru, rejected};
use super::txt::FOREIGN_CHANGES;

/// How TXT data is read: each `string` is the text itself (module documentation, note 3).
const TXT_READ: TxtDialect = TxtDialect::Raw;

/// How TXT data is written.
const TXT_WRITE: TxtDialect = TxtDialect::Raw;

/// The most bytes one `string` of a TXT record holds.
// Source: Docs 4.6.9 ("text — arbitrary binary data record, up to 255 bytes").
const STRING_MAX: usize = 255;

/// Why a zone with staged changes is not read.
const STAGED_READ: &str = "the zone has staged changes that are not committed; its record \
     listing could show them as if they were published, so it is not read until they are \
     committed or rolled back";

// ---- Reading -------------------------------------------------------------------------------------

/// A value as the API listed it, for a record of type `rtype`: canonical where its fields parse,
/// non-canonical otherwise (design section 4.9).
pub(super) fn read_record(rtype: RecordType, rr: &Rr) -> RecordData {
    match rtype {
        RecordType::TXT => read_txt(rr),
        RecordType::A | RecordType::AAAA => read_address(rtype, &rr.fields),
        RecordType::CNAME | RecordType::NS | RecordType::PTR | RecordType::DNAME => {
            read_target(rtype, &rr.fields)
        }
        RecordType::MX => read_mx(&rr.fields),
        RecordType::SRV => read_srv(&rr.fields),
        RecordType::SOA => read_soa(&rr.fields),
        _ => read_other(&rr.fields),
    }
}

/// The fields joined by spaces, a missing one as empty text: the text of non-canonical data.
fn composed(fields: &[Option<String>]) -> String {
    fields
        .iter()
        .map(|field| field.as_deref().unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `fields` as presentation text of `rtype`, parsed strictly. Every field must be present, and
/// the fields at `names` must be absolute names with the trailing dot (module documentation,
/// note 1); otherwise, and when the text does not parse, the composed text is non-canonical.
fn read_fields(rtype: RecordType, fields: &[Option<String>], names: &[usize]) -> RecordData {
    let text = composed(fields);
    let complete = !fields.is_empty() && fields.iter().all(Option::is_some);
    let absolute = names.iter().all(|&index| {
        fields
            .get(index)
            .and_then(Option::as_deref)
            .is_some_and(|name| name.ends_with('.'))
    });
    if complete && absolute {
        RecordData::from_provider(rtype, &text, None, TXT_READ)
    } else {
        RecordData::non_canonical(&text)
    }
}

/// A and AAAA: the address, the text of the type's element.
// Source: Docs 4.6.2 (`<a>IP</a>`), 4.6.3 (`<aaaa>ipv6</aaaa>`).
fn read_address(rtype: RecordType, fields: &[Option<String>]) -> RecordData {
    read_fields(rtype, fields, &[])
}

/// CNAME, NS, PTR and DNAME: one absolute name in the element's `name`.
// Source: Docs 4.6.4 (`<cname><name>canonical</name></cname>`), 4.6.5 (`<ns><name>`), 4.6.8
// (`<ptr><name>`, "absolute host name (with the dot at the end of the name)"), 4.6.10
// (`<dname><name>`).
fn read_target(rtype: RecordType, fields: &[Option<String>]) -> RecordData {
    read_fields(rtype, fields, &[0])
}

/// MX: `preference`, then the absolute name in `exchange/name`.
// Source: Docs 4.6.6 (`<mx><preference>priority</preference><exchange><name>mail-relay</name>
// </exchange></mx>`).
fn read_mx(fields: &[Option<String>]) -> RecordData {
    read_fields(RecordType::MX, fields, &[1])
}

/// SRV: `priority`, `weight`, `port`, then the absolute name in `target/name`.
// Source: Docs 4.6.7 (`<srv><priority>`, `<weight>`, `<port>`, `<target><name>`).
fn read_srv(fields: &[Option<String>]) -> RecordData {
    read_fields(RecordType::SRV, fields, &[3])
}

/// SOA: `mname/name`, `rname/name`, `serial`, `refresh`, `retry`, `expire`, `minimum`.
// Source: Docs 4.6.1 and the listing example of 4.5.2.
fn read_soa(fields: &[Option<String>]) -> RecordData {
    read_fields(RecordType::SOA, fields, &[0, 1])
}

/// HINFO, NAPTR, RP and any other type: the crate has no canonical text for them (design section
/// 4.7), so their fields are carried as non-canonical data.
// Source: Docs 4.6.11 to 4.6.13 for the fields of HINFO, NAPTR and RP.
fn read_other(fields: &[Option<String>]) -> RecordData {
    RecordData::non_canonical(&composed(fields))
}

/// TXT: the `string` elements joined, read with the `Raw` rule.
// Source: Docs 4.6.9 (`<txt>(<string>text</string>)+</txt>`); module documentation, note 3.
fn read_txt(rr: &Rr) -> RecordData {
    match rr.txt.as_deref() {
        Some(text) => RecordData::from_provider(RecordType::TXT, text, None, TXT_READ),
        None => RecordData::non_canonical(""),
    }
}

// ---- Writing -------------------------------------------------------------------------------------

/// The content of a record to stage.
#[derive(Debug)]
pub(super) enum Encoded {
    /// The fields of a type in `api::SHAPES`.
    Fields(&'static Shape, Vec<String>),
    /// The strings of a TXT record.
    Strings(Vec<String>),
}

impl Encoded {
    fn content(&self) -> Content<'_> {
        match self {
            Encoded::Fields(shape, values) => Content::Fields(shape, values),
            Encoded::Strings(strings) => Content::Strings(strings),
        }
    }
}

/// The API's content for a canonical value of `rtype`, or `None` when the client cannot send it
/// (module documentation).
pub(super) fn encode(rtype: RecordType, data: &RecordData) -> Option<Encoded> {
    if !data.is_canonical() {
        return None;
    }
    match rtype {
        RecordType::A | RecordType::AAAA => write_address(rtype, data),
        RecordType::CNAME | RecordType::NS | RecordType::PTR | RecordType::DNAME => {
            write_target(rtype, data)
        }
        RecordType::MX => write_mx(data),
        RecordType::SRV => write_srv(data),
        RecordType::TXT => write_txt(data),
        _ => None,
    }
}

/// The shape of `rtype` with `values`.
fn fields(rtype: RecordType, values: Vec<String>) -> Option<Encoded> {
    let shape = shape(&rtype.to_string())?;
    (shape.len() == values.len()).then_some(Encoded::Fields(shape, values))
}

/// A and AAAA: the canonical address as the element's text.
// Source: Docs 4.6.2 (`<a>192.168.0.1</a>`), 4.6.3 (`<aaaa>222:10:2521:1:210:4bff:fe10:d24</aaaa>`).
fn write_address(rtype: RecordType, data: &RecordData) -> Option<Encoded> {
    fields(rtype, vec![data.as_str().to_owned()])
}

/// CNAME, NS, PTR and DNAME: the absolute name with its trailing dot in the element's `name`.
// Source: Docs 4.6.4, 4.6.5, 4.6.8 and 4.6.10 (examples `test.ru.`, `ns3-l2.nic.ru.`,
// `www.test.ru.`).
fn write_target(rtype: RecordType, data: &RecordData) -> Option<Encoded> {
    let target = TargetName::parse(data.as_str()).ok()?;
    fields(rtype, vec![host(&target)?])
}

/// MX: the preference, then the exchange with its trailing dot.
// Source: Docs 4.6.6 (example `<preference>10</preference>`, `<name>mail.test.ru.</name>`).
fn write_mx(data: &RecordData) -> Option<Encoded> {
    let mx = Mx::from_data(data).ok()?;
    fields(
        RecordType::MX,
        vec![mx.preference.to_string(), host(&mx.exchange)?],
    )
}

/// SRV: priority, weight, port, then the target with its trailing dot.
// Source: Docs 4.6.7 (example `0`, `5`, `5060`, `sipserver.test.ru.`).
fn write_srv(data: &RecordData) -> Option<Encoded> {
    let srv = Srv::from_data(data).ok()?;
    fields(
        RecordType::SRV,
        vec![
            srv.priority.to_string(),
            srv.weight.to_string(),
            srv.port.to_string(),
            host(&srv.target)?,
        ],
    )
}

/// TXT: the value itself, cut into strings (module documentation, note 3).
// Source: Docs 4.6.9.
fn write_txt(data: &RecordData) -> Option<Encoded> {
    let txt = Txt::from_data(data).ok()?;
    Some(Encoded::Strings(txt_strings(&txt)?))
}

/// The strings of a TXT value: at most [`STRING_MAX`] bytes each, cut where neither side of the
/// cut is a space. `None` for a value outside what is established (module documentation, note
/// 3), or one that cannot be cut so.
fn txt_strings(txt: &Txt) -> Option<Vec<String>> {
    let bytes = txt.as_bytes();
    let printable = bytes
        .iter()
        .all(|&b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\');
    let edges = bytes.first() != Some(&b' ') && bytes.last() != Some(&b' ');
    if bytes.is_empty() || !printable || !edges {
        return None;
    }
    // The value itself, in the `Raw` dialect; the cuts below fall between ASCII bytes.
    let text = TXT_WRITE.write(txt)?;
    let mut out = Vec::new();
    let mut rest = text.as_str();
    while rest.len() > STRING_MAX {
        let cut = (1..=STRING_MAX).rev().find(|&at| {
            rest.as_bytes().get(at - 1) != Some(&b' ') && rest.as_bytes().get(at) != Some(&b' ')
        })?;
        out.push(rest.get(..cut)?.to_owned());
        rest = rest.get(cut..)?;
    }
    out.push(rest.to_owned());
    Some(out)
}

/// A domain name as written: absolute with its trailing dot; `None` for a name whose canonical
/// text needs a backslash escape.
fn host(name: &TargetName) -> Option<String> {
    let text = name.as_str();
    (!text.contains('\\')).then(|| text.to_owned())
}

/// The owner name as written: relative to the zone, `@` for the apex.
fn owner<'n>(name: &'n DomainName, zone: &DomainName) -> Result<&'n str, Error> {
    match name.relative_to(zone) {
        Some("") => Ok("@"),
        Some(relative) => Ok(relative),
        None => Err(Error::name_outside_zone(name.clone(), zone.clone())),
    }
}

/// A record's TTL as listed: `ProviderDefault` for a record without `<ttl>`, which takes the
/// zone's default ("If ttl setting has not been set in the request, TTL default value will be
/// applied", Docs 4.6); `None` for a number outside the model's range.
pub(super) fn read_ttl(secs: Option<u32>) -> Option<RrsetTtl> {
    match secs {
        None => Some(RrsetTtl::ProviderDefault),
        Some(secs) => RrsetTtl::from_secs(secs).ok(),
    }
}

/// The `<ttl>` a staged record carries: the number, or none for the zone's default (and for a
/// TTL the read could not state, which a record added to such a set has always been given).
pub(super) fn api_ttl(ttl: Option<RrsetTtl>) -> Option<u32> {
    ttl.and_then(RrsetTtl::explicit).map(Ttl::as_secs)
}

fn not_sendable() -> Error {
    Error::InvalidInput {
        detail: Detail::constant("the provider's encoding of this record data is not established"),
    }
}

// ---- One operation -------------------------------------------------------------------------------

/// What the edits of one operation did so far.
#[derive(Clone, Copy, Debug, Default)]
struct Progress {
    /// Edits sent (or about to be sent).
    attempted: usize,
    /// Edits the API answered with success.
    staged: usize,
    /// An edit failed in a way that leaves open whether it was staged.
    unknown: bool,
}

/// One record-level operation: the client, the zone lock once the read has taken it, the zone's
/// service as the read found it, and what its edits did. A reading operation (`get_rrset`) only
/// reads.
pub(super) struct RecordOp<'a> {
    client: &'a Nicru,
    writing: bool,
    zone_guard: Mutex<Option<NameGuard>>,
    service: Mutex<Option<String>>,
    progress: Mutex<Progress>,
}

impl<'a> RecordOp<'a> {
    fn new(client: &'a Nicru, writing: bool) -> RecordOp<'a> {
        RecordOp {
            client,
            writing,
            zone_guard: Mutex::new(None),
            service: Mutex::new(None),
            progress: Mutex::new(Progress::default()),
        }
    }

    /// An operation that only reads.
    pub(super) fn reading(client: &'a Nicru) -> RecordOp<'a> {
        RecordOp::new(client, false)
    }

    /// An operation that writes; [`RecordOp::finish`] completes it.
    pub(super) fn writing(client: &'a Nicru) -> RecordOp<'a> {
        RecordOp::new(client, true)
    }

    /// Takes the zone lock unless this operation holds it already.
    async fn lock_zone(&self, zone: &DomainName) {
        let held = self
            .zone_guard
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some();
        if held {
            return;
        }
        let guard = self.client.state().zone_locks.lock(zone).await;
        *self
            .zone_guard
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(guard);
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

    fn progress(&self) -> Progress {
        *self.progress.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn update_progress(&self, change: impl FnOnce(&mut Progress)) {
        change(&mut self.progress.lock().unwrap_or_else(PoisonError::into_inner));
    }

    /// Sends one edit. The zone is marked for a rollback before the edit is sent (design
    /// section 3.2), so that an operation that fails or is dropped after it is never published
    /// half-applied.
    async fn stage(
        &self,
        zone: &DomainName,
        edit: impl Future<Output = Result<(), EditError>>,
    ) -> Result<(), Error> {
        self.client.mark_for(zone, Pending::Rollback);
        self.update_progress(|p| p.attempted += 1);
        match edit.await {
            Ok(()) => {
                self.update_progress(|p| p.staged += 1);
                Ok(())
            }
            Err(failed) => {
                if !failed.refused {
                    self.update_progress(|p| p.unknown = true);
                }
                Err(failed.error)
            }
        }
    }

    /// Ends a writing operation after the record layer returned `result`, still under the zone
    /// lock (module documentation). Every edit staged: commit, and a failed commit is the
    /// result (`Error::Transient`; the zone stays marked for a commit, so the next operation
    /// publishes this complete change). An error after edits that may have been staged: they
    /// are rolled back; if that fails, its error is the result and the zone stays marked for a
    /// rollback. Nothing staged: the result as it is.
    pub(super) async fn finish<T>(
        &self,
        zone: &DomainName,
        result: Result<T, Error>,
    ) -> Result<T, Error> {
        let progress = self.progress();
        if progress.attempted == 0 {
            return result;
        }
        let service = match self.service() {
            Ok(service) => service,
            Err(e) => return Err(e),
        };
        match result {
            Ok(value) => {
                // The layer stages every edit of its plan before it returns success: what is
                // staged now is exactly this operation's complete change.
                self.client.mark_for(zone, Pending::Commit);
                self.client.commit_own(zone, &service).await?;
                Ok(value)
            }
            Err(error) if progress.staged == 0 && !progress.unknown => {
                // Every edit sent was refused by its answer: nothing is staged.
                self.client.unmark(zone);
                Err(error)
            }
            Err(error) => {
                self.client.discard_own(zone, &service).await?;
                Err(error)
            }
        }
    }
}

impl RrsetBase for RecordOp<'_> {
    fn provider(&self) -> ProviderId {
        ProviderId::Nicru
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.client.locks
    }

    fn can_send(&self, rtype: RecordType, data: &RecordData) -> bool {
        encode(rtype, data).is_some()
    }
}

impl PerRecord for RecordOp<'_> {
    /// The record's identifier.
    type Handle = String;
    /// The service is kept by the operation; the read lists the whole zone and carries what
    /// else is at the name.
    type Context = Neighbors;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<RecordsRead<String, Neighbors>, Error> {
        self.lock_zone(zone).await;
        let target = self.client.resolve_zone(zone).await?;
        if self.writing {
            self.client.settle_leftovers(zone, &target).await?;
        } else {
            self.client.settle_before_read(zone, &target).await?;
        }
        *self.service.lock().unwrap_or_else(PoisonError::into_inner) = Some(target.service.clone());
        let listing = self.client.api.records(&target.service, zone).await?;
        if listing.has_changes == Some(true) {
            // Staged after the zone lookup: not by this process, which holds the zone lock and
            // has settled its own.
            return Err(rejected(if self.writing {
                FOREIGN_CHANGES
            } else {
                STAGED_READ
            }));
        }
        let (records, others): (Vec<_>, Vec<_>) = listing
            .records
            .into_iter()
            .filter(|rr| rr.owner.as_ref() == Some(name))
            .partition(|rr| rr.rtype.parse::<RecordType>().ok() == Some(rtype));
        // The listing holds every record of the zone, and the API documents no disabled
        // records: the other records of the name are all the data there besides this type.
        let neighbors = Neighbors::of(
            rtype,
            others.iter().map(|rr| rr.rtype.parse::<RecordType>().ok()),
        );
        let records = records
            .into_iter()
            .map(|rr| Stored {
                data: read_record(rtype, &rr),
                // The API documents no disabled records.
                enabled: true,
                ttl: read_ttl(rr.ttl),
                handle: rr.id,
            })
            .collect();
        Ok(RecordsRead {
            context: neighbors,
            records,
        })
    }

    async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &Neighbors,
        data: &RecordData,
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let encoded = encode(rtype, data).ok_or_else(not_sendable)?;
        let owner = owner(name, zone)?;
        // The provider's default, requested, configured or as read, is sent as no TTL: the
        // zone's default applies (Docs 4.6). So is a TTL the read could not state, as before.
        let ttl = api_ttl(ttl.resolve(self.client.ttl));
        let service = self.service()?;
        let type_name = rtype.to_string();
        self.stage(
            zone,
            self.client
                .api
                .add_record(&service, zone, owner, ttl, &type_name, encoded.content()),
        )
        .await
    }

    async fn update(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        context: &Neighbors,
        record: &Stored<String>,
        update: &RecordUpdate<'_>,
    ) -> Result<(), Error> {
        if update.enable || update.data.is_some() {
            // The records read are all enabled, and `updates_in_place` is false: the layer never
            // asks for this.
            return Err(Error::Protocol {
                detail: Detail::constant("the provider has no edit call for this change"),
            });
        }
        let Some(ttl) = update.ttl else {
            return Ok(());
        };
        // No edit call: the same value with the new TTL, and the deletion of the old record.
        // Both are staged and published by the operation's one commit. For a singleton type
        // (CNAME, DNAME) the deletion is staged first, so that the zone never holds two staged
        // records of the type at the name (design section 3.4); for other types the new record
        // goes first, as the record layer orders a replacement.
        if encode(rtype, &record.data).is_none() {
            return Err(Error::InvalidInput {
                detail: Detail::constant(
                    "the TTL of a record whose value this client cannot write cannot be changed",
                ),
            });
        }
        let renewed = SetTtl::Requested(ttl);
        if singleton(rtype) {
            self.delete(zone, name, rtype, context, record).await?;
            return self
                .create(zone, name, rtype, context, &record.data, renewed)
                .await;
        }
        self.create(zone, name, rtype, context, &record.data, renewed)
            .await?;
        self.delete(zone, name, rtype, context, record).await
    }

    async fn delete(
        &self,
        zone: &DomainName,
        _name: &DomainName,
        _rtype: RecordType,
        _context: &Neighbors,
        record: &Stored<String>,
    ) -> Result<(), Error> {
        let service = self.service()?;
        self.stage(
            zone,
            self.client
                .api
                .delete_record(&service, zone, &record.handle),
        )
        .await
    }

    fn updates_in_place(&self) -> bool {
        false
    }

    fn holds_cname(&self, _rtype: RecordType, context: &Neighbors) -> Option<bool> {
        context.holds_cname()
    }

    fn holds_other_data(&self, _rtype: RecordType, context: &Neighbors) -> Option<bool> {
        context.holds_other_data()
    }
}

// ---- Listing -------------------------------------------------------------------------------------

/// The records of one owner name and type, as the listing gathers them.
struct Group {
    name: Option<DomainName>,
    type_name: String,
    rtype: Option<RecordType>,
    ttl: Option<RrsetTtl>,
    records: Vec<RecordData>,
}

/// The types whose records the client can represent: TXT and the types of `api::SHAPES`.
fn shown(rtype: RecordType) -> bool {
    let name = rtype.to_string();
    name == TXT || shape(&name).is_some()
}

impl Nicru {
    /// Before a read of `zone`, under the zone lock: staged changes of this process left by an
    /// earlier operation are committed or rolled back first, as their mark says, as a write
    /// does; other staged changes are `Error::Rejected` (module documentation, "Reads"). A
    /// zone without staged changes has its mark cleared.
    async fn settle_before_read(&self, zone: &DomainName, target: &Zone) -> Result<(), Error> {
        if target.has_changes && !self.is_marked(zone) {
            return Err(rejected(STAGED_READ));
        }
        self.settle_leftovers(zone, target).await
    }

    /// `list_rrsets`: every record of the zone, grouped by owner name and type, under the zone
    /// lock and only while the zone has no staged changes (module documentation).
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(&RecordOp::reading(self), zone)?;
        let _zone_guard = self.state().zone_locks.lock(zone).await;
        let target = self.resolve_zone(zone).await?;
        self.settle_before_read(zone, &target).await?;
        let listing = self.api.records(&target.service, zone).await?;
        if listing.has_changes == Some(true) {
            return Err(rejected(STAGED_READ));
        }
        let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
        for rr in &listing.records {
            let rtype = rr.rtype.parse::<RecordType>().ok();
            // Spellings of one name or type that mean the same land in one group; names that
            // are not valid share one group per type.
            let key = (
                rr.owner
                    .as_ref()
                    .map_or_else(|| "raw:".to_owned(), |n| n.as_str().to_owned()),
                rtype.map_or_else(|| format!("raw:{}", rr.rtype), |t| t.to_string()),
            );
            let ttl = read_ttl(rr.ttl);
            let group = groups.entry(key).or_insert_with(|| Group {
                name: rr.owner.clone(),
                type_name: rr.rtype.clone(),
                rtype,
                ttl: None,
                records: Vec::new(),
            });
            // The smallest TTL of the set (design section 3.6, `TtlSupport::PerRecord`).
            group.ttl = RrsetTtl::of_records([group.ttl, ttl]);
            if let Some(rtype) = rtype.filter(|&t| shown(t)) {
                group.records.push(read_record(rtype, rr));
            }
        }
        let mut out = Listing::new(zone);
        for group in groups.into_values() {
            let type_name = group
                .rtype
                .map_or_else(|| group.type_name.clone(), |rtype| rtype.to_string());
            match group.rtype {
                Some(rtype) if shown(rtype) => {
                    out.push(group.name, &type_name, group.ttl, group.records);
                }
                // A type whose element no source shows, or no record type at all: reported,
                // never dropped. A name that is not valid, or not within the zone, is reported
                // under the zone's name, as `Listing::push` does.
                rtype => match group.name.filter(|n| n.is_within(zone)) {
                    None => out.skip(zone.clone(), &type_name, SkipReason::UnsupportedName),
                    Some(name) => {
                        let reason = match rtype {
                            Some(_) => SkipReason::NotPlainRecords,
                            None => SkipReason::UnknownType,
                        };
                        out.skip(name, &type_name, reason);
                    }
                },
            }
        }
        out.finish(ProviderId::Nicru)
    }
}

#[cfg(test)]
mod tests {
    use super::{Encoded, encode, read_record, txt_strings};
    use crate::providers::nicru::api::{Rr, shape};
    use crate::record::{RecordData, RecordType, Txt};

    fn rr(rtype: &str, fields: &[Option<&str>], txt: Option<&str>) -> Rr {
        Rr {
            id: "1".into(),
            owner: None,
            rtype: rtype.into(),
            ttl: None,
            txt: txt.map(str::to_owned),
            fields: fields.iter().map(|f| f.map(str::to_owned)).collect(),
        }
    }

    fn data(rtype: RecordType, text: &str) -> RecordData {
        RecordData::parse(rtype, text).unwrap()
    }

    #[test]
    fn each_type_reads_into_canonical_text() {
        for (rtype, fields, canonical) in [
            (RecordType::A, vec![Some("192.0.2.1")], "192.0.2.1"),
            (RecordType::AAAA, vec![Some("2001:DB8:0::1")], "2001:db8::1"),
            (
                RecordType::CNAME,
                vec![Some("Target.example.net.")],
                "target.example.net.",
            ),
            (
                RecordType::NS,
                vec![Some("ns1.example.net.")],
                "ns1.example.net.",
            ),
            (
                RecordType::PTR,
                vec![Some("www.example.org.")],
                "www.example.org.",
            ),
            (
                RecordType::DNAME,
                vec![Some("example.net.")],
                "example.net.",
            ),
            (
                RecordType::MX,
                vec![Some("10"), Some("mail.example.org.")],
                "10 mail.example.org.",
            ),
            (
                RecordType::SRV,
                vec![Some("0"), Some("5"), Some("5060"), Some("sip.example.org.")],
                "0 5 5060 sip.example.org.",
            ),
            (
                RecordType::SOA,
                vec![
                    Some("ns3-l2.nic.ru."),
                    Some("dns.nic.ru."),
                    Some("2011112002"),
                    Some("1440"),
                    Some("3600"),
                    Some("2592000"),
                    Some("600"),
                ],
                "ns3-l2.nic.ru. dns.nic.ru. 2011112002 1440 3600 2592000 600",
            ),
        ] {
            let got = read_record(rtype, &rr(&rtype.to_string(), &fields, None));
            assert!(got.is_canonical(), "{rtype} {fields:?}");
            assert_eq!(got.as_str(), canonical, "{rtype}");
        }
        let txt = read_record(
            RecordType::TXT,
            &rr("TXT", &[], Some("Location this machine: City")),
        );
        assert_eq!(txt.as_str(), "\"Location this machine: City\"");
    }

    #[test]
    fn fields_that_do_not_parse_are_non_canonical() {
        for (rtype, fields, kept) in [
            (
                RecordType::A,
                vec![Some("not an address")],
                "not an address",
            ),
            (RecordType::A, vec![None], ""),
            (RecordType::CNAME, vec![Some("www")], "www"),
            (RecordType::CNAME, vec![Some("@")], "@"),
            (
                RecordType::MX,
                vec![Some("10"), Some("mail.example.org")],
                "10 mail.example.org",
            ),
            (
                RecordType::MX,
                vec![Some("70000"), Some("mail.example.org.")],
                "70000 mail.example.org.",
            ),
            (
                RecordType::SRV,
                vec![Some("0"), None, Some("5060"), Some("sip.example.org.")],
                "0  5060 sip.example.org.",
            ),
            (
                "HINFO".parse().unwrap(),
                vec![Some("PC-Intel-700mhz"), Some("RUEL 6.0")],
                "PC-Intel-700mhz RUEL 6.0",
            ),
        ] {
            let got = read_record(rtype, &rr(&rtype.to_string(), &fields, None));
            assert!(!got.is_canonical(), "{rtype} {fields:?}");
            assert_eq!(got.as_str(), kept, "{rtype}");
        }
    }

    #[test]
    fn each_type_writes_the_documented_fields() {
        for (rtype, text, expected) in [
            (RecordType::A, "192.0.2.1", vec!["192.0.2.1"]),
            (RecordType::AAAA, "2001:db8::1", vec!["2001:db8::1"]),
            (
                RecordType::CNAME,
                "target.example.net.",
                vec!["target.example.net."],
            ),
            (RecordType::NS, "ns1.example.net.", vec!["ns1.example.net."]),
            (
                RecordType::PTR,
                "www.example.org.",
                vec!["www.example.org."],
            ),
            (RecordType::DNAME, "example.net.", vec!["example.net."]),
            (
                RecordType::MX,
                "10 mail.example.org.",
                vec!["10", "mail.example.org."],
            ),
            (RecordType::MX, "0 .", vec!["0", "."]),
            (
                RecordType::SRV,
                "1 5 5060 sip.example.org.",
                vec!["1", "5", "5060", "sip.example.org."],
            ),
        ] {
            let Some(Encoded::Fields(got_shape, values)) = encode(rtype, &data(rtype, text)) else {
                panic!("{rtype} {text}");
            };
            assert_eq!(got_shape.rtype, shape(&rtype.to_string()).unwrap().rtype);
            assert_eq!(values, expected, "{rtype}");
            // Read back through the same fields, the value is the same.
            let fields: Vec<Option<&str>> = values.iter().map(|v| Some(v.as_str())).collect();
            let back = read_record(rtype, &rr(&rtype.to_string(), &fields, None));
            assert_eq!(back, data(rtype, text), "{rtype}");
        }
        let Some(Encoded::Strings(strings)) = encode(
            RecordType::TXT,
            &data(RecordType::TXT, "\"v=spf1 mx -all\""),
        ) else {
            panic!("TXT");
        };
        assert_eq!(strings, ["v=spf1 mx -all"]);
    }

    #[test]
    fn long_txt_values_are_cut_away_from_spaces() {
        let plain = "a".repeat(600);
        let strings = txt_strings(&Txt::new(plain.as_bytes()).unwrap()).unwrap();
        assert_eq!(
            strings.iter().map(String::len).collect::<Vec<_>>(),
            [255, 255, 90]
        );
        assert_eq!(strings.concat(), plain);
        // A space at byte 255 moves the cut back.
        let spaced = format!("{} {}", "b".repeat(255), "c".repeat(10));
        let strings = txt_strings(&Txt::new(spaced.as_bytes()).unwrap()).unwrap();
        assert_eq!(strings.concat(), spaced);
        assert!(
            strings
                .iter()
                .all(|s| s.len() <= 255 && !s.starts_with(' ') && !s.ends_with(' '))
        );
        // No cut possible: a run of spaces over a whole string.
        let blank = format!("x{}x", " ".repeat(300));
        assert!(txt_strings(&Txt::new(blank.as_bytes()).unwrap()).is_none());
    }

    #[test]
    fn values_without_an_established_encoding_are_not_sent() {
        for (rtype, text) in [
            (RecordType::CNAME, "a\\.b.example.net."),
            (RecordType::TXT, "\"quo\\\"te\""),
            (RecordType::TXT, "\"back\\\\slash\""),
            (RecordType::TXT, "\" leading\""),
            (RecordType::TXT, "\"trailing \""),
            (RecordType::TXT, "\"\""),
            (RecordType::TXT, "\"caf\\195\\169\""),
            (RecordType::SOA, "a.example. b.example. 1 2 3 4 5"),
            (RecordType::CAA, "0 issue \"ca.example.net\""),
            (RecordType::TLSA, "3 1 1 0a1b"),
        ] {
            assert!(
                encode(rtype, &data(rtype, text)).is_none(),
                "{rtype} {text}"
            );
        }
        assert!(encode(RecordType::A, &RecordData::non_canonical("x")).is_none());
    }
}
