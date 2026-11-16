//! Record-level operations: the whole-set shape of the record layer over DNS UPDATE, with the
//! preconditions carried as RFC 2136 prerequisites (`Preconditions::Atomic`, design sections 3.4
//! and 11.3).
//!
//! The layer takes the per-name lock, reads, evaluates `Expect`, decides the outcome and calls
//! the methods below. Every message names one owner name and one type:
//!
//! - read: a signed QUERY for `name type IN` to the configured server. Only answer records owned
//!   by exactly `name`, of that type and class IN, count. The RDATA is taken as the server sent
//!   it, with compressed names expanded (RFC 3597 section 4), and converted with
//!   `RecordData::from_wire`; RDATA that does not convert is carried as non-canonical data in
//!   the generic form of RFC 3597 and written back unchanged (design section 4.9). A CNAME owned
//!   by `name` in the answer to a query for another type (RFC 1034 section 4.3.2, step 3a) is
//!   remembered for the write. An answer without the AA bit is a referral when its authority
//!   section holds the NS RRset of a zone cut at or above `name` (RFC 1034 section 4.3.2, step
//!   3b): the NS RRset of the cut itself is read from there, as the delegation it is in the
//!   parent zone; any other name at or below a cut is refused (`Error::Rejected`); a non-AA
//!   answer without a referral is `Error::ZoneNotFound`, as in the TXT value operations. A
//!   REFUSED query is `Error::Forbidden`: the record model has no outcome for a write whose
//!   prior state was not seen (`SetOutcome` has no counterpart of `AddOutcome::Accepted`), so
//!   the record-level operations need a key that may query the zone and are refused rather than
//!   reporting a guessed outcome.
//! - write: one UPDATE (RFC 2136 sections 2.4 and 2.5), applied by the server as one
//!   transaction (section 3.4.2.1):
//!   - when the read found no RRset: the prerequisite "RRset does not exist" (2.4.3). For a type
//!     other than CNAME also "no CNAME RRset at the name" (a server silently ignores the add of
//!     a non-CNAME RR at a name that owns a CNAME, section 3.4.2.2); a CNAME seen by the read is
//!     refused before anything is sent (`Error::Rejected`). For a CNAME also "name is not in
//!     use" (2.4.5), since a server silently ignores a CNAME added next to other RRsets
//!     (3.4.2.2); its failure, YXDOMAIN, is `Error::Rejected`. Prerequisites are evaluated in
//!     order (section 3.2.5), so the "RRset does not exist" answer YXRRSET comes first.
//!   - when the read found the RRset: the prerequisite "RRset exists (value dependent)" (2.4.2)
//!     with every RR as read, then "delete an RRset" (2.5.2).
//!   - then "add to an RRset" (2.5.1) for every member: records that stay with their RDATA as
//!     read, new values with their wire form. All of them carry the TTL of the write, so the
//!     RRset has one TTL afterwards.
//! - delete: one UPDATE with the prerequisite "RRset exists (value dependent)" with every RR as
//!   read, then "delete an RRset". "Delete all RRsets from a name" (2.5.3) is never sent.
//!
//! The prerequisites always name the RRset as the read found it, which after the layer's
//! evaluation is the caller's expectation: `Expect::Absent` travels as "RRset does not exist"
//! and `Expect::Matches` as "RRset exists (value dependent)" with the expected RRs, exactly as
//! the server holds them. A failed prerequisite (YXRRSET, NXRRSET) therefore means the RRset
//! changed after the read: `Error::Conflict`, and the layer runs the operation once more from
//! the read, which evaluates `Expect` against the new state and ends in `PreconditionFailed`
//! when the caller's expectation no longer holds. A prerequisite cannot express a TTL; a TTL in
//! `Expect::Matches` is compared by the layer after its read.
//!
//! The updates are sent exactly once (`Transport::send_once`): a repeat of an update that was
//! applied but whose answer was lost would fail its own prerequisite and misreport the outcome.
//! Reads are repeated as every query is.
//!
//! Size: one UPDATE must fit the 65535 octets of the TCP framing (RFC 1035 section 4.2.2).
//! A requested RRset that cannot fit is refused before any request; a write that would not fit
//! once the RRs read are included in its prerequisite is refused after the read, before the
//! update is sent (`Error::InvalidInput`).
//!
//! SOA is read-only and the apex NS RRset is not writable (design section 3.4); the layer refuses
//! both before any request, so the special rules of RFC 2136 sections 3.4.2.2 to 3.4.2.4 for
//! them never apply to a message of this client.

use std::borrow::Cow;

use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::{DomainName, TargetName};
use crate::provider::Expect;
use crate::record::{RecordData, RecordType, RrSet, RrsetTtl, Ttl};
use crate::redact::Detail;
use crate::rrsets::{Current, Found, Member, RrsetBase, SetTtl, Stored, WholeRead, WholeSet};

use super::client::Rfc2136;
use super::transport::Answer;
use super::txt::rcode_error;
use super::wire::{self, Builder, CLASS_IN, HEADER_LEN, MAX_MESSAGE, TYPE_CNAME, TYPE_NS, rcode};

/// The most a TSIG record adds to a message (RFC 8945 section 4.2): the key name (at most 255
/// octets) and the fixed RR fields (10), the algorithm name (13 octets for each of `hmac-sha256.`,
/// `hmac-sha384.` and `hmac-sha512.`), time, fudge and MAC size (10), the MAC (at most 64, from
/// `hmac-sha512`), original ID, error and other length (6).
const TSIG_RESERVE: usize = 255 + 10 + 13 + 10 + 64 + 6;

/// Fixed fields of a resource record after its owner name: type, class, TTL, RDLENGTH.
const RR_FIXED: usize = 10;

fn invalid(text: &'static str) -> Error {
    Error::InvalidInput {
        code: None,
        detail: Detail::constant(text),
    }
}

fn too_large() -> Error {
    invalid("the update would not fit one DNS message (65535 octets)")
}

fn cname_present() -> Error {
    Error::Rejected {
        code: None,
        status: None,
        detail: Detail::constant(
            "the name holds a CNAME: a server ignores other records added next to it (RFC 2136 \
             section 3.4.2.2)",
        ),
    }
}

/// What a read learned that the write needs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReadContext {
    /// The answer to a query for a type other than CNAME held a CNAME owned by the name.
    cname: bool,
}

/// The RRset as read: the RDATA of every RR, uncompressed, as the server sent it.
#[derive(Clone, Debug)]
pub(crate) struct Prior(Vec<Vec<u8>>);

impl RrsetBase for Rfc2136 {
    fn provider(&self) -> ProviderId {
        ProviderId::Rfc2136
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }

    /// Every canonical value of a type with a code has a wire form (design section 4.8).
    fn can_send(&self, rtype: RecordType, data: &RecordData) -> bool {
        data.to_wire(rtype).is_ok()
    }
}

/// The type code; the layer offers only types that have one (`TypeSet::AnyWithCode`).
fn code(rtype: RecordType) -> Result<u16, Error> {
    rtype
        .code()
        .ok_or_else(|| Error::unsupported_record_type(ProviderId::Rfc2136, rtype))
}

/// The wire length of `name`, as [`wire::put_name`] writes it.
fn name_len(name: &DomainName) -> usize {
    TargetName::from(name).wire().len()
}

impl WholeSet for Rfc2136 {
    /// The RDATA as the server sent it, uncompressed.
    type Handle = Vec<u8>;
    type Snapshot = Prior;
    type Context = ReadContext;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> WholeRead<Self> {
        let code = code(rtype)?;
        let request = Builder::query(name, code).finish()?;
        let answer = self.transport.exchange(&request, "query").await?;
        match answer.rcode() {
            rcode::NOERROR | rcode::NXDOMAIN => {}
            rcode::REFUSED => {
                return Err(Error::Forbidden {
                    detail: Detail::constant(
                        "the server refused the query (REFUSED): the record-level operations \
                         need a key that may query the zone",
                    ),
                });
            }
            rcode::NOTAUTH => return Err(Error::zone_not_found(zone.clone())),
            other => return Err(rcode_error(other)),
        }
        let (records, cname) = if answer.response.authoritative() {
            let records = owned(&answer, &answer.response.answers, name, code)?;
            let cname = code != TYPE_CNAME
                && answer.response.answers.iter().any(|record| {
                    record.rtype == TYPE_CNAME
                        && record.class == CLASS_IN
                        && record.name == name.as_str()
                });
            (records, cname)
        } else {
            (referral(&answer, zone, name, code)?, false)
        };
        let ttl = records.iter().map(|(_, ttl)| *ttl).min();
        let stored: Vec<Stored<Vec<u8>>> = records
            .into_iter()
            .map(|(rdata, _)| Stored {
                data: data_of(rtype, &rdata),
                enabled: true,
                ttl: None,
                handle: rdata,
            })
            .collect();
        let found = (!stored.is_empty()).then(|| {
            let prior = Prior(stored.iter().map(|record| record.handle.clone()).collect());
            Found {
                records: stored,
                ttl: ttl.map(RrsetTtl::Explicit),
                snapshot: prior,
            }
        });
        Ok(Current {
            context: ReadContext { cname },
            found,
        })
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        context: &ReadContext,
        prior: Option<&Prior>,
        members: &[Member<'_, Vec<u8>>],
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let code = code(rtype)?;
        let ttl = match ttl {
            SetTtl::Requested(RrsetTtl::Explicit(ttl))
            | SetTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => ttl.as_secs(),
            SetTtl::Existing(None | Some(RrsetTtl::ProviderDefault))
            | SetTtl::Default
            | SetTtl::Requested(RrsetTtl::ProviderDefault) => self.ttl,
        };
        let mut update = Builder::update(zone);
        match prior {
            None => {
                if context.cname {
                    return Err(cname_present());
                }
                update.prereq_rrset_absent(name, code)?;
                if code == TYPE_CNAME {
                    update.prereq_name_unused(name)?;
                } else {
                    update.prereq_rrset_absent(name, TYPE_CNAME)?;
                }
            }
            Some(Prior(rdatas)) => {
                for rdata in rdatas {
                    update.prereq_rr(name, code, rdata)?;
                }
                update.delete_rrset(name, code)?;
            }
        }
        for member in members {
            let rdata = match member {
                Member::Kept(record) | Member::Enabled(record) => Cow::Borrowed(&record.handle),
                Member::Added(data) => Cow::Owned(
                    data.to_wire(rtype)
                        .map_err(|_| invalid("the record data has no wire form"))?,
                ),
            };
            update.add(name, code, ttl, &rdata)?;
        }
        self.send_update(zone, name, update).await
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &ReadContext,
        prior: &Prior,
    ) -> Result<(), Error> {
        let code = code(rtype)?;
        let mut update = Builder::update(zone);
        for rdata in &prior.0 {
            update.prereq_rr(name, code, rdata)?;
        }
        update.delete_rrset(name, code)?;
        self.send_update(zone, name, update).await
    }
}

impl Rfc2136 {
    /// Sends a record-level UPDATE once and maps its RCODE (RFC 2136 section 2.2; design
    /// sections 3.4 and 11.3).
    async fn send_update(
        &self,
        zone: &DomainName,
        name: &DomainName,
        update: Builder,
    ) -> Result<(), Error> {
        let request = update.finish().map_err(|_| too_large())?;
        if request.len() + TSIG_RESERVE > MAX_MESSAGE {
            return Err(too_large());
        }
        let answer = self.transport.send_once(&request, "update").await?;
        match answer.rcode() {
            rcode::NOERROR => Ok(()),
            // A prerequisite naming the RRset as read failed: it changed after the read.
            rcode::YXRRSET | rcode::NXRRSET => Err(Error::Conflict {
                detail: Detail::constant(
                    "the rrset changed after it was read (the server answered YXRRSET or \
                     NXRRSET to the update's prerequisite)",
                ),
            }),
            // Only the "name is not in use" prerequisite of a new CNAME answers YXDOMAIN.
            rcode::YXDOMAIN => Err(Error::Rejected {
                code: None,
                status: None,
                detail: Detail::constant(
                    "the name holds other records (YXDOMAIN): a server ignores a CNAME added \
                     next to them (RFC 2136 section 3.4.2.2)",
                ),
            }),
            rcode::REFUSED => Err(Error::Forbidden {
                detail: Detail::constant(
                    "the server refused the update (REFUSED): its allow-update or update-policy \
                     does not let this key change the rrset",
                ),
            }),
            rcode::NOTAUTH => Err(Error::zone_not_found(zone.clone())),
            rcode::NOTZONE => Err(Error::name_outside_zone(name.clone(), zone.clone())),
            other => Err(rcode_error(other)),
        }
    }

    /// Refuses before any request a `set_rrset` whose UPDATE cannot fit one message whatever the
    /// server holds: the requested RRs, the RRs of an `Expect::Matches` set (sent back as the
    /// prerequisite), the prerequisites and the deletion of the RRset, and the TSIG record.
    /// Values without a wire form are left to the layer, which refuses them.
    pub(super) fn check_size(
        &self,
        zone: &DomainName,
        rrset: &RrSet,
        expect: Expect<'_>,
    ) -> Result<(), Error> {
        let rtype = rrset.rtype();
        let owner = name_len(rrset.name()) + RR_FIXED;
        let records = |set: &RrSet| -> usize {
            set.records()
                .iter()
                .filter_map(|data| data.to_wire(rtype).ok())
                .map(|rdata| owner + rdata.len())
                .sum()
        };
        let mut len = HEADER_LEN + name_len(zone) + 4 + 3 * owner + records(rrset) + TSIG_RESERVE;
        if let Expect::Matches(prev) = expect {
            len += records(prev);
        }
        if len > MAX_MESSAGE {
            return Err(too_large());
        }
        Ok(())
    }

    /// Whether the record layer's checks before any request (design section 3.1, steps 1 to 3)
    /// pass for a `set_rrset`, so that the size check comes after them in the order of section
    /// 3.1. Step 4's other checks give the same error kind.
    pub(super) fn set_target_valid(&self, zone: &DomainName, rrset: &RrSet) -> bool {
        let caps = RrsetBase::capabilities(self);
        caps.supports(Operation::SetRrset)
            && caps.can_write(rrset.rtype())
            && rrset.rtype() != RecordType::SOA
            && !zone.is_root()
            && !zone.is_wildcard()
            && rrset.name().is_within(zone)
    }
}

/// The records of `section` owned by exactly `name`, of type `code` and class IN, with their
/// uncompressed RDATA and TTL.
fn owned(
    answer: &Answer,
    section: &[wire::Record],
    name: &DomainName,
    code: u16,
) -> Result<Vec<(Vec<u8>, Ttl)>, Error> {
    let mut out = Vec::new();
    for record in section {
        if record.rtype != code || record.class != CLASS_IN || record.name != name.as_str() {
            continue;
        }
        let rdata = wire::rdata_uncompressed(&answer.buf, record).map_err(|_| Error::Protocol {
            detail: Detail::constant("an answer record points outside the message"),
        })?;
        out.push((rdata, ttl_of(record.ttl)));
    }
    Ok(out)
}

/// A TTL as received. A value with the most significant bit set is taken as zero (RFC 2181
/// section 8).
fn ttl_of(secs: u32) -> Ttl {
    Ttl::from_secs(secs)
        .or_else(|_| Ttl::from_secs(0))
        .unwrap_or(Ttl::MAX)
}

/// A non-authoritative answer: the NS RRset of the zone cut at `name` when the query was for NS
/// at a delegation; any other referral is refused; anything else is not an answer from an
/// authority for the zone.
fn referral(
    answer: &Answer,
    zone: &DomainName,
    name: &DomainName,
    code: u16,
) -> Result<Vec<(Vec<u8>, Ttl)>, Error> {
    let cut = answer.response.authority.iter().any(|record| {
        record.rtype == TYPE_NS
            && record.class == CLASS_IN
            && record.name != zone.as_str()
            && DomainName::parse(&record.name)
                .is_ok_and(|owner| owner.is_within(zone) && name.is_within(&owner))
    });
    if !cut {
        return Err(Error::zone_not_found(zone.clone()));
    }
    let delegation = owned(answer, &answer.response.authority, name, code)?;
    if code == TYPE_NS && !delegation.is_empty() {
        return Ok(delegation);
    }
    Err(Error::Rejected {
        code: None,
        status: None,
        detail: Detail::constant(
            "the name is at or below a delegation to another zone: the server answers with a \
             referral, so its records cannot be read",
        ),
    })
}

/// The value of RDATA of type `rtype`: canonical through `RecordData::from_wire`, or the RFC 3597
/// generic form kept as non-canonical data when the RDATA is not valid for its type (design
/// section 4.9).
fn data_of(rtype: RecordType, rdata: &[u8]) -> RecordData {
    RecordData::from_wire(rtype, rdata).unwrap_or_else(|_| {
        let hex: String = rdata.iter().map(|b| format!("{b:02x}")).collect();
        RecordData::non_canonical(&format!("\\# {} {hex}", rdata.len()))
    })
}
