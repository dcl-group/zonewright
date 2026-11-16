//! TXT value operations: the `PerRecord` shape of the value layer over DNS UPDATE.
//!
//! The native unit is the individual RR (design section 11.1). The value layer takes the
//! per-name lock, reads, computes the outcome and calls the methods below:
//!
//! - read: a signed QUERY for `name TXT IN` to the configured server. Only answer records owned
//!   by exactly `name`, of type TXT and class IN, count (a CNAME and the records it leads to are
//!   not TXT records at the name). A NOERROR or NXDOMAIN answer without the AA bit does not come
//!   from an authority for the zone and is `Error::ZoneNotFound`: an empty answer from a server
//!   that is not authoritative must not turn a removal into "not present". REFUSED (a server
//!   that lets the key update but not query, design section 11.3) is
//!   [`PerRecordRead::Unavailable`], and the layer takes the blind path of design section 3.5.
//! - create: an UPDATE with one "add to an RRset" record (RFC 2136 section 2.5.1). It names only
//!   our RR; the server adds it to the RRset and leaves the others alone. It carries the
//!   prerequisite "no CNAME RRset at the name" (section 2.4.3): a server silently ignores the
//!   add of a non-CNAME record at a name that holds a CNAME (section 3.4.2.2) and still answers
//!   NOERROR, so without the prerequisite the add would report success for a value that was
//!   never stored. A failed prerequisite (YXRRSET, section 3.2.5) is `Error::Rejected`. The
//!   prerequisite is evaluated with the update, so it holds on the blind path too and against a
//!   CNAME created between the read and the write; it changes nothing that could hold a foreign
//!   value.
//! - delete: an UPDATE with one "delete an RR from an RRset" record (RFC 2136 section 2.5.4)
//!   carrying the RDATA exactly as the server returned it, so a value stored with other
//!   character-string boundaries is matched too (the server compares RDATA, section 3.4.2.4).
//!   The deletion of a whole RRset (class ANY, section 2.5.2) is never sent.
//! - delete without a read: the same, with the value's canonical encoding (255-octet
//!   character-strings).
//!
//! No message carries a prerequisite about TXT records: a single-RR change cannot lose a foreign
//! value, hence `ValueGuarantee::PerValue`. The only prerequisite is the CNAME guard of create.
//!
//! TXT values travel as wire-format RDATA (RFC 1035 section 3.3.14), so every value the record
//! model holds can be written, not only plain ones; the only bound is the size of the message.
//!
//! TTL (design sections 3.6 and 11.3): an add to an existing RRset carries the smallest TTL the
//! read returned, a new RRset the caller's TTL or the configured one. After a refused read the
//! TTL of an existing RRset is unknown and the add carries the caller's or the configured TTL;
//! a server may then apply it to the whole RRset (RFC 2136 section 3.4.2.2), and the outcome is
//! `Accepted`.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{RrsetTtl, Txt};
use crate::redact::Detail;
use crate::values::{PerRecord, PerRecordRead, TxtBase, TxtRecord, WriteTtl};

use super::client::Rfc2136;
use super::wire::{self, Builder, CLASS_IN, TYPE_CNAME, TYPE_TXT, rcode};

/// Room for everything of an UPDATE except the TXT RDATA: header (12), zone section (at most
/// 255 + 4), the CNAME prerequisite (at most 255 + 10), the update record's owner and fixed
/// fields (at most 255 + 10) and the TSIG record (at most 255 + 10 for owner and fixed fields,
/// 13 for the algorithm name, 16 for the fixed RDATA fields, 64 for the MAC): 1159 octets,
/// rounded up.
const MESSAGE_OVERHEAD: usize = 1280;

impl TxtBase for Rfc2136 {
    fn provider(&self) -> ProviderId {
        ProviderId::Rfc2136
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }

    /// The value's RDATA must leave room for the rest of the message within the 65535 octets of
    /// the TCP framing (design section 3.1, check 4).
    fn check_value(&self, value: &Txt) -> Result<(), Error> {
        let rdata = encode(value)?;
        if rdata.len() + MESSAGE_OVERHEAD > wire::MAX_MESSAGE {
            return Err(Error::InvalidInput {
                code: None,
                detail: Detail::constant("the TXT value is too long for one DNS message"),
            });
        }
        Ok(())
    }
}

/// The value's canonical TXT RDATA: 255-octet character-strings.
fn encode(value: &Txt) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(value.as_bytes().len() + value.as_bytes().len() / 255 + 1);
    value.encode(&mut out).map_err(|_| Error::InvalidInput {
        code: None,
        detail: Detail::constant("the TXT value cannot be encoded as RDATA"),
    })?;
    Ok(out)
}

impl PerRecord for Rfc2136 {
    /// The RDATA as the server returned it.
    type Handle = Vec<u8>;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> Result<PerRecordRead<Vec<u8>>, Error> {
        let request = Builder::query(name, TYPE_TXT).finish()?;
        let answer = self.transport.exchange(&request, "query").await?;
        match answer.rcode() {
            rcode::NOERROR | rcode::NXDOMAIN => {}
            rcode::REFUSED => return Ok(PerRecordRead::Unavailable),
            rcode::NOTAUTH => return Err(Error::zone_not_found(zone.clone())),
            other => return Err(rcode_error(other)),
        }
        if !answer.response.authoritative() {
            return Err(Error::zone_not_found(zone.clone()));
        }
        let mut records = Vec::new();
        for record in &answer.response.answers {
            if record.rtype != TYPE_TXT || record.class != CLASS_IN || record.name != name.as_str()
            {
                continue;
            }
            let rdata = answer
                .rdata(record)
                .ok_or(Error::Protocol {
                    detail: Detail::constant("an answer record points outside the message"),
                })?
                .to_vec();
            records.push(TxtRecord {
                value: wire::txt_data(&rdata).and_then(|data| Txt::new(data).ok()),
                ttl: RrsetTtl::from_secs(record.ttl).ok(),
                handle: rdata,
            });
        }
        Ok(PerRecordRead::Records(records))
    }

    async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let ttl = match ttl {
            WriteTtl::New(Some(RrsetTtl::Explicit(ttl)))
            | WriteTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => ttl.as_secs(),
            WriteTtl::New(None | Some(RrsetTtl::ProviderDefault))
            | WriteTtl::Existing(None | Some(RrsetTtl::ProviderDefault)) => self.ttl,
        };
        let mut update = Builder::update(zone);
        update.prereq_rrset_absent(name, TYPE_CNAME)?;
        update.add(name, TYPE_TXT, ttl, &encode(value)?)?;
        self.update(zone, name, update, "update").await
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        record: &TxtRecord<Vec<u8>>,
    ) -> Result<(), Error> {
        let mut update = Builder::update(zone);
        update.delete_rr(name, TYPE_TXT, &record.handle)?;
        self.update(zone, name, update, "update").await
    }

    async fn delete_blind(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> Result<(), Error> {
        let mut update = Builder::update(zone);
        update.delete_rr(name, TYPE_TXT, &encode(value)?)?;
        self.update(zone, name, update, "update").await
    }
}

impl Rfc2136 {
    /// Sends an UPDATE and maps its RCODE (RFC 2136 section 2.2; design section 11.3).
    async fn update(
        &self,
        zone: &DomainName,
        name: &DomainName,
        update: Builder,
        op: &'static str,
    ) -> Result<(), Error> {
        let answer = self.transport.exchange(&update.finish()?, op).await?;
        match answer.rcode() {
            rcode::NOERROR => Ok(()),
            rcode::REFUSED => Err(Error::Forbidden {
                detail: Detail::constant(
                    "the server refused the update (REFUSED): its allow-update or update-policy \
                     does not let this key change the name",
                ),
            }),
            rcode::NOTAUTH => Err(Error::zone_not_found(zone.clone())),
            rcode::NOTZONE => Err(Error::name_outside_zone(name.clone(), zone.clone())),
            // Only the CNAME guard of create is a prerequisite that can fail this way.
            rcode::YXRRSET => Err(Error::Rejected {
                code: None,
                status: None,
                detail: Detail::constant(
                    "the name holds a CNAME (YXRRSET): a server ignores a TXT record added next \
                     to a CNAME (RFC 2136 section 3.4.2.2)",
                ),
            }),
            other => Err(rcode_error(other)),
        }
    }
}

/// The error for an RCODE no operation expects. SERVFAIL is transient (design section 11.3).
pub(super) fn rcode_error(code: u8) -> Error {
    if code == rcode::SERVFAIL {
        return Error::Transient {
            detail: Detail::constant("the server answered SERVFAIL"),
        };
    }
    Error::Rejected {
        code: None,
        status: None,
        detail: Detail::constant(rcode_text(code)),
    }
}

/// What an RCODE says (RFC 1035 section 4.1.1, RFC 2136 section 2.2).
pub(super) fn rcode_text(code: u8) -> &'static str {
    match code {
        rcode::NOERROR => "the server answered NOERROR",
        rcode::FORMERR => "the server could not interpret the request (FORMERR)",
        rcode::SERVFAIL => "the server answered SERVFAIL",
        rcode::NXDOMAIN => "the server answered NXDOMAIN",
        rcode::NOTIMP => "the server does not support the operation (NOTIMP)",
        rcode::REFUSED => "the server refused the request (REFUSED)",
        rcode::YXDOMAIN => "the server answered YXDOMAIN",
        rcode::YXRRSET => "the server answered YXRRSET",
        rcode::NXRRSET => "the server answered NXRRSET",
        rcode::NOTAUTH => "the server is not authoritative for the zone (NOTAUTH)",
        rcode::NOTZONE => "the name is not within the zone (NOTZONE)",
        _ => "the server answered with an unexpected response code",
    }
}
