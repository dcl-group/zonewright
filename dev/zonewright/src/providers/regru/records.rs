//! Record-level operations: the `PerRecord` shape of the record layer (`crate::rrsets`) over the
//! zone functions of the API, the listing of a zone, and the mapping between the API's content and
//! `RecordData`.
//!
//! The native unit is the individual record without an identifier: a record is created by a
//! per-type add function and removed by its owner name, its type and its content
//! (`zone/remove_record`; documentation 9.18). Hence the per-record shape,
//! `Preconditions::ReadThenWrite` and no `atomic_rrset_write`: replacing an rrset is several
//! requests, creates first and removals last (the record layer decides the order). The record
//! layer does the checks, takes the per-name lock, reads, evaluates the expectation and computes
//! the requests; this file turns them into the API's calls:
//!
//! - read: `zone/get_resource_records`, every record of the zone in one answer (complete or an
//!   error, `api::Api::records`), filtered here by exact name and type. The handle of a record is
//!   its content exactly as the API returned it. Records with the same content at one name and
//!   type are one record to this client, since a removal by content removes all of them;
//! - create: `zone/add_alias` (A), `zone/add_aaaa` (AAAA) or `zone/add_txt` (TXT), sent once, with
//!   the name relative to the zone and the value. No add function has a TTL parameter
//!   (documentation 9.2, 9.3, 9.9), so the capabilities say that a TTL cannot be set and the
//!   record layer refuses a requested one before any request;
//! - delete: `zone/remove_record` with the type and the content the read returned, sent once and
//!   never without a content (`api::Api::remove_record` refuses a blank one before any request;
//!   without it the function removes every record of the type at the name), followed by a read of
//!   the zone as in `txt.rs`: the documentation names no answer for a content nothing holds, so a
//!   `success` alone does not prove that the record is gone, and a record with that content still
//!   there is `Error::Protocol`;
//! - update: not used. The API has no function that changes a record; `zone/update_records`
//!   (documentation 9.12) only sequences add and remove actions in one request, stops at the first
//!   failing action without undoing the earlier ones (so it is not atomic), and is available to
//!   partners only. A TTL change is refused before any request, and no type here is a singleton.
//!
//! # Content per type
//!
//! Source of every row: the documentation, <https://www.reg.ru/reseller/api2doc>, opened for this
//! client (read on 2026-11-14 in a browser; section numbers are its own).
//!
//! | Type | Read from `content` (9.11)                           | Written with                   | Removed with (9.18)        |
//! | ---- | ---------------------------------------------------- | ------------------------------ | -------------------------- |
//! | A    | the IPv4 address ("IP address for A"; example)       | `zone/add_alias`, `ipaddr` (9.2) | `record_type` `A`, `content` (example) |
//! | AAAA | the IPv6 address ("IPv6 address for AAAA")           | `zone/add_aaaa`, `ipaddr` (9.3)  | `record_type` `AAAA`, `content` |
//! | TXT  | the value, read with the `Auto` rule (as `txt.rs`)   | `zone/add_txt`, `text` (9.9)     | `record_type` `TXT`, `content` |
//!
//! `priority` is not sent on a removal: "not applicable to the removal of an A record and similar
//! records" (9.18), and the TXT value operations remove TXT records without it as lego does.
//!
//! TXT: dialect `Auto` on read and `Raw` on write, plain values only (`Txt::is_plain`), the rule of
//! the TXT value operations (`txt.rs`). The documentation allows only alphanumeric ASCII in `text`
//! (9.9); a plain value outside that is sent as the TXT value operations send it, and the API's
//! refusal (`TEXT_CONTAINS_INVALID_CHARACTERS`) is `Error::InvalidInput`.
//!
//! Names: relative to the zone, `@` for the apex and `*` for a wildcard (9.2, 9.3, 9.11).
//!
//! # Types left out
//!
//! The documentation has add functions for CAA, CNAME, HTTPS, MX, NS and SRV (9.4 to 9.10) but
//! gives the listing's `content` only for A and AAAA (and says nothing on how a host name is
//! spelled there: `zone/add_mx` takes the relative `mail` in its example, so relative and absolute
//! spellings cannot be told apart). Those types are therefore not in `record_types`. In a listing,
//! an rrset of a type whose listing entry carries a priority the content may not hold (MX, SRV
//! and HTTPS: their add functions take `priority` as a field of its own) is reported in `skipped`
//! as `NotPlainRecords`, since the content alone is not the value; any other type's content is
//! carried as non-canonical data (design section 4.9), never parsed by a guessed rule.
//!
//! TTL, disabled records, SOA: the listing states no TTL per record (only the zone's `soa` object,
//! which is not a record and not listed), so every rrset reads with no TTL; `state` is documented
//! as obsolete and every record is published.

use std::collections::BTreeMap;

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::provider::{SkipReason, ZoneListing};
use crate::record::{RecordData, RecordType, Txt, TxtDialect};
use crate::redact::Detail;
use crate::rrsets::{
    self, Listing, PerRecord, RecordUpdate, RecordsRead, RrsetBase, SetTtl, Stored,
};

use super::api::{A, AAAA, Rr, TXT};
use super::client::Regru;
use super::txt::subdomain;

/// How TXT content is read: quoted text as presentation format, anything else as the value (the
/// TXT value operations' rule, design section 11.2).
const TXT_READ: TxtDialect = TxtDialect::Auto;

/// How TXT content is written: the value itself (lego regru.go lines 147 and 170 pass the value
/// unquoted).
const TXT_WRITE: TxtDialect = TxtDialect::Raw;

/// The types this client reads and writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    A,
    Aaaa,
    Txt,
}

impl Kind {
    /// The kind of `rtype`; `None` for a type outside `record_types`.
    pub(super) fn of(rtype: RecordType) -> Option<Kind> {
        match rtype {
            RecordType::A => Some(Kind::A),
            RecordType::AAAA => Some(Kind::Aaaa),
            RecordType::TXT => Some(Kind::Txt),
            _ => None,
        }
    }

    /// The type name of `rectype` and `record_type`.
    fn api_name(self) -> &'static str {
        match self {
            Kind::A => A,
            Kind::Aaaa => AAAA,
            Kind::Txt => TXT,
        }
    }
}

// ---- Reading -------------------------------------------------------------------------------------

/// A value as the API returned it in `content`: canonical where it parses, non-canonical
/// otherwise (design section 4.9).
pub(super) fn read_content(kind: Kind, content: &str) -> RecordData {
    match kind {
        Kind::A => read_a(content),
        Kind::Aaaa => read_aaaa(content),
        Kind::Txt => read_txt(content),
    }
}

/// A: the IPv4 address.
// Source: the documentation, 9.11 (`content`: "IP address for A"; the example answer has
// `"content": "111.222.111.222"` with `"rectype": "A"`).
fn read_a(content: &str) -> RecordData {
    RecordData::from_provider(RecordType::A, content, None, TXT_READ)
}

/// AAAA: the IPv6 address, in whatever spelling the API uses (the parser canonicalizes it).
// Source: the documentation, 9.11 (`content`: "IPv6 address for AAAA").
fn read_aaaa(content: &str) -> RecordData {
    RecordData::from_provider(RecordType::AAAA, content, None, TXT_READ)
}

/// TXT: the value, read with the `Auto` rule.
// Source: the documentation, 9.11 (`content`) and 9.9 (`text`, the value itself); how the
// listing spells TXT content is not documented, so quoted text is read as presentation format
// and anything else as the value (design section 4.4), as in `txt.rs`.
fn read_txt(content: &str) -> RecordData {
    RecordData::from_provider(RecordType::TXT, content, None, TXT_READ)
}

/// What a listing does with an rrset of the API type `type_name`.
#[derive(Debug, PartialEq, Eq)]
enum Listed {
    /// A type this client reads.
    Read(Kind),
    /// A type whose content form is not documented: carried as non-canonical data.
    Opaque,
    /// A type whose value includes a priority the listing keeps apart from `content`: skipped.
    Skip,
}

/// How a listing treats `type_name` (see the module documentation).
// Source: the documentation, 9.7 (`zone/add_mx`: `priority`), 9.10 (`zone/add_srv`: `priority`,
// `weight`, `port`, `target`), 9.6 (`zone/add_https`: `priority`) and 9.11 (`prio` next to
// `content` in the listing).
fn listed(type_name: &str) -> Listed {
    match type_name.parse::<RecordType>() {
        Ok(rtype) => match Kind::of(rtype) {
            Some(kind) => Listed::Read(kind),
            None if matches!(
                rtype,
                RecordType::MX | RecordType::SRV | RecordType::HTTPS | RecordType::SVCB
            ) =>
            {
                Listed::Skip
            }
            None => Listed::Opaque,
        },
        // `Listing::push` reports an unknown type name in `skipped`.
        Err(_) => Listed::Opaque,
    }
}

/// Whether `rr` is a record of `kind` at `name`, compared as names (`@` is the zone itself).
fn is_at(rr: &Rr, zone: &DomainName, name: &DomainName, kind: Kind) -> bool {
    rr.rectype
        .as_deref()
        .is_some_and(|rtype| rtype.eq_ignore_ascii_case(kind.api_name()))
        && rr
            .subname
            .as_deref()
            .and_then(|sub| DomainName::from_relative(sub.trim(), zone).ok())
            .as_ref()
            == Some(name)
}

// ---- Writing -------------------------------------------------------------------------------------

/// The field value of a create of a canonical value of `rtype`, or `None` when the client cannot
/// send it.
pub(super) fn encode(rtype: RecordType, data: &RecordData) -> Option<(Kind, String)> {
    if !data.is_canonical() {
        return None;
    }
    let kind = Kind::of(rtype)?;
    let text = match kind {
        Kind::A => write_a(data),
        Kind::Aaaa => write_aaaa(data),
        Kind::Txt => write_txt(data)?,
    };
    Some((kind, text))
}

/// A: the canonical address (four decimal octets) as `ipaddr`.
// Source: the documentation, 9.2 (`zone/add_alias`: `subdomain`, `ipaddr`; example
// `111.111.111.111`).
fn write_a(data: &RecordData) -> String {
    data.as_str().to_owned()
}

/// AAAA: the canonical address (RFC 5952) as `ipaddr`.
// Source: the documentation, 9.3 (`zone/add_aaaa`: `subdomain`, `ipaddr`; example
// `aa11::a111:11aa:aaa1:aa1a`, a compressed lowercase form).
fn write_aaaa(data: &RecordData) -> String {
    data.as_str().to_owned()
}

/// TXT: a plain value, itself, as `text`.
// Source: the documentation, 9.9 (`zone/add_txt`: `subdomain`, `text`); lego regru.go lines 147
// and 170 (the value unquoted).
fn write_txt(data: &RecordData) -> Option<String> {
    let txt = Txt::from_data(data).ok().filter(Txt::is_plain)?;
    TXT_WRITE.write(&txt)
}

fn not_sendable() -> Error {
    Error::InvalidInput {
        detail: Detail::constant("the provider's encoding of this record data is not established"),
    }
}

/// The kind of `rtype`; the layer has refused every other type already.
fn kind_of(rtype: RecordType) -> Result<Kind, Error> {
    Kind::of(rtype).ok_or_else(|| Error::unsupported_record_type(ProviderId::Regru, rtype))
}

// ---- The record layer ----------------------------------------------------------------------------

impl RrsetBase for Regru {
    fn provider(&self) -> ProviderId {
        ProviderId::Regru
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }

    fn can_send(&self, rtype: RecordType, data: &RecordData) -> bool {
        encode(rtype, data).is_some()
    }
}

impl PerRecord for Regru {
    /// The record's content exactly as the API returned it.
    type Handle = String;
    /// Nothing: the domain's name is the key of every call.
    type Context = ();

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<RecordsRead<String, ()>, Error> {
        let kind = kind_of(rtype)?;
        let mut records: Vec<Stored<String>> = Vec::new();
        for rr in self.api.records(zone).await? {
            if !is_at(&rr, zone, name, kind) {
                continue;
            }
            let content = rr.content.unwrap_or_default();
            // One removal by this content removes every copy, so copies are one record.
            if records.iter().any(|r| r.handle == content) {
                continue;
            }
            records.push(Stored {
                data: read_content(kind, &content),
                // `state` is obsolete (documentation 9.11): every record is published.
                enabled: true,
                // The listing states no TTL per record.
                ttl: None,
                handle: content,
            });
        }
        Ok(RecordsRead {
            context: (),
            records,
        })
    }

    async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &(),
        data: &RecordData,
        // No add function takes a TTL (documentation 9.2, 9.3, 9.9); the record layer refuses a
        // requested one before any request, and the others leave the zone's settings in charge.
        _ttl: SetTtl,
    ) -> Result<(), Error> {
        let (kind, text) = encode(rtype, data).ok_or_else(not_sendable)?;
        let sub = subdomain(zone, name)?;
        match kind {
            Kind::A | Kind::Aaaa => {
                self.api
                    .add_address(zone, sub, kind.api_name(), &text)
                    .await
            }
            Kind::Txt => self.api.add_txt(zone, sub, &text).await,
        }
    }

    async fn update(
        &self,
        _zone: &DomainName,
        _name: &DomainName,
        _rtype: RecordType,
        _context: &(),
        _record: &Stored<String>,
        update: &RecordUpdate<'_>,
    ) -> Result<(), Error> {
        if update.enable || update.data.is_some() {
            // The API has no disabled records, no type here is a singleton and
            // `updates_in_place` is false: the layer never asks for either.
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the client was asked for a record update the provider's API does not offer",
                ),
            });
        }
        // A TTL change: the TTL cannot be set at all (the capabilities say so, and the layer
        // refuses a requested TTL before any request).
        Err(Error::InvalidInput {
            detail: Detail::constant("the provider's API cannot set the TTL of a record"),
        })
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _context: &(),
        record: &Stored<String>,
    ) -> Result<(), Error> {
        let kind = kind_of(rtype)?;
        let sub = subdomain(zone, name)?;
        self.api
            .remove_record(zone, sub, kind.api_name(), &record.handle)
            .await?;
        // The documentation does not say what the function answers for a content nothing
        // holds, so a `success` does not prove that the record is gone; a new read does. The
        // comparison is by content: a record with the same value in another spelling is a
        // record of its own, removed by its own call.
        let now = PerRecord::read(self, zone, name, rtype).await?;
        if now.records.iter().any(|r| r.handle == record.handle) {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider reported the removal, but the record is still in the zone",
                ),
            });
        }
        Ok(())
    }

    fn updates_in_place(&self) -> bool {
        false
    }
}

/// The records of one owner name and type, as the listing gathers them.
struct Group {
    name: Option<DomainName>,
    type_name: String,
    records: Vec<RecordData>,
}

impl Regru {
    /// `list_rrsets`: every record of the zone in one answer, grouped by owner name and type.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let rrs = self.api.records(zone).await?;
        // Spellings of one name that mean the same land in one group; the type name is compared
        // without regard to case.
        let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
        for rr in &rrs {
            // `Api::records` has refused an answer with a record without a name or a type.
            let sub = rr.subname.as_deref().unwrap_or_default();
            let type_name = rr
                .rectype
                .as_deref()
                .unwrap_or_default()
                .to_ascii_uppercase();
            let name = DomainName::from_relative(sub.trim(), zone).ok();
            let key = name
                .as_ref()
                .map_or_else(|| format!("raw:{sub}"), |n| n.as_str().to_owned());
            let content = rr.content.as_deref().unwrap_or_default();
            let group = groups
                .entry((key, type_name.clone()))
                .or_insert_with(|| Group {
                    name,
                    type_name,
                    records: Vec::new(),
                });
            let data = match listed(&group.type_name) {
                Listed::Read(kind) => read_content(kind, content),
                Listed::Opaque | Listed::Skip => RecordData::non_canonical(content),
            };
            group.records.push(data);
        }
        let mut listing = Listing::new(zone);
        for group in groups.into_values() {
            match (listed(&group.type_name), group.name) {
                (Listed::Skip, Some(name)) if name.is_within(zone) => {
                    listing.skip(name, &group.type_name, SkipReason::NotPlainRecords);
                }
                (_, name) => listing.push(name, &group.type_name, None, group.records),
            }
        }
        listing.finish(ProviderId::Regru)
    }
}

#[cfg(test)]
mod tests {
    use super::{Kind, Listed, encode, listed, read_content};
    use crate::record::{RecordData, RecordType};

    fn data(rtype: RecordType, text: &str) -> RecordData {
        RecordData::parse(rtype, text).unwrap()
    }

    #[test]
    fn each_type_reads_into_canonical_text() {
        for (kind, content, canonical) in [
            (Kind::A, "192.0.2.1", "192.0.2.1"),
            (Kind::A, " 192.0.2.1 ", "192.0.2.1"),
            (Kind::Aaaa, "2001:DB8:0::1", "2001:db8::1"),
            (Kind::Txt, "abc", "\"abc\""),
            (Kind::Txt, "\"abc\"", "\"abc\""),
        ] {
            let got = read_content(kind, content);
            assert!(got.is_canonical(), "{kind:?} {content}");
            assert_eq!(got.as_str(), canonical, "{kind:?} {content}");
        }
    }

    #[test]
    fn unparseable_content_is_non_canonical() {
        for (kind, content) in [
            (Kind::A, "not an address"),
            (Kind::A, "192.0.2.01"),
            (Kind::Aaaa, "192.0.2.1"),
            (Kind::Txt, "\"open"),
        ] {
            let got = read_content(kind, content);
            assert!(!got.is_canonical(), "{kind:?} {content}");
            assert_eq!(got.as_str(), content, "{kind:?}");
        }
    }

    #[test]
    fn each_type_writes_the_documented_field_value() {
        for (rtype, text, kind, expected) in [
            (RecordType::A, "192.0.2.1", Kind::A, "192.0.2.1"),
            (RecordType::AAAA, "2001:db8::1", Kind::Aaaa, "2001:db8::1"),
            (RecordType::TXT, "\"abc123\"", Kind::Txt, "abc123"),
        ] {
            let (got_kind, got) = encode(rtype, &data(rtype, text)).unwrap();
            assert_eq!((got_kind, got.as_str()), (kind, expected), "{rtype}");
            // Read back from the same text, the value is the same.
            assert_eq!(read_content(kind, &got), data(rtype, text), "{rtype}");
        }
    }

    #[test]
    fn values_without_an_established_encoding_are_not_sent() {
        for (rtype, text) in [
            (RecordType::TXT, "\"two words\""),
            (RecordType::TXT, "\"quo\\\"te\""),
            (RecordType::TXT, "\"\""),
            (RecordType::MX, "10 mail.example.org."),
            (RecordType::CNAME, "target.example.net."),
            (RecordType::CAA, "0 issue \"ca.example.net\""),
            (RecordType::SRV, "1 5 5060 sip.example.org."),
        ] {
            assert!(
                encode(rtype, &data(rtype, text)).is_none(),
                "{rtype} {text}"
            );
        }
        assert!(encode(RecordType::A, &RecordData::non_canonical("x")).is_none());
    }

    #[test]
    fn listing_treatment_per_type() {
        assert_eq!(listed("A"), Listed::Read(Kind::A));
        assert_eq!(listed("AAAA"), Listed::Read(Kind::Aaaa));
        assert_eq!(listed("TXT"), Listed::Read(Kind::Txt));
        for t in ["MX", "SRV", "HTTPS", "SVCB"] {
            assert_eq!(listed(t), Listed::Skip, "{t}");
        }
        for t in ["CNAME", "NS", "CAA", "NOT A TYPE"] {
            assert_eq!(listed(t), Listed::Opaque, "{t}");
        }
    }
}
