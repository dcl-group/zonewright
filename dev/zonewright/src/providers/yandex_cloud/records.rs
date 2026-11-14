//! Record-level operations: the `WholeSet` shape of the record layer (`crate::rrsets`) over the
//! record set primitives of `rrset.rs`, the listing of a zone, and the mapping between the API's
//! `data` elements and `RecordData`.
//!
//! The native unit is the record set, addressed by name and type, and every change goes through
//! the strict `updateRecordSets`: a write over an existing set carries that set, exactly as read,
//! in `deletions` and the new set in `additions`; a write of a new set carries only the
//! addition, which the API refuses when a set of that name and type exists; a delete carries only
//! the deletion. "Returns error when: Deleted record is not found; Found record with matched
//! type and name but different TTL, value, or description; Attempted to add record with existing
//! name and type"
//! (<https://yandex.cloud/en/docs/dns/api-ref/DnsZone/updateRecordSets>). So the provider
//! checks, in the request that writes, that the set is still the one the client read, whatever
//! the caller's `Expect`: `Preconditions::Atomic`. The record layer evaluates `Expect` against
//! the read and, after `Error::Conflict` (a refusal that a new read explains by a changed set,
//! `rrset.rs`), runs the operation once more from the read.
//!
//! - `Expect::Absent`: the layer refuses an existing set after the read; a set created between
//!   the read and the write makes the addition-only write fail, and the re-run then finds the set
//!   and ends in `PreconditionFailed`.
//! - `Expect::Any`: read, then the strict write conditional on what was read, repeated once on a
//!   conflict. `upsertRecordSets` is not used: it is documented as "Method without strict
//!   control" whose `replacements` "Entirely replace specified record sets"
//!   (<https://yandex.cloud/en/docs/dns/api-ref/DnsZone/upsertRecordSets>); design section 3.4
//!   requires the conditional write for every write at an atomic provider, and the TXT value
//!   operations, which share the record sets, rely on it.
//!
//! # Data per type
//!
//! The API reference describes `data` only as "Data of the record set", 1 to 100 elements of 1 to
//! 1024 characters (`RecordSet`, [listRecordSets]). The text form of each type is given by the
//! Cloud DNS page on resource records ([record types], read 2026-11-14), which says that the
//! service uses the master file format (a `;` outside double quotes starts a comment) and gives
//! a description and examples for each type:
//!
//! | Type        | Form and examples on the record types page                                       |
//! | ----------- | -------------------------------------------------------------------------------- |
//! | A           | an IPv4 address: `192.0.2.1`                                                     |
//! | AAAA        | an IPv6 address: `2001:db8::1`                                                   |
//! | CNAME       | an FQDN with the trailing dot: `host.example.com.`                               |
//! | ANAME       | like CNAME, may coexist with other types: `example.com.website.yandexcloud.net`  |
//! | MX          | preference and exchange: `10 mx-primary.example.com.`                            |
//! | NS          | a name server: `ns1.example.com.`                                                |
//! | PTR         | a name: `host1.example.com.`                                                     |
//! | SRV         | priority, weight, port, target: `10 70 8080 host.example.com.`                   |
//! | CAA         | flag, tag, value in double quotes: `0 issue "ca.example.net"`                    |
//! | SVCB, HTTPS | priority, target, parameters: `1 . alpn=h3,h3-29,h2 ipv4hint=10.0.0.1`           |
//! | TXT         | text; spaces separate strings, so a value with spaces is quoted: `"v=spf1 … -all"` |
//! | SOA         | created automatically: `ns1.yandexcloud.net. mx.cloud.yandex.net. 1 10800 …`      |
//!
//! These are the presentation formats of the types (RFC 1035 section 5), which is what the
//! canonical text of design section 4.3 is. The page states the format of the whole: "The
//! service uses MASTER FILES format." In that format (RFC 1035 section 5.1) a domain name
//! without the trailing dot is relative to the origin, here the zone, and spaces separate
//! character-strings. A value is therefore read with `RecordData::from_provider` with the zone as
//! the origin (`www` inside a CNAME is `www.<zone>.`, never the absolute `www.`), and TXT with the
//! `Auto` rule except that unquoted text with whitespace is read as presentation format, several
//! strings (the page: "The space character serves as a separator. If an input string has spaces,
//! it will be perceived as multiple strings."). Unquoted text without whitespace, which is what
//! the TXT value operations write, reads back as itself. A value is written as its canonical
//! text, names absolute with the trailing dot, with these limits, each checked by
//! [`write_content`]:
//!
//! - Escapes. No source says how the API treats a backslash escape. A value whose canonical text
//!   needs one (a TXT or CAA value with `"`, `\` or a byte outside printable ASCII; a name with
//!   such a label) is not sent; the page also says "Only ASCII characters are supported".
//!   Printable ASCII TXT without `"` and `\`, spaces included, is sent as quoted 255-octet chunks
//!   ("Chunks longer than 255 characters are split automatically", same page; design section
//!   11.2).
//! - Length. A data element is at most 1024 characters ([listRecordSets]; the page: "TXT records
//!   have a maximum length of 1024 characters"), counted on the text sent.
//! - CAA. Only the tags the page lists: `issue`, `issuewild`, `iodef`, `contactemail`,
//!   `contactphone`.
//! - SVCB and HTTPS. Only the parameters the page names with the spelling of RFC 9460:
//!   `mandatory`, `alpn`, `no-default-alpn`, `port`, `ipv4hint`, `ipv6hint`. The page writes
//!   `alpn` unquoted (`alpn=h3,h3-29,h2`), and so does the client, for identifiers of letters,
//!   digits, `-`, `.`, `_` and `/` only; other identifiers would need the quoted or escaped form,
//!   which the page does not show. `ech` (the page names an older `echconfig`) and numbered keys
//!   are not sent.
//! - ANAME. The page's example (`example.com.website.yandexcloud.net`) has no trailing dot, which
//!   in the master file format the page names would be relative to the zone; the client writes
//!   the canonical name with the dot, the absolute form the page uses for CNAME, which ANAME
//!   "works like", and reads a dotless name as relative, by the stated format.
//! - SOA is read only (design section 3.4); TLSA is not accepted by the API (it is not on the
//!   page) and is not in `record_types`. A type the API lists that is outside `record_types` is
//!   still listed, canonical where its text parses.
//!
//! Data elements the API returns are read by the same format. A value read this way that the
//! caller asks for again is `Unchanged`, and the provider's text is left as it is; a write keeps
//! every element it does not change verbatim as it was read, and the strict condition protects the
//! set.
//!
//! # Attributes the model does not carry
//!
//! A record set has a `description`. A write over an existing set repeats it, with the set's
//! name and type, in the addition (and the whole object as read in the deletion); a new set gets
//! none. The record set has one TTL; there are no per-record attributes and no disabled records.
//!
//! [listRecordSets]: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/listRecordSets
//! [record types]: https://yandex.cloud/en/docs/dns/concepts/resource-record

use serde_json::{Map, Value};

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::provider::ZoneListing;
use crate::record::{Caa, RecordData, RecordType, SvcParam, Svcb, Ttl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::rrsets::{self, Current, Found, Listing, Member, RrsetBase, SetTtl, Stored, WholeSet};

use super::client::YandexCloud;
use super::rrset::{RecordSet, data_of, relative, ttl_of};
use super::txt::MAX_DATA;

/// How TXT data is read at record level: quoted text as presentation format, other text as the
/// value (design section 11.2), except unquoted text with whitespace (see [`unquoted_strings`]).
const TXT_READ: TxtDialect = TxtDialect::Auto;

/// Unquoted TXT text with whitespace: several character-strings separated by the whitespace,
/// whose value is their concatenation (the canonical TXT value joins its strings, design section
/// 4.3). `None` for text this rule does not cover: quoted text, text without whitespace, and
/// text with a character the master file format gives a meaning (`"`, `\`, `;`, `(`, `)`),
/// which then stays non-canonical.
// Source: https://yandex.cloud/en/docs/dns/concepts/resource-record, TXT ("The service uses
// MASTER FILES format", "The space character serves as a separator. If an input string has
// spaces, it will be perceived as multiple strings."), read 2026-11-14.
fn unquoted_strings(content: &str) -> Option<RecordData> {
    let text = content.trim();
    if text.starts_with('"') || !text.contains(|c: char| c.is_ascii_whitespace()) {
        return None;
    }
    if text.contains(['"', '\\', ';', '(', ')']) {
        return Some(RecordData::non_canonical(text));
    }
    let joined: String = text.split_ascii_whitespace().collect();
    Some(
        Txt::new(joined)
            .and_then(|value| value.to_data())
            .unwrap_or_else(|_| RecordData::non_canonical(text)),
    )
}

/// Longest data element.
// Source: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/listRecordSets (`data[]`: "The
// maximum string length in characters for each value is 1024").
const MAX_ELEMENT: usize = 1024;

/// CAA tags the record types page lists.
// Source: https://yandex.cloud/en/docs/dns/concepts/resource-record, CAA.
const CAA_TAGS: &[&str] = &[
    "issue",
    "issuewild",
    "iodef",
    "contactemail",
    "contactphone",
];

/// A value as the API returned it, in the master file format with `zone` as the origin (see the
/// module documentation).
// Source: https://yandex.cloud/en/docs/dns/concepts/resource-record ("The service uses MASTER
// FILES format"), read 2026-11-14; RFC 1035 section 5.1 (relative names and the origin).
pub(super) fn read_content(zone: &DomainName, rtype: RecordType, content: &str) -> RecordData {
    if rtype == RecordType::TXT
        && let Some(data) = unquoted_strings(content)
    {
        return data;
    }
    RecordData::from_provider(rtype, content, Some(zone), TXT_READ)
}

/// The API's text for a value, or `None` when the client cannot send it (see the module
/// documentation).
pub(super) fn write_content(rtype: RecordType, data: &RecordData) -> Option<String> {
    if !data.is_canonical() || data.as_str().contains('\\') {
        return None;
    }
    let text = match rtype {
        RecordType::A
        | RecordType::AAAA
        | RecordType::CNAME
        | RecordType::ANAME
        | RecordType::MX
        | RecordType::NS
        | RecordType::PTR
        | RecordType::SRV
        | RecordType::TXT => Some(data.as_str().to_owned()),
        RecordType::CAA => caa_content(data),
        RecordType::SVCB | RecordType::HTTPS => svcb_content(data),
        _ => None,
    }?;
    (text.chars().count() <= MAX_ELEMENT).then_some(text)
}

/// CAA: the canonical text, for a tag the record types page lists.
// Source: https://yandex.cloud/en/docs/dns/concepts/resource-record, CAA ("128 issue
// \"ca.example.net\"", the tags issue, issuewild, iodef, contactemail, contactphone).
fn caa_content(data: &RecordData) -> Option<String> {
    let caa = Caa::from_data(data).ok()?;
    CAA_TAGS
        .contains(&caa.tag.as_str())
        .then(|| data.as_str().to_owned())
}

/// SVCB and HTTPS: the canonical text with `alpn` unquoted, for the parameters the record types
/// page names.
// Source: https://yandex.cloud/en/docs/dns/concepts/resource-record, SVCB and HTTPS ("1
// svc1.example.net. ipv6hint=2001:db8::1 port=1234", "1 . alpn=h3,h3-29,h2 ipv4hint=10.0.0.1
// ipv6hint=::1"; parameters port, alpn, no-default-alpn, ipv4hint, ipv6hint, mandatory).
fn svcb_content(data: &RecordData) -> Option<String> {
    /// Keys of the named parameters, for `mandatory` (RFC 9460 section 14.3.2).
    const NAMED: &[u16] = &[1, 2, 3, 4, 6];
    let svcb = Svcb::from_data(data).ok()?;
    for param in &svcb.params {
        let sendable = match param {
            SvcParam::Mandatory(keys) => keys.iter().all(|key| NAMED.contains(key)),
            SvcParam::Alpn(ids) => ids.iter().all(|id| {
                !id.is_empty()
                    && id.iter().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'/')
                    })
            }),
            SvcParam::NoDefaultAlpn
            | SvcParam::Port(_)
            | SvcParam::Ipv4Hint(_)
            | SvcParam::Ipv6Hint(_) => true,
            _ => false,
        };
        if !sendable {
            return None;
        }
    }
    let text = data.as_str();
    // Canonical text writes `alpn="id1,id2"`; the identifiers hold no quote (checked above).
    match text.find("alpn=\"") {
        None => Some(text.to_owned()),
        Some(start) => {
            let (head, rest) = text.split_at(start);
            let quoted = rest.get("alpn=\"".len()..)?;
            let end = quoted.find('"')?;
            let ids = quoted.get(..end)?;
            let tail = quoted.get(end + 1..)?;
            Some(format!("{head}alpn={ids}{tail}"))
        }
    }
}

impl RrsetBase for YandexCloud {
    fn provider(&self) -> ProviderId {
        ProviderId::YandexCloud
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }

    fn max_records(&self) -> Option<usize> {
        Some(MAX_DATA)
    }

    fn can_send(&self, rtype: RecordType, data: &RecordData) -> bool {
        write_content(rtype, data).is_some()
    }
}

/// The record layer's view of a record set the API returned.
fn found(
    zone: &DomainName,
    rtype: RecordType,
    set: Value,
) -> Result<Found<String, RecordSet>, Error> {
    let records = data_of(&set)?
        .into_iter()
        .map(|text| Stored {
            data: read_content(zone, rtype, text),
            enabled: true,
            ttl: None,
            handle: text.to_owned(),
        })
        .collect();
    Ok(Found {
        records,
        ttl: ttl_of(&set).and_then(|secs| Ttl::from_secs(secs).ok()),
        snapshot: RecordSet(set),
    })
}

impl WholeSet for YandexCloud {
    /// The data element as the API returned it.
    type Handle = String;
    type Snapshot = RecordSet;
    /// The zone identifier the read used.
    type Context = String;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Current<String, RecordSet, String>, Error> {
        let (zone_id, set) = self.read_set(zone, name, &rtype.to_string()).await?;
        Ok(Current {
            context: zone_id,
            found: set.map(|set| found(zone, rtype, set)).transpose()?,
        })
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        zone_id: &String,
        prior: Option<&RecordSet>,
        members: &[Member<'_, String>],
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let type_name = rtype.to_string();
        let data =
            members
                .iter()
                .map(|member| match member {
                    Member::Kept(record) | Member::Enabled(record) => {
                        Ok(Value::String(record.handle.clone()))
                    }
                    Member::Added(data) => write_content(rtype, data).map(Value::String).ok_or(
                        Error::InvalidInput {
                            detail: Detail::constant(
                                "the provider's encoding of this record data is not established",
                            ),
                        },
                    ),
                })
                .collect::<Result<Vec<Value>, Error>>()?;
        let (deletions, addition) = match prior {
            None => {
                let ttl = match ttl {
                    SetTtl::Requested(ttl) | SetTtl::Existing(Some(ttl)) => ttl.as_secs(),
                    SetTtl::Existing(None) | SetTtl::Default => self.ttl,
                };
                let mut set = Map::new();
                set.insert(
                    "name".into(),
                    Value::String(relative(zone, name)?.to_owned()),
                );
                set.insert("type".into(), Value::String(type_name.clone()));
                set.insert("ttl".into(), Value::String(ttl.to_string()));
                set.insert("data".into(), Value::Array(data));
                (Vec::new(), Value::Object(set))
            }
            Some(prior) => (vec![prior.0.clone()], replaced(prior, data, ttl)),
        };
        let written = self
            .api
            .update_record_sets(zone_id, &deletions, &[addition])
            .await?;
        self.settle(zone, name, &type_name, zone_id, prior, written, false)
            .await
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        zone_id: &String,
        prior: &RecordSet,
    ) -> Result<(), Error> {
        let written = self
            .api
            .update_record_sets(zone_id, std::slice::from_ref(&prior.0), &[])
            .await?;
        self.settle(
            zone,
            name,
            &rtype.to_string(),
            zone_id,
            Some(prior),
            written,
            true,
        )
        .await
    }
}

/// The record set that replaces `prior`: its name, type, TTL and description as read, with
/// `data`; the TTL replaced only when the caller asked for one (design section 3.6). The TTL is
/// sent as a string (an int64 in proto3 JSON).
// Source: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/updateRecordSets (`RecordSet`:
// `name`, `type`, `ttl`, `data[]`, `description`).
fn replaced(prior: &RecordSet, data: Vec<Value>, ttl: SetTtl) -> Value {
    let mut set = Map::new();
    for key in ["name", "type", "ttl", "description"] {
        if let Some(value) = prior.0.get(key) {
            set.insert(key.to_owned(), value.clone());
        }
    }
    if let SetTtl::Requested(ttl) = ttl {
        set.insert("ttl".into(), Value::String(ttl.as_secs().to_string()));
    }
    set.insert("data".into(), Value::Array(data));
    Value::Object(set)
}

/// The owner name of a listed record set. A name with the trailing dot is absolute, `@` is the
/// apex, and any other text is relative to the zone, as the API takes names (`rrset.rs`).
/// Text without the trailing dot that ends with the zone's own name could be either an absolute
/// name or a relative one, and is not interpreted: `None`, which the listing reports as skipped.
// Source: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/listRecordSets (`name`: "Domain
// name"; the filter example `name="works.on.my.machine."` spells a name absolute with the
// dot); lego yandexcloud.go:136 (names relative to the zone).
pub(super) fn owner_name(zone: &DomainName, text: &str) -> Option<DomainName> {
    if text.ends_with('.') {
        return DomainName::parse(text).ok();
    }
    if text == "@" {
        return Some(zone.clone());
    }
    let lower = text.to_ascii_lowercase();
    let suffix = zone.without_dot().to_ascii_lowercase();
    if lower == suffix || lower.ends_with(&format!(".{suffix}")) {
        return None;
    }
    DomainName::from_relative(text, zone).ok()
}

impl YandexCloud {
    /// `list_rrsets`: every record set of the zone, all pages, under the zone-ID cache.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let (_, sets) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| async move {
                    Ok(match self.api.record_sets(&id.id).await? {
                        Some(sets) => crate::http::Attempt::Done(sets),
                        None => crate::http::Attempt::Stale,
                    })
                },
            )
            .await?;
        let shape = || Error::Protocol {
            detail: Detail::constant(
                "the provider's record set listing is not in the expected form",
            ),
        };
        let mut listing = Listing::new(zone);
        for set in &sets {
            let name = set.get("name").and_then(Value::as_str).ok_or_else(shape)?;
            let type_name = set.get("type").and_then(Value::as_str).ok_or_else(shape)?;
            let ttl = ttl_of(set).and_then(|secs| Ttl::from_secs(secs).ok());
            let data = data_of(set)?;
            // A type name that maps to no record type is skipped by the listing, whatever the
            // data hold; the data are then never parsed.
            let records = match type_name.parse::<RecordType>() {
                Ok(rtype) => data
                    .iter()
                    .map(|text| read_content(zone, rtype, text))
                    .collect(),
                Err(_) => data
                    .iter()
                    .map(|text| RecordData::non_canonical(text))
                    .collect(),
            };
            listing.push(owner_name(zone, name), type_name, ttl, records);
        }
        listing.finish(ProviderId::YandexCloud)
    }
}

#[cfg(test)]
mod tests {
    use super::{owner_name, write_content};
    use crate::name::DomainName;
    use crate::record::{RecordData, RecordType};

    fn dn(name: &str) -> DomainName {
        DomainName::parse(name).unwrap()
    }

    #[test]
    fn owner_names_are_read_absolute_relative_or_not_at_all() {
        let zone = dn("example.org");
        for (text, expected) in [
            ("www.example.org.", Some("www.example.org.")),
            ("example.org.", Some("example.org.")),
            ("@", Some("example.org.")),
            ("www", Some("www.example.org.")),
            ("*.www", Some("*.www.example.org.")),
            ("www.example.org", None),
            ("Example.ORG", None),
            ("example.net.", Some("example.net.")),
            ("bad..name", None),
        ] {
            assert_eq!(owner_name(&zone, text), expected.map(dn), "{text}");
        }
    }

    #[test]
    fn content_is_written_in_the_documented_form() {
        let send = |rtype: RecordType, text: &str| {
            write_content(rtype, &RecordData::parse(rtype, text).unwrap())
        };
        assert_eq!(
            send(RecordType::HTTPS, "1 . alpn=h3,h3-29,h2 ipv4hint=10.0.0.1").as_deref(),
            Some("1 . alpn=h3,h3-29,h2 ipv4hint=10.0.0.1")
        );
        assert_eq!(
            send(
                RecordType::SVCB,
                "1 svc1.example.net. ipv6hint=2001:db8::1 port=1234"
            )
            .as_deref(),
            Some("1 svc1.example.net. port=1234 ipv6hint=2001:db8::1")
        );
        assert_eq!(
            send(
                RecordType::SVCB,
                "1 . mandatory=alpn alpn=h2 no-default-alpn"
            )
            .as_deref(),
            Some("1 . mandatory=alpn alpn=h2 no-default-alpn")
        );
        assert_eq!(send(RecordType::HTTPS, "1 . ech=AAAA"), None);
        assert_eq!(send(RecordType::HTTPS, "1 . key999=x"), None);
        assert_eq!(send(RecordType::HTTPS, "1 . alpn=\"a b\""), None);
        assert_eq!(
            send(RecordType::CAA, "0 issue \"ca.example.net\"").as_deref(),
            Some("0 issue \"ca.example.net\"")
        );
        assert_eq!(
            send(RecordType::CAA, "0 issuemail \"ca.example.net\""),
            None
        );
        assert_eq!(send(RecordType::TXT, "\"say \\\"hi\\\"\""), None);
        assert_eq!(send(RecordType::SOA, "a. b. 1 2 3 4 5"), None);
        assert_eq!(send(RecordType::TLSA, "3 1 1 0a1b"), None);
        let long = format!("\"{}\"", "a".repeat(1100));
        assert_eq!(send(RecordType::TXT, &long), None);
        let fits = format!("\"{}\"", "a".repeat(1000));
        assert!(send(RecordType::TXT, &fits).is_some());
        assert_eq!(
            send(RecordType::ANAME, "Target.Example.net").as_deref(),
            Some("target.example.net.")
        );
    }
}
