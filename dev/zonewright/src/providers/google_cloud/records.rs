//! Record-level operations: the `WholeSet` shape of the record layer (`crate::rrsets`) over the
//! rrset primitives of `rrset.rs`, the listing of a zone, and the mapping between the API's
//! `rrdatas` and `RecordData`.
//!
//! The native unit is the rrset, addressed by name and type, and every write is one
//! `changes.create`: a write over an existing rrset carries it, exactly as read, in `deletions`
//! and the new rrset in `additions`; a write of a new rrset carries only the addition, which the
//! API refuses when an rrset of that name and type exists; a delete carries only the deletion.
//! "A Change represents a set of ResourceRecordSet additions and deletions applied atomically to
//! a ManagedZone"; `deletions`: "Must match existing data exactly"
//! (<https://www.googleapis.com/discovery/v1/apis/dns/v1/rest>, `Change`). So the provider
//! checks, in the request that writes, that the rrset is still the one the client read, whatever
//! the caller's `Expect`: `Preconditions::Atomic`. The record layer evaluates `Expect` against
//! the read and, after `Error::Conflict` (a refusal that a new read explains by a changed rrset,
//! `rrset.rs`), runs the operation once more from the read. `resourceRecordSets.patch` and
//! `create` are not used: they carry no condition, and the documentation of `patch` disagrees
//! with the discovery document on its update mask.
//!
//! # Data per type
//!
//! `rrdatas` are "As defined in RFC 1035 (section 5) and RFC 1034 (section 3.6.1)" (discovery
//! document, `ResourceRecordSet.rrdatas`): the presentation format, which is what the canonical
//! text of design section 4.3 is. `record_types` holds the types of the supported record types
//! page (<https://docs.cloud.google.com/dns/docs/records-overview>) whose data form a source shows
//! for this API: A and AAAA (addresses), CNAME and NS (a name with the trailing dot), MX ("The MX
//! record you enter must end with a dot"), SRV, CAA, TLSA and TXT, each in the form dns-update
//! writes (`src/providers/google_cloud_dns.rs`, `rrdata_for_record`), and SOA, read only (created
//! with the zone; "These records can't be deleted by using the Cloud DNS API", records page). The
//! page also lists ALIAS, DNSKEY, DS, HTTPS, IPSECKEY, NAPTR, PTR, SPF, SSHFP and SVCB; no source
//! shows their data for this API, so they are listed by `list_rrsets` (canonical where the text
//! parses) and cannot be read alone or written.
//!
//! Names inside values carry the trailing dot. A value whose name lacks it (one that reads
//! differently relative to the zone than absolute), and `@`, are non-canonical data (design
//! section 4.9): in the master-file format the rrdatas follow, a dotless name is relative to an
//! origin the API does not state.
//!
//! TXT is read by [`read_txt`], the rule the TXT value operations read by too.
//!
//! A value is written as its canonical text, with these limits, each checked by
//! [`write_content`]:
//!
//! - Escapes. RFC 1035 section 5.1 defines `\X` and `\DDD`, but no source shows how this API
//!   stores or returns an escaped value. A value whose canonical text needs a backslash (a TXT or
//!   CAA value with `"`, `\` or a byte outside printable ASCII; a name with such a label) is not
//!   sent: an assumption, conservative.
//! - Length. "Each TXT record has a 1000-character limit" (records-overview page); the client
//!   counts it on the text sent, quotes included, which is the stricter reading (an assumption).
//!
//! A canonical value read from the API that the caller asks for again is `Unchanged`, and the
//! provider's text is left as it is; a write keeps every element it does not change verbatim as
//! it was read, and the exact match of the deletion protects the rrset.

use serde_json::Value;

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::provider::{SkipReason, ZoneListing};
use crate::record::{RecordData, RecordType, RrsetTtl, Txt};
use crate::redact::Detail;
use crate::rrsets::{self, Current, Found, Listing, Member, RrsetBase, SetTtl, Stored, WholeSet};

use super::client::GoogleCloud;
use super::rrset::{
    Snapshot, is_plain, new_rrset, owner_of, replaced, rrdatas_of, ttl_of, type_of,
};

/// Longest TXT rrdata, counted on the text sent.
// Source: https://docs.cloud.google.com/dns/docs/records-overview ("Each TXT record has a
// 1000-character limit").
const MAX_TXT: usize = 1000;

/// The value of TXT data, the one rule both levels read TXT by: the record level here
/// ([`read_content`]) and the TXT value operations (`txt.rs`). The rrdata is read by the strict
/// presentation parser (design section 4.4): one or more quoted character-strings joined, or one
/// unquoted character-string, as RFC 1035 section 5.1 defines them. Anything else is `None`:
/// unterminated quotes, several unquoted strings; the record level reports it as non-canonical
/// data and the value operations never take it for a value of theirs.
// Source: discovery document, `ResourceRecordSet.rrdatas` ("As defined in RFC 1035 (section
// 5)"); records-overview page (a long value is divided "into 255-byte strings" and each string
// enclosed "in quotation marks"). lego writes the ACME value unquoted and unquotes what it reads
// (googlecloud.go:232 and 466-473), so both forms are read.
pub(super) fn read_txt(text: &str) -> Option<Txt> {
    RecordData::parse(RecordType::TXT, text)
        .ok()
        .and_then(|data| Txt::from_data(&data).ok())
}

/// A value as the API returned it, held to the documented form (module documentation).
pub(super) fn read_content(zone: &DomainName, rtype: RecordType, text: &str) -> RecordData {
    if rtype == RecordType::TXT {
        return read_txt(text)
            .and_then(|value| value.to_data().ok())
            .unwrap_or_else(|| RecordData::non_canonical(text));
    }
    let Ok(absolute) = RecordData::parse(rtype, text) else {
        return RecordData::non_canonical(text);
    };
    // A dotless name (or `@`) is the only text the two readings take differently.
    if RecordData::parse_relative(rtype, text, zone).ok().as_ref() != Some(&absolute) {
        return RecordData::non_canonical(text);
    }
    absolute
}

/// The API's text for a value of `rtype`, or `None` when the client does not send it:
/// non-canonical data, canonical text with a backslash escape, and TXT text longer than 1000
/// characters (module documentation). The one writing rule of both levels.
pub(super) fn write_content(rtype: RecordType, data: &RecordData) -> Option<String> {
    let text = data.as_str();
    let sendable = data.is_canonical()
        && !text.contains('\\')
        && (rtype != RecordType::TXT || text.chars().count() <= MAX_TXT);
    sendable.then(|| text.to_owned())
}

impl RrsetBase for GoogleCloud {
    fn provider(&self) -> ProviderId {
        ProviderId::GoogleCloud
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }

    fn can_send(&self, rtype: RecordType, data: &RecordData) -> bool {
        write_content(rtype, data).is_some()
    }
}

/// The record layer's view of a plain rrset the API returned.
fn found(
    zone: &DomainName,
    rtype: RecordType,
    set: Value,
) -> Result<Found<String, Snapshot>, Error> {
    let records = rrdatas_of(&set)?
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
        ttl: ttl_of(&set).and_then(|secs| RrsetTtl::from_secs(secs).ok()),
        snapshot: Snapshot(set),
    })
}

impl WholeSet for GoogleCloud {
    /// The rrdata as the API returned it.
    type Handle = String;
    type Snapshot = Snapshot;
    /// The managed zone identifier the read used.
    type Context = String;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Current<String, Snapshot, String>, Error> {
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
        prior: Option<&Snapshot>,
        members: &[Member<'_, String>],
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let type_name = rtype.to_string();
        let rrdatas =
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
                            code: None,
                        },
                    ),
                })
                .collect::<Result<Vec<Value>, Error>>()?;
        let (deletions, addition) = match prior {
            None => {
                let ttl = match ttl {
                    SetTtl::Requested(RrsetTtl::Explicit(ttl))
                    | SetTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => ttl.as_secs(),
                    // No default TTL of its own: the layer never passes it, and the setting
                    // stands in.
                    SetTtl::Existing(None | Some(RrsetTtl::ProviderDefault))
                    | SetTtl::Default
                    | SetTtl::Requested(RrsetTtl::ProviderDefault) => self.ttl,
                };
                (Vec::new(), new_rrset(name, &type_name, ttl, rrdatas))
            }
            Some(prior) => {
                // An existing rrset keeps its TTL as read unless the caller asked for one (design
                // section 3.6); one read without a TTL gets the setting, the only number the
                // client has.
                let ttl = match ttl {
                    SetTtl::Requested(RrsetTtl::Explicit(ttl)) => Some(ttl.as_secs()),
                    _ if ttl_of(&prior.0).is_none() => Some(self.ttl),
                    _ => None,
                };
                (vec![prior.0.clone()], replaced(prior, rrdatas, ttl))
            }
        };
        let written = self
            .api
            .change(zone_id, &deletions, std::slice::from_ref(&addition))
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
        prior: &Snapshot,
    ) -> Result<(), Error> {
        let written = self
            .api
            .change(zone_id, std::slice::from_ref(&prior.0), &[])
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

impl GoogleCloud {
    /// `list_rrsets`: every rrset of the zone, all pages, under the zone-ID cache.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let (_, sets) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| async move {
                    Ok(match self.api.rrsets(&id.id, None).await? {
                        Some(sets) => crate::http::Attempt::Done(sets),
                        None => crate::http::Attempt::Stale,
                    })
                },
            )
            .await?;
        let shape = || Error::Protocol {
            detail: Detail::constant("the provider's rrset listing is not in the expected form"),
        };
        let mut listing = Listing::new(zone);
        for set in &sets {
            let type_name = type_of(set).ok_or_else(shape)?;
            let owner = owner_of(set);
            if !is_plain(set) {
                match owner {
                    Some(owner) if owner.is_within(zone) => {
                        listing.skip(owner, type_name, SkipReason::NotPlainRecords);
                    }
                    _ => listing.skip(zone.clone(), type_name, SkipReason::UnsupportedName),
                }
                continue;
            }
            let ttl = ttl_of(set).and_then(|secs| RrsetTtl::from_secs(secs).ok());
            let rrdatas = rrdatas_of(set)?;
            // A type name that maps to no record type is skipped by the listing, whatever the
            // data hold; the data are then never parsed.
            let records = match type_name.parse::<RecordType>() {
                Ok(rtype) => rrdatas
                    .iter()
                    .map(|text| read_content(zone, rtype, text))
                    .collect(),
                Err(_) => rrdatas
                    .iter()
                    .map(|text| RecordData::non_canonical(text))
                    .collect(),
            };
            listing.push(owner, type_name, ttl, records);
        }
        listing.finish(ProviderId::GoogleCloud)
    }
}

#[cfg(test)]
mod tests {
    use super::{read_content, read_txt, write_content};
    use crate::name::DomainName;
    use crate::record::{RecordData, RecordType, Txt};

    fn zone() -> DomainName {
        DomainName::parse("example.org").unwrap()
    }

    #[test]
    fn content_is_read_in_the_documented_form() {
        let mx = read_content(&zone(), RecordType::MX, "10 mail.example.net.");
        assert!(mx.is_canonical());
        assert_eq!(mx.as_str(), "10 mail.example.net.");
        assert!(!read_content(&zone(), RecordType::MX, "10 mail").is_canonical());
        assert!(!read_content(&zone(), RecordType::CNAME, "@").is_canonical());
        assert!(!read_content(&zone(), RecordType::A, "not-an-address").is_canonical());
        let txt = read_content(&zone(), RecordType::TXT, "\"v=spf1 \" \"-all\"");
        assert_eq!(txt, Txt::new("v=spf1 -all").unwrap().to_data().unwrap());
        assert_eq!(read_txt("token").unwrap().as_bytes(), b"token");
        assert_eq!(read_txt("\"token\"").unwrap().as_bytes(), b"token");
        assert_eq!(read_txt("two words"), None);
        assert_eq!(read_txt("\"open"), None);
    }

    #[test]
    fn content_is_written_without_escapes_and_within_the_limit() {
        let send = |rtype: RecordType, text: &str| {
            write_content(rtype, &RecordData::parse(rtype, text).unwrap())
        };
        assert_eq!(
            send(RecordType::CAA, "0 issue \"ca.example.net\"").as_deref(),
            Some("0 issue \"ca.example.net\"")
        );
        assert_eq!(send(RecordType::CAA, "0 issue \"a\\\\b\""), None);
        assert_eq!(send(RecordType::TXT, "\"say \\\"hi\\\"\""), None);
        assert_eq!(
            send(RecordType::TXT, "\"v=spf1 -all\"").as_deref(),
            Some("\"v=spf1 -all\"")
        );
        let fits = Txt::new("a".repeat(980)).unwrap().to_data().unwrap();
        assert!(write_content(RecordType::TXT, &fits).is_some());
        let long = Txt::new("a".repeat(1000)).unwrap().to_data().unwrap();
        assert_eq!(write_content(RecordType::TXT, &long), None);
        assert_eq!(
            write_content(RecordType::TXT, &RecordData::non_canonical("x")),
            None
        );
    }
}
