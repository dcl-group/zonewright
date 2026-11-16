//! Record-level operations: the `WholeSet` shape of the record layer (`crate::rrsets`) over the
//! rrset primitives of `rrset.rs`, the listing of a zone, and the mapping between the API's
//! `content` text and `RecordData`.
//!
//! The native unit is the rrset, written whole by one create or update without a condition the
//! provider checks, hence `Preconditions::ReadThenWrite` and `atomic_rrset_write`. The record
//! layer does the checks, takes the per-name lock, reads, evaluates the expectation and computes
//! the member list; this file turns members into the API's records and back.
//!
//! # Content per type
//!
//! The OpenAPI document describes `content` only as "the content of the DNS record" (schema
//! `Records`). The per-type form is taken from the provider's own Terraform provider
//! documentation for the `selectel_domains_rrset_v2` resource (`docs/resources/
//! domains_rrset_v2.md` in `github.com/selectel/terraform-provider-selectel`, read at commit
//! `0274bf2`, 2026-09-30; "Terraform docs" below), which gives an example and a template for
//! each type it lists:
//!
//! | Type  | Terraform docs template and example                                   |
//! | ----- | --------------------------------------------------------------------- |
//! | A     | `<ipv4_address>`: `127.0.0.1`                                         |
//! | AAAA  | `<ipv6_address>`: `2400:cb00:2049:1::a29f:1804`                       |
//! | TXT   | `<text>`, "any text wrapped in `\"`": `"hello, world!"`               |
//! | CNAME | `<target>` "with a dot at the end": `origin.com.`                     |
//! | ALIAS | `<target>`: `origin.com.`                                             |
//! | NS    | `<name_server>`: `a.ns.selectel.ru.`                                  |
//! | MX    | `<priority> <host>`: `10 mail.example.org.`                           |
//! | SRV   | `<priority> <weight> <port> <target>`: `10 20 30 example.org.`        |
//! | SSHFP | `<algorithm> <fingerprint_type> <fingerprint>` (hex): `1 1 7491…0b49` |
//! | CAA   | `<flag> <tag> <value>`, value "wrapped in `\"`": `128 issue "…"`      |
//!
//! Every one of these is the type's presentation format (RFC 1035 section 5) with absolute names,
//! which is what the canonical text of design section 4.3 is. So a value is written as its
//! canonical text and read with `RecordData::from_provider`, held to the stated format: names
//! "with a dot at the end" and TXT "wrapped in `\"`". No source says what a name without the
//! trailing dot inside a value, or unquoted TXT text, means (relative to the zone or absolute;
//! one string or several), so such a value is kept as non-canonical data (design section 4.9):
//! it never compares equal to an absolute name or to a quoted value, and a `set_rrset` that asks
//! for one replaces it rather than answering `Unchanged`. Two limits keep the client within what
//! the sources establish:
//!
//! - Escapes. No source says how the API treats a backslash escape (`\"`, `\\`, `\DDD`) in
//!   content. Canonical text needs one for a TXT or CAA value with `"`, `\` or a byte outside
//!   printable ASCII, and for a name with such a label. Such a value is not sent
//!   ([`RrsetBase::can_send`] is false, `Error::InvalidInput`) unless the rrset already holds a
//!   record with that value, which is then written back exactly as the API returned it (design
//!   section 11.2). Printable ASCII without `"` and `\`, spaces included and of any length in
//!   quoted 255-octet chunks, is sent.
//! - Types. DNAME, HTTPS and SVCB are in the API's `AllowedRecordTypes` and in the control
//!   panel's list, but no source gives their content form, so they are not in `record_types`:
//!   they appear in a listing (canonical where their text parses, non-canonical otherwise) and
//!   cannot be read alone or written. SOA is read-only: "created automatically ... cannot be
//!   edited or deleted" (<https://docs.selectel.ru/en/networks-services/dns/records/add-record/>);
//!   its content form is not documented either, which is harmless for a type that is only read:
//!   text the parser refuses is carried as non-canonical data. TLSA is not accepted by the API
//!   (not in `AllowedRecordTypes`).
//!
//! The NS rrset at the apex is created with the zone and "cannot be edited or deleted" (same
//! page; the Terraform docs say NS records can be managed "only for a subdomain"); the record
//! layer refuses writes to it before any request.
//!
//! # Disabled records and attributes the model does not carry
//!
//! A disabled record (`Records.disabled`) is not published (design section 3.4): it is not part
//! of the rrset as read, a write keeps it disabled and in place, a requested value that a
//! disabled record holds enables that record instead of adding a duplicate, and a delete of an
//! rrset that has disabled records writes them back alone instead of deleting the rrset. The
//! rrset's `comment` and `managed_by` travel back unchanged on every update, and `managed_by`
//! also on a delete, which removes a managed rrset like any other (`rrset.rs`). A new rrset gets
//! neither.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::provider::ZoneListing;
use crate::record::{RecordData, RecordType, RrsetTtl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::rrsets::{self, Current, Found, Listing, Member, RrsetBase, SetTtl, Stored, WholeSet};

use super::api::{Record, Rrset};
use super::client::SelectelV2;

/// Most records of one rrset.
// Source: the OpenAPI, `RRSetCreateForm` and `RRSetUpdateForm` (`records`: 1 to 100 items).
pub(super) const MAX_RECORDS: usize = 100;

/// The value of TXT content, the one rule both levels read TXT by: the record level here
/// ([`read_content`]) and the TXT value operations (`txt.rs`). Content "wrapped in `\"`", one
/// quoted string or several separated by whitespace, is read by the strict presentation parser
/// (design section 4.4), several strings joined. Anything else is `None`: unquoted text, text
/// mixing quoted and unquoted parts, an unterminated quote. No source says what such content
/// means (one string or several; joined how), so the record level reports it as non-canonical
/// data and the TXT value operations never take it for a value of theirs: an add puts the value
/// next to it, a remove answers `NotPresent`.
// Source: Terraform docs (module documentation): TXT "Any text wrapped in `\"`"; the OpenAPI
// describes `content` only as "the content of the DNS record". Several quoted strings are what
// the record level writes for a value longer than 255 octets (design section 11.2).
pub(super) fn read_txt(content: &str) -> Option<Txt> {
    if !content.trim_start().starts_with('"') {
        return None;
    }
    TxtDialect::Presentation.read(content)
}

/// A value as the API returned it, held to the documented form (see the module documentation):
/// TXT content by [`read_txt`], and a value with a name that lacks the trailing dot (one that
/// reads differently relative to `zone` than absolute) is non-canonical data.
// Source: Terraform docs (module documentation): CNAME, ALIAS and SRV targets and MX hosts
// "with a dot at the end"; TXT "Any text wrapped in `\"`". Neither the Terraform docs nor
// https://docs.selectel.ru/en/networks-services/dns/records/add-record/ (read 2026-11-14) say
// what a name without the dot or unquoted text means.
pub(super) fn read_content(zone: &DomainName, rtype: RecordType, content: &str) -> RecordData {
    if rtype == RecordType::TXT {
        return read_txt(content)
            .and_then(|value| value.to_data().ok())
            .unwrap_or_else(|| RecordData::non_canonical(content));
    }
    let absolute = RecordData::from_provider(rtype, content, None, TxtDialect::Presentation);
    // A dotless name (or `@`) is the only text the two readings take differently.
    if absolute.is_canonical()
        && RecordData::parse_relative(rtype, content, zone)
            .ok()
            .as_ref()
            != Some(&absolute)
    {
        return RecordData::non_canonical(content);
    }
    absolute
}

/// The API's text for a value, or `None` when the client cannot send it: non-canonical data,
/// and canonical text with a backslash escape (see the module documentation).
pub(super) fn write_content(data: &RecordData) -> Option<String> {
    (data.is_canonical() && !data.as_str().contains('\\')).then(|| data.as_str().to_owned())
}

impl RrsetBase for SelectelV2 {
    fn provider(&self) -> ProviderId {
        ProviderId::SelectelV2
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }

    fn max_records(&self) -> Option<usize> {
        Some(MAX_RECORDS)
    }

    fn can_send(&self, _rtype: RecordType, data: &RecordData) -> bool {
        write_content(data).is_some()
    }
}

/// The record layer's view of an rrset the API returned.
fn found(zone: &DomainName, rtype: RecordType, rrset: Rrset) -> Found<Record, Rrset> {
    let records = rrset
        .records
        .iter()
        .map(|record| Stored {
            data: read_content(zone, rtype, &record.content),
            enabled: !record.disabled,
            ttl: None,
            handle: record.clone(),
        })
        .collect();
    Found {
        records,
        ttl: RrsetTtl::from_secs(rrset.ttl).ok(),
        snapshot: rrset,
    }
}

impl WholeSet for SelectelV2 {
    type Handle = Record;
    type Snapshot = Rrset;
    /// The zone identifier the read used.
    type Context = String;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Current<Record, Rrset, String>, Error> {
        let (zone_id, rrset) = self.read_rrset(zone, name, &rtype.to_string()).await?;
        Ok(Current {
            context: zone_id,
            found: rrset.map(|rrset| found(zone, rtype, rrset)),
        })
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        zone_id: &String,
        prior: Option<&Rrset>,
        members: &[Member<'_, Record>],
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let records = members
            .iter()
            .map(|member| match member {
                Member::Kept(record) => Ok(record.handle.clone()),
                Member::Enabled(record) => Ok(Record {
                    disabled: false,
                    ..record.handle.clone()
                }),
                Member::Added(data) => Ok(Record {
                    content: write_content(data).ok_or(Error::InvalidInput {
                        detail: Detail::constant(
                            "the provider's encoding of this record data is not established",
                        ),
                        code: None,
                    })?,
                    disabled: false,
                }),
            })
            .collect::<Result<Vec<Record>, Error>>()?;
        let ttl = match ttl {
            SetTtl::Requested(RrsetTtl::Explicit(ttl))
            | SetTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => ttl.as_secs(),
            // No default TTL of its own: the layer never passes it, and the setting stands in.
            SetTtl::Existing(None | Some(RrsetTtl::ProviderDefault))
            | SetTtl::Default
            | SetTtl::Requested(RrsetTtl::ProviderDefault) => self.ttl,
        };
        match prior {
            None => {
                self.create_rrset(zone, name, &rtype.to_string(), zone_id, &records, ttl)
                    .await
            }
            Some(prior) => self.update_rrset(zone, zone_id, prior, &records, ttl).await,
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        zone_id: &String,
        prior: &Rrset,
    ) -> Result<(), Error> {
        self.delete_rrset_checked(zone, name, &rtype.to_string(), zone_id, prior)
            .await
    }
}

impl SelectelV2 {
    /// `list_rrsets`: every rrset of the zone, all pages, under the zone-ID cache.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let (_, all) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| async move {
                    match self.api.all_rrsets(zone, &id.id).await {
                        Ok(all) => Ok(crate::http::Attempt::Done(all)),
                        Err(Error::ZoneNotFound { .. }) => Ok(crate::http::Attempt::Stale),
                        Err(e) => Err(e),
                    }
                },
            )
            .await?;
        let mut listing = Listing::new(zone);
        for rrset in all {
            let name = DomainName::parse(&rrset.name).ok();
            let ttl = RrsetTtl::from_secs(rrset.ttl).ok();
            let enabled: Vec<&str> = rrset
                .records
                .iter()
                .filter(|record| !record.disabled)
                .map(|record| record.content.as_str())
                .collect();
            // A type name that maps to no record type is skipped by the listing, whatever the
            // records hold; the content is then never parsed.
            let records = match rrset.rtype.parse::<RecordType>() {
                Ok(rtype) => enabled
                    .iter()
                    .map(|content| read_content(zone, rtype, content))
                    .collect(),
                Err(_) => enabled
                    .iter()
                    .map(|content| RecordData::non_canonical(content))
                    .collect(),
            };
            listing.push(name, &rrset.rtype, ttl, records);
        }
        listing.finish(ProviderId::SelectelV2)
    }
}
