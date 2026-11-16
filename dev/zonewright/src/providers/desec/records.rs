//! Record-level operations: the `WholeSet` shape of the record layer (`crate::rrsets`) over the
//! rrset primitives of `rrset.rs`, the listing of a zone, and the mapping between the API's
//! record content and `RecordData`.
//!
//! The native unit is the rrset, created by `POST` and replaced whole by `PATCH`, one request
//! each, without a condition the provider checks (the documentation mentions no ETag, If-Match or
//! version), hence `Preconditions::ReadThenWrite` and `atomic_rrset_write`. The record layer does
//! the checks, takes the per-name lock, reads, evaluates the expectation and computes the member
//! list; this file turns members into the API's records and back. An rrset has no attribute the
//! model does not carry: `created`, `touched`, `name` and `domain` are read-only, and a change
//! sends `records` and `ttl` only.
//!
//! # Content
//!
//! "Records must be given in presentation format (a.k.a. "BIND" or zone file format). Record
//! values that are not given in canonical form, such as `0:0000::1` for an IPv6 address, will be
//! converted by the API into canonical form" (RRsets, field `records`,
//! <https://desec.readthedocs.io/en/latest/dns/rrsets.html>). Names inside values carry the
//! trailing dot: "when a record value contains a domain name, it is in almost all cases required
//! to add a final dot" (same field; "must be terminated by a dot" for CNAME, MX and NS under
//! "Caveats"). TXT content "must be enclosed in double quotes", may hold several quoted strings,
//! and binary data is written with `\DDD` escapes ("TXT record").
//!
//! So a value is written as its canonical text (design section 4.3), which is presentation format
//! with absolute names, and read with the strict parser. Content that reads differently relative
//! to the zone than absolute (a name without the trailing dot) and TXT content that is not quoted
//! are outside the documented form and are kept as non-canonical data (design section 4.9): they
//! never compare equal to a value, and a `set_rrset` that asks for one replaces them.
//!
//! Escapes: the documentation gives them for TXT only. Canonical text needs a backslash escape
//! for a CAA value with `"`, `\` or a byte outside printable ASCII, and for a name with such a
//! label; such a value of another type than TXT is not sent ([`RrsetBase::can_send`] is false,
//! `Error::InvalidInput`) unless the rrset holds it already, in which case it is written back
//! exactly as the API returned it. This is an assumption, conservative: whether the API reads
//! those escapes as RFC 1035 does is not documented. TXT values of any bytes are sent; the TXT
//! value operations follow the same rule ([`write_content`]), so `txt_plain_only` is false.
//!
//! # Types
//!
//! The documentation lists "at least" these supported types: A, AAAA, AFSDB, APL, CAA, CDNSKEY,
//! CDS, CERT, CNAME, DHCID, DNAME, DNSKEY, DLV, DS, EUI48, EUI64, HINFO, HTTPS, KX, L32, L64, LOC,
//! LP, MX, NAPTR, NID, NS, OPENPGPKEY, PTR, RP, SMIMEA, SPF, SRV, SSHFP, SVCB, TLSA, TXT, URI
//! ("Supported Types"). `record_types` holds those of them with a canonical form in the crate
//! (design section 4.3), minus the DNSSEC types the provider manages itself (DNSKEY, DS, CDNSKEY,
//! CDS: "Automatically Managed Types"). The others are listed by `list_rrsets` (as non-canonical
//! data where the parser does not read them) and cannot be read alone or written. SOA "cannot be
//! read or written through this interface" ("SOA record"); it is not in a listing. ALIAS and
//! ANAME are refused by the API ("Unsupported Types"). The NS rrset at the apex is created with
//! the domain ("NS records pointing to deSEC's name servers … will be created", Domains, field
//! `zonefile`); the record layer refuses writes to it before any request.
//!
//! Examples of content are documented for A and AAAA, CNAME, MX, NS, TLSA and TXT. For CAA, DNAME,
//! HTTPS, PTR, SRV, SSHFP and SVCB the general rule above is the only source: that the API's
//! canonical text of those types (it may quote every SVCB parameter value or split long hex, for
//! example) reads back equal to the crate's is inferred, not observed, until a live run.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::provider::ZoneListing;
use crate::record::{RecordData, RecordType, RrsetTtl, Txt};
use crate::redact::Detail;
use crate::rrsets::{self, Current, Found, Listing, Member, RrsetBase, SetTtl, Stored, WholeSet};

use super::api::Rrset;
use super::client::Desec;

/// Most records of one rrset.
// Source: RRsets, field `records`: "The maximum number of array elements is 4091".
pub(super) const MAX_RECORDS: usize = 4091;

/// The value of TXT content, the one rule both levels read TXT by: the record level here
/// ([`read_content`]) and the TXT value operations (`txt.rs`). Content in double quotes, one
/// quoted string or several separated by whitespace, is read by the strict presentation parser
/// (design section 4.4), several strings joined. Anything else is `None`: unquoted text, an
/// unterminated quote. The documentation requires the quotes, so no meaning is given for such
/// content; the record level reports it as non-canonical data and the value operations never
/// take it for a value of theirs.
// Source: RRsets, "TXT record": "The contents of the `TXT` record must be enclosed in double
// quotes"; "Record values consisting of several token strings separated by whitespace are
// permitted"; "Token strings longer than 255 characters are automatically split".
pub(super) fn read_txt(content: &str) -> Option<Txt> {
    if !content.trim_start().starts_with('"') {
        return None;
    }
    RecordData::parse(RecordType::TXT, content)
        .ok()
        .and_then(|data| Txt::from_data(&data).ok())
}

/// A value as the API returned it, held to the documented form (module documentation).
pub(super) fn read_content(zone: &DomainName, rtype: RecordType, content: &str) -> RecordData {
    if rtype == RecordType::TXT {
        return read_txt(content)
            .and_then(|value| value.to_data().ok())
            .unwrap_or_else(|| RecordData::non_canonical(content));
    }
    let Ok(absolute) = RecordData::parse(rtype, content) else {
        return RecordData::non_canonical(content);
    };
    // A dotless name (or `@`) is the only text the two readings take differently.
    if RecordData::parse_relative(rtype, content, zone)
        .ok()
        .as_ref()
        != Some(&absolute)
    {
        return RecordData::non_canonical(content);
    }
    absolute
}

/// The API's text for a value of `rtype`, or `None` when the client does not send it:
/// non-canonical data, and canonical text with a backslash escape in a type other than TXT
/// (module documentation). The one writing rule of both levels.
pub(super) fn write_content(rtype: RecordType, data: &RecordData) -> Option<String> {
    let escaped = rtype != RecordType::TXT && data.as_str().contains('\\');
    (data.is_canonical() && !escaped).then(|| data.as_str().to_owned())
}

impl RrsetBase for Desec {
    fn provider(&self) -> ProviderId {
        ProviderId::Desec
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

    fn can_send(&self, rtype: RecordType, data: &RecordData) -> bool {
        write_content(rtype, data).is_some()
    }
}

/// The record layer's view of an rrset the API returned.
fn found(zone: &DomainName, rtype: RecordType, rrset: Rrset) -> Found<String, Rrset> {
    let records = rrset
        .records
        .iter()
        .map(|content| Stored {
            data: read_content(zone, rtype, content),
            enabled: true,
            ttl: None,
            handle: content.clone(),
        })
        .collect();
    Found {
        records,
        ttl: rrset.ttl.and_then(|ttl| RrsetTtl::from_secs(ttl).ok()),
        snapshot: rrset,
    }
}

impl WholeSet for Desec {
    /// The record's content as the API returned it.
    type Handle = String;
    type Snapshot = Rrset;
    /// Nothing: the zone name is the key of every path.
    type Context = ();

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Current<String, Rrset, ()>, Error> {
        let rrset = self.read_rrset(zone, name, &rtype.to_string()).await?;
        Ok(Current {
            context: (),
            found: rrset.map(|rrset| found(zone, rtype, rrset)),
        })
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _: &(),
        prior: Option<&Rrset>,
        members: &[Member<'_, String>],
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let records = members
            .iter()
            .map(|member| match member {
                Member::Kept(record) | Member::Enabled(record) => Ok(record.handle.clone()),
                Member::Added(data) => write_content(rtype, data).ok_or(Error::InvalidInput {
                    detail: Detail::constant(
                        "the provider's encoding of this record data is not established",
                    ),
                    code: None,
                }),
            })
            .collect::<Result<Vec<String>, Error>>()?;
        let ttl = match ttl {
            SetTtl::Requested(RrsetTtl::Explicit(ttl))
            | SetTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => ttl.as_secs(),
            // An existing rrset whose TTL the read did not state keeps the number the API
            // returned, if any.
            SetTtl::Existing(None) => prior.and_then(|prior| prior.ttl).unwrap_or(self.ttl),
            // No default TTL of its own: the layer never passes it, and the setting stands in.
            SetTtl::Existing(Some(RrsetTtl::ProviderDefault))
            | SetTtl::Default
            | SetTtl::Requested(RrsetTtl::ProviderDefault) => self.ttl,
        };
        let rtype = rtype.to_string();
        match prior {
            None => self.create_rrset(zone, name, &rtype, &records, ttl).await,
            Some(_) => self.replace_rrset(zone, name, &rtype, &records, ttl).await,
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _: &(),
        _: &Rrset,
    ) -> Result<(), Error> {
        self.delete_rrset(zone, name, &rtype.to_string()).await
    }
}

impl Desec {
    /// `list_rrsets`: every rrset of the zone, all pages.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let mut listing = Listing::new(zone);
        for rrset in self.api.rrsets(zone).await? {
            let ttl = rrset.ttl.and_then(|ttl| RrsetTtl::from_secs(ttl).ok());
            // A type name that maps to no record type is skipped by the listing, whatever the
            // records hold; the content is then never parsed.
            let records: Vec<RecordData> = match rrset.rtype.parse::<RecordType>() {
                Ok(rtype) => rrset
                    .records
                    .iter()
                    .map(|content| read_content(zone, rtype, content))
                    .collect(),
                Err(_) => rrset
                    .records
                    .iter()
                    .map(|content| RecordData::non_canonical(content))
                    .collect(),
            };
            listing.push(rrset.owner, &rrset.rtype, ttl, records);
        }
        listing.finish(ProviderId::Desec)
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
        let mx = read_content(&zone(), RecordType::MX, "10 mail.a4a.de.");
        assert!(mx.is_canonical());
        assert_eq!(mx.as_str(), "10 mail.a4a.de.");
        // A name without the trailing dot reads differently relative to the zone.
        let dotless = read_content(&zone(), RecordType::MX, "10 mail");
        assert!(!dotless.is_canonical());
        let cname = read_content(&zone(), RecordType::CNAME, "@");
        assert!(!cname.is_canonical());
        assert!(!read_content(&zone(), RecordType::A, "not-an-address").is_canonical());
        let txt = read_content(
            &zone(),
            RecordType::TXT,
            "\"token 1 of record 1\" \"token 2\"",
        );
        assert_eq!(
            txt,
            Txt::new("token 1 of record 1token 2")
                .unwrap()
                .to_data()
                .unwrap()
        );
        assert!(!read_content(&zone(), RecordType::TXT, "unquoted").is_canonical());
        assert_eq!(read_txt("\"\\013\"").unwrap().as_bytes(), b"\r");
        assert_eq!(read_txt("plain"), None);
    }

    #[test]
    fn escapes_are_sent_for_txt_only() {
        let txt = Txt::new("say \"hi\" \\ ключ").unwrap().to_data().unwrap();
        assert!(write_content(RecordType::TXT, &txt).is_some());
        let caa = RecordData::parse(RecordType::CAA, "0 issue \"a\\\\b\"").unwrap();
        assert_eq!(write_content(RecordType::CAA, &caa), None);
        let caa = RecordData::parse(RecordType::CAA, "0 issue \"letsencrypt.org\"").unwrap();
        assert_eq!(
            write_content(RecordType::CAA, &caa).as_deref(),
            Some("0 issue \"letsencrypt.org\"")
        );
        let raw = RecordData::non_canonical("x");
        assert_eq!(write_content(RecordType::TXT, &raw), None);
    }
}
