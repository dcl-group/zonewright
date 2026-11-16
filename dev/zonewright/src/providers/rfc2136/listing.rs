//! `list_rrsets`: the zone as a zone transfer delivers it (`axfr.rs`), grouped into rrsets in
//! the form the record-level read gives them (design section 3.4).
//!
//! - Values: the RDATA as received, compressed names expanded, converted as `get_rrset` converts
//!   it (`records::data_of`): canonical `RecordData` through `RecordData::from_wire`, which has a
//!   canonical form for every type with a code (the generic form of RFC 3597 for a type without
//!   its own), and RDATA that is not valid for its type as non-canonical data in the generic
//!   form (design section 4.9). A listed set is therefore exactly what `get_rrset` returns for
//!   it, and a `set_rrset` of it is `Unchanged`. The TTL of a set is the smallest TTL of its
//!   records, as at the record level.
//! - Duplicates: an RR received twice (same owner, type and RDATA) counts once (RFC 5936
//!   section 2.2: "AXFR clients MUST ignore any duplicate RRs received").
//! - SOA and the apex NS rrset are listed like every other set, as every client lists them
//!   (design section 3.4); the SOA is the one that opened the transfer. Delegation NS sets and
//!   glue below them are part of the zone (RFC 5936 sections 3.2 and 3.3) and are listed too.
//! - Skipped, never dropped (`ZoneListing::skipped`): the records a DNSSEC signer keeps for a
//!   signed zone, DNSKEY, RRSIG, NSEC, NSEC3 and NSEC3PARAM (RFC 4034 sections 2 to 4, RFC 5155
//!   sections 3 and 4; RFC 4035 section 2 adds them when a zone is signed), are not records an
//!   application reconciles: `SkipReason::NotPlainRecords`. So are a query or meta type and a
//!   set the model cannot hold (two records of a singleton type), as `Listing::push` decides; an
//!   owner name that is not a valid `DomainName` or not within the zone is
//!   `SkipReason::UnsupportedName` under the zone's name.

use std::collections::BTreeMap;

use crate::error::Error;
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::provider::{SkipReason, ZoneListing};
use crate::record::{RecordType, RrsetTtl};
use crate::rrsets::{self, Listing};

use super::axfr::{self, Transferred};
use super::client::Rfc2136;
use super::records::{data_of, ttl_of};

/// DNSKEY, RRSIG, NSEC, NSEC3 and NSEC3PARAM (RFC 4034 section 2.1, 3.1 and 4.1; RFC 5155
/// sections 3.1 and 4.1).
const SIGNER_TYPES: [u16; 5] = [48, 46, 47, 50, 51];

impl Rfc2136 {
    /// `list_rrsets`: every rrset of the zone by one zone transfer. Takes no lock, as the
    /// record-level read takes none.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let records = axfr::transfer(&self.transport, zone).await?;
        build(zone, records)
    }
}

/// The records of one owner name and type: RDATA and TTL of each.
type Members = Vec<(Vec<u8>, u32)>;

/// Groups the records of a transfer into the listing (module documentation).
fn build(zone: &DomainName, records: Vec<Transferred>) -> Result<ZoneListing, Error> {
    let mut groups: BTreeMap<(String, u16), Members> = BTreeMap::new();
    for record in records {
        let members = groups.entry((record.name, record.rtype)).or_default();
        if !members.iter().any(|(rdata, _)| *rdata == record.rdata) {
            members.push((record.rdata, record.ttl));
        }
    }
    let mut listing = Listing::new(zone);
    for ((owner, code), members) in groups {
        let rtype = RecordType::from_code(code);
        let type_name = rtype.to_string();
        let name = DomainName::parse(&owner).ok();
        if SIGNER_TYPES.contains(&code) {
            match name.filter(|name| name.is_within(zone)) {
                Some(name) => listing.skip(name, &type_name, SkipReason::NotPlainRecords),
                None => listing.skip(zone.clone(), &type_name, SkipReason::UnsupportedName),
            }
            continue;
        }
        let ttl = members
            .iter()
            .map(|(_, ttl)| *ttl)
            .min()
            .map(|ttl| RrsetTtl::Explicit(ttl_of(ttl)));
        let data = members
            .iter()
            .map(|(rdata, _)| data_of(rtype, rdata))
            .collect();
        listing.push(name, &type_name, ttl, data);
    }
    listing.finish(ProviderId::Rfc2136)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::RecordData;

    fn record(name: &str, rtype: u16, ttl: u32, rdata: &[u8]) -> Transferred {
        Transferred {
            name: name.to_owned(),
            rtype,
            ttl,
            rdata: rdata.to_vec(),
        }
    }

    /// Records in any order and duplicates become sets with the smallest TTL; signer records,
    /// meta types, names outside the zone and invalid names are skipped with their reason.
    #[test]
    fn records_group_into_sets() {
        let zone = DomainName::parse("example.org").unwrap();
        let listing = build(
            &zone,
            vec![
                record("a.example.org.", 1, 300, &[192, 0, 2, 2]),
                record("b.example.org.", 16, 60, b"\x01x"),
                record("a.example.org.", 1, 120, &[192, 0, 2, 1]),
                record("a.example.org.", 1, 600, &[192, 0, 2, 2]),
                record("a.example.org.", 46, 60, &[0; 20]),
                record("a.example.org.", 128, 60, &[]),
                record("a.example.net.", 1, 60, &[192, 0, 2, 3]),
                record("a\\.b.example.org.", 1, 60, &[192, 0, 2, 4]),
                record("c.example.org.", 1, 60, &[192, 0, 2]),
            ],
        )
        .unwrap();
        let sets: Vec<(String, String, Option<RrsetTtl>, Vec<String>)> = listing
            .rrsets
            .iter()
            .map(|set| {
                (
                    set.name().to_string(),
                    set.rtype().to_string(),
                    set.ttl(),
                    set.records().iter().map(RecordData::to_string).collect(),
                )
            })
            .collect();
        let ttl = |secs| Some(RrsetTtl::from_secs(secs).unwrap());
        assert_eq!(
            sets,
            [
                (
                    "a.example.org.".to_owned(),
                    "A".to_owned(),
                    ttl(120),
                    vec!["192.0.2.1".to_owned(), "192.0.2.2".to_owned()]
                ),
                (
                    "b.example.org.".to_owned(),
                    "TXT".to_owned(),
                    ttl(60),
                    vec!["\"x\"".to_owned()]
                ),
                (
                    "c.example.org.".to_owned(),
                    "A".to_owned(),
                    ttl(60),
                    vec!["\\# 3 c00002".to_owned()]
                ),
            ]
        );
        assert!(!listing.rrsets[2].records()[0].is_canonical());
        let skipped: Vec<(String, String, SkipReason)> = listing
            .skipped
            .iter()
            .map(|s| (s.name.to_string(), s.type_name.clone(), s.reason))
            .collect();
        assert_eq!(skipped.len(), 4, "{skipped:?}");
        for entry in [
            ("example.org.", "A", SkipReason::UnsupportedName),
            ("a.example.org.", "RRSIG", SkipReason::NotPlainRecords),
            ("a.example.org.", "NXNAME", SkipReason::NotPlainRecords),
        ] {
            let entry = (entry.0.to_owned(), entry.1.to_owned(), entry.2);
            assert!(skipped.contains(&entry), "{entry:?} in {skipped:?}");
        }
    }
}
