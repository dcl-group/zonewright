//! Where a listed record is: the owner name of each record of the listings a read or a zone
//! listing gathered (`api::Api::zone_listings`), decided the same way for both, so that what
//! `list_rrsets` shows at a name is exactly what `get_rrset` and the TXT value operations find
//! there.
//!
//! # The two forms of a stated name
//!
//! A record states its owner in `data.subdomain`, and the description gives that field two
//! forms: the listing's record schema (`dns-record`) describes it as the subdomain with the
//! example `sub.somedomain.ru`, a full name; the `v2` record schema (`dns-record-v2`) as "only
//! the subdomain without the main domain, `sub` for `sub.example.com`", absent at the domain
//! itself. A name without a trailing dot that ends with the zone's name reads both ways:
//! `www.example.org` in `example.org` is `www.example.org.` as a full name and
//! `www.example.org.example.org.` relative to the zone; `example.org` is the zone itself or
//! `example.org.example.org.`. Taking either reading on trust would let a record of one name be
//! read, replaced or deleted as a record of the other.
//!
//! So each listing's form is decided from what it states, never guessed per record:
//!
//! - a stated name whose full reading is not a name within the zone (`www`,
//!   `_acme-challenge`) can only be relative: the listing states names relative to the zone;
//! - in the listing of a subdomain, a reading that is not at or below that subdomain is
//!   excluded, since the listing holds the records of that subdomain ("all user DNS records of a
//!   domain or subdomain", `getDomainDNSRecords`). When one reading is left, it proves its form
//!   (`www.example.org` in the listing of `www.example.org.` is the full name);
//! - a listing that proves both forms, or that holds a record with no reading at or below the
//!   subdomain it is the listing of, is `Error::Protocol`;
//! - a listing that proves neither form takes the form the other listings of the same operation
//!   prove (assumption, not documented: one endpoint states names in one form in every listing
//!   of one domain; listings that prove different forms are `Error::Protocol`). When no listing
//!   proves a form, every name that reads both ways stays ambiguous: a read of either of its
//!   names fails with `Error::Protocol` instead of guessing (when the record has the operation's
//!   type; a record of another type then counts as data of an unknown type), and a zone listing
//!   reports it, and every rrset it may belong to, in `skipped`.
//!
//! An absent, empty or `@` name is the zone itself in the zone's listing; in the listing of a
//! subdomain it could be that subdomain or the zone, so it is `Error::Protocol`. A name with a
//! trailing dot is a full name in either form.
//!
//! A record shown by several listings (the zone's and a subdomain's) is one record, taken once
//! by its identifier; two listings that place it at different names are `Error::Protocol`.

use std::collections::HashMap;

use crate::error::Error;
use crate::name::DomainName;
use crate::redact::Detail;

use super::api::{Listed, Record};

/// Where a listed record is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Owner {
    /// At this name.
    At(DomainName),
    /// At one of these two names (relative reading first); the listings do not say which.
    Ambiguous(DomainName, DomainName),
    /// At no name the client can hold: the stated name does not parse, or lies outside the
    /// zone. Never the name of an operation; a zone listing reports it in `skipped`.
    Unplaced,
}

impl Owner {
    /// Whether the record may be at `name` without the listings saying so.
    pub(super) fn may_be(&self, name: &DomainName) -> bool {
        matches!(self, Owner::Ambiguous(a, b) if a == name || b == name)
    }
}

/// A listed record and where it is.
#[derive(Debug)]
pub(super) struct Placed<'a> {
    /// The owner name.
    pub(super) owner: Owner,
    /// The record as listed.
    pub(super) record: &'a Record,
}

/// The form in which a listing states names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    Relative,
    Full,
}

/// What one stated name can mean in one listing.
#[derive(Debug)]
enum Reading {
    /// One name in either form: the zone itself, or a name with a trailing dot.
    Fixed(DomainName),
    /// Only the relative reading is left.
    Relative(DomainName),
    /// Only the full reading is left.
    Full(DomainName),
    /// Both readings are left.
    Both {
        relative: DomainName,
        full: DomainName,
    },
    /// No reading is a name the client can hold within the zone.
    None,
}

fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

/// Whether `name` can be in the listing of `of`: anywhere in the zone's listing and in a listing
/// whose name the client cannot hold, at or below the subdomain otherwise.
fn fits(name: &DomainName, of: Option<&DomainName>, zone: &DomainName) -> bool {
    name.is_within(zone) && of.is_none_or(|of| of == zone || name.is_within(of))
}

/// The readings of one record's stated name in the listing of `of` (`None`: a stated subdomain
/// whose name the client cannot hold).
fn reading(record: &Record, of: Option<&DomainName>, zone: &DomainName) -> Result<Reading, Error> {
    let of_zone = of == Some(zone);
    let text = record.subdomain().map_or("", str::trim);
    if text.is_empty() || text == "@" {
        return if of_zone {
            Ok(Reading::Fixed(zone.clone()))
        } else {
            Err(protocol(
                "the provider's listing of a subdomain states a record without its name",
            ))
        };
    }
    let fixed = text.ends_with('.');
    let full = DomainName::parse(text)
        .ok()
        .filter(|name| fits(name, of, zone));
    let relative = if fixed {
        None
    } else {
        DomainName::from_relative(text, zone)
            .ok()
            .filter(|name| fits(name, of, zone))
    };
    let found = match (full, relative) {
        (Some(full), _) if fixed => Reading::Fixed(full),
        (Some(full), Some(relative)) => Reading::Both { relative, full },
        (Some(full), None) => Reading::Full(full),
        (None, Some(relative)) => Reading::Relative(relative),
        (None, None) => Reading::None,
    };
    if matches!(found, Reading::None) && !of_zone && of.is_some() {
        return Err(protocol(
            "the provider's listing of a subdomain holds a record that is not at or below it",
        ));
    }
    Ok(found)
}

/// The form `readings` prove, `None` when they prove none.
fn proven(readings: &[Reading]) -> Result<Option<Form>, Error> {
    let relative = readings.iter().any(|r| matches!(r, Reading::Relative(_)));
    let full = readings.iter().any(|r| matches!(r, Reading::Full(_)));
    match (relative, full) {
        (true, true) => Err(two_forms()),
        (true, false) => Ok(Some(Form::Relative)),
        (false, true) => Ok(Some(Form::Full)),
        (false, false) => Ok(None),
    }
}

fn two_forms() -> Error {
    protocol("the provider states record names both relative to the zone and as full names")
}

/// Every record of `listings` once, with its owner (see the module documentation).
pub(super) fn place<'a>(
    zone: &DomainName,
    listings: &'a [Listed],
) -> Result<Vec<Placed<'a>>, Error> {
    let mut read = Vec::with_capacity(listings.len());
    let mut proven_forms = Vec::new();
    for listed in listings {
        let readings = listed
            .records
            .iter()
            .map(|record| reading(record, listed.of.as_ref(), zone))
            .collect::<Result<Vec<_>, _>>()?;
        let form = proven(&readings)?;
        proven_forms.extend(form);
        read.push((listed, readings, form));
    }
    let common = match (
        proven_forms.contains(&Form::Relative),
        proven_forms.contains(&Form::Full),
    ) {
        (true, true) => return Err(two_forms()),
        (true, false) => Some(Form::Relative),
        (false, true) => Some(Form::Full),
        (false, false) => None,
    };

    let mut placed = Vec::new();
    let mut seen: HashMap<u64, Owner> = HashMap::new();
    for (listed, readings, form) in read {
        for (record, reading) in listed.records.iter().zip(readings) {
            let owner = match (reading, form.or(common)) {
                (Reading::Fixed(name), _) => Owner::At(name),
                (Reading::Both { relative, .. }, Some(Form::Relative))
                | (Reading::Relative(relative), Some(Form::Relative)) => Owner::At(relative),
                (Reading::Both { full, .. }, Some(Form::Full))
                | (Reading::Full(full), Some(Form::Full)) => Owner::At(full),
                (Reading::Both { relative, full }, None) => Owner::Ambiguous(relative, full),
                // A single reading decides its listing's form, so it never meets the other one.
                (Reading::Relative(_) | Reading::Full(_), _) => return Err(two_forms()),
                (Reading::None, _) => Owner::Unplaced,
            };
            if let Some(id) = record.id() {
                match seen.get(&id) {
                    Some(earlier) if *earlier == owner => continue,
                    Some(_) => {
                        return Err(protocol(
                            "the provider's listings show one record at two different names",
                        ));
                    }
                    None => {
                        seen.insert(id, owner.clone());
                    }
                }
            }
            placed.push(Placed { owner, record });
        }
    }
    Ok(placed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Owner, place};
    use crate::error::ErrorKind;
    use crate::name::DomainName;
    use crate::providers::timeweb_cloud::api::{Listed, Record};

    fn dn(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    fn record(id: u64, subdomain: serde_json::Value) -> Record {
        serde_json::from_value(json!({
            "id": id, "type": "A", "ttl": 60,
            "data": {"subdomain": subdomain, "value": "192.0.2.1"}
        }))
        .unwrap()
    }

    fn listed(of: Option<&str>, records: &[(u64, serde_json::Value)]) -> Listed {
        Listed {
            of: of.map(dn),
            records: records
                .iter()
                .map(|(id, s)| record(*id, s.clone()))
                .collect(),
        }
    }

    fn owners(listings: &[Listed]) -> Result<Vec<Owner>, ErrorKind> {
        place(&dn("example.org"), listings)
            .map(|placed| placed.into_iter().map(|p| p.owner).collect())
            .map_err(|e| e.kind())
    }

    fn at(name: &str) -> Owner {
        Owner::At(dn(name))
    }

    #[test]
    fn a_relative_name_proves_the_relative_form() {
        let zone = listed(
            Some("example.org"),
            &[
                (1, json!(null)),
                (2, json!("www")),
                (3, json!("example.org")),
            ],
        );
        assert_eq!(
            owners(&[zone]),
            Ok(vec![
                at("example.org"),
                at("www.example.org"),
                at("example.org.example.org")
            ])
        );
    }

    #[test]
    fn a_subdomain_listing_proves_its_form() {
        // Full: the relative reading of the stated name is not below the listed name.
        let zone = listed(
            Some("example.org"),
            &[(1, json!("example.org")), (2, json!("www.example.org"))],
        );
        let www = listed(Some("www.example.org"), &[(2, json!("www.example.org"))]);
        assert_eq!(
            owners(&[zone, www]),
            Ok(vec![at("example.org"), at("www.example.org")])
        );
        // Relative: the lookalike's own listing states it relative to the zone.
        let zone = listed(
            Some("example.org"),
            &[(1, json!(null)), (2, json!("example.org"))],
        );
        let odd = listed(
            Some("example.org.example.org"),
            &[(2, json!("example.org"))],
        );
        assert_eq!(
            owners(&[zone, odd]),
            Ok(vec![at("example.org"), at("example.org.example.org")])
        );
    }

    #[test]
    fn names_stay_ambiguous_when_nothing_decides() {
        let zone = listed(
            Some("example.org"),
            &[(1, json!(null)), (2, json!("example.org"))],
        );
        assert_eq!(
            owners(&[zone]),
            Ok(vec![
                at("example.org"),
                Owner::Ambiguous(dn("example.org.example.org"), dn("example.org"))
            ])
        );
        let owner = Owner::Ambiguous(dn("example.org.example.org"), dn("example.org"));
        assert!(owner.may_be(&dn("example.org")));
        assert!(owner.may_be(&dn("example.org.example.org")));
        assert!(!owner.may_be(&dn("www.example.org")));
        assert!(!at("example.org").may_be(&dn("example.org")));
    }

    #[test]
    fn inconsistent_listings_are_protocol() {
        // Both forms in one listing.
        let www = listed(
            Some("www.example.org"),
            &[(1, json!("www")), (2, json!("x.www.example.org"))],
        );
        assert_eq!(owners(&[www]), Err(ErrorKind::Protocol));
        // Each form in a listing of its own.
        let zone = listed(Some("example.org"), &[(1, json!("www"))]);
        let www = listed(Some("www.example.org"), &[(1, json!("www.example.org"))]);
        assert_eq!(owners(&[zone, www]), Err(ErrorKind::Protocol));
        // A record without a name in the listing of a subdomain.
        let sub = listed(Some("www.example.org"), &[(1, json!("@"))]);
        assert_eq!(owners(&[sub]), Err(ErrorKind::Protocol));
        // A record that is not below the listed subdomain in any reading.
        let sub = listed(Some("www.example.org"), &[(1, json!("mail"))]);
        assert_eq!(owners(&[sub]), Err(ErrorKind::Protocol));
        // One record at two names.
        let a = listed(Some("example.org"), &[(1, json!("a")), (1, json!("b"))]);
        assert_eq!(owners(&[a]), Err(ErrorKind::Protocol));
    }

    #[test]
    fn names_outside_the_zone_or_unparsable_are_unplaced() {
        let zone = listed(
            Some("example.org"),
            &[
                (1, json!("bad name")),
                (2, json!("other.net.")),
                (3, json!("www")),
                (3, json!("www")),
            ],
        );
        assert_eq!(
            owners(&[zone]),
            Ok(vec![
                Owner::Unplaced,
                Owner::Unplaced,
                at("www.example.org")
            ])
        );
        // A listing of a subdomain the client cannot name excludes nothing.
        let raw = listed(None, &[(4, json!("x"))]);
        assert_eq!(owners(&[raw]), Ok(vec![at("x.example.org")]));
    }
}
