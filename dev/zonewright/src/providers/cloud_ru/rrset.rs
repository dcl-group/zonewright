//! The record primitives both layers build on: read the record of one name and type under the
//! zone cache, create it, replace its values, delete it, and read it again before a write.
//! `txt.rs` (the TXT value layer) and `records.rs` (the record layer) call these with the API's
//! type name; the rules for each answer live here once.
//!
//! - read: `GET /v1/publicRecordsSole?publicZoneId=` (the whole zone, every page), under the
//!   zone-ID cache; the record whose type and owner name are exactly the requested ones. More
//!   than one is `Error::Protocol` (design section 11.3). Every listed record must belong to the
//!   zone the listing asked for (`publicZoneId`, required in `v1PublicRecordSole`); a record of
//!   another zone, or one without the field, is `Error::Protocol`: the listing did not honor its
//!   filter, and no write may follow it.
//! - create: `POST /v1/publicRecordsSole` in the zone the read used, sent once. What the service
//!   answers to a create of a name and type that exists is not documented, so any refusal is
//!   followed by a new read: a record found there now is `Error::Conflict` (someone created it
//!   after our read; nothing was overwritten), otherwise the refusal is the error.
//! - update: `PATCH /v1/publicRecordsSole/{id}` with the full value list and the TTL, carrying the
//!   description, tags and GSLB data as read, sent once.
//! - delete: `DELETE /v1/publicRecordsSole/{id}`, sent once. A "not found" answer to it is
//!   success only when a new read finds no record; the zone may have been recreated with the
//!   record in it, and then its values are still published (`Error::Conflict`).
//! - re-read: the record read again immediately before a write; a change since the first read
//!   is `Error::Conflict` and nothing is written (design section 3.5).
//!
//! A record marked read-only is `Error::Rejected` for any write (design section 11.3). Every write
//! waits for its operation (design section 3.7). An update or a delete answered "not found" drops
//! the cached zone ID: the zone or the record changed after the read and nothing was written; the
//! caller's repeat starts with a fresh read.
//!
//! # Owner names
//!
//! The specification does not describe the form of `name` (`v1PublicRecordSole.name` is
//! "Наименование записи публичной зоны", a string, nothing more). The console takes the subdomain
//! relative to the zone and `@` for the zone itself
//! (<https://cloud.ru/docs/evolution-dns/ug/topics/guides__add-record>). Assumption (not
//! documented): the API uses the same form, and the client sends it. A record's owner is
//! recognized in three spellings that cannot be confused: `@` (or nothing) for the zone, an
//! absolute name with a trailing dot, and a relative name. A name without a trailing dot that
//! also reads as an absolute name inside the zone (`_acme-challenge.example.org` in
//! `example.org`) is ambiguous: it is the requested name as an absolute name, or another name as a
//! relative one. When either reading is the requested name, the read fails with `Error::Protocol`
//! instead of guessing, so that a published value is never reported absent and a create is never
//! sent over a record the client could not place. A listing reports such a record in `skipped`
//! instead (`records.rs`). (lego's client for this provider talks to the retired Cloud DNS API,
//! not to Evolution DNS, and establishes nothing about this form.)
//!
//! # Wildcards
//!
//! A wildcard record is a record with the wildcard flag; its `name` is the part below which it
//! applies, empty (the zone's own name) for `*.<zone>`. Source: Wildcard records
//! (<https://cloud.ru/docs/evolution-dns/ug/topics/concepts__record-types-wildcard>): "«*»
//! означает, что ... включена опция Wildcard и поле Поддомен не заполнено", and the wildcard
//! records "api.example.com" and "public.api.example.com" that answer for the names below them;
//! the flag is `wildcard` of `v1PublicRecordSole` and `v1CreatePublicRecordSoleRequest`. So the
//! owner `*.x.<zone>` is the record with the flag and the name of `x.<zone>`, and a record with the
//! flag never stands for its `name` itself. The update body has no `wildcard`, so an update never
//! changes it.

use crate::error::Error;
use crate::http::{Attempt, ZoneId};
use crate::name::DomainName;
use crate::redact::Detail;

use super::api::{NewRecord, Record, RecordUpdate, Written};
use super::client::CloudRu;

impl CloudRu {
    /// The record of `name` and type `rtype` (the API's spelling), with the zone identifier the
    /// read ended with.
    pub(super) async fn read_record(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
    ) -> Result<(String, Option<Record>), Error> {
        let (zone_id, record) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| self.read_record_in(zone, name, rtype, id),
            )
            .await?;
        Ok((zone_id.id, record))
    }

    /// The read phase under the zone cache: the record in the zone `id`, or `Stale` when the API
    /// does not know the zone.
    async fn read_record_in(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        id: ZoneId,
    ) -> Result<Attempt<Option<Record>>, Error> {
        let listed = match self.api.records(zone, &id.id).await {
            Ok(listed) => listed,
            Err(Error::ZoneNotFound { .. }) => return Ok(Attempt::Stale),
            Err(e) => return Err(e),
        };
        // The owner the requested name is below of, for a wildcard name.
        let base = name.is_wildcard().then(|| name.parent()).flatten();
        let mut found = Vec::new();
        for item in listed {
            let text = |key: &str| item.get(key).and_then(serde_json::Value::as_str);
            if text("publicZoneId") != Some(id.id.as_str()) {
                return Err(Error::Protocol {
                    detail: Detail::constant(
                        "the provider's record listing holds a record of another zone",
                    ),
                });
            }
            if !text("type").is_some_and(|t| t.eq_ignore_ascii_case(rtype)) {
                continue;
            }
            let wildcard = item
                .get("wildcard")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let owner = match (wildcard, &base) {
                (false, _) => Some(name),
                (true, Some(base)) => Some(base),
                // A wildcard record never stands for a name that is not a wildcard.
                (true, None) => None,
            };
            let same_name = match (owner, text("name")) {
                (Some(owner), Some(spelled)) => is_owner(zone, owner, spelled)?,
                (Some(owner), None) => owner == zone,
                (None, _) => false,
            };
            if same_name {
                let record: Record = serde_json::from_value(item).map_err(|_| Error::Protocol {
                    detail: Detail::constant("the provider's record is not in the expected form"),
                })?;
                found.push(record);
            }
        }
        if found.len() > 1 {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider returned more than one record for one name and type",
                ),
            });
        }
        Ok(Attempt::Done(found.pop()))
    }

    /// Reads the record again and fails with `Error::Conflict` unless it is as it was (`prior`;
    /// `None`: there was none). Called immediately before a write (design section 3.5).
    pub(super) async fn reread_unchanged(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        prior: Option<&Record>,
    ) -> Result<(), Error> {
        let (_, again) = self.read_record(zone, name, rtype).await?;
        if again.as_ref() == prior {
            Ok(())
        } else {
            Err(Error::Conflict {
                detail: Detail::constant("the record changed between the read and the write"),
            })
        }
    }

    /// Creates the record in the zone the read used.
    pub(super) async fn create_record(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        zone_id: &str,
        values: &[String],
        ttl: u64,
    ) -> Result<(), Error> {
        let (owner, wildcard) = owner_text(zone, name)?;
        let record = NewRecord {
            public_zone_id: zone_id,
            name: &owner,
            rtype,
            values,
            ttl,
            wildcard,
        };
        let refusal = match self.api.create_record(&record).await? {
            Written::Done => return Ok(()),
            Written::NotFound => {
                self.forget_zone(zone);
                vanished()
            }
            Written::Refused(e) => e,
        };
        // The answer to a duplicate create is not documented: read again. A record there now
        // was created by someone else after our read, and nothing of it was overwritten.
        match self.read_record(zone, name, rtype).await?.1 {
            Some(_) => Err(Error::Conflict {
                detail: Detail::constant(
                    "a record of this name and type was created between the read and the write",
                ),
            }),
            None => Err(refusal),
        }
    }

    /// Replaces the values and the TTL of `prior`, keeping its description, tags and GSLB data.
    pub(super) async fn update_record(
        &self,
        zone: &DomainName,
        prior: &Record,
        values: &[String],
        ttl: u64,
    ) -> Result<(), Error> {
        writable(prior)?;
        let update = RecordUpdate {
            values,
            ttl,
            description: prior.description.as_ref(),
            tags: prior.tags.as_ref(),
            gslb_data: prior.gslb_data.as_ref(),
        };
        match self.api.update_record(&prior.id, &update).await? {
            Written::Done => Ok(()),
            Written::NotFound => {
                self.forget_zone(zone);
                Err(vanished())
            }
            Written::Refused(e) => Err(e),
        }
    }

    /// Deletes `prior`. A "not found" answer is success only when a new read finds no record.
    pub(super) async fn delete_record(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        prior: &Record,
    ) -> Result<(), Error> {
        writable(prior)?;
        match self.api.delete_record(&prior.id).await? {
            Written::Done => Ok(()),
            // The record is gone, or the zone identifier is (a zone recreated with the record in
            // it). Only a new read under a freshly looked-up zone tells them apart.
            Written::NotFound => {
                self.forget_zone(zone);
                match self.read_record(zone, name, rtype).await?.1 {
                    None => Ok(()),
                    Some(_) => Err(Error::Conflict {
                        detail: Detail::constant(
                            "the record was found again after its delete was answered \"not \
                             found\"; the zone changed between the read and the delete",
                        ),
                    }),
                }
            }
            Written::Refused(e) => Err(e),
        }
    }
}

/// True when the API's `name` of a record in `zone` is `name`: `@` (or nothing) for the zone
/// itself, an absolute name with a trailing dot, or a name relative to the zone. A name without
/// a trailing dot that also reads as an absolute name inside the zone is ambiguous; when either
/// reading is `name`, the answer is `Error::Protocol`.
pub(super) fn is_owner(zone: &DomainName, name: &DomainName, text: &str) -> Result<bool, Error> {
    let text = text.trim();
    if text.is_empty() || text == "@" {
        return Ok(zone == name);
    }
    if text.ends_with('.') {
        return Ok(DomainName::parse(text).is_ok_and(|owner| &owner == name));
    }
    let relative = DomainName::from_relative(text, zone).is_ok_and(|owner| &owner == name);
    let absolute = DomainName::parse(text)
        .ok()
        .filter(|owner| owner.is_within(zone));
    match absolute {
        Some(owner) if relative || &owner == name => Err(Error::Protocol {
            detail: Detail::constant(
                "the provider returned a record name without a trailing dot that reads both as \
                 a relative and as an absolute name; the record cannot be placed",
            ),
        }),
        _ => Ok(relative),
    }
}

/// The owner of a listed record: its `name` (see [`is_owner`] for the spellings) and the wildcard
/// flag. `None` for a name that is not a valid name inside the zone, and for an ambiguous one.
pub(super) fn listed_owner(zone: &DomainName, text: &str, wildcard: bool) -> Option<DomainName> {
    let text = text.trim();
    let base = if text.is_empty() || text == "@" {
        zone.clone()
    } else if text.ends_with('.') {
        DomainName::parse(text).ok()?
    } else {
        if DomainName::parse(text).is_ok_and(|owner| owner.is_within(zone)) {
            return None;
        }
        DomainName::from_relative(text, zone).ok()?
    };
    let owner = if wildcard {
        base.prepend("*").ok()?
    } else {
        base
    };
    owner.is_within(zone).then_some(owner)
}

/// The owner name as the client sends it: relative to the zone, `@` for the zone itself, and the
/// wildcard flag, which stands for the leftmost `*` label.
pub(super) fn owner_text(zone: &DomainName, name: &DomainName) -> Result<(String, bool), Error> {
    let (base, wildcard) = match name.parent() {
        Some(parent) if name.is_wildcard() => (parent, true),
        _ => (name.clone(), false),
    };
    match base.relative_to(zone) {
        Some("") => Ok(("@".to_owned(), wildcard)),
        Some(relative) => Ok((relative.to_owned(), wildcard)),
        // Unreachable after the layers' checks (a wildcard of the zone's parent included); an
        // error rather than a panic.
        None => Err(Error::name_outside_zone(name.clone(), zone.clone())),
    }
}

/// A read-only record cannot be changed (design section 11.3).
pub(super) fn writable(record: &Record) -> Result<(), Error> {
    if record.read_only {
        return Err(Error::Rejected {
            status: None,
            detail: Detail::constant("the record is read-only at the provider"),
        });
    }
    Ok(())
}

/// A write addressed a zone or a record that no longer exists: it changed after the read, and
/// nothing was written.
fn vanished() -> Error {
    Error::Conflict {
        detail: Detail::constant(
            "the zone or the record was removed between the read and the write",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{is_owner, listed_owner, owner_text};
    use crate::error::ErrorKind;
    use crate::name::DomainName;

    fn dn(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    #[test]
    fn owner_names_in_the_recognized_forms() {
        let zone = dn("example.org");
        let name = dn("_acme-challenge.example.org");
        for text in [
            "_acme-challenge",
            "_ACME-challenge",
            "_acme-challenge.example.org.",
        ] {
            assert!(is_owner(&zone, &name, text).unwrap(), "{text}");
            assert!(!is_owner(&zone, &zone, text).unwrap(), "{text}");
        }
        for text in ["@", "", "example.org."] {
            assert!(is_owner(&zone, &zone, text).unwrap(), "{text}");
            assert!(!is_owner(&zone, &name, text).unwrap(), "{text}");
        }
        assert!(!is_owner(&zone, &name, "a..b").unwrap());
        // Another name without a trailing dot, whichever way it is read.
        assert!(!is_owner(&zone, &name, "www.example.org").unwrap());
        assert!(!is_owner(&zone, &name, "www").unwrap());
    }

    #[test]
    fn ambiguous_owner_names_are_protocol() {
        let zone = dn("example.org");
        let name = dn("_acme-challenge.example.org");
        // The requested name as a dotless absolute name.
        let e = is_owner(&zone, &name, "_acme-challenge.example.org").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol);
        // The zone's own name without a dot, for the apex.
        let e = is_owner(&zone, &zone, "example.org").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol);
        // A relative name that also reads as an absolute name inside the zone.
        let deep = dn("a.example.org.example.org");
        let e = is_owner(&zone, &deep, "a.example.org").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol);
    }

    #[test]
    fn listed_owners() {
        let zone = dn("example.org");
        for (text, wildcard, owner) in [
            ("@", false, Some("example.org")),
            ("", false, Some("example.org")),
            ("www", false, Some("www.example.org")),
            ("www.example.org.", false, Some("www.example.org")),
            ("@", true, Some("*.example.org")),
            ("", true, Some("*.example.org")),
            ("api", true, Some("*.api.example.org")),
            // Ambiguous, outside the zone, or not a name.
            ("www.example.org", false, None),
            ("example.org", false, None),
            ("www.example.net.", false, None),
            ("a b", false, None),
            ("*.x", true, None),
        ] {
            assert_eq!(
                listed_owner(&zone, text, wildcard),
                owner.map(dn),
                "{text} {wildcard}"
            );
        }
    }

    #[test]
    fn owner_text_is_relative() {
        let zone = dn("example.org");
        assert_eq!(owner_text(&zone, &zone).unwrap(), ("@".to_owned(), false));
        assert_eq!(
            owner_text(&zone, &dn("_acme-challenge.www.example.org")).unwrap(),
            ("_acme-challenge.www".to_owned(), false)
        );
        assert_eq!(
            owner_text(&zone, &dn("*.example.org")).unwrap(),
            ("@".to_owned(), true)
        );
        assert_eq!(
            owner_text(&zone, &dn("*.api.example.org")).unwrap(),
            ("api".to_owned(), true)
        );
        assert!(owner_text(&zone, &dn("example.net")).is_err());
    }
}
