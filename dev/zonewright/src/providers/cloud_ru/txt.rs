//! TXT value operations: the `WholeSet` shape of the value layer over the record API.
//!
//! The service keeps one record per name and type, holding every value of that name and type
//! (the provider's limitations page), and replaces the values whole by `PATCH`, without a
//! condition the provider checks. Hence `ValueGuarantee::ReadThenWrite`, with the extra read the
//! design assigns to this provider ([`WholeSet::reread_before_write`], design section 3.5): the
//! value layer reads, computes the new value list, reads again and refuses with
//! `Error::Conflict` if the record changed, and only then calls [`WholeSet::write`] or
//! [`WholeSet::delete`]. This file maps those onto the API:
//!
//! - read: `GET /v1/publicRecordsSole?publicZoneId=` (the whole zone, every page), under the
//!   zone-ID cache; the TXT record whose owner name is exactly the requested one. More than one
//!   is `Error::Protocol` (design section 11.3). A record with the wildcard flag stands for the
//!   names below its owner and is never the requested name's record;
//! - write without a prior record: `POST /v1/publicRecordsSole` in the zone the read used, with
//!   the configured or requested TTL. What the service answers to a create of a name and type
//!   that exists is not documented, so any refusal is followed by a new read: a record found
//!   there now is `Error::Conflict` (someone created it after our read; nothing was
//!   overwritten), otherwise the refusal is the error;
//! - write over a prior record: `PATCH /v1/publicRecordsSole/{id}` with the full value list, and
//!   the TTL, description, tags and GSLB data as read;
//! - delete: `DELETE /v1/publicRecordsSole/{id}`, sent once, for the last value. Whether a
//!   record can be written with no values is not documented, so the last value is removed by
//!   deleting the record. A "not found" answer to it is success only when a new read finds no
//!   record; the zone may have been recreated with the record in it, and then the value is still
//!   published.
//!
//! A record marked read-only is `Error::Rejected` for any write (design section 11.3). Every
//! write waits for its operation (design section 3.7).
//!
//! Owner names. The specification does not describe the form of `name` (`v1PublicRecordSole.name`
//! is "Наименование записи публичной зоны", a string, nothing more). The console takes the
//! subdomain relative to the zone and `@` for the zone itself (the provider's guide to creating
//! a record). Assumption (not documented): the API uses the same form, and the client sends it.
//! A record's owner is recognized in three spellings that cannot be confused: `@` (or nothing)
//! for the zone, an absolute name with a trailing dot, and a relative name. A name without a
//! trailing dot that also reads as an absolute name inside the zone (`_acme-challenge.example.org`
//! in `example.org`) is ambiguous: it is the requested name as an absolute name, or another name
//! as a relative one. When either reading is the requested name, the read fails with
//! `Error::Protocol` instead of guessing, so that a published value is never reported absent and
//! a create is never sent over a record the client could not place. (lego's client for this
//! provider talks to the retired Cloud DNS API, not to Evolution DNS, and establishes nothing
//! about this form.) Wildcard owner names are refused (`Error::InvalidInput`) before any
//! request: the service expresses a wildcard through a flag whose interplay with `name` is not
//! documented.
//!
//! Every listed record must belong to the zone the listing asked for (`publicZoneId`, required
//! in `v1PublicRecordSole`); a record of another zone, or one without the field, is
//! `Error::Protocol`: the listing did not honor its filter, and no write may follow it.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Raw`. Plain values, the only
//! ones the capabilities accept, are spelled the same in either.

use crate::error::Error;
use crate::http::{Attempt, ZoneId};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{Ttl, TxtDialect};
use crate::redact::Detail;
use crate::values::{Member, SetRead, SetState, TxtBase, TxtRecord, TxtSet, WholeSet, WriteTtl};

use super::api::{NewRecord, Record, RecordUpdate, TXT, Written};
use super::client::CloudRu;

/// How TXT values are read.
const READ: TxtDialect = TxtDialect::Auto;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Raw;

impl TxtBase for CloudRu {
    fn provider(&self) -> ProviderId {
        ProviderId::CloudRu
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl WholeSet for CloudRu {
    /// A value as the API spells it, written back unchanged.
    type Handle = String;
    type Snapshot = Record;
    /// The zone identifier the read used.
    type Context = String;

    async fn read(&self, zone: &DomainName, name: &DomainName) -> SetRead<String, Record, String> {
        if name.is_wildcard() {
            return Err(Error::InvalidInput {
                detail: Detail::constant(
                    "wildcard names are not supported for this provider: how the API spells \
                     them is not established",
                ),
            });
        }
        let (zone_id, record) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| self.read_txt(zone, name, id),
            )
            .await?;
        Ok(SetState {
            context: zone_id.id,
            set: record.map(txt_set),
        })
    }

    fn reread_before_write(&self) -> bool {
        true
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        zone_id: &String,
        prior: Option<&Record>,
        members: &[Member<'_, String>],
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let values = values(members)?;
        let Some(prior) = prior else {
            return self.create(zone, name, zone_id, &values, ttl).await;
        };
        writable(prior)?;
        let update = RecordUpdate {
            values: &values,
            // An existing record keeps its TTL (design section 3.6).
            ttl: prior.ttl,
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

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        _zone_id: &String,
        prior: &Record,
    ) -> Result<(), Error> {
        writable(prior)?;
        match self.api.delete_record(&prior.id).await? {
            Written::Done => Ok(()),
            // The record is gone, or the zone identifier is (a zone recreated with the record in
            // it). Only a new read under a freshly looked-up zone tells them apart.
            Written::NotFound => {
                self.forget_zone(zone);
                match self.read(zone, name).await?.set {
                    None => Ok(()),
                    Some(_) => Err(Error::Conflict {
                        detail: Detail::constant(
                            "the TXT record was found again after its delete was answered \
                             \"not found\"; the zone changed between the read and the delete",
                        ),
                    }),
                }
            }
            Written::Refused(e) => Err(e),
        }
    }
}

impl CloudRu {
    /// Creates the record in the zone the read used.
    async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        zone_id: &str,
        values: &[String],
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let owner = owner_text(zone, name)?;
        let record = NewRecord {
            public_zone_id: zone_id,
            name: owner,
            rtype: TXT,
            values,
            ttl: u64::from(self.new_ttl(ttl)),
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
        match self.read(zone, name).await?.set {
            Some(_) => Err(Error::Conflict {
                detail: Detail::constant(
                    "a record of this name and type was created between the read and the write",
                ),
            }),
            None => Err(refusal),
        }
    }

    /// The read phase under the zone cache: the TXT record of `name` in the zone `id`, or
    /// `Stale` when the API does not know the zone.
    async fn read_txt(
        &self,
        zone: &DomainName,
        name: &DomainName,
        id: ZoneId,
    ) -> Result<Attempt<Option<Record>>, Error> {
        let listed = match self.api.records(zone, &id.id).await {
            Ok(listed) => listed,
            Err(Error::ZoneNotFound { .. }) => return Ok(Attempt::Stale),
            Err(e) => return Err(e),
        };
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
            let is_txt = text("type").is_some_and(|t| t.eq_ignore_ascii_case(TXT));
            let wildcard = item
                .get("wildcard")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if !is_txt || wildcard {
                continue;
            }
            let same_name = match text("name") {
                Some(owner) => is_owner(zone, name, owner)?,
                None => false,
            };
            if same_name {
                let record: Record = serde_json::from_value(item).map_err(|_| Error::Protocol {
                    detail: Detail::constant(
                        "the provider's TXT record is not in the expected form",
                    ),
                })?;
                found.push(record);
            }
        }
        if found.len() > 1 {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider returned more than one TXT record for one name",
                ),
            });
        }
        Ok(Attempt::Done(found.pop()))
    }

    /// The TTL of a new record: the caller's, else the configured one.
    fn new_ttl(&self, ttl: WriteTtl) -> u32 {
        match ttl {
            WriteTtl::New(Some(ttl)) | WriteTtl::Existing(Some(ttl)) => ttl.as_secs(),
            WriteTtl::New(None) | WriteTtl::Existing(None) => self.ttl,
        }
    }
}

/// True when the API's `name` of a record in `zone` is `name`: `@` (or nothing) for the zone
/// itself, an absolute name with a trailing dot, or a name relative to the zone. A name without
/// a trailing dot that also reads as an absolute name inside the zone is ambiguous; when either
/// reading is `name`, the answer is `Error::Protocol`.
fn is_owner(zone: &DomainName, name: &DomainName, text: &str) -> Result<bool, Error> {
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

/// The owner name as the client sends it: relative to the zone, `@` for the zone itself.
fn owner_text<'a>(zone: &DomainName, name: &'a DomainName) -> Result<&'a str, Error> {
    match name.relative_to(zone) {
        Some("") => Ok("@"),
        Some(relative) => Ok(relative),
        // Unreachable after the value layer's checks; an error rather than a panic.
        None => Err(Error::name_outside_zone(name.clone(), zone.clone())),
    }
}

/// The value layer's view of a record.
fn txt_set(record: Record) -> TxtSet<String, Record> {
    let ttl = u32::try_from(record.ttl)
        .ok()
        .and_then(|secs| Ttl::from_secs(secs).ok());
    let records = record
        .values
        .iter()
        .map(|value| TxtRecord {
            value: READ.read(value),
            ttl,
            handle: value.clone(),
        })
        .collect();
    TxtSet {
        records,
        ttl,
        snapshot: record,
    }
}

/// The values to write: those kept, unchanged, then the value added.
fn values(members: &[Member<'_, String>]) -> Result<Vec<String>, Error> {
    members
        .iter()
        .map(|member| match member {
            Member::Kept(record) => Ok(record.handle.clone()),
            Member::Added(value) => WRITE.write(value).ok_or(Error::InvalidInput {
                detail: Detail::constant("the TXT value cannot be written in this dialect"),
            }),
        })
        .collect()
}

/// A read-only record cannot be changed (design section 11.3).
fn writable(record: &Record) -> Result<(), Error> {
    if record.read_only {
        return Err(Error::Rejected {
            status: None,
            detail: Detail::constant("the TXT record is read-only at the provider"),
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
    use super::{is_owner, owner_text};
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
    fn owner_text_is_relative() {
        let zone = dn("example.org");
        assert_eq!(owner_text(&zone, &zone).unwrap(), "@");
        assert_eq!(
            owner_text(&zone, &dn("_acme-challenge.www.example.org")).unwrap(),
            "_acme-challenge.www"
        );
        assert!(owner_text(&zone, &dn("example.net")).is_err());
    }
}
