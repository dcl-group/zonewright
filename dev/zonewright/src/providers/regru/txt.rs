//! TXT value operations: the `PerRecord` shape of the value layer over the record API.
//!
//! A record has no identifier. It is identified by its owner name, its type and its content, so
//! the handle of a record is its content exactly as the API returned it, and a removal names that
//! content (`zone/remove_record` with `content`; documentation 9.18). A request therefore names
//! only our value and a foreign value cannot be part of it (`ValueGuarantee::PerValue`). The
//! value layer takes the per-name lock, reads and decides; this file maps its calls onto the
//! API:
//!
//! - read: `zone/get_resource_records` for the whole zone, in one answer; the records of type TXT
//!   whose `subname` is the name asked for, compared as names (`@` is the zone itself);
//! - create: `zone/add_txt`, sent once, with the name relative to the zone and the value. The
//!   function has no TTL parameter (documentation 9.9), so the TTL the value layer chose is not
//!   sent and the capabilities say that a TTL cannot be set;
//! - delete: `zone/remove_record` with the content the read returned, sent once, followed by a
//!   read of the zone. The documentation names no answer for a content nothing holds (the mock
//!   assumes `success`, and the client does not rely on it), so a `success` does not prove that
//!   the record is gone: the read does, and a record with that content still there is
//!   `Error::Protocol`. A removal that matched nothing because another writer got there first is
//!   the same state as one that matched. A writer outside the process that adds the same content
//!   again between the removal and the read also leads to `Error::Protocol`: nothing more is
//!   deleted, and the caller's repeat removes the value, which is one value however many records
//!   hold it.
//!
//! A removal deletes every record at the name with that content: two identical records are one
//! value to the value layer, which also counts them as one.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Raw`. lego sends the value
//! itself in `text`, unquoted (providers/dns/regru/regru.go lines 147 and 170 pass
//! `info.Value`). Plain values, the only ones the capabilities accept, need no escape.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{RrsetTtl, Txt, TxtDialect};
use crate::redact::Detail;
use crate::values::{PerRecord, PerRecordRead, TxtBase, TxtRecord, WriteTtl};

use super::api::TXT;
use super::client::Regru;

/// How TXT content is read.
const READ: TxtDialect = TxtDialect::Auto;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Raw;

/// The name relative to the zone as the API spells it: `@` for the zone itself.
// Source: the documentation, 9.11 (`subname`: "@ for the domain itself") and 9.18 (`subdomain`
// `@` in the request example).
pub(super) fn subdomain<'a>(zone: &DomainName, name: &'a DomainName) -> Result<&'a str, Error> {
    match name.relative_to(zone) {
        Some("") => Ok("@"),
        Some(relative) => Ok(relative),
        None => Err(Error::name_outside_zone(name.clone(), zone.clone())),
    }
}

impl TxtBase for Regru {
    fn provider(&self) -> ProviderId {
        ProviderId::Regru
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl PerRecord for Regru {
    /// The record's content exactly as the API returned it.
    type Handle = String;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> Result<PerRecordRead<String>, Error> {
        let records = self
            .api
            .records(zone)
            .await?
            .into_iter()
            .filter(|rr| {
                rr.rectype
                    .as_deref()
                    .is_some_and(|rtype| rtype.eq_ignore_ascii_case(TXT))
                    && rr
                        .subname
                        .as_deref()
                        .and_then(|sub| DomainName::from_relative(sub, zone).ok())
                        .as_ref()
                        == Some(name)
            })
            .map(|rr| {
                let content = rr.content.unwrap_or_default();
                TxtRecord {
                    value: READ.read(&content),
                    // No TTL is stated or settable: the provider's.
                    ttl: Some(RrsetTtl::ProviderDefault),
                    handle: content,
                }
            })
            .collect();
        Ok(PerRecordRead::Records(records))
    }

    async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        _ttl: WriteTtl,
    ) -> Result<(), Error> {
        let sub = subdomain(zone, name)?;
        let text = WRITE.write(value).ok_or(Error::InvalidInput {
            detail: Detail::constant("the TXT value cannot be written in this dialect"),
        })?;
        self.api.add_txt(zone, sub, &text).await
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        record: &TxtRecord<String>,
    ) -> Result<(), Error> {
        let sub = subdomain(zone, name)?;
        self.api
            .remove_record(zone, sub, TXT, &record.handle)
            .await?;
        // The documentation does not say what the function answers for a content nothing
        // holds, so a `success` does not prove that the record is gone. Reading the zone again
        // does: a record with the content just named that is still there, with the API having
        // said `success`, is not reported as removed. The comparison is by content, not by
        // value: another record that holds the same value in another spelling (quoted, say) is
        // a record of its own, which the value layer removes with its own call.
        let PerRecordRead::Records(now) = self.read(zone, name).await? else {
            return Ok(());
        };
        if now.iter().any(|r| r.handle == record.handle) {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider reported the removal, but the value is still in the zone",
                ),
            });
        }
        Ok(())
    }
}
