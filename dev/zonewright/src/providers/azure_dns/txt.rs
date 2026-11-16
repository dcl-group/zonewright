//! TXT value operations: the `WholeSet` shape of the value layer over the record set API.
//!
//! The record set is the native unit and is replaced whole, under a condition the service
//! checks (`If-Match` with the etag read, `If-None-Match: *` for a create), hence
//! `ValueGuarantee::Conditional`: a value another writer adds between the read and the write
//! makes the write fail instead of being lost, and the value layer runs the operation once more
//! from the read. No source documents a call that adds or removes one value. lego reads the
//! record set and writes it back without a condition, keeps only the first string of each
//! record, and deletes the whole record set on cleanup (`providers/dns/azuredns/public.go`,
//! Present and CleanUp); none of that is copied.
//!
//! - read: the TXT record set of the name (`GET …/TXT/{name}`);
//! - write without a prior set: a create (`PUT` with `If-None-Match: *`) with the configured
//!   or requested TTL;
//! - write over a prior set: a `PUT` with `If-Match`, the records kept exactly as read plus the
//!   new one, the TTL and the `metadata` as read;
//! - delete: the last value is removed by deleting the record set (`DELETE` with `If-Match`).
//!   The record set goes with its `metadata`: the contract of design section 3.5 deletes the
//!   rrset when the value was its only one, and no source says that the service keeps or serves
//!   a TXT record set without records, so the client does not write one to keep the metadata.
//!
//! A TXT record set without records, should the service return one (the reference does not say
//! that a record list may be empty, nor that it may not), reads as no set; it is carried in the
//! read's context, and an add writes into it under its etag, its `metadata` kept.
//!
//! TXT strings (design sections 4.4 and 11.2): read by `content::read_txt` and written by
//! `content::txt_record`, the rule the record level follows as well. A record outside the rule
//! is never a value of ours: an add puts the value next to it, a remove leaves it.

use serde_json::Value;

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{RrsetTtl, Txt};
use crate::redact::Detail;
use crate::values::{Member, SetRead, SetState, TxtBase, TxtRecord, TxtSet, WholeSet, WriteTtl};

use super::api::RecordSet;
use super::client::AzureDns;
use super::content::{self, not_plain};

/// The API's spelling of the TXT type.
const TXT: &str = "TXT";

impl TxtBase for AzureDns {
    fn provider(&self) -> ProviderId {
        ProviderId::AzureDns
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }

    /// A value the client cannot send is refused before any request.
    fn check_value(&self, value: &Txt) -> Result<(), Error> {
        if content::txt_strings(value).is_some() {
            Ok(())
        } else {
            Err(Error::InvalidInput {
                detail: Detail::constant(
                    "Azure DNS TXT values are sent as printable ASCII without '\"' and '\\', at \
                     least one character long",
                ),
                code: None,
            })
        }
    }
}

impl WholeSet for AzureDns {
    /// The record object as the API returned it.
    type Handle = Value;
    type Snapshot = RecordSet;
    /// A TXT record set without records, which a create writes into.
    type Context = Option<RecordSet>;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> SetRead<Value, RecordSet, Option<RecordSet>> {
        let Some(set) = self.read_record_set(zone, name, TXT).await? else {
            return Ok(SetState {
                context: None,
                set: None,
            });
        };
        if set.is_alias() {
            return Err(not_plain());
        }
        let items = set.records()?;
        if items.is_empty() {
            return Ok(SetState {
                context: Some(set),
                set: None,
            });
        }
        let ttl = set.ttl().and_then(|ttl| RrsetTtl::from_secs(ttl).ok());
        let records = items
            .into_iter()
            .map(|item| TxtRecord {
                value: content::read_txt(&item),
                ttl,
                handle: item,
            })
            .collect();
        Ok(SetState {
            context: None,
            set: Some(TxtSet {
                records,
                ttl,
                snapshot: set,
            }),
        })
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        context: &Option<RecordSet>,
        prior: Option<&RecordSet>,
        members: &[Member<'_, Value>],
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let records = members
            .iter()
            .map(|member| match member {
                Member::Kept(record) => Ok(record.handle.clone()),
                Member::Added(value) => content::txt_record(value).ok_or(Error::InvalidInput {
                    detail: Detail::constant("the TXT value cannot be written in this dialect"),
                    code: None,
                }),
            })
            .collect::<Result<Vec<Value>, Error>>()?;
        match prior {
            // An existing record set keeps its TTL (design section 3.6).
            Some(prior) => {
                self.write_record_set(zone, name, TXT, Some(prior), records, None)
                    .await
            }
            None => {
                let ttl = self.new_ttl(ttl);
                self.write_record_set(zone, name, TXT, context.as_ref(), records, Some(ttl))
                    .await
            }
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        _: &Option<RecordSet>,
        prior: &RecordSet,
    ) -> Result<(), Error> {
        self.delete_record_set(zone, name, TXT, prior).await
    }
}

impl AzureDns {
    /// The TTL of a new record set: the caller's, else the configured one.
    fn new_ttl(&self, ttl: WriteTtl) -> u32 {
        match ttl {
            WriteTtl::New(Some(RrsetTtl::Explicit(ttl)))
            | WriteTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => ttl.as_secs(),
            // No default TTL of its own: the layer never passes it, and the setting stands in.
            WriteTtl::New(None | Some(RrsetTtl::ProviderDefault))
            | WriteTtl::Existing(None | Some(RrsetTtl::ProviderDefault)) => self.ttl,
        }
    }
}
