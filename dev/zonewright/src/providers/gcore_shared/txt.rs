//! TXT value operations: the `WholeSet` shape of the value layer over the rrset API.
//!
//! The rrset is the native unit and is replaced whole, without a condition the provider checks,
//! hence `ValueGuarantee::ReadThenWrite`. No source documents a call that adds or removes one
//! value: lego and dns-update both read the rrset and write it back whole (lego `AddRRSet`,
//! dns-update `add_to_rrset` and `remove_from_rrset`). The value layer takes the per-name lock,
//! reads, computes the new member list and calls [`WholeSet::write`] or [`WholeSet::delete`];
//! this file maps those onto the rrset primitives of the core, which the record layer shares:
//!
//! - read: the TXT rrset of the name (`GET …/{name}/TXT`);
//! - write without a prior set: a create (`POST`) with the configured or requested TTL;
//! - write over a prior set: a replacement (`PUT`) with the full record list and the TTL as read;
//! - delete: the last value is removed by deleting the rrset, as dns-update's
//!   `remove_from_rrset` does when no record remains.
//!
//! lego's cleanup deletes the whole TXT rrset at the name, values of other writers included
//! (`DeleteRRSet`); this client does not (hard rule 2).
//!
//! TXT dialect (design sections 4.4 and 11.2): a record's `content` is one string, the value
//! itself (`content::read_txt`, the rule the record level reads TXT by too), and a value is
//! written as one string. Content in any other form is never a value of ours: an add puts the
//! value next to it, a remove leaves it. Only plain values are accepted
//! (`Capabilities::txt_plain_only`), the form of an ACME value: no source says how the API treats
//! a quote, a backslash or a non-ASCII byte inside the string. (A space inside is carried as is;
//! `content.rs` gives the rule and its source for the record level.)
//!
//! Disabled records (design section 3.4): a disabled record is not published, so it never counts
//! as holding a value and is written back as it was; a value being added that a disabled record
//! already holds is enabled rather than duplicated.

use serde_json::Value;

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{RrsetTtl, Txt};
use crate::redact::Detail;
use crate::values::{Member, SetRead, SetState, TxtBase, TxtRecord, TxtSet, WholeSet, WriteTtl};

use super::api::{Record, Rrset, TXT};
use super::{Core, content, not_plain};

impl TxtBase for Core {
    fn provider(&self) -> ProviderId {
        self.flavor.provider
    }

    fn capabilities(&self) -> &Capabilities {
        self.flavor.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl WholeSet for Core {
    type Handle = Record;
    type Snapshot = Rrset;
    /// Nothing: the zone name is the key of every path.
    type Context = ();

    async fn read(&self, zone: &DomainName, name: &DomainName) -> SetRead<Record, Rrset, ()> {
        let rrset = self.read_rrset(zone, name, TXT).await?;
        if rrset.as_ref().is_some_and(|rrset| rrset.dynamic) {
            return Err(not_plain());
        }
        Ok(SetState {
            context: (),
            set: rrset.map(txt_set),
        })
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        _: &(),
        prior: Option<&Rrset>,
        members: &[Member<'_, Record>],
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let records = records(members)?;
        match prior {
            None => {
                let ttl = self.new_ttl(ttl);
                self.create_rrset(zone, name, TXT, &records, ttl).await
            }
            // An existing rrset keeps its TTL (design section 3.6); an answer without one gets
            // the setting, the only number the client has.
            Some(prior) => {
                let ttl = prior.ttl.unwrap_or(self.ttl);
                self.replace_rrset(zone, name, TXT, &records, ttl).await
            }
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        _: &(),
        _: &Rrset,
    ) -> Result<(), Error> {
        self.delete_rrset(zone, name, TXT).await
    }
}

impl Core {
    /// The TTL of a new rrset: the caller's, else the configured one.
    fn new_ttl(&self, ttl: WriteTtl) -> u32 {
        match ttl {
            WriteTtl::New(Some(RrsetTtl::Explicit(ttl)))
            | WriteTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => ttl.as_secs(),
            // No default TTL a read shows: the layer never passes it, and the setting stands in.
            WriteTtl::New(None | Some(RrsetTtl::ProviderDefault))
            | WriteTtl::Existing(None | Some(RrsetTtl::ProviderDefault)) => self.ttl,
        }
    }
}

/// The value layer's view of an rrset.
fn txt_set(rrset: Rrset) -> TxtSet<Record, Rrset> {
    let ttl = rrset.ttl.and_then(|ttl| RrsetTtl::from_secs(ttl).ok());
    let records = rrset
        .records
        .iter()
        .map(|record| TxtRecord {
            value: decode(record),
            ttl,
            handle: record.clone(),
        })
        .collect();
    TxtSet {
        records,
        ttl,
        snapshot: rrset,
    }
}

/// The published value of a record: `None` for a disabled record and for content in another
/// form, which are kept as they are and never equal a value.
fn decode(record: &Record) -> Option<Txt> {
    if record.enabled {
        content::read_txt(&record.content)
    } else {
        None
    }
}

/// The records to write: those kept, unchanged, then the value added, unless a disabled record
/// holds it already, which is enabled instead.
fn records(members: &[Member<'_, Record>]) -> Result<Vec<Record>, Error> {
    let mut records: Vec<Record> = members
        .iter()
        .filter_map(|member| match member {
            Member::Kept(record) => Some(record.handle.clone()),
            Member::Added(_) => None,
        })
        .collect();
    for member in members {
        let Member::Added(value) = member else {
            continue;
        };
        let disabled_copy = records
            .iter_mut()
            .find(|r| !r.enabled && content::read_txt(&r.content).as_ref() == Some(*value));
        match disabled_copy {
            Some(record) => record.enabled = true,
            None => {
                let text = value.as_str().ok_or(Error::InvalidInput {
                    detail: Detail::constant("the TXT value cannot be written in this dialect"),
                    code: None,
                })?;
                records.push(Record::new(vec![Value::String(text.to_owned())]));
            }
        }
    }
    Ok(records)
}
