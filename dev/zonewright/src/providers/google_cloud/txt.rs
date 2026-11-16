//! TXT value operations: the `WholeSet` shape of the value layer over the conditional change.
//!
//! The rrset is the native unit, addressed by name and type, and it is replaced through
//! `changes.create`, whose deletions must match the stored rrset exactly. Every write therefore
//! carries the old rrset as the client read it, and the provider refuses the change if the rrset
//! changed in between: `ValueGuarantee::Conditional` (design sections 3.4 and 3.5). The value
//! layer takes the per-name lock, reads, computes the new member list and calls
//! [`WholeSet::write`] or [`WholeSet::delete`]; this file maps those onto the rrset primitives of
//! `rrset.rs`:
//!
//! - read: the TXT rrset of the name, under the zone-ID cache;
//! - write without a prior rrset: `additions` only, with the configured or requested TTL; that
//!   it is refused when an rrset was created meanwhile is assumed (`rrset.rs`, "A new rrset");
//! - write over a prior rrset: `deletions` with the JSON object read, unchanged, and `additions`
//!   with the same object and the new data;
//! - delete: `deletions` only; the last value is removed by deleting the rrset.
//!
//! lego deletes the rrset in one change and adds the new one in another (googlecloud.go:194-255),
//! and its cleanup deletes every TXT rrset at the name, other values included
//! (googlecloud.go:307-330); the client does neither.
//!
//! TXT dialect (design sections 4.4 and 11.2): read by `records::read_txt`, the rule the record
//! level reads TXT by, so that both levels agree on what a record holds; written by
//! `records::write_content`, the canonical text (a plain value in double quotes). Data in
//! another form is never a value of ours: an add puts the value next to it, a remove leaves it.

use serde_json::Value;

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{RecordType, RrsetTtl};
use crate::redact::Detail;
use crate::values::{Member, SetRead, SetState, TxtBase, TxtRecord, TxtSet, WholeSet, WriteTtl};

use super::client::GoogleCloud;
use super::records::{read_txt, write_content};
use super::rrset::{Snapshot, new_rrset, replaced, rrdatas_of, ttl_of};

/// The record type as the API spells it.
const TXT: &str = "TXT";

impl TxtBase for GoogleCloud {
    fn provider(&self) -> ProviderId {
        ProviderId::GoogleCloud
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
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
    ) -> SetRead<String, Snapshot, String> {
        let (zone_id, set) = self.read_set(zone, name, TXT).await?;
        Ok(SetState {
            context: zone_id,
            set: set.map(txt_set).transpose()?,
        })
    }

    async fn write(
        &self,
        zone: &DomainName,
        name: &DomainName,
        zone_id: &String,
        prior: Option<&Snapshot>,
        members: &[Member<'_, String>],
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let rrdatas = rrdatas(members)?;
        let (deletions, addition) = match prior {
            None => (Vec::new(), new_rrset(name, TXT, self.new_ttl(ttl), rrdatas)),
            // An existing rrset keeps its TTL (design section 3.6); one read without a TTL gets
            // the setting, the only number the client has.
            Some(prior) => {
                let ttl = ttl_of(&prior.0).is_none().then_some(self.ttl);
                (vec![prior.0.clone()], replaced(prior, rrdatas, ttl))
            }
        };
        let written = self
            .api
            .change(zone_id, &deletions, std::slice::from_ref(&addition))
            .await?;
        self.settle(zone, name, TXT, zone_id, prior, written, false)
            .await
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        zone_id: &String,
        prior: &Snapshot,
    ) -> Result<(), Error> {
        let written = self
            .api
            .change(zone_id, std::slice::from_ref(&prior.0), &[])
            .await?;
        self.settle(zone, name, TXT, zone_id, Some(prior), written, true)
            .await
    }
}

impl GoogleCloud {
    /// The TTL of a new rrset: the caller's, else the configured one.
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

/// The value layer's view of a plain rrset.
fn txt_set(set: Value) -> Result<TxtSet<String, Snapshot>, Error> {
    let ttl = ttl_of(&set).and_then(|secs| RrsetTtl::from_secs(secs).ok());
    let records = rrdatas_of(&set)?
        .into_iter()
        .map(|text| TxtRecord {
            value: read_txt(text),
            ttl,
            handle: text.to_owned(),
        })
        .collect();
    Ok(TxtSet {
        records,
        ttl,
        snapshot: Snapshot(set),
    })
}

/// The rrdatas to write: those kept, unchanged, then the value added, in canonical text.
fn rrdatas(members: &[Member<'_, String>]) -> Result<Vec<Value>, Error> {
    members
        .iter()
        .map(|member| match member {
            Member::Kept(record) => Ok(Value::String(record.handle.clone())),
            Member::Added(value) => value
                .to_data()
                .ok()
                .and_then(|data| write_content(RecordType::TXT, &data))
                .map(Value::String)
                .ok_or(Error::InvalidInput {
                    detail: Detail::constant("the TXT value cannot be written in this dialect"),
                    code: None,
                }),
        })
        .collect()
}
