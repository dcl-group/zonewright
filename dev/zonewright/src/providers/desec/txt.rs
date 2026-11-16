//! TXT value operations: the `WholeSet` shape of the value layer over the rrset API.
//!
//! The rrset is the native unit and is replaced whole, without a condition the provider checks,
//! hence `ValueGuarantee::ReadThenWrite`. No source documents a call that adds or removes one
//! value: lego reads the rrset and writes it back whole (`providers/dns/desec/desec.go`, Present
//! and CleanUp, `PATCH` with the full list), and so does dns-update (`providers/desec.rs`). The
//! value layer takes the per-name lock, reads, computes the new member list and calls
//! [`WholeSet::write`] or [`WholeSet::delete`]; this file maps those onto the rrset primitives
//! of `rrset.rs`, which the record layer shares:
//!
//! - read: the TXT rrset of the name (`GET …/rrsets/{subname}/TXT/`);
//! - write without a prior set: a create (`POST …/rrsets/`) with the configured or requested
//!   TTL;
//! - write over a prior set: a change (`PATCH`) with the full record list and the TTL as read;
//! - delete: the last value is removed by deleting the rrset (`DELETE`).
//!
//! lego's cleanup filters out the exact quoted string it sent (`%q` of the value), which misses
//! a value the API stored re-split or re-escaped; this client compares decoded values.
//!
//! TXT dialect (design sections 4.4 and 11.2): read by `records::read_txt`, the rule the record
//! level reads TXT by, so that both levels agree on what a record holds; written by
//! `records::write_content`, the canonical text, which is the presentation form with the escapes
//! the documentation gives. Content in another form is never a value of ours: an add puts the
//! value next to it, a remove leaves it.

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{RecordType, RrsetTtl};
use crate::redact::Detail;
use crate::values::{Member, SetRead, SetState, TxtBase, TxtRecord, TxtSet, WholeSet, WriteTtl};

use super::api::{Rrset, TXT};
use super::client::Desec;
use super::records::{MAX_RECORDS, read_txt, write_content};

impl TxtBase for Desec {
    fn provider(&self) -> ProviderId {
        ProviderId::Desec
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl WholeSet for Desec {
    /// The record's content as the API returned it.
    type Handle = String;
    type Snapshot = Rrset;
    /// Nothing: the zone name is the key of every path.
    type Context = ();

    async fn read(&self, zone: &DomainName, name: &DomainName) -> SetRead<String, Rrset, ()> {
        let rrset = self.read_rrset(zone, name, TXT).await?;
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
        members: &[Member<'_, String>],
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

impl Desec {
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

/// The value layer's view of an rrset.
fn txt_set(rrset: Rrset) -> TxtSet<String, Rrset> {
    let ttl = rrset.ttl.and_then(|ttl| RrsetTtl::from_secs(ttl).ok());
    let records = rrset
        .records
        .iter()
        .map(|content| TxtRecord {
            value: read_txt(content),
            ttl,
            handle: content.clone(),
        })
        .collect();
    TxtSet {
        records,
        ttl,
        snapshot: rrset,
    }
}

/// The records to write: those kept, unchanged, then the values added, in canonical text.
fn records(members: &[Member<'_, String>]) -> Result<Vec<String>, Error> {
    let records = members
        .iter()
        .map(|member| match member {
            Member::Kept(record) => Ok(record.handle.clone()),
            Member::Added(value) => value
                .to_data()
                .ok()
                .and_then(|data| write_content(RecordType::TXT, &data))
                .ok_or(Error::InvalidInput {
                    detail: Detail::constant("the TXT value cannot be written in this dialect"),
                    code: None,
                }),
        })
        .collect::<Result<Vec<String>, Error>>()?;
    if records.len() > MAX_RECORDS {
        return Err(Error::InvalidInput {
            detail: Detail::constant("a deSEC rrset holds at most 4091 records"),
            code: None,
        });
    }
    Ok(records)
}
