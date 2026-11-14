//! TXT value operations: the `WholeSet` shape of the value layer over `getData` and
//! `changeRecords`.
//!
//! The unit is the TXT set of one name, replaced whole by `changeRecords`, without a condition
//! the provider checks, hence `ValueGuarantee::ReadThenWrite`: a writer outside this process that
//! changes the name between the read and the write can lose its change. The value layer takes
//! the per-name lock, reads, computes the new member list and calls [`WholeSet::write`] or
//! [`WholeSet::delete`]; this file maps those onto the API:
//!
//! - read: `dns/getData` for the full name. The answer must name the requested name and be
//!   complete (see `api::parse_records`). A name that holds any record besides TXT records (A,
//!   MX, NS, CNAME, the name server settings, any other type), a TXT record that cannot be
//!   written back as it is, or a `set_type` other than 1 is refused with `Error::Rejected`, for
//!   add and for remove alike, before anything is written;
//! - write: `dns/changeRecords` with group 1 holding only the TXT members, kept ones as read
//!   and ours in the dialect below. The API deletes the A and MX records a group 1 request
//!   leaves out (`api::Api::change_records`), which is why the read must have found none; a
//!   writer outside this process that adds one between the read and the write loses it, as it
//!   would lose a TXT value (`ValueGuarantee::ReadThenWrite`);
//! - delete: the same request with an empty TXT list. The API has no separate call to delete a
//!   set, so the last value is removed by writing the group without records.
//!
//! TXT dialect (design sections 4.4 and 11.2): read `Auto`, write `Raw`. The DNS page shows
//! TXT values unquoted (`"value": "TXT record"`), and plain values, the only ones the
//! capabilities accept, need no escape.
//!
//! TTL (design section 3.6, `TtlSupport::PerRecord`): the API keeps a TTL per record (lego's
//! observed answer, `getData-real.json`, and its `ttl` per written record). A kept record is
//! written back with the TTL it was read with; a value that joins an existing set takes the
//! set's TTL, the smallest among its records; a new set takes the caller's TTL or the
//! configured one. A kept record whose TTL the read does not state is refused by
//! `api::parse_records`, so no TTL is ever invented for a record that is not ours.

use serde_json::{Value, json};

use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{Ttl, TxtDialect};
use crate::redact::Detail;
use crate::values::{Member, SetRead, SetState, TxtBase, TxtRecord, TxtSet, WholeSet, WriteTtl};

use super::api::{self, Parsed, TxtEntry};
use super::client::Beget;

/// How TXT content is read.
const READ: TxtDialect = TxtDialect::Auto;

/// How a value being added is written.
const WRITE: TxtDialect = TxtDialect::Raw;

impl TxtBase for Beget {
    fn provider(&self) -> ProviderId {
        ProviderId::Beget
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }
}

impl WholeSet for Beget {
    type Handle = TxtEntry;
    type Snapshot = Parsed;
    /// Nothing: the name is the key of every call.
    type Context = ();

    async fn read(&self, _zone: &DomainName, name: &DomainName) -> SetRead<TxtEntry, Parsed, ()> {
        let result = self.api.get_data(name).await?;
        let parsed = api::parse_records(&result)?;
        let set = if parsed.txt.is_empty() {
            None
        } else {
            let records: Vec<TxtRecord<TxtEntry>> = parsed
                .txt
                .iter()
                .map(|entry| TxtRecord {
                    value: READ.read(&entry.text),
                    ttl: entry.ttl.as_ref().and_then(ttl_of),
                    handle: entry.clone(),
                })
                .collect();
            // The set's TTL is the smallest of its records' (design section 3.6).
            let ttl = records.iter().filter_map(|record| record.ttl).min();
            Some(TxtSet {
                records,
                ttl,
                snapshot: parsed.clone(),
            })
        };
        Ok(SetState { context: (), set })
    }

    async fn write(
        &self,
        _zone: &DomainName,
        name: &DomainName,
        _context: &(),
        _prior: Option<&Parsed>,
        members: &[Member<'_, TxtEntry>],
        ttl: WriteTtl,
    ) -> Result<(), Error> {
        let mut txt = Vec::with_capacity(members.len());
        for member in members {
            txt.push(match member {
                Member::Kept(record) => {
                    let entry = &record.handle;
                    api::txt_json(&entry.text, entry.priority.as_ref(), entry.ttl.clone())
                }
                Member::Added(value) => {
                    let text = WRITE.write(value).ok_or(Error::InvalidInput {
                        detail: Detail::constant("the TXT value cannot be written in this dialect"),
                    })?;
                    api::txt_json(&text, None, self.added_ttl(ttl))
                }
            });
        }
        self.api.change_records(name, txt).await
    }

    async fn delete(
        &self,
        _zone: &DomainName,
        name: &DomainName,
        _context: &(),
        _prior: &Parsed,
    ) -> Result<(), Error> {
        self.api.change_records(name, Vec::new()).await
    }
}

impl Beget {
    /// The TTL of the value being added, as the JSON the API takes, or `None` to send none.
    fn added_ttl(&self, ttl: WriteTtl) -> Option<Value> {
        match ttl {
            WriteTtl::New(Some(ttl)) | WriteTtl::Existing(Some(ttl)) => Some(json!(ttl.as_secs())),
            WriteTtl::New(None) => Some(json!(self.ttl)),
            WriteTtl::Existing(None) => None,
        }
    }
}

/// A TTL the API stated as a number or a string of digits.
fn ttl_of(value: &Value) -> Option<Ttl> {
    let secs = match value {
        Value::Number(n) => n.as_u64()?,
        Value::String(s) => s.trim().parse().ok()?,
        _ => return None,
    };
    Ttl::from_secs(u32::try_from(secs).ok()?).ok()
}
