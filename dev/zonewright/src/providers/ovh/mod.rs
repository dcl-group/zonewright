//! OVHcloud (provider ID `ovh`): the OVHcloud API's `/domain/zone` endpoints, version 1.0,
//! authenticated with an application key, an application secret and a consumer key.
//!
//! The metadata is present in every build. The client, `Ovh`, with its settings `OvhConfig`
//! and credentials `OvhCredentials`, is compiled with the cargo feature `ovh`.
//!
//! This version offers `check`, `list_zones`, the record-level operations (`list_rrsets`,
//! `get_rrset`, `set_rrset`, `delete_rrset`) for A, AAAA, CAA, CNAME, MX, NS, SRV, TLSA and TXT,
//! and the TXT value operations on plain values. The API's unit is the individual record: the
//! TXT value operations create and delete single records and never write a foreign value (see
//! [`ValueGuarantee::PerValue`](crate::ValueGuarantee::PerValue)); replacing an rrset is several
//! requests, creates before deletes, without a condition the provider checks (see
//! [`Preconditions::ReadThenWrite`](crate::Preconditions::ReadThenWrite)). Record changes are
//! staged by the API and published by a refresh of the whole zone, which the client sends at the
//! end of every write operation that reaches the provider, whatever its outcome, and, while a
//! refresh this client started a write for has not succeeded, also before a read and on every
//! exit of a write operation in the zone. That mark is kept in the client only: a change left
//! staged by a dropped operation or a failed refresh in a client that is gone is published by
//! the next write operation in the zone that reaches the provider, in any process. The client assumes, without a source,
//! that the record endpoints report the staged state. TXT reads cover `fieldType` TXT only:
//! records of the types SPF, DKIM and DMARC, which the name servers may serve as TXT, are not
//! part of a TXT rrset the client reads or writes. The OAuth2 service-account credentials of
//! the API are not supported.

pub(crate) mod meta;

#[cfg(feature = "ovh")]
mod api;
#[cfg(feature = "ovh")]
mod client;
#[cfg(feature = "ovh")]
mod config;
#[cfg(feature = "ovh")]
mod records;
#[cfg(feature = "ovh")]
mod txt;

#[cfg(feature = "ovh")]
pub use client::Ovh;
#[cfg(feature = "ovh")]
pub(crate) use client::from_json;
#[cfg(feature = "ovh")]
pub use config::{OvhConfig, OvhCredentials};
