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
//! end of every write operation; when the refresh fails, the operation's error says that the
//! changes are stored but not published, and the repeat of the operation publishes them. The
//! OAuth2 service-account credentials of the API are not supported.

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
