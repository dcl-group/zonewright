//! DNSimple (provider ID `dnsimple`): the DNSimple API v2, authenticated with an API access
//! token.
//!
//! The metadata is present in every build. The client, `Dnsimple`, with its settings
//! `DnsimpleConfig` and credentials `DnsimpleCredentials`, is compiled with the cargo feature
//! `dnsimple`.
//!
//! This version offers `check`, `list_zones`, the record-level operations (`list_rrsets`,
//! `get_rrset`, `set_rrset`, `delete_rrset`) for A, AAAA, CAA, CNAME, MX, NS, SRV and TXT, with
//! SOA read-only, and the TXT value operations on plain values. The API's unit is the individual
//! record: the TXT value operations create and delete single records and never write a foreign
//! value (see [`ValueGuarantee::PerValue`](crate::ValueGuarantee::PerValue)); replacing an rrset
//! is several requests, creates before deletes, without a condition the provider checks (see
//! [`Preconditions::ReadThenWrite`](crate::Preconditions::ReadThenWrite)).

pub(crate) mod meta;

#[cfg(feature = "dnsimple")]
mod api;
#[cfg(feature = "dnsimple")]
mod client;
#[cfg(feature = "dnsimple")]
mod config;
#[cfg(feature = "dnsimple")]
mod records;
#[cfg(feature = "dnsimple")]
mod txt;

#[cfg(feature = "dnsimple")]
pub use client::Dnsimple;
#[cfg(feature = "dnsimple")]
pub(crate) use client::from_json;
#[cfg(feature = "dnsimple")]
pub use config::{DnsimpleConfig, DnsimpleCredentials};
