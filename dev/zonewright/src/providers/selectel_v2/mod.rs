//! Selectel v2 (provider ID `selectel_v2`): the Selectel DNS v2 API, authenticated through the
//! provider's Keystone identity service.
//!
//! The metadata is present in every build. The client, `SelectelV2`, with its settings
//! `SelectelV2Config` and credentials `SelectelV2Credentials`, is compiled with the cargo
//! feature `selectel_v2`.
//!
//! This version offers `check`, `list_zones`, the record-level operations (`list_rrsets`,
//! `get_rrset`, `set_rrset`, `delete_rrset`) for A, AAAA, ALIAS, CAA, CNAME, MX, NS, SRV, SSHFP and
//! TXT, with SOA read-only, and the TXT value operations on plain values. Every write reads the
//! rrset and writes it back whole: a concurrent writer outside this process can lose its change
//! (see [`Preconditions::ReadThenWrite`](crate::Preconditions::ReadThenWrite) and
//! [`ValueGuarantee::ReadThenWrite`](crate::ValueGuarantee::ReadThenWrite)).

pub(crate) mod meta;

#[cfg(feature = "selectel_v2")]
mod api;
#[cfg(feature = "selectel_v2")]
mod client;
#[cfg(feature = "selectel_v2")]
mod config;
#[cfg(feature = "selectel_v2")]
mod records;
#[cfg(feature = "selectel_v2")]
mod rrset;
#[cfg(feature = "selectel_v2")]
mod txt;

#[cfg(feature = "selectel_v2")]
pub use client::SelectelV2;
#[cfg(feature = "selectel_v2")]
pub(crate) use client::from_json;
#[cfg(feature = "selectel_v2")]
pub use config::{SelectelV2Config, SelectelV2Credentials};
