//! Gcore (provider ID `gcore`): Gcore Managed DNS, through its DNS API v2, authenticated with a
//! permanent API token.
//!
//! The metadata is present in every build. The client, `Gcore`, with its settings `GcoreConfig`
//! and credentials `GcoreCredentials`, is compiled with the cargo feature `gcore`.
//!
//! This version offers `check`, `list_zones`, the record-level operations (`list_rrsets`,
//! `get_rrset`, `set_rrset`, `delete_rrset`) for A, AAAA, CAA, CNAME, MX, NS, SRV and TXT, with
//! SOA read-only, and the TXT value operations on plain values. Every write reads the rrset and
//! writes it back whole: a concurrent writer outside this process can lose its change (see
//! [`Preconditions::ReadThenWrite`](crate::Preconditions::ReadThenWrite) and
//! [`ValueGuarantee::ReadThenWrite`](crate::ValueGuarantee::ReadThenWrite)). An rrset that selects
//! its answers per query (pickers, metadata) is never changed.

pub(crate) mod meta;

#[cfg(feature = "gcore")]
mod client;
#[cfg(feature = "gcore")]
mod config;

#[cfg(feature = "gcore")]
pub use client::Gcore;
#[cfg(feature = "gcore")]
pub(crate) use client::from_json;
#[cfg(feature = "gcore")]
pub use config::{GcoreConfig, GcoreCredentials};
