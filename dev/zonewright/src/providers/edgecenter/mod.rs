//! EdgeCenter (provider ID `edgecenter`): EdgeCenter DNS, through its DNS API v2 (a fork of
//! Gcore's), authenticated with a permanent API token.
//!
//! The metadata is present in every build. The client, `EdgeCenter`, with its settings
//! `EdgeCenterConfig` and credentials `EdgeCenterCredentials`, is compiled with the cargo feature
//! `edgecenter`.
//!
//! This version offers `check`, `list_zones`, the record-level operations (`list_rrsets`,
//! `get_rrset`, `set_rrset`, `delete_rrset`) for A, AAAA, CAA, CNAME, MX, NS, SRV and TXT,
//! with SOA read-only, and the TXT value operations on plain values. Every write reads the rrset
//! and writes it back whole: a concurrent writer outside this process can lose its change (see
//! [`Preconditions::ReadThenWrite`](crate::Preconditions::ReadThenWrite) and
//! [`ValueGuarantee::ReadThenWrite`](crate::ValueGuarantee::ReadThenWrite)). An rrset that selects
//! its answers per query (filters, metadata) is never changed. Requests are spaced to the API's
//! documented rate limit.

pub(crate) mod meta;

#[cfg(feature = "edgecenter")]
mod client;
#[cfg(feature = "edgecenter")]
mod config;

#[cfg(feature = "edgecenter")]
pub use client::EdgeCenter;
#[cfg(feature = "edgecenter")]
pub(crate) use client::from_json;
#[cfg(feature = "edgecenter")]
pub use config::{EdgeCenterConfig, EdgeCenterCredentials};
