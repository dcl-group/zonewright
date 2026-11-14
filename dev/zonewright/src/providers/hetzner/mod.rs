//! Hetzner (provider ID `hetzner`): the Hetzner Cloud API's zones and RRSets, authenticated with
//! a project API token. This is not the legacy DNS API.
//!
//! The metadata is present in every build. The client, `Hetzner`, with its settings
//! `HetznerConfig` and credentials `HetznerCredentials`, is compiled with the cargo feature
//! `hetzner`.
//!
//! This version offers `check`, `list_zones`, the TXT value operations and the record-level
//! operations. The TXT value operations accept plain values only. They use the API's
//! value-level actions, so they add one value and remove only the values that equal ours and
//! never write a foreign one (see
//! [`ValueGuarantee::PerValue`](crate::ValueGuarantee::PerValue)). The record-level operations
//! read an rrset and then create it or replace its records in one request; the API checks no
//! condition, so a change made by another process in between is overwritten (see
//! [`Preconditions::ReadThenWrite`](crate::Preconditions::ReadThenWrite)). Record comments and
//! rrset labels are kept; an rrset with change protection is not changed. Only zones in primary
//! mode can be read or changed. Writes are actions the API completes asynchronously; an
//! operation returns after its action has finished.

pub(crate) mod meta;

#[cfg(feature = "hetzner")]
mod api;
#[cfg(feature = "hetzner")]
mod client;
#[cfg(feature = "hetzner")]
mod config;
#[cfg(feature = "hetzner")]
mod records;
#[cfg(feature = "hetzner")]
mod rrset;
#[cfg(feature = "hetzner")]
mod txt;

#[cfg(feature = "hetzner")]
pub use client::Hetzner;
#[cfg(feature = "hetzner")]
pub(crate) use client::from_json;
#[cfg(feature = "hetzner")]
pub use config::{HetznerConfig, HetznerCredentials};
