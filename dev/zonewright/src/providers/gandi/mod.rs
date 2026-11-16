//! Gandi (provider ID `gandi`): Gandi LiveDNS through its API v5, authenticated with a personal
//! access token.
//!
//! The metadata is present in every build. The client, `Gandi`, with its settings `GandiConfig`
//! and credentials `GandiCredentials`, is compiled with the cargo feature `gandi`.
//!
//! This version offers `check`, `list_zones`, the record-level operations (`list_rrsets`,
//! `get_rrset`, `set_rrset`, `delete_rrset`) for A, AAAA, CNAME, MX, NS, SRV and TXT, and the
//! TXT value operations on plain values. The TXT value operations use the API's value-level
//! call, so they add one value and remove only the values that equal ours and never write a
//! foreign one (see [`ValueGuarantee::PerValue`](crate::ValueGuarantee::PerValue)). The
//! record-level operations read an rrset and then create it or replace it whole in one request;
//! the API checks no condition, so a change made by another process in between is overwritten
//! (see [`Preconditions::ReadThenWrite`](crate::Preconditions::ReadThenWrite)). The zone listing
//! shows the domains of the personal organization, or of the organization the `sharing_id`
//! setting names.

pub(crate) mod meta;

#[cfg(feature = "gandi")]
mod api;
#[cfg(feature = "gandi")]
mod client;
#[cfg(feature = "gandi")]
mod config;
#[cfg(feature = "gandi")]
mod content;
#[cfg(feature = "gandi")]
mod records;
#[cfg(feature = "gandi")]
mod rrset;
#[cfg(feature = "gandi")]
mod txt;

#[cfg(feature = "gandi")]
pub use client::Gandi;
#[cfg(feature = "gandi")]
pub(crate) use client::from_json;
#[cfg(feature = "gandi")]
pub use config::{GandiConfig, GandiCredentials};
