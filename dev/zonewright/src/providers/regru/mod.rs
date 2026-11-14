//! reg.ru (provider ID `regru`): the reg.ru API 2, authenticated with the account's user name
//! and API password and, when the account requires it, a TLS client certificate.
//!
//! The metadata is present in every build. The client, `Regru`, with its settings `RegruConfig`
//! and credentials `RegruCredentials`, is compiled with the cargo feature `regru`.
//!
//! This version offers `check`, the TXT value operations and the record-level operations for A,
//! AAAA and TXT. The API has no zone listing, so `list_zones` is unsupported. No operation can set
//! a TTL, and TXT values are plain values only. The API's unit is the individual record without
//! an identifier, removed by its content, so the TXT value operations never write a foreign value
//! (see [`ValueGuarantee::PerValue`](crate::ValueGuarantee::PerValue)) and replacing an rrset is
//! several requests, creates before removals.

pub(crate) mod meta;

#[cfg(feature = "regru")]
mod api;
#[cfg(feature = "regru")]
mod client;
#[cfg(feature = "regru")]
mod config;
#[cfg(feature = "regru")]
mod records;
#[cfg(feature = "regru")]
mod txt;

#[cfg(feature = "regru")]
pub use client::Regru;
#[cfg(feature = "regru")]
pub(crate) use client::from_json;
#[cfg(feature = "regru")]
pub use config::{RegruConfig, RegruCredentials};
