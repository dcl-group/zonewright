//! Cloud.ru (provider ID `cloud_ru`): the public zones of Cloud.ru Evolution DNS, authenticated
//! with an access key exchanged for a bearer token.
//!
//! The metadata is present in every build. The client, `CloudRu`, with its settings
//! `CloudRuConfig` and credentials `CloudRuCredentials`, is compiled with the cargo feature
//! `cloud_ru`.
//!
//! This version offers `check`, `list_zones` and the TXT value operations. The TXT value
//! operations accept plain values only. They read the record that holds every value of the name,
//! read it again immediately before the write and refuse with `Error::Conflict` if it changed,
//! and write it back whole: a concurrent writer outside this process can still lose its change
//! in the remaining window (see
//! [`ValueGuarantee::ReadThenWrite`](crate::ValueGuarantee::ReadThenWrite)). Every write waits
//! for the provider-side operation it starts.

pub(crate) mod meta;

#[cfg(feature = "cloud_ru")]
mod api;
#[cfg(feature = "cloud_ru")]
mod client;
#[cfg(feature = "cloud_ru")]
mod config;
#[cfg(feature = "cloud_ru")]
mod txt;

#[cfg(feature = "cloud_ru")]
pub use client::CloudRu;
#[cfg(feature = "cloud_ru")]
pub(crate) use client::from_json;
#[cfg(feature = "cloud_ru")]
pub use config::{CloudRuConfig, CloudRuCredentials};
