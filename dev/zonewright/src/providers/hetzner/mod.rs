//! Hetzner (provider ID `hetzner`): the Hetzner Cloud API's zones and RRSets, authenticated with
//! a project API token. This is not the legacy DNS API.
//!
//! The metadata is present in every build. The client, `Hetzner`, with its settings
//! `HetznerConfig` and credentials `HetznerCredentials`, is compiled with the cargo feature
//! `hetzner`.
//!
//! This version offers `check`, `list_zones` and the TXT value operations. The TXT value
//! operations accept plain values only. The API changes an rrset by value, so they add one value
//! and remove only the values that equal ours and never write a foreign one (see
//! [`ValueGuarantee::PerValue`](crate::ValueGuarantee::PerValue)). Only zones in primary mode can
//! be changed. Writes are actions the API completes asynchronously; an operation returns after
//! its action has finished.

pub(crate) mod meta;

#[cfg(feature = "hetzner")]
mod api;
#[cfg(feature = "hetzner")]
mod client;
#[cfg(feature = "hetzner")]
mod config;
#[cfg(feature = "hetzner")]
mod txt;

#[cfg(feature = "hetzner")]
pub use client::Hetzner;
#[cfg(feature = "hetzner")]
pub(crate) use client::from_json;
#[cfg(feature = "hetzner")]
pub use config::{HetznerConfig, HetznerCredentials};
