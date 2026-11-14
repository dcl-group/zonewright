//! Timeweb Cloud (provider ID `timeweb_cloud`): the Timeweb Cloud public API, authenticated with
//! an API token.
//!
//! The metadata is present in every build. The client, `TimewebCloud`, with its settings
//! `TimewebCloudConfig` and credentials `TimewebCloudCredentials`, is compiled with the cargo
//! feature `timeweb_cloud`.
//!
//! This version offers `check`, `list_zones` and the TXT value operations. The TXT value
//! operations accept plain values only. The API's unit is the individual record with an
//! identifier, so they create and delete single records and never write a foreign value (see
//! `ValueGuarantee::PerValue`).
//!
//! Records are created and deleted with the provider's `v2` calls and read with the listing of
//! the owner name; the client keeps no state between operations.

pub(crate) mod meta;

#[cfg(feature = "timeweb_cloud")]
mod api;
#[cfg(feature = "timeweb_cloud")]
mod client;
#[cfg(feature = "timeweb_cloud")]
mod config;
#[cfg(feature = "timeweb_cloud")]
mod txt;

#[cfg(feature = "timeweb_cloud")]
pub use client::TimewebCloud;
#[cfg(feature = "timeweb_cloud")]
pub(crate) use client::from_json;
#[cfg(feature = "timeweb_cloud")]
pub use config::{TimewebCloudConfig, TimewebCloudCredentials};
