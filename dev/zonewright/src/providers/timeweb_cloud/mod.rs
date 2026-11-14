//! Timeweb Cloud (provider ID `timeweb_cloud`): the Timeweb Cloud public API, authenticated with
//! an API token.
//!
//! The metadata is present in every build. The client, `TimewebCloud`, with its settings
//! `TimewebCloudConfig` and credentials `TimewebCloudCredentials`, is compiled with the cargo
//! feature `timeweb_cloud`.
//!
//! This version offers `check`, `list_zones`, the TXT value operations and the record-level
//! operations for A, AAAA, CNAME, MX and TXT. The TXT value operations accept plain values only.
//! The API's unit is the individual record with an identifier, so they create and delete single
//! records and never write a foreign value (see `ValueGuarantee::PerValue`); a record-level
//! replacement is several requests, creates before deletes.
//!
//! Records are created and deleted with the provider's `v2` calls. Every read, of one name or
//! of the whole zone, lists the zone and each of its subdomains, so a read of a name and the
//! listing of the zone always agree; a record whose stated name could be at either of two names
//! is never guessed at. The client keeps no state between operations.

pub(crate) mod meta;

#[cfg(feature = "timeweb_cloud")]
mod api;
#[cfg(feature = "timeweb_cloud")]
mod client;
#[cfg(feature = "timeweb_cloud")]
mod config;
#[cfg(feature = "timeweb_cloud")]
mod names;
#[cfg(feature = "timeweb_cloud")]
mod records;
#[cfg(feature = "timeweb_cloud")]
mod txt;

#[cfg(feature = "timeweb_cloud")]
pub use client::TimewebCloud;
#[cfg(feature = "timeweb_cloud")]
pub(crate) use client::from_json;
#[cfg(feature = "timeweb_cloud")]
pub use config::{TimewebCloudConfig, TimewebCloudCredentials};
