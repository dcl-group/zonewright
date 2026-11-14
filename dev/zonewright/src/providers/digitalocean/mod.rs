//! DigitalOcean (provider ID `digitalocean`): the DigitalOcean DNS API v2, authenticated with a
//! personal access token.
//!
//! The metadata is present in every build. The client, `DigitalOcean`, with its settings
//! `DigitalOceanConfig` and credentials `DigitalOceanCredentials`, is compiled with the
//! cargo feature `digitalocean`.
//!
//! This version offers `check`, `list_zones`, the record-level operations (`list_rrsets`,
//! `get_rrset`, `set_rrset`, `delete_rrset`) for A, AAAA, CAA, CNAME, MX, NS, SRV and TXT, with
//! SOA read-only, and the TXT value operations on plain values. The API's unit is the individual
//! record: the TXT value operations create and delete single records and never write a foreign
//! value (see [`ValueGuarantee::PerValue`](crate::ValueGuarantee::PerValue)); replacing an rrset
//! is several requests, creates before deletes, without a condition the provider checks (see
//! [`Preconditions::ReadThenWrite`](crate::Preconditions::ReadThenWrite)).

pub(crate) mod meta;

#[cfg(feature = "digitalocean")]
mod api;
#[cfg(feature = "digitalocean")]
mod client;
#[cfg(feature = "digitalocean")]
mod config;
#[cfg(feature = "digitalocean")]
mod records;
#[cfg(feature = "digitalocean")]
mod txt;

#[cfg(feature = "digitalocean")]
pub use client::DigitalOcean;
#[cfg(feature = "digitalocean")]
pub(crate) use client::from_json;
#[cfg(feature = "digitalocean")]
pub use config::{DigitalOceanConfig, DigitalOceanCredentials};
