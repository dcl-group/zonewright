//! Cloudflare (provider ID `cloudflare`): the Cloudflare DNS API v4, authenticated with an API
//! token.
//!
//! The metadata is present in every build. The client, `Cloudflare`, with its settings
//! `CloudflareConfig` and credentials `CloudflareCredentials`, is compiled with the cargo
//! feature `cloudflare`.
//!
//! This version offers `check`, `list_zones` and the TXT value operations. The TXT value
//! operations accept plain values only; the API's unit is the individual record, so they create
//! and delete single records and never touch a foreign value (see
//! [`ValueGuarantee::PerValue`](crate::ValueGuarantee::PerValue)).

pub(crate) mod meta;

#[cfg(feature = "cloudflare")]
mod api;
#[cfg(feature = "cloudflare")]
mod client;
#[cfg(feature = "cloudflare")]
mod config;
#[cfg(feature = "cloudflare")]
mod txt;

#[cfg(feature = "cloudflare")]
pub use client::Cloudflare;
#[cfg(feature = "cloudflare")]
pub(crate) use client::from_json;
#[cfg(feature = "cloudflare")]
pub use config::{CloudflareConfig, CloudflareCredentials};
