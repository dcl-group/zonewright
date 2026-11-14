//! Cloudflare (provider ID `cloudflare`).
//!
//! The metadata is present in every build. The client is compiled with the cargo feature
//! `cloudflare`.

pub(crate) mod meta;

#[cfg(feature = "cloudflare")]
mod client;

#[cfg(feature = "cloudflare")]
pub use client::Cloudflare;
#[cfg(feature = "cloudflare")]
pub(crate) use client::from_json;
