//! RFC 2136 (provider ID `rfc2136`).
//!
//! The metadata is present in every build. The client is compiled with the cargo feature
//! `rfc2136`.

pub(crate) mod meta;

#[cfg(feature = "rfc2136")]
mod client;

#[cfg(feature = "rfc2136")]
pub use client::Rfc2136;
#[cfg(feature = "rfc2136")]
pub(crate) use client::from_json;
