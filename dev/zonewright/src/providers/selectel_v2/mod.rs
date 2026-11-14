//! Selectel v2 (provider ID `selectel_v2`).
//!
//! The metadata is present in every build. The client is compiled with the cargo feature
//! `selectel_v2`.

pub(crate) mod meta;

#[cfg(feature = "selectel_v2")]
mod client;

#[cfg(feature = "selectel_v2")]
pub use client::SelectelV2;
#[cfg(feature = "selectel_v2")]
pub(crate) use client::from_json;
