//! Hetzner (provider ID `hetzner`).
//!
//! The metadata is present in every build. The client is compiled with the cargo feature
//! `hetzner`.

pub(crate) mod meta;

#[cfg(feature = "hetzner")]
mod client;

#[cfg(feature = "hetzner")]
pub use client::Hetzner;
#[cfg(feature = "hetzner")]
pub(crate) use client::from_json;
