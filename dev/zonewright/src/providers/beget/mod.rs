//! Beget (provider ID `beget`).
//!
//! The metadata is present in every build. The client is compiled with the cargo feature
//! `beget`.

pub(crate) mod meta;

#[cfg(feature = "beget")]
mod client;

#[cfg(feature = "beget")]
pub use client::Beget;
#[cfg(feature = "beget")]
pub(crate) use client::from_json;
