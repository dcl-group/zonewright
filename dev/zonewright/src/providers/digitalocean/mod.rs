//! DigitalOcean (provider ID `digitalocean`).
//!
//! The metadata is present in every build. The client is compiled with the cargo feature
//! `digitalocean`.

pub(crate) mod meta;

#[cfg(feature = "digitalocean")]
mod client;

#[cfg(feature = "digitalocean")]
pub use client::DigitalOcean;
#[cfg(feature = "digitalocean")]
pub(crate) use client::from_json;
