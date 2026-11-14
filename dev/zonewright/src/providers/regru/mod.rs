//! reg.ru (provider ID `regru`).
//!
//! The metadata is present in every build. The client is compiled with the cargo feature
//! `regru`.

pub(crate) mod meta;

#[cfg(feature = "regru")]
mod client;

#[cfg(feature = "regru")]
pub use client::Regru;
#[cfg(feature = "regru")]
pub(crate) use client::from_json;
