//! Cloud.ru (provider ID `cloud_ru`).
//!
//! The metadata is present in every build. The client is compiled with the cargo feature
//! `cloud_ru`.

pub(crate) mod meta;

#[cfg(feature = "cloud_ru")]
mod client;

#[cfg(feature = "cloud_ru")]
pub use client::CloudRu;
#[cfg(feature = "cloud_ru")]
pub(crate) use client::from_json;
