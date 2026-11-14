//! Yandex 360 (provider ID `yandex_360`): the DNS service of API 360 for business, authenticated
//! with the OAuth token of an application.
//!
//! The metadata is present in every build. The client, `Yandex360`, with its settings
//! `Yandex360Config` and credentials `Yandex360Credentials`, is compiled with the cargo
//! feature `yandex_360`.
//!
//! This version offers `check`, `list_zones` and the TXT value operations. The TXT value
//! operations accept plain values only. The API's unit is the individual record, so they create
//! and delete single records and never write a foreign value (see
//! [`ValueGuarantee::PerValue`](crate::ValueGuarantee::PerValue)). Only domains delegated to
//! Yandex name servers can be managed.

pub(crate) mod meta;

#[cfg(feature = "yandex_360")]
mod api;
#[cfg(feature = "yandex_360")]
mod client;
#[cfg(feature = "yandex_360")]
mod config;
#[cfg(feature = "yandex_360")]
mod txt;

#[cfg(feature = "yandex_360")]
pub use client::Yandex360;
#[cfg(feature = "yandex_360")]
pub(crate) use client::from_json;
#[cfg(feature = "yandex_360")]
pub use config::{Yandex360Config, Yandex360Credentials};
