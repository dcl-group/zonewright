//! Yandex 360 (provider ID `yandex_360`).
//!
//! The metadata is present in every build. The client is compiled with the cargo feature
//! `yandex_360`.

pub(crate) mod meta;

#[cfg(feature = "yandex_360")]
mod client;

#[cfg(feature = "yandex_360")]
pub use client::Yandex360;
#[cfg(feature = "yandex_360")]
pub(crate) use client::from_json;
