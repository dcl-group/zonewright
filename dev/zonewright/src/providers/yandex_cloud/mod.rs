//! Yandex Cloud (provider ID `yandex_cloud`).
//!
//! The metadata is present in every build. The client is compiled with the cargo feature
//! `yandex_cloud`.

pub(crate) mod meta;

#[cfg(feature = "yandex_cloud")]
mod client;

#[cfg(feature = "yandex_cloud")]
pub use client::YandexCloud;
#[cfg(feature = "yandex_cloud")]
pub(crate) use client::from_json;
