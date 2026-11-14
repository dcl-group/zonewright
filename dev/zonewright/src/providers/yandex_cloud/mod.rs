//! Yandex Cloud (provider ID `yandex_cloud`): Yandex Cloud DNS, authenticated with a service
//! account's authorized key through the provider's IAM token service.
//!
//! The metadata is present in every build. The client, `YandexCloud`, with its settings
//! `YandexCloudConfig` and credentials `YandexCloudCredentials` (holding an `AuthorizedKey`),
//! is compiled with the cargo feature `yandex_cloud`.
//!
//! This version offers `check`, `list_zones`, the record-level operations and the TXT value
//! operations. The TXT value operations accept plain values only. Every write reads the record
//! set and writes it back with the provider's strict call, which refuses the write if the set
//! changed after the read, so a concurrent writer outside this process cannot lose its change
//! (see [`ValueGuarantee::Conditional`](crate::ValueGuarantee::Conditional) and
//! [`Preconditions::Atomic`](crate::Preconditions::Atomic)).

pub(crate) mod meta;

#[cfg(feature = "yandex_cloud")]
mod api;
#[cfg(feature = "yandex_cloud")]
mod client;
#[cfg(feature = "yandex_cloud")]
mod config;
#[cfg(feature = "yandex_cloud")]
mod records;
#[cfg(feature = "yandex_cloud")]
mod rrset;
#[cfg(feature = "yandex_cloud")]
mod txt;

#[cfg(feature = "yandex_cloud")]
pub use client::YandexCloud;
#[cfg(feature = "yandex_cloud")]
pub(crate) use client::from_json;
#[cfg(feature = "yandex_cloud")]
pub use config::{AuthorizedKey, YandexCloudConfig, YandexCloudCredentials};
