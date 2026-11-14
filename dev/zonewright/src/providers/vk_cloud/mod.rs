//! VK Cloud (provider ID `vk_cloud`): the VK Cloud public DNS API, authenticated through the
//! provider's Keystone identity service.
//!
//! The metadata is present in every build. The client, `VkCloud`, with its settings
//! `VkCloudConfig` and credentials `VkCloudCredentials`, is compiled with the cargo feature
//! `vk_cloud`.
//!
//! This version offers `check`, `list_zones` and the TXT value operations. The TXT value
//! operations accept plain values only; the API's unit is the individual TXT record, so they
//! create and delete single records and never touch a foreign value (see
//! [`ValueGuarantee::PerValue`](crate::ValueGuarantee::PerValue)).

pub(crate) mod meta;

#[cfg(feature = "vk_cloud")]
mod api;
#[cfg(feature = "vk_cloud")]
mod client;
#[cfg(feature = "vk_cloud")]
mod config;
#[cfg(feature = "vk_cloud")]
mod txt;

#[cfg(feature = "vk_cloud")]
pub use client::VkCloud;
#[cfg(feature = "vk_cloud")]
pub(crate) use client::from_json;
#[cfg(feature = "vk_cloud")]
pub use config::{VkCloudConfig, VkCloudCredentials};
