//! VK Cloud (provider ID `vk_cloud`).
//!
//! The metadata is present in every build. The client is compiled with the cargo feature
//! `vk_cloud`.

pub(crate) mod meta;

#[cfg(feature = "vk_cloud")]
mod client;

#[cfg(feature = "vk_cloud")]
pub use client::VkCloud;
#[cfg(feature = "vk_cloud")]
pub(crate) use client::from_json;
