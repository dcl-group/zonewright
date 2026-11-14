//! Route 53 (provider ID `route53`).
//!
//! The metadata is present in every build. The client is compiled with the cargo feature
//! `route53`.

pub(crate) mod meta;

#[cfg(feature = "route53")]
mod client;

#[cfg(feature = "route53")]
pub use client::Route53;
#[cfg(feature = "route53")]
pub(crate) use client::from_json;
