//! Route 53 (provider ID `route53`): the Amazon Route 53 API, authenticated with AWS Signature
//! Version 4.
//!
//! The metadata is present in every build. The client, `Route53`, with its settings
//! `Route53Config` and credentials `Route53Credentials`, is compiled with the cargo feature
//! `route53`.
//!
//! This version offers `check`, `list_zones`, the record-level operations and the TXT value
//! operations. The TXT value operations accept plain values only. Every write changes the rrset
//! with an atomic change batch that repeats the old set as read, so a concurrent change by a
//! writer outside this process makes the provider refuse the write instead of losing that
//! change (see [`ValueGuarantee::Conditional`](crate::ValueGuarantee::Conditional) and
//! [`Preconditions::Atomic`](crate::Preconditions::Atomic)). Alias and routing-policy sets are
//! reported in a listing as sets the model cannot hold and are never changed.

pub(crate) mod meta;

#[cfg(feature = "route53")]
mod api;
#[cfg(feature = "route53")]
mod client;
#[cfg(feature = "route53")]
mod config;
#[cfg(feature = "route53")]
mod content;
#[cfg(feature = "route53")]
mod records;
#[cfg(feature = "route53")]
mod txt;

#[cfg(feature = "route53")]
pub use client::Route53;
#[cfg(feature = "route53")]
pub(crate) use client::from_json;
#[cfg(feature = "route53")]
pub use config::{Route53Config, Route53Credentials};
