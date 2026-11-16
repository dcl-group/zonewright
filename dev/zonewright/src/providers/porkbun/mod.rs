//! Porkbun (provider ID `porkbun`): the Porkbun API v3, authenticated with an API key and its
//! secret API key.
//!
//! The metadata is present in every build. The client, `Porkbun`, with its settings
//! `PorkbunConfig` and credentials `PorkbunCredentials`, is compiled with the cargo feature
//! `porkbun`.
//!
//! This version offers `check`, `list_zones`, the record-level operations (`list_rrsets`,
//! `get_rrset`, `set_rrset`, `delete_rrset`) for A, AAAA, CAA, CNAME, MX, NS, SRV, TLSA and TXT,
//! and the TXT value operations on plain values. The API's unit is the individual record: the
//! TXT value operations create and delete single records and never write a foreign value (see
//! [`ValueGuarantee::PerValue`](crate::ValueGuarantee::PerValue)); replacing an rrset is several
//! requests, creates before deletes, without a condition the provider checks (see
//! [`Preconditions::ReadThenWrite`](crate::Preconditions::ReadThenWrite)).

pub(crate) mod meta;

#[cfg(feature = "porkbun")]
mod api;
#[cfg(feature = "porkbun")]
mod client;
#[cfg(feature = "porkbun")]
mod config;
#[cfg(feature = "porkbun")]
mod records;
#[cfg(feature = "porkbun")]
mod txt;

#[cfg(feature = "porkbun")]
pub use client::Porkbun;
#[cfg(feature = "porkbun")]
pub(crate) use client::from_json;
#[cfg(feature = "porkbun")]
pub use config::{PorkbunConfig, PorkbunCredentials};
