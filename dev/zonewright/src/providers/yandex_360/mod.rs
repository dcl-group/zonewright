//! Yandex 360 (provider ID `yandex_360`): the DNS service of API 360 for business, authenticated
//! with the OAuth token of an application.
//!
//! The metadata is present in every build. The client, `Yandex360`, with its settings
//! `Yandex360Config` and credentials `Yandex360Credentials`, is compiled with the cargo
//! feature `yandex_360`.
//!
//! This version offers `check`, `list_zones`, the record-level operations (`list_rrsets`,
//! `get_rrset`, `set_rrset`, `delete_rrset`) for A, AAAA, CAA, CNAME, MX, SRV and TXT, and the
//! TXT value operations on plain values. The API's unit is the individual record: the TXT value
//! operations create and delete single records and never write a foreign value (see
//! [`ValueGuarantee::PerValue`](crate::ValueGuarantee::PerValue)); replacing an rrset is several
//! requests, creates before deletes, without a condition the provider checks (see
//! [`Preconditions::ReadThenWrite`](crate::Preconditions::ReadThenWrite)). NS records are listed
//! as skipped sets: the API's documentation does not name the field of their value. Only domains
//! delegated to Yandex name servers can be managed.
//!
//! The record level writes the zone's own name as `@`, as the help page of the provider's console
//! does; the TXT value operations still refuse to add a value there.

pub(crate) mod meta;

#[cfg(feature = "yandex_360")]
mod api;
#[cfg(feature = "yandex_360")]
mod client;
#[cfg(feature = "yandex_360")]
mod config;
#[cfg(feature = "yandex_360")]
mod records;
#[cfg(feature = "yandex_360")]
mod txt;

#[cfg(feature = "yandex_360")]
pub use client::Yandex360;
#[cfg(feature = "yandex_360")]
pub(crate) use client::from_json;
#[cfg(feature = "yandex_360")]
pub use config::{Yandex360Config, Yandex360Credentials};
