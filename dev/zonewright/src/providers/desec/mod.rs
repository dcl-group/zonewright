//! deSEC (provider ID `desec`): the deSEC DNS API (`https://desec.io/api/v1`), authenticated
//! with an API token.
//!
//! The metadata is present in every build. The client, `Desec`, with its settings `DesecConfig`
//! and credentials `DesecCredentials`, is compiled with the cargo feature `desec`.
//!
//! This version offers `check`, `list_zones`, the record-level operations (`list_rrsets`,
//! `get_rrset`, `set_rrset`, `delete_rrset`) for A, AAAA, CAA, CNAME, DNAME, HTTPS, MX, NS, PTR,
//! SRV, SSHFP, SVCB, TLSA and TXT, and the TXT value operations on any value. Every write reads
//! the rrset and writes it back whole: a concurrent writer outside this process can lose its
//! change (see [`Preconditions::ReadThenWrite`](crate::Preconditions::ReadThenWrite) and
//! [`ValueGuarantee::ReadThenWrite`](crate::ValueGuarantee::ReadThenWrite)). The provider's rate
//! limits are tight, especially for writes; a throttled write ends with
//! [`Error::RateLimited`](crate::Error::RateLimited).

pub(crate) mod meta;

#[cfg(feature = "desec")]
mod api;
#[cfg(feature = "desec")]
mod client;
#[cfg(feature = "desec")]
mod config;
#[cfg(feature = "desec")]
mod records;
#[cfg(feature = "desec")]
mod rrset;
#[cfg(feature = "desec")]
mod txt;

#[cfg(feature = "desec")]
pub use client::Desec;
#[cfg(feature = "desec")]
pub(crate) use client::from_json;
#[cfg(feature = "desec")]
pub use config::{DesecConfig, DesecCredentials};
