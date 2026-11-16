//! RFC 2136 (provider ID `rfc2136`): DNS dynamic update (RFC 2136) authenticated with TSIG
//! (RFC 8945), sent over TCP to a name server the application's operator runs.
//!
//! The metadata is present in every build. The client, `Rfc2136`, with its settings
//! `Rfc2136Config` and credentials `Rfc2136Credentials`, is compiled with the cargo feature
//! `rfc2136`. It does not use HTTP: it speaks DNS over TCP with its own wire format and TSIG.
//!
//! This version offers `check`, the TXT value operations, the record-level operations `get`,
//! `set` and `delete` for every type with a type code, and `list_rrsets` by zone transfer
//! (AXFR, RFC 5936, signed with the same key). The TXT value operations add and remove one RR at
//! a time, so a foreign value is never part of a write
//! ([`ValueGuarantee::PerValue`](crate::ValueGuarantee::PerValue)). The record-level operations
//! read by query and write one UPDATE per operation whose prerequisites name the RRset as read
//! ([`Preconditions::Atomic`](crate::Preconditions::Atomic)); they need a key that may query the
//! zone. The listing needs a key that may transfer the zone. The protocol has no listing of
//! zones.

pub(crate) mod meta;

#[cfg(feature = "rfc2136")]
mod axfr;
#[cfg(feature = "rfc2136")]
mod client;
#[cfg(feature = "rfc2136")]
mod config;
#[cfg(feature = "rfc2136")]
mod listing;
#[cfg(feature = "rfc2136")]
mod records;
#[cfg(feature = "rfc2136")]
mod transport;
#[cfg(feature = "rfc2136")]
mod tsig;
#[cfg(feature = "rfc2136")]
mod txt;
#[cfg(feature = "rfc2136")]
mod wire;

#[cfg(feature = "rfc2136")]
pub use client::Rfc2136;
#[cfg(feature = "rfc2136")]
pub(crate) use client::from_json;
#[cfg(feature = "rfc2136")]
pub use config::{Rfc2136Config, Rfc2136Credentials};
