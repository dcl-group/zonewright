//! acme-dns (provider ID `acme_dns`): the HTTP API of an acme-dns server
//! (<https://github.com/joohoi/acme-dns>).
//!
//! The metadata is present in every build. The client, `AcmeDns`, with its settings
//! `AcmeDnsConfig` and credentials `AcmeDnsCredentials`, is compiled with the cargo feature
//! `acme_dns`.
//!
//! acme-dns is a small authoritative DNS server for DNS-01 challenges. The application creates a
//! registration once (the server's register call), points the `_acme-challenge` name of each
//! domain at the registration's `fulldomain` with a CNAME, and later stores challenge values
//! through the update call. That call is the whole API: there is no read, no delete and nothing
//! but TXT, and the server keeps the two most recent values per registration.
//!
//! This version therefore offers `check` and `add_txt_value` only:
//!
//! - `add_txt_value` always returns `AddOutcome::Accepted`, because the state before the write
//!   cannot be observed. The client keeps a bounded process-local memory of recent sends so that
//!   a needless repeat, which the server would write into the other slot, does not displace a
//!   live value (design section 11.3, `docs/design/11-providers.md` in the repository).
//! - `remove_txt_value` is not offered (`Error::Unsupported`, capability off). The server drops
//!   the oldest value when a third arrives; the application decides that a missing removal is
//!   acceptable.
//! - `list_zones` and every record-level operation are not offered.
//!
//! The "zone" of this provider is the acme-dns server's own domain, and the name of a value is the
//! `fulldomain` of a registration.

pub(crate) mod meta;

#[cfg(feature = "acme_dns")]
mod api;
#[cfg(feature = "acme_dns")]
mod client;
#[cfg(feature = "acme_dns")]
mod config;
#[cfg(feature = "acme_dns")]
mod state;

#[cfg(feature = "acme_dns")]
pub use client::AcmeDns;
#[cfg(feature = "acme_dns")]
pub(crate) use client::from_json;
#[cfg(feature = "acme_dns")]
pub use config::{AcmeDnsConfig, AcmeDnsCredentials};
#[cfg(feature = "acme_dns")]
pub(crate) use state::State;
