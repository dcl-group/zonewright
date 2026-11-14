//! acme-dns (provider ID `acme_dns`).
//!
//! The metadata is present in every build. The client is compiled with the cargo feature
//! `acme_dns`.

pub(crate) mod meta;

#[cfg(feature = "acme_dns")]
mod client;

#[cfg(feature = "acme_dns")]
pub use client::AcmeDns;
#[cfg(feature = "acme_dns")]
pub(crate) use client::from_json;

// PLACEHOLDER: the acme_dns client defines the contents of its state when it is ported.
/// Process-local memory of the acme-dns client: per server URL and name, the values this process
/// sent (design section 11.3).
///
/// Held by [`Context`](crate::Context), so it outlives any one client.
#[cfg(feature = "acme_dns")]
// TEMPORARY (core phase): read by the client when it is ported.
#[allow(dead_code)]
#[derive(Debug, Default)]
pub(crate) struct State {}
