//! Timeweb Cloud (provider ID `timeweb_cloud`).
//!
//! The metadata is present in every build. The client is compiled with the cargo feature
//! `timeweb_cloud`.

pub(crate) mod meta;

#[cfg(feature = "timeweb_cloud")]
mod client;

#[cfg(feature = "timeweb_cloud")]
pub use client::TimewebCloud;
#[cfg(feature = "timeweb_cloud")]
pub(crate) use client::from_json;

// PLACEHOLDER: the timeweb_cloud client defines the contents of its state when it is ported.
/// Process-local memory of the Timeweb Cloud client: the records this process created, by ID, so
/// they can be removed even if a listing does not show them (design section 11.3).
///
/// Held by [`Context`](crate::Context), so it outlives any one client.
#[cfg(feature = "timeweb_cloud")]
// TEMPORARY (core phase): read by the client when it is ported.
#[allow(dead_code)]
#[derive(Debug, Default)]
pub(crate) struct State {}
