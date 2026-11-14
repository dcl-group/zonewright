//! nic.ru (provider ID `nicru`).
//!
//! The metadata is present in every build. The client is compiled with the cargo feature
//! `nicru`.

pub(crate) mod meta;

#[cfg(feature = "nicru")]
mod client;

#[cfg(feature = "nicru")]
pub use client::Nicru;
#[cfg(feature = "nicru")]
pub(crate) use client::from_json;

/// Process-local state of the nic.ru client (design section 11.3): a lock per zone, held for the
/// whole read, edit and commit, and the zones that hold staged changes of this process.
///
/// Held by [`Context`](crate::Context), so it outlives any one client.
#[cfg(feature = "nicru")]
// TEMPORARY (core phase): read by the client when it is ported.
#[allow(dead_code)]
#[derive(Debug, Default)]
pub(crate) struct State {
    /// One lock per zone, taken after the name lock (design section 3.3).
    pub(crate) zone_locks: crate::locks::NameLocks,
    /// Zones in which this process has staged changes that are not committed yet.
    pub(crate) staged: std::sync::Mutex<std::collections::HashSet<crate::name::DomainName>>,
}
