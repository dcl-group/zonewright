//! nic.ru (provider ID `nicru`): the RU-CENTER DNS hosting API ("DNS-master"), authenticated
//! with the provider's OAuth 2 server.
//!
//! The metadata is present in every build. The client, `Nicru`, with its settings
//! `NicruConfig` and credentials `NicruCredentials`, is compiled with the cargo feature
//! `nicru`.
//!
//! This version offers `check`, `list_zones` and the TXT value operations, for plain values
//! only. Every value is a record of its own, so a request never names a foreign value. Changes
//! are staged and published by a commit that covers the whole zone: the client refuses a zone
//! that has staged changes it did not make, and a zone left with this process's staged changes
//! when the process ends has to be committed by hand.

pub(crate) mod meta;

#[cfg(feature = "nicru")]
mod api;
#[cfg(feature = "nicru")]
mod client;
#[cfg(feature = "nicru")]
mod config;
#[cfg(feature = "nicru")]
mod txt;

#[cfg(feature = "nicru")]
pub use client::Nicru;
#[cfg(feature = "nicru")]
pub(crate) use client::from_json;
#[cfg(feature = "nicru")]
pub use config::{NicruConfig, NicruCredentials};

/// Process-local state of the nic.ru client (design section 11.3): a lock per zone, held for the
/// whole read, edit and commit, and the zones that hold staged changes of this process.
///
/// Held by [`Context`](crate::Context), so it outlives any one client. It is lost with the
/// process: a zone left with staged changes of this process then needs a commit by hand.
#[cfg(feature = "nicru")]
#[derive(Debug, Default)]
pub(crate) struct State {
    /// One lock per zone, taken after the name lock (design section 3.3).
    pub(crate) zone_locks: crate::locks::NameLocks,
    /// Zones in which this process has staged changes that are not committed yet.
    pub(crate) staged: std::sync::Mutex<std::collections::HashSet<crate::name::DomainName>>,
}
