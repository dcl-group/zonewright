//! nic.ru (provider ID `nicru`): the RU-CENTER DNS hosting API ("DNS-master"), authenticated
//! with the provider's OAuth 2 server.
//!
//! The metadata is present in every build. The client, `Nicru`, with its settings
//! `NicruConfig` and credentials `NicruCredentials`, is compiled with the cargo feature
//! `nicru`.
//!
//! This version offers `check`, `list_zones`, the TXT value operations for plain values, and the
//! record-level operations for A, AAAA, CNAME, DNAME, MX, NS, PTR, SRV and TXT (SOA read only).
//! Every value is a record of its own, so a request never names a foreign value. Changes are
//! staged and published by a commit that covers the whole zone: the client refuses a zone that
//! has staged changes it did not make, publishes all edits of one operation with one commit,
//! rolls back the edits of an operation that failed part-way, and a zone left with this
//! process's staged changes when the process ends has to be committed or rolled back by hand.

pub(crate) mod meta;

#[cfg(feature = "nicru")]
mod api;
#[cfg(feature = "nicru")]
mod client;
#[cfg(feature = "nicru")]
mod config;
#[cfg(feature = "nicru")]
mod records;
#[cfg(feature = "nicru")]
mod txt;

#[cfg(feature = "nicru")]
pub use client::Nicru;
#[cfg(feature = "nicru")]
pub(crate) use client::from_json;
#[cfg(feature = "nicru")]
pub use config::{NicruConfig, NicruCredentials};

/// Process-local state of the nic.ru client (design section 11.3): a lock per zone, held for the
/// whole read, edit and commit, and the zones that hold staged changes of this process, with
/// what is to become of them.
///
/// Held by [`Context`](crate::Context), so it outlives any one client. It is lost with the
/// process: a zone left with staged changes of this process then needs a commit by hand.
#[cfg(feature = "nicru")]
#[derive(Debug, Default)]
pub(crate) struct State {
    /// One lock per zone, taken after the name lock (design section 3.3).
    pub(crate) zone_locks: crate::locks::NameLocks,
    /// Zones in which this process has staged changes that are not committed yet.
    pub(crate) staged:
        std::sync::Mutex<std::collections::HashMap<crate::name::DomainName, Pending>>,
}

/// What the next operation in a zone does with staged changes of this process it finds there.
#[cfg(feature = "nicru")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pending {
    /// They are a complete change (one TXT edit, or every edit of a record-level operation):
    /// commit them.
    Commit,
    /// They may be part of a record-level change that did not finish: roll them back, so that a
    /// half-applied replacement is never published.
    Rollback,
}
