//! Timeweb Cloud (provider ID `timeweb_cloud`): the Timeweb Cloud public API, authenticated with
//! an API token.
//!
//! The metadata is present in every build. The client, `TimewebCloud`, with its settings
//! `TimewebCloudConfig` and credentials `TimewebCloudCredentials`, is compiled with the cargo
//! feature `timeweb_cloud`.
//!
//! This version offers `check`, `list_zones` and the TXT value operations. The TXT value
//! operations accept plain values only. The API's unit is the individual record with an
//! identifier, so they create and delete single records and never write a foreign value (see
//! `ValueGuarantee::PerValue`).
//!
//! A record this process created is remembered by its identifier (see `State`), so that it can
//! be removed even when the zone listing does not show it.

pub(crate) mod meta;

#[cfg(feature = "timeweb_cloud")]
mod api;
#[cfg(feature = "timeweb_cloud")]
mod client;
#[cfg(feature = "timeweb_cloud")]
mod config;
#[cfg(feature = "timeweb_cloud")]
mod txt;

#[cfg(feature = "timeweb_cloud")]
pub use client::TimewebCloud;
#[cfg(feature = "timeweb_cloud")]
pub(crate) use client::from_json;
#[cfg(feature = "timeweb_cloud")]
pub use config::{TimewebCloudConfig, TimewebCloudCredentials};

#[cfg(feature = "timeweb_cloud")]
mod state {
    //! The process-local memory of created records.

    use std::collections::HashMap;
    use std::fmt;
    use std::sync::{Mutex, PoisonError};
    use std::time::{Duration, Instant};

    use crate::name::DomainName;

    /// Most records the memory holds.
    pub(crate) const MAX_ENTRIES: usize = 1024;

    /// How long an entry is kept after the record was created.
    pub(crate) const MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

    /// A record: the API endpoint it was created at, its zone and its identifier. The endpoint
    /// is part of the key so that clients of one `Context` pointed at different servers never
    /// see each other's identifiers. It holds no secret: a validated endpoint has no user info
    /// and no query.
    type Key = (String, DomainName, u64);

    /// What the record held when this process created it, and when that was.
    #[derive(Clone, Debug)]
    struct Entry {
        name: DomainName,
        value: Vec<u8>,
        created: Instant,
    }

    /// Process-local memory of the Timeweb Cloud client: the records this process created, by
    /// ID, so they can be removed even if a listing does not show them (design section 11.3).
    ///
    /// Held by `Context`, so it outlives any one client. It holds at most [`MAX_ENTRIES`]
    /// records; an entry is dropped when its record is removed or [`MAX_AGE`] after the record
    /// was created, and when the memory is full the oldest entry makes room for a new one. It
    /// stores names, values, identifiers and the endpoint, never a credential.
    ///
    /// An identifier is a hint, not proof that the record is still ours: the API can change a
    /// record in place under the same identifier. The client therefore uses an entry only while
    /// a complete listing does not show that identifier at all.
    #[derive(Default)]
    pub(crate) struct State {
        created: Mutex<HashMap<Key, Entry>>,
    }

    impl fmt::Debug for State {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("State")
                .field("records", &self.len())
                .finish()
        }
    }

    impl State {
        fn map(&self) -> std::sync::MutexGuard<'_, HashMap<Key, Entry>> {
            // Every state of the map is usable.
            self.created.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// Number of entries held, expired ones included until they are next purged.
        pub(crate) fn len(&self) -> usize {
            self.map().len()
        }

        /// Remembers that the record `id` of `zone` at `endpoint` was created now with `value`
        /// at `name`.
        pub(crate) fn remember(
            &self,
            endpoint: &str,
            zone: &DomainName,
            name: &DomainName,
            value: &[u8],
            id: u64,
        ) {
            self.remember_at(endpoint, zone, name, value, id, Instant::now());
        }

        pub(crate) fn remember_at(
            &self,
            endpoint: &str,
            zone: &DomainName,
            name: &DomainName,
            value: &[u8],
            id: u64,
            now: Instant,
        ) {
            let mut map = self.map();
            let key = (endpoint.to_owned(), zone.clone(), id);
            if map.len() >= MAX_ENTRIES && !map.contains_key(&key) {
                map.retain(|_, entry| live(entry, now));
                if map.len() >= MAX_ENTRIES {
                    let oldest = map
                        .iter()
                        .min_by_key(|(_, entry)| entry.created)
                        .map(|(key, _)| key.clone());
                    if let Some(oldest) = oldest {
                        map.remove(&oldest);
                    }
                }
            }
            map.insert(
                key,
                Entry {
                    name: name.clone(),
                    value: value.to_vec(),
                    created: now,
                },
            );
        }

        /// The identifiers of the live entries created with `value` at `name` in `zone` at
        /// `endpoint`, in ascending order. Expired entries are dropped.
        pub(crate) fn recall(
            &self,
            endpoint: &str,
            zone: &DomainName,
            name: &DomainName,
            value: &[u8],
        ) -> Vec<u64> {
            self.recall_at(endpoint, zone, name, value, Instant::now())
        }

        pub(crate) fn recall_at(
            &self,
            endpoint: &str,
            zone: &DomainName,
            name: &DomainName,
            value: &[u8],
            now: Instant,
        ) -> Vec<u64> {
            let mut map = self.map();
            map.retain(|_, entry| live(entry, now));
            let mut ids: Vec<u64> = map
                .iter()
                .filter(|((entry_endpoint, entry_zone, _), entry)| {
                    entry_endpoint == endpoint
                        && entry_zone == zone
                        && entry.name == *name
                        && entry.value == value
                })
                .map(|((_, _, id), _)| *id)
                .collect();
            ids.sort_unstable();
            ids
        }

        /// Forgets the record `id` of `zone` at `endpoint`.
        pub(crate) fn forget(&self, endpoint: &str, zone: &DomainName, id: u64) {
            self.map().remove(&(endpoint.to_owned(), zone.clone(), id));
        }
    }

    fn live(entry: &Entry, now: Instant) -> bool {
        now.saturating_duration_since(entry.created) < MAX_AGE
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const AT: &str = "https://api.example.test/api";

        fn dn(text: &str) -> DomainName {
            DomainName::parse(text).unwrap()
        }

        #[test]
        fn remembers_recalls_and_forgets() {
            let state = State::default();
            let (zone, name) = (dn("example.org"), dn("_acme-challenge.example.org"));
            assert!(state.recall(AT, &zone, &name, b"v").is_empty());
            state.remember(AT, &zone, &name, b"v", 7);
            assert_eq!(state.recall(AT, &zone, &name, b"v"), [7]);
            assert!(state.recall(AT, &zone, &name, b"w").is_empty());
            assert!(state.recall(AT, &dn("example.net"), &name, b"v").is_empty());
            assert!(state.recall(AT, &zone, &dn("example.org"), b"v").is_empty());
            assert!(
                state
                    .recall("http://127.0.0.1:9/api", &zone, &name, b"v")
                    .is_empty()
            );
            state.forget(AT, &dn("example.net"), 7);
            state.forget("http://127.0.0.1:9/api", &zone, 7);
            assert_eq!(state.recall(AT, &zone, &name, b"v"), [7]);
            state.forget(AT, &zone, 7);
            assert!(state.recall(AT, &zone, &name, b"v").is_empty());
            assert_eq!(state.len(), 0);
        }

        #[test]
        fn every_copy_of_a_value_is_remembered() {
            let state = State::default();
            let (zone, name) = (dn("example.org"), dn("_acme-challenge.example.org"));
            state.remember(AT, &zone, &name, b"v", 9);
            state.remember(AT, &zone, &name, b"v", 7);
            assert_eq!(state.recall(AT, &zone, &name, b"v"), [7, 9]);
            // An identifier the provider hands out again replaces what was remembered for it.
            state.remember(AT, &zone, &name, b"w", 7);
            assert_eq!(state.recall(AT, &zone, &name, b"v"), [9]);
            assert_eq!(state.recall(AT, &zone, &name, b"w"), [7]);
        }

        #[test]
        fn entries_expire_after_a_day() {
            let state = State::default();
            let (zone, name) = (dn("example.org"), dn("a.example.org"));
            let start = Instant::now();
            state.remember_at(AT, &zone, &name, b"v", 1, start);
            let almost = start + MAX_AGE - Duration::from_secs(1);
            assert_eq!(state.recall_at(AT, &zone, &name, b"v", almost), [1]);
            let expired = start + MAX_AGE;
            assert!(state.recall_at(AT, &zone, &name, b"v", expired).is_empty());
            assert_eq!(state.len(), 0);
        }

        #[test]
        fn memory_is_bounded_and_drops_the_oldest() {
            let state = State::default();
            let zone = dn("example.org");
            let name = dn("a.example.org");
            let start = Instant::now();
            for i in 0..MAX_ENTRIES + 10 {
                let n = u64::try_from(i).unwrap();
                let at = start + Duration::from_secs(n);
                state.remember_at(AT, &zone, &name, format!("v{i}").as_bytes(), n, at);
            }
            assert_eq!(state.len(), MAX_ENTRIES);
            let now = start + Duration::from_secs(5000);
            assert!(state.recall_at(AT, &zone, &name, b"v0", now).is_empty());
            assert!(state.recall_at(AT, &zone, &name, b"v9", now).is_empty());
            assert_eq!(state.recall_at(AT, &zone, &name, b"v10", now), [10]);
            let last = format!("v{}", MAX_ENTRIES + 9);
            assert_eq!(
                state
                    .recall_at(AT, &zone, &name, last.as_bytes(), now)
                    .len(),
                1
            );
        }
    }
}

#[cfg(feature = "timeweb_cloud")]
pub(crate) use state::State;
