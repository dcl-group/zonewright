//! The cache of provider zone identifiers (design section 3.8).
//!
//! Clients cache the provider's identifier for a zone name for the life of the client. A cached
//! identifier goes stale when the zone is deleted and created again. A "not found" answer to a
//! request that used a cached identifier evicts the entry; the read then resolves the zone
//! afresh once and repeats, before it concludes anything.
//!
//! Only reads are repeated. [`ZoneCache::read_zone`] runs the client's read phase and returns
//! the identifier it ended with; the client performs its write afterwards, outside the cache,
//! so a write can never run twice. A write answered "not found" evicts the entry with
//! [`ZoneCache::evict`] and fails; the caller's repeat of the operation starts with a read.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Mutex, PoisonError};

use crate::error::Error;
use crate::name::DomainName;

/// A zone identifier handed to an operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ZoneId {
    /// The provider's identifier.
    pub(crate) id: String,
    /// True when the identifier was resolved during this call, false when it came from the
    /// cache. An answer that cannot tell a missing zone from a missing rrset is conclusive only
    /// for a fresh identifier.
    pub(crate) fresh: bool,
}

/// What a read made of its answer.
#[derive(Debug)]
pub(crate) enum Attempt<T> {
    /// A result the identifier does not put in doubt.
    Done(T),
    /// A "not found" answer that may come from a stale identifier: a missing zone, or (with a
    /// cached identifier) an answer that cannot tell a missing zone from a missing rrset.
    Stale,
}

/// Zone name to provider identifier.
#[derive(Debug, Default)]
pub(crate) struct ZoneCache {
    map: Mutex<HashMap<DomainName, String>>,
}

impl ZoneCache {
    /// An empty cache.
    pub(crate) fn new() -> ZoneCache {
        ZoneCache::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<DomainName, String>> {
        // Every state of the map is a valid cache; a panic elsewhere cannot corrupt it.
        self.map.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The cached identifier of `zone`.
    pub(crate) fn get(&self, zone: &DomainName) -> Option<String> {
        self.lock().get(zone).cloned()
    }

    /// Records `id` for `zone`, replacing what was there. `check` calls this with the
    /// identifiers it resolved afresh.
    pub(crate) fn insert(&self, zone: &DomainName, id: &str) {
        self.lock().insert(zone.clone(), id.to_owned());
    }

    /// Removes the entry of `zone` if it is still `id`, so that an eviction based on an old
    /// identifier does not remove a newer one.
    pub(crate) fn evict(&self, zone: &DomainName, id: &str) {
        let mut map = self.lock();
        if map.get(zone).is_some_and(|cached| cached == id) {
            map.remove(zone);
        }
    }

    /// Runs the read phase `read` with the identifier of `zone`: the cached one, or one from
    /// `resolve` (which is then cached). When `read` reports [`Attempt::Stale`] for a cached
    /// identifier, the entry is evicted, the zone is resolved afresh, and `read` runs once more
    /// with the fresh identifier. [`Attempt::Stale`] for a fresh identifier is
    /// `Error::ZoneNotFound`, and the entry is evicted. `resolve` returns `Error::ZoneNotFound`
    /// itself when the zone does not exist.
    ///
    /// `read` may run twice, so it must not change anything at the provider. The identifier it
    /// ended with is returned with its value, for the write that follows.
    pub(crate) async fn read_zone<T, R, RFut, O, OFut>(
        &self,
        zone: &DomainName,
        resolve: R,
        mut read: O,
    ) -> Result<(ZoneId, T), Error>
    where
        R: Fn() -> RFut,
        RFut: Future<Output = Result<String, Error>>,
        O: FnMut(ZoneId) -> OFut,
        OFut: Future<Output = Result<Attempt<T>, Error>>,
    {
        let first = match self.get(zone) {
            Some(id) => ZoneId { id, fresh: false },
            None => self.resolve(zone, &resolve).await?,
        };
        let was_fresh = first.fresh;
        match read(first.clone()).await? {
            Attempt::Done(value) => return Ok((first, value)),
            Attempt::Stale => self.evict(zone, &first.id),
        }
        if was_fresh {
            return Err(Error::zone_not_found(zone.clone()));
        }
        let again = self.resolve(zone, &resolve).await?;
        match read(again.clone()).await? {
            Attempt::Done(value) => Ok((again, value)),
            Attempt::Stale => {
                self.evict(zone, &again.id);
                Err(Error::zone_not_found(zone.clone()))
            }
        }
    }

    async fn resolve<R, RFut>(&self, zone: &DomainName, resolve: &R) -> Result<ZoneId, Error>
    where
        R: Fn() -> RFut,
        RFut: Future<Output = Result<String, Error>>,
    {
        let id = resolve().await?;
        self.insert(zone, &id);
        Ok(ZoneId { id, fresh: true })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use crate::error::ErrorKind;

    fn zone() -> DomainName {
        DomainName::parse("example.test").unwrap()
    }

    #[tokio::test]
    async fn the_identifier_is_resolved_once_and_cached() {
        let cache = ZoneCache::new();
        let resolves = AtomicU32::new(0);
        for expect_fresh in [true, false, false] {
            let (used, fresh) = cache
                .read_zone(
                    &zone(),
                    || async {
                        resolves.fetch_add(1, Ordering::SeqCst);
                        Ok("id-1".to_owned())
                    },
                    |id| async move {
                        assert_eq!(id.id, "id-1");
                        Ok(Attempt::Done(id.fresh))
                    },
                )
                .await
                .unwrap();
            assert_eq!(fresh, expect_fresh);
            assert_eq!(used.fresh, expect_fresh);
        }
        assert_eq!(resolves.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_stale_identifier_is_dropped_and_the_operation_retried_once() {
        let cache = ZoneCache::new();
        // The zone was recreated: the cache holds the old identifier.
        cache.insert(&zone(), "old");
        let resolves = AtomicU32::new(0);
        let ops = AtomicU32::new(0);
        let (used, out) = cache
            .read_zone(
                &zone(),
                || async {
                    resolves.fetch_add(1, Ordering::SeqCst);
                    Ok("new".to_owned())
                },
                |id| {
                    ops.fetch_add(1, Ordering::SeqCst);
                    async move {
                        Ok(if id.id == "old" {
                            Attempt::Stale
                        } else {
                            Attempt::Done(id)
                        })
                    }
                },
            )
            .await
            .unwrap();
        assert_eq!(
            out,
            ZoneId {
                id: "new".to_owned(),
                fresh: true
            }
        );
        assert_eq!(used, out);
        assert_eq!(resolves.load(Ordering::SeqCst), 1);
        assert_eq!(ops.load(Ordering::SeqCst), 2);
        assert_eq!(cache.get(&zone()).as_deref(), Some("new"));
    }

    #[tokio::test]
    async fn stale_with_a_fresh_identifier_is_zone_not_found() {
        let cache = ZoneCache::new();
        let ops = AtomicU32::new(0);
        let e = cache
            .read_zone(
                &zone(),
                || async { Ok("id".to_owned()) },
                |_| {
                    ops.fetch_add(1, Ordering::SeqCst);
                    async { Ok(Attempt::<()>::Stale) }
                },
            )
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ZoneNotFound);
        assert_eq!(ops.load(Ordering::SeqCst), 1);
        assert_eq!(cache.get(&zone()), None);

        // Cached, stale, resolved again, still stale: one retry, then not found.
        cache.insert(&zone(), "old");
        ops.store(0, Ordering::SeqCst);
        let e = cache
            .read_zone(
                &zone(),
                || async { Ok("id".to_owned()) },
                |_| {
                    ops.fetch_add(1, Ordering::SeqCst);
                    async { Ok(Attempt::<()>::Stale) }
                },
            )
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ZoneNotFound);
        assert_eq!(ops.load(Ordering::SeqCst), 2);
        assert_eq!(cache.get(&zone()), None);
    }

    #[tokio::test]
    async fn resolve_failures_and_errors_pass_through() {
        let cache = ZoneCache::new();
        let e = cache
            .read_zone(
                &zone(),
                || async { Err(Error::zone_not_found(zone())) },
                |_| async { Ok(Attempt::Done(())) },
            )
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ZoneNotFound);
        cache.insert(&zone(), "id");
        let e = cache
            .read_zone(
                &zone(),
                || async { Ok("id".to_owned()) },
                |_| async { Err::<Attempt<()>, _>(Error::transient("down")) },
            )
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Transient);
        // An error that says nothing about the identifier keeps the entry.
        assert_eq!(cache.get(&zone()).as_deref(), Some("id"));
    }

    #[test]
    fn eviction_names_the_identifier() {
        let cache = ZoneCache::new();
        cache.insert(&zone(), "new");
        cache.evict(&zone(), "old");
        assert_eq!(cache.get(&zone()).as_deref(), Some("new"));
        cache.evict(&zone(), "new");
        assert_eq!(cache.get(&zone()), None);
    }
}
