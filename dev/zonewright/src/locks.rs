//! Per-name serialization of mutating operations (design section 3.3).
//!
//! The lock is an async mutex keyed by an absolute name. The key does not include the record
//! type, the zone or the provider. Locks are created on first use and removed when no operation
//! holds or waits for them, so the map does not grow with the number of names ever touched.
//!
//! Rules for callers:
//!
//! - Take a lock after the checks of design section 3.1 and hold the guard for the whole
//!   operation: the read, the write, automatic retries and polling.
//! - An operation takes at most one name lock. A client that also needs a zone-wide lock
//!   (nic.ru) keeps a second [`NameLocks`] keyed by zone and takes the name lock first, the zone
//!   lock second.
//! - Read operations take no lock.
//! - Waiting has no timeout of its own. Dropping the waiting future, or the guard, is always
//!   safe and releases everything.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use crate::name::DomainName;

type LockMap = HashMap<DomainName, Arc<AsyncMutex<()>>>;

/// A set of async locks keyed by name. Cheap to clone; clones share the locks.
#[derive(Clone, Default)]
pub(crate) struct NameLocks {
    map: Arc<Mutex<LockMap>>,
}

impl fmt::Debug for NameLocks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NameLocks")
            .field("names", &self.len())
            .finish()
    }
}

impl NameLocks {
    /// An empty set.
    pub(crate) fn new() -> NameLocks {
        NameLocks::default()
    }

    /// Waits until no other holder of `name` remains and returns the guard. The lock is held
    /// until the guard is dropped.
    pub(crate) async fn lock(&self, name: &DomainName) -> NameGuard {
        let entry = {
            let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(map.entry(name.clone()).or_default())
        };
        // Declared before the waiting future, so on cancellation the future is dropped first and
        // the ticket then sees the true number of remaining users of the entry.
        let ticket = Ticket {
            map: Arc::clone(&self.map),
            name: name.clone(),
            entry: Some(Arc::clone(&entry)),
        };
        let guard = entry.lock_owned().await;
        NameGuard {
            _guard: guard,
            _ticket: ticket,
        }
    }

    /// The number of names that currently have a holder or a waiter.
    pub(crate) fn len(&self) -> usize {
        self.map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// Holds one name lock. Dropping it releases the lock.
#[must_use = "the lock is released when the guard is dropped"]
pub(crate) struct NameGuard {
    // Field order matters: the mutex guard is released before the ticket removes the entry.
    _guard: OwnedMutexGuard<()>,
    _ticket: Ticket,
}

impl fmt::Debug for NameGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NameGuard").finish_non_exhaustive()
    }
}

/// Registration of one holder or waiter. On drop it removes the map entry if nobody else uses
/// it. Every clone of an entry's `Arc` taken from the map is taken under the map's mutex, and the
/// count is checked under the same mutex, so an entry is never removed while someone is about to
/// wait on it.
struct Ticket {
    map: Arc<Mutex<LockMap>>,
    name: DomainName,
    entry: Option<Arc<AsyncMutex<()>>>,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        drop(self.entry.take());
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        if map
            .get(&self.name)
            .is_some_and(|entry| Arc::strong_count(entry) == 1)
        {
            map.remove(&self.name);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::NameLocks;
    use crate::name::DomainName;

    fn dn(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    #[tokio::test]
    async fn same_name_is_serialized() {
        let locks = NameLocks::new();
        let name = dn("a.example.org");
        let guard = locks.lock(&name).await;
        let task = {
            let locks = locks.clone();
            let name = name.clone();
            tokio::spawn(async move {
                let _guard = locks.lock(&name).await;
            })
        };
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(!task.is_finished());
        drop(guard);
        task.await.unwrap();
        assert_eq!(locks.len(), 0);
    }

    #[tokio::test]
    async fn other_names_are_not_blocked() {
        let locks = NameLocks::new();
        let _a = locks.lock(&dn("a.example.org")).await;
        let b = tokio::time::timeout(Duration::from_secs(5), locks.lock(&dn("b.example.org")))
            .await
            .unwrap();
        assert_eq!(locks.len(), 2);
        drop(b);
        assert_eq!(locks.len(), 1);
    }

    #[tokio::test]
    async fn the_key_is_the_whole_name() {
        let locks = NameLocks::new();
        let _parent = locks.lock(&dn("example.org")).await;
        let _child = tokio::time::timeout(Duration::from_secs(5), locks.lock(&dn("a.example.org")))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn dropped_waiter_leaves_no_entry() {
        let locks = NameLocks::new();
        let name = dn("a.example.org");
        let guard = locks.lock(&name).await;
        let waited = tokio::time::timeout(Duration::from_millis(20), locks.lock(&name)).await;
        assert!(waited.is_err());
        assert_eq!(locks.len(), 1);
        drop(guard);
        assert_eq!(locks.len(), 0);
    }

    #[tokio::test]
    async fn waiter_cancelled_after_holder_released_leaves_no_entry() {
        let locks = NameLocks::new();
        let name = dn("a.example.org");
        let guard = locks.lock(&name).await;
        let waiter = {
            let locks = locks.clone();
            let name = name.clone();
            tokio::spawn(async move {
                let _guard = locks.lock(&name).await;
            })
        };
        tokio::task::yield_now().await;
        // The waiter is aborted before it can run again: it is still inside its waiting future
        // when it is dropped.
        drop(guard);
        waiter.abort();
        let _ = waiter.await;
        assert_eq!(locks.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn holders_never_overlap() {
        let locks = NameLocks::new();
        let name = dn("a.example.org");
        let inside = Arc::new(AtomicUsize::new(0));
        let max_inside = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let locks = locks.clone();
            let name = name.clone();
            let inside = Arc::clone(&inside);
            let max_inside = Arc::clone(&max_inside);
            tasks.push(tokio::spawn(async move {
                let _guard = locks.lock(&name).await;
                let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                max_inside.fetch_max(now, Ordering::SeqCst);
                tokio::task::yield_now().await;
                inside.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(max_inside.load(Ordering::SeqCst), 1);
        assert_eq!(locks.len(), 0);
    }
}
