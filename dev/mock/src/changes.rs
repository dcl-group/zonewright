//! Changes of the records a provider mock holds, reported in one form for every provider.
//!
//! Every provider mock that implements [`ChangeSource`] owns a [`Changes`] hub and reports each
//! change of its published records there, as a [`Change`]: the complete rrset of one name and
//! type as a DNS server would answer it after the change, or its removal. A test subscribes
//! ([`Changes::subscribe`]) to see what was written, or links the mock to a
//! [`DnsMock`](crate::dns::DnsMock) ([`link`](crate::link::link)) so that what the provider holds
//! is answered over DNS.
//!
//! How a mock reports its changes is described in the crate documentation, section "Reporting
//! changes".

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::mpsc;

/// One change of the records a provider mock holds, as a DNS server would see it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Change {
    /// The zone, lower case, without the trailing dot (`example.org`).
    pub zone: String,
    /// The owner name, fully qualified, lower case, without the trailing dot.
    pub name: String,
    /// The record type as its mnemonic in upper case (`TXT`, `A`, `CNAME`).
    pub rtype: String,
    /// The whole rrset after the change, or `None` when the name no longer has records of the type.
    pub rrset: Option<ChangedRrset>,
    /// Who made the change.
    pub origin: Origin,
}

impl Change {
    /// A change. `zone` and `name` are lowercased and lose a trailing dot; `rtype` is uppercased.
    pub fn new(
        zone: &str,
        name: &str,
        rtype: &str,
        rrset: Option<ChangedRrset>,
        origin: Origin,
    ) -> Change {
        Change {
            zone: plain(zone),
            name: plain(name),
            rtype: rtype.trim().to_ascii_uppercase(),
            rrset,
            origin,
        }
    }
}

/// The rrset of a [`Change`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChangedRrset {
    /// The TTL the provider holds for the set; `None` when its API has no TTL for it.
    pub ttl: Option<u32>,
    /// Every value of the set, in zone-file text form (RFC 1035 section 5.1): a TXT value as its
    /// quoted character-strings, a name inside a value fully qualified with the trailing dot.
    pub values: Vec<String>,
}

impl ChangedRrset {
    /// An rrset of these values.
    pub fn new(ttl: Option<u32>, values: Vec<String>) -> ChangedRrset {
        ChangedRrset { ttl, values }
    }
}

/// Who made a [`Change`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Origin {
    /// A request to the mock's API.
    Api,
    /// The test's control handle (seeding, `insert_rrset`, `delete_rrset`, a reset).
    Control,
}

/// The published state of a provider mock at one moment: what a DNS server for its zones would
/// answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Published {
    /// Every zone, also the empty ones, in the form of [`Change::zone`].
    pub zones: Vec<String>,
    /// One [`Change`] with [`Origin::Control`] per published rrset; none of them is a removal.
    pub rrsets: Vec<Change>,
}

impl Published {
    /// An empty state.
    pub fn new() -> Published {
        Published::default()
    }

    /// Adds a zone; a zone added twice is listed once.
    pub fn zone(&mut self, zone: &str) {
        let zone = plain(zone);
        if !self.zones.contains(&zone) {
            self.zones.push(zone);
        }
    }

    /// Adds a whole rrset, for a provider whose API works with rrsets. An empty `values` adds
    /// nothing. The zone is added too.
    pub fn rrset(
        &mut self,
        zone: &str,
        name: &str,
        rtype: &str,
        ttl: Option<u32>,
        values: Vec<String>,
    ) {
        self.zone(zone);
        if values.is_empty() {
            return;
        }
        let rrset = ChangedRrset::new(ttl, values);
        self.rrsets
            .push(Change::new(zone, name, rtype, Some(rrset), Origin::Control));
    }

    /// Adds one record to the rrset of its name and type, for a provider whose API works with
    /// individual records: the value is appended unless the set holds it already, and the TTL of
    /// the set is the smallest of the TTLs given for it (`None` counts only when no record of the
    /// set has a TTL). The zone is added too.
    pub fn record(&mut self, zone: &str, name: &str, rtype: &str, ttl: Option<u32>, value: String) {
        self.zone(zone);
        let key = Change::new(zone, name, rtype, None, Origin::Control);
        let found = self
            .rrsets
            .iter_mut()
            .find(|c| c.zone == key.zone && c.name == key.name && c.rtype == key.rtype);
        match found.and_then(|c| c.rrset.as_mut()) {
            Some(rrset) => {
                rrset.ttl = match (rrset.ttl, ttl) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                if !rrset.values.contains(&value) {
                    rrset.values.push(value);
                }
            }
            None => self.rrsets.push(Change {
                rrset: Some(ChangedRrset::new(ttl, vec![value])),
                ..key
            }),
        }
    }
}

/// A provider mock whose published records can be observed.
pub trait ChangeSource {
    /// The hub that reports every change of this mock.
    fn changes(&self) -> &Changes;
    /// The published state at this moment, one `Change` with `Origin::Control` per rrset, plus
    /// the names of all zones (also empty ones).
    fn published(&self) -> Published;
}

/// The hub a provider mock reports its changes to. Cheap to clone; every clone is the same hub.
///
/// Any number of subscribers; each gets every change emitted after it subscribed, through an
/// unbounded queue of its own. Emitting never blocks and never fails: a subscriber that went away
/// is forgotten.
#[derive(Clone, Default)]
pub struct Changes(Arc<Mutex<Hub>>);

#[derive(Default)]
struct Hub {
    /// Number of changes emitted so far; also the sequence number of the last one.
    emitted: u64,
    subscribers: Vec<mpsc::UnboundedSender<(u64, Change)>>,
}

impl fmt::Debug for Changes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hub = self.hub();
        f.debug_struct("Changes")
            .field("emitted", &hub.emitted)
            .field("subscribers", &hub.subscribers.len())
            .finish()
    }
}

impl Changes {
    /// A hub without subscribers.
    pub fn new() -> Changes {
        Changes::default()
    }

    fn hub(&self) -> MutexGuard<'_, Hub> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A stream of every change emitted from now on.
    pub fn subscribe(&self) -> ChangeStream {
        ChangeStream {
            rx: self.subscribe_at().1,
        }
    }

    /// Subscribes and returns the number of changes emitted before the subscription, read in
    /// the same step: every change with a higher sequence number reaches the receiver.
    pub(crate) fn subscribe_at(&self) -> (u64, mpsc::UnboundedReceiver<(u64, Change)>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut hub = self.hub();
        hub.subscribers.push(tx);
        (hub.emitted, rx)
    }

    /// Number of changes emitted so far.
    pub fn emitted(&self) -> u64 {
        self.hub().emitted
    }

    /// Reports one change to every subscriber.
    ///
    /// A mock calls this while it holds the lock that guards its state, so that subscribers see
    /// the changes in the order the mock applied them.
    pub fn emit(&self, change: Change) {
        let mut hub = self.hub();
        hub.emitted += 1;
        let seq = hub.emitted;
        hub.subscribers
            .retain(|tx| tx.send((seq, change.clone())).is_ok());
    }

    /// Emits one change, with `origin`, for every rrset that differs between `before` and
    /// `after`, in the order of zone, name and type. An rrset in `before` that is missing from
    /// `after` is emitted as a removal. Zones are not compared.
    pub fn emit_diff(&self, before: &Published, after: &Published, origin: Origin) {
        let index =
            |published: &Published| -> BTreeMap<(String, String, String), Option<ChangedRrset>> {
                published
                    .rrsets
                    .iter()
                    .map(|c| {
                        (
                            (c.zone.clone(), c.name.clone(), c.rtype.clone()),
                            c.rrset.clone(),
                        )
                    })
                    .collect()
            };
        let old = index(before);
        let mut new = index(after);
        let mut keys: Vec<(String, String, String)> = old.keys().cloned().collect();
        keys.extend(new.keys().filter(|k| !old.contains_key(*k)).cloned());
        keys.sort();
        for key in keys {
            let was = old.get(&key).cloned().flatten();
            let now = new.remove(&key).flatten();
            if was != now {
                let (zone, name, rtype) = key;
                self.emit(Change {
                    zone,
                    name,
                    rtype,
                    rrset: now,
                    origin,
                });
            }
        }
    }
}

/// The changes a subscriber receives, in the order they were emitted.
#[derive(Debug)]
pub struct ChangeStream {
    rx: mpsc::UnboundedReceiver<(u64, Change)>,
}

impl ChangeStream {
    /// The next change; waits for one. `None` once the hub and all its clones are gone and every
    /// change has been read.
    pub async fn next(&mut self) -> Option<Change> {
        self.rx.recv().await.map(|(_, change)| change)
    }

    /// The next change if one is waiting, without waiting.
    pub fn try_next(&mut self) -> Option<Change> {
        self.rx.try_recv().ok().map(|(_, change)| change)
    }
}

/// `name` lower case, trimmed, without the trailing dot.
fn plain(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txt(zone: &str, name: &str, values: &[&str]) -> Change {
        let values = values.iter().map(|v| format!("\"{v}\"")).collect();
        Change::new(
            zone,
            name,
            "txt",
            Some(ChangedRrset::new(Some(60), values)),
            Origin::Control,
        )
    }

    #[test]
    fn names_are_normalized() {
        let change = Change::new(
            "Example.ORG.",
            "WWW.example.org.",
            "cname",
            None,
            Origin::Api,
        );
        assert_eq!(change.zone, "example.org");
        assert_eq!(change.name, "www.example.org");
        assert_eq!(change.rtype, "CNAME");
    }

    #[test]
    fn records_are_grouped_into_rrsets() {
        let mut published = Published::new();
        published.zone("empty.test.");
        published.record(
            "example.org",
            "a.example.org",
            "TXT",
            Some(300),
            "\"x\"".into(),
        );
        published.record(
            "example.org",
            "A.example.org.",
            "TXT",
            Some(120),
            "\"y\"".into(),
        );
        published.record("example.org", "a.example.org", "TXT", None, "\"x\"".into());
        published.record(
            "example.org",
            "a.example.org",
            "A",
            None,
            "192.0.2.1".into(),
        );
        assert_eq!(published.zones, ["empty.test", "example.org"]);
        assert_eq!(published.rrsets.len(), 2);
        let txt = published.rrsets[0].rrset.as_ref().unwrap();
        assert_eq!(txt.ttl, Some(120));
        assert_eq!(txt.values, ["\"x\"", "\"y\""]);
        assert_eq!(published.rrsets[1].rrset.as_ref().unwrap().ttl, None);
    }

    #[tokio::test]
    async fn subscribers_see_changes_in_order_from_their_subscription_on() {
        let changes = Changes::new();
        changes.emit(txt("example.org", "a.example.org", &["0"]));
        let mut first = changes.subscribe();
        changes.emit(txt("example.org", "a.example.org", &["1"]));
        let mut second = changes.subscribe();
        changes.emit(txt("example.org", "a.example.org", &["2"]));
        assert_eq!(changes.emitted(), 3);

        let values = |c: Change| c.rrset.unwrap().values;
        assert_eq!(values(first.next().await.unwrap()), ["\"1\""]);
        assert_eq!(values(first.try_next().unwrap()), ["\"2\""]);
        assert!(first.try_next().is_none());
        assert_eq!(values(second.try_next().unwrap()), ["\"2\""]);

        // A subscriber that went away does not stop the others.
        drop(first);
        changes.emit(txt("example.org", "a.example.org", &["3"]));
        assert_eq!(values(second.try_next().unwrap()), ["\"3\""]);
        drop(changes);
        assert!(second.next().await.is_none());
    }

    #[test]
    fn a_diff_emits_what_changed_and_removals() {
        let changes = Changes::new();
        let mut stream = changes.subscribe();
        let mut before = Published::new();
        before
            .rrsets
            .push(txt("example.org", "a.example.org", &["1"]));
        before
            .rrsets
            .push(txt("example.org", "b.example.org", &["1"]));
        before
            .rrsets
            .push(txt("example.org", "c.example.org", &["1"]));
        let mut after = Published::new();
        after
            .rrsets
            .push(txt("example.org", "c.example.org", &["2"]));
        after
            .rrsets
            .push(txt("example.org", "b.example.org", &["1"]));
        after
            .rrsets
            .push(txt("example.org", "d.example.org", &["1"]));
        changes.emit_diff(&before, &after, Origin::Api);

        let mut seen = Vec::new();
        while let Some(change) = stream.try_next() {
            assert_eq!(change.origin, Origin::Api);
            seen.push((change.name, change.rrset.map(|r| r.values)));
        }
        assert_eq!(
            seen,
            [
                ("a.example.org".to_owned(), None),
                ("c.example.org".to_owned(), Some(vec!["\"2\"".to_owned()])),
                ("d.example.org".to_owned(), Some(vec!["\"1\"".to_owned()])),
            ]
        );
    }
}
