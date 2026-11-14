//! The acme-dns client's process-local memory of recently sent values (design section 11.3).
//!
//! The server has no read, and an update with a value it already holds is written into the other
//! one of the registration's two slots (`pkg/database/db.go`, `Update`: the row with the oldest
//! `LastUpdate` is overwritten, whatever it holds). A needless repeat therefore displaces a live
//! neighbor, such as the wildcard value next to the base name's. The memory lets the client skip
//! a repeat.
//!
//! What is kept, per server URL and name: at most two values this process sent, each with the
//! time of the send and whether the server answered 2xx (`confirmed`) or the outcome is unknown
//! (a timeout, a lost connection, a 5xx). An entry is forgotten
//!
//! - 15 minutes after it was recorded,
//! - when a third value for the name displaces the oldest,
//! - on a definite refusal of its own send,
//! - when more than 1,024 names are remembered and its name was used least recently.
//!
//! The memory also paces the sends to one name: a send waits until [`PACE`] has passed since the
//! previous send to that name ended. The server stamps a write with whole seconds and overwrites
//! the row with the smallest stamp, with no tie-breaker (`pkg/database/db.go`, `Update`:
//! `ORDER BY LastUpdate LIMIT 1` on `time.Now().Unix()`), so two writes within one second leave
//! two rows with the same stamp, and the next write overwrites either of them. The memory would
//! then believe the wrong value displaced, and could later suppress the send of a value the server
//! no longer holds. With the sends at least a second apart the server's stamps follow the order
//! of the sends, and the oldest value is the one overwritten, as the memory assumes. This holds
//! for the sends of one `Context`; another writer to the same registration is not paced.
//!
//! Losing the memory (a restart) is safe: the value is then sent again, as it was in the first
//! place. The memory only ever suppresses a send, and what the client reports for a suppressed
//! send is the same as for a made one (`AddOutcome::Accepted`): it never claims that the value is
//! there.
//!
//! Values are not secrets but are never written to `tracing`; `Debug` shows counts only.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::time::Instant;

use crate::name::DomainName;

/// How many values the server keeps per registration.
// Source: the project's README, "Rolling update of two TXT records", and `pkg/database/db.go`:
// every registration has two rows, `Update` overwrites the one with the oldest `LastUpdate`.
pub(super) const SLOTS: usize = 2;

/// How long an entry is remembered: the time in which a neighbor can still be needed by an
/// unfinished challenge. A choice of this client (design section 11.3).
pub(super) const LIFETIME: Duration = Duration::from_secs(15 * 60);

/// Most names remembered; the least recently used is dropped beyond it.
pub(super) const MAX_NAMES: usize = 1024;

/// Least time between the end of one send to a name and the start of the next. The server
/// stamps writes with whole seconds (`pkg/database/db.go`, `Update`, `time.Now().Unix()`): two
/// writes processed at least a second apart get different stamps. The extra 100 ms absorbs a
/// difference in clock rate between the client and the server. A choice of this client.
pub(super) const PACE: Duration = Duration::from_millis(1100);

/// Shared by every client of one `Context`: cheap to clone, clones share the memory.
#[derive(Clone, Default)]
pub(crate) struct State {
    inner: Arc<Mutex<Memory>>,
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("State")
            .field("names", &self.lock().names.len())
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct Memory {
    names: HashMap<Key, Entry>,
    /// Incremented on every use; orders the names by recency.
    clock: u64,
}

/// The server URL (as the client's endpoint spells it) and the name.
type Key = (String, DomainName);

#[derive(Default)]
struct Entry {
    /// Oldest first, at most [`SLOTS`].
    sent: Vec<Sent>,
    /// `Memory::clock` at the last use.
    used: u64,
    /// When the last send to the name that may have written ended (a 2xx or an unknown outcome);
    /// the next send waits until [`PACE`] has passed since.
    last_write: Option<Instant>,
}

/// One value this process sent.
#[derive(Clone)]
pub(super) struct Sent {
    value: String,
    confirmed: bool,
    at: Instant,
}

impl Sent {
    fn live(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.at) < LIFETIME
    }
}

/// What [`State::begin`] decided.
pub(super) struct Begin {
    /// Whether the request is to be sent. False: the memory answers for it.
    pub(super) send: bool,
    /// The older value a send displaces from the memory, which the server is about to overwrite.
    pub(super) displaced: Option<Sent>,
}

/// How a send ended, as far as the client can tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    /// The server answered 2xx.
    Confirmed,
    /// The server, or the client before it connected, refused the request: nothing was stored.
    Refused,
    /// Unknown: a timeout, a lost connection, a 5xx, an unreadable answer.
    Unknown,
}

impl State {
    fn lock(&self) -> MutexGuard<'_, Memory> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The earliest time at which the next send to `name` may start ([`PACE`] after the end of
    /// the previous send that may have written), or `None` when it may start now. Records
    /// nothing, so a caller that waits and is dropped meanwhile leaves no trace.
    pub(super) fn pace(&self, server: &str, name: &DomainName) -> Option<Instant> {
        let memory = self.lock();
        let key = (server.to_owned(), name.clone());
        memory
            .names
            .get(&key)
            .and_then(|entry| entry.last_write)
            .and_then(|at| at.checked_add(PACE))
    }

    /// Decides whether `value` is to be sent to `name` and records the intent: a value that is
    /// to be sent is remembered, unconfirmed, before the request goes out, so that a dropped
    /// future cannot leave a stored value that the memory does not know about.
    ///
    /// - A live confirmed entry for the value: not sent.
    /// - A live unconfirmed entry: sent again only if the name has no other live entry.
    /// - Anything else: sent. A third value displaces the oldest.
    pub(super) fn begin(
        &self,
        server: &str,
        name: &DomainName,
        value: &str,
        now: Instant,
    ) -> Begin {
        let mut memory = self.lock();
        memory.clock += 1;
        let tick = memory.clock;
        let key = (server.to_owned(), name.clone());
        if !memory.names.contains_key(&key) && memory.names.len() >= MAX_NAMES {
            memory.drop_least_recently_used();
        }
        let entry = memory.names.entry(key).or_default();
        entry.used = tick;
        entry.sent.retain(|s| s.live(now));
        if let Some(own) = entry.sent.iter().position(|s| s.value == value) {
            let confirmed = entry.sent.get(own).is_some_and(|s| s.confirmed);
            let others = entry.sent.len() > 1;
            if confirmed || others {
                return Begin {
                    send: false,
                    displaced: None,
                };
            }
            if let Some(sent) = entry.sent.get_mut(own) {
                sent.at = now;
            }
            return Begin {
                send: true,
                displaced: None,
            };
        }
        let displaced = if entry.sent.len() >= SLOTS {
            Some(entry.sent.remove(0))
        } else {
            None
        };
        entry.sent.push(Sent {
            value: value.to_owned(),
            confirmed: false,
            at: now,
        });
        Begin {
            send: true,
            displaced,
        }
    }

    /// Records how a send that [`State::begin`] allowed ended.
    pub(super) fn finish(
        &self,
        server: &str,
        name: &DomainName,
        value: &str,
        outcome: Outcome,
        displaced: Option<Sent>,
        now: Instant,
    ) {
        let mut memory = self.lock();
        let key = (server.to_owned(), name.clone());
        let Some(entry) = memory.names.get_mut(&key) else {
            // Forgotten meanwhile (the least recently used name): nothing to settle.
            return;
        };
        match outcome {
            Outcome::Confirmed => {
                entry.last_write = Some(now);
                if let Some(sent) = entry.sent.iter_mut().find(|s| s.value == value) {
                    sent.confirmed = true;
                }
            }
            Outcome::Refused => {
                entry.sent.retain(|s| s.value != value);
                // The server was not touched, so the value the send was about to displace is
                // still in its slot.
                if let Some(old) = displaced
                    && old.live(now)
                    && entry.sent.len() < SLOTS
                {
                    entry.sent.insert(0, old);
                }
                // An empty entry is dropped unless it still paces the next send.
                let pacing = entry
                    .last_write
                    .is_some_and(|at| now.saturating_duration_since(at) < PACE);
                if entry.sent.is_empty() && !pacing {
                    memory.names.remove(&key);
                }
            }
            Outcome::Unknown => entry.last_write = Some(now),
        }
    }
}

impl Memory {
    fn drop_least_recently_used(&mut self) {
        let oldest = self
            .names
            .iter()
            .min_by_key(|(_, entry)| entry.used)
            .map(|(key, _)| key.clone());
        if let Some(key) = oldest {
            self.names.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: &str = "https://auth.example.org/";

    fn name(i: usize) -> DomainName {
        DomainName::parse(&format!("r{i}.auth.example.org")).unwrap()
    }

    fn sent(state: &State, name: &DomainName, value: &str, now: Instant) -> bool {
        let begin = state.begin(SERVER, name, value, now);
        if begin.send {
            state.finish(
                SERVER,
                name,
                value,
                Outcome::Confirmed,
                begin.displaced,
                now,
            );
        }
        begin.send
    }

    #[test]
    fn a_confirmed_value_is_not_sent_again() {
        let state = State::default();
        let (n, now) = (name(0), Instant::now());
        assert!(sent(&state, &n, "a", now));
        assert!(!sent(&state, &n, "a", now));
        assert!(sent(&state, &n, "b", now));
        assert!(!sent(&state, &n, "a", now));
        assert!(!sent(&state, &n, "b", now));
    }

    #[test]
    fn a_third_value_displaces_the_oldest() {
        let state = State::default();
        let (n, now) = (name(0), Instant::now());
        for value in ["a", "b"] {
            assert!(sent(&state, &n, value, now));
        }
        let begin = state.begin(SERVER, &n, "c", now);
        assert!(begin.send);
        assert!(begin.displaced.is_some_and(|d| d.value == "a"));
        state.finish(SERVER, &n, "c", Outcome::Confirmed, None, now);
        // "a" is forgotten, so it is sent again; that displaces "b".
        assert!(sent(&state, &n, "a", now));
        assert!(sent(&state, &n, "b", now));
    }

    #[test]
    fn at_most_two_values_are_kept_per_name() {
        let state = State::default();
        let (n, now) = (name(0), Instant::now());
        for value in ["a", "b", "c", "d"] {
            assert!(sent(&state, &n, value, now));
        }
        assert_eq!(
            state
                .lock()
                .names
                .values()
                .map(|e| e.sent.len())
                .sum::<usize>(),
            2
        );
    }

    #[test]
    fn entries_expire_after_fifteen_minutes() {
        let state = State::default();
        let (n, start) = (name(0), Instant::now());
        assert!(sent(&state, &n, "a", start));
        assert!(!sent(
            &state,
            &n,
            "a",
            start + LIFETIME - Duration::from_secs(1)
        ));
        assert!(sent(&state, &n, "a", start + LIFETIME));
    }

    #[test]
    fn an_unconfirmed_value_is_sent_again_only_without_a_live_neighbor() {
        let state = State::default();
        let (n, now) = (name(0), Instant::now());
        // Alone: sent again.
        let begin = state.begin(SERVER, &n, "a", now);
        assert!(begin.send);
        state.finish(SERVER, &n, "a", Outcome::Unknown, begin.displaced, now);
        assert!(state.begin(SERVER, &n, "a", now).send);
        state.finish(SERVER, &n, "a", Outcome::Confirmed, None, now);
        // With a live neighbor: not sent again.
        let m = name(1);
        assert!(sent(&state, &m, "a", now));
        let begin = state.begin(SERVER, &m, "b", now);
        state.finish(SERVER, &m, "b", Outcome::Unknown, begin.displaced, now);
        assert!(!state.begin(SERVER, &m, "b", now).send);
        // The neighbor expires: sent again.
        let later = now + LIFETIME;
        assert!(state.begin(SERVER, &m, "b", later).send);
    }

    #[test]
    fn a_refused_send_is_forgotten_and_restores_the_displaced_value() {
        let state = State::default();
        let (n, now) = (name(0), Instant::now());
        for value in ["a", "b"] {
            assert!(sent(&state, &n, value, now));
        }
        let begin = state.begin(SERVER, &n, "c", now);
        assert!(begin.displaced.is_some());
        state.finish(SERVER, &n, "c", Outcome::Refused, begin.displaced, now);
        assert!(!sent(&state, &n, "a", now), "a is still in its slot");
        assert!(!sent(&state, &n, "b", now));
        assert!(sent(&state, &n, "c", now), "c was refused, so it is new");
    }

    #[test]
    fn at_most_1024_names_are_kept_and_the_least_recently_used_is_dropped() {
        let state = State::default();
        let now = Instant::now();
        for i in 0..MAX_NAMES {
            assert!(sent(&state, &name(i), "a", now));
        }
        // Use name 0 again, so that name 1 is the least recently used.
        assert!(!sent(&state, &name(0), "a", now));
        assert!(sent(&state, &name(MAX_NAMES), "a", now));
        assert_eq!(state.lock().names.len(), MAX_NAMES);
        assert!(!sent(&state, &name(0), "a", now), "name 0 was used last");
        assert!(sent(&state, &name(1), "a", now), "name 1 was dropped");
    }

    #[test]
    fn sends_to_a_name_are_paced() {
        let state = State::default();
        let (n, m, now) = (name(0), name(1), Instant::now());
        assert!(state.pace(SERVER, &n).is_none());
        // A confirmed send and an unknown one pace the next send; a refused one does not.
        assert!(sent(&state, &n, "a", now));
        assert_eq!(state.pace(SERVER, &n), Some(now + PACE));
        assert!(
            state.pace(SERVER, &m).is_none(),
            "another name is not paced"
        );
        let later = now + Duration::from_secs(5);
        let begin = state.begin(SERVER, &n, "b", later);
        state.finish(SERVER, &n, "b", Outcome::Unknown, begin.displaced, later);
        assert_eq!(state.pace(SERVER, &n), Some(later + PACE));
        let begin = state.begin(SERVER, &m, "a", now);
        state.finish(SERVER, &m, "a", Outcome::Refused, begin.displaced, now);
        assert!(state.pace(SERVER, &m).is_none());
        // A refusal that empties an entry keeps it while it still paces.
        let o = name(2);
        let begin = state.begin(SERVER, &o, "a", now);
        state.finish(SERVER, &o, "a", Outcome::Unknown, begin.displaced, now);
        let begin = state.begin(SERVER, &o, "a", now);
        state.finish(SERVER, &o, "a", Outcome::Refused, begin.displaced, now);
        assert_eq!(state.pace(SERVER, &o), Some(now + PACE));
    }

    #[test]
    fn servers_do_not_share_entries() {
        let state = State::default();
        let (n, now) = (name(0), Instant::now());
        assert!(state.begin("https://one.example.org/", &n, "a", now).send);
        assert!(state.begin("https://two.example.org/", &n, "a", now).send);
    }

    #[test]
    fn debug_shows_no_values() {
        let state = State::default();
        let now = Instant::now();
        assert!(sent(&state, &name(0), "SecretLookingValue", now));
        assert!(!format!("{state:?}").contains("SecretLooking"));
    }
}
