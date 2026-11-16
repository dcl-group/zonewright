//! Makes a [`DnsMock`] serve what a provider mock holds.
//!
//! An application that answers the DNS-01 challenge writes TXT records through a provider API;
//! an ACME server (for example Pebble, started with `-dnsserver <address>`) then asks a DNS server
//! for them. In a test, the provider is one of this crate's provider mocks and the DNS server a
//! [`DnsMock`]; [`link`] connects the two:
//!
//! ```text
//! let provider = SelectelV2Mock::start(Seed::standard()).await;
//! let dns = DnsMock::start(Role::Authoritative).await;
//! let link = link(&provider, &dns, LinkOptions::new());
//! // ... the application writes `_acme-challenge.example.org` TXT through provider.base_url() ...
//! link.settled().await;
//! // ... dns.addr() now answers the value, with the AA flag ...
//! ```
//!
//! When the link is made, every zone of the provider mock becomes a served zone of the
//! [`DnsMock`] and every published rrset becomes records. From then on every [`Change`] the
//! provider mock reports is applied as it arrives: an rrset replaces the records of its name and
//! type, a removal removes them. A zone created later is served once a change arrives for it; a
//! zone that holds no records by then is not served (queries into it are refused). A zone removed
//! from the provider mock keeps being served, without records.
//!
//! The types converted from zone-file text to wire form are A, AAAA, TXT, CNAME, NS, MX and CAA;
//! a name inside a value must be fully qualified, with the trailing dot. A change of another type
//! is skipped, and so is a value that cannot be read or whose wire form would be over 65 535
//! octets; both are counted in [`Link::skipped`]. The other values of a set are applied. An rrset
//! whose owner name cannot be written on the wire (a label over 63 octets, or over 255 octets in
//! all) is skipped as a whole and counted once. The TTL of the records is the set's TTL, or
//! [`DEFAULT_TTL`] when the provider has none.
//!
//! A linked zone has no SOA record, so its negative answers have an empty authority section; a
//! test that needs one adds it with `DnsMock::add(zone, TYPE_SOA, ttl, Data::Soa { .. })`. The
//! link never touches it.
//!
//! The link is deterministic for tests without sleeps: [`Link::settled`] waits until what was
//! written has reached the [`DnsMock`], and [`Link::hold`] keeps changes back until
//! [`Link::release`], to test what an application does while a record has not propagated yet.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::{Notify, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::changes::{Change, ChangeSource, Changes, Published};
use crate::dns::{
    Data, DnsMock, Handle, TYPE_A, TYPE_AAAA, TYPE_CAA, TYPE_CNAME, TYPE_MX, TYPE_NS, TYPE_TXT,
    encodable,
};

/// The TTL of linked records whose provider holds none for their set.
pub const DEFAULT_TTL: u32 = 60;

/// How many times [`link`] reads a source that keeps changing while the link is being made.
const START_ATTEMPTS: usize = 8;

/// The delay used when the one given is too long to add to the current time: roughly thirty
/// years, the bound `tokio::time` itself puts on long durations (`safe_delay` in
/// `tokio/src/time/mod.rs`, tokio 1.54).
const FAR: Duration = Duration::from_secs(86_400 * 365 * 30);

/// How a [`Link`] behaves.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct LinkOptions {
    /// Each change becomes visible in DNS this long after the link received it, which is at
    /// once after the provider mock made it. Measured with `tokio::time`, so that it also works
    /// under a paused clock. `None`: at once.
    pub delay: Option<Duration>,
    /// Start in the held state ([`Link::hold`]). The state when the link is made is served
    /// regardless; only the changes after it are held.
    pub held: bool,
}

impl LinkOptions {
    /// No delay, not held.
    pub fn new() -> LinkOptions {
        LinkOptions::default()
    }

    /// With this delay.
    pub fn delay(mut self, delay: Duration) -> LinkOptions {
        self.delay = Some(delay);
        self
    }

    /// Held from the start, or not.
    pub fn held(mut self, held: bool) -> LinkOptions {
        self.held = held;
        self
    }
}

/// A running link from a provider mock to a [`DnsMock`]. Dropping it ends the link; the records
/// already in the [`DnsMock`] stay.
#[derive(Debug)]
pub struct Link {
    changes: Changes,
    shared: Arc<Shared>,
    task: JoinHandle<()>,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    /// Wakes the task after [`Link::release`].
    wake: Notify,
    /// Signalled after every step of the task and every hold or release.
    progress: watch::Sender<()>,
}

#[derive(Debug)]
struct State {
    held: bool,
    /// Sequence number of the last change received from the source.
    received: u64,
    /// Sequence number of the last change applied to the DNS mock.
    applied: u64,
    skipped: usize,
    queue: VecDeque<Pending>,
}

#[derive(Debug)]
struct Pending {
    seq: u64,
    due: Instant,
    change: Change,
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Makes `dns` serve what `source` holds, now and as it changes.
///
/// Must be called inside a Tokio runtime; the link runs as a task on it. The state at the call is
/// served when the call returns. A source that changes while the link is being made is read
/// again until its state and the subscription agree.
///
/// The link writes whole rrsets. When two links into one [`DnsMock`], or a link and the test's
/// own [`DnsMock::add`], [`DnsMock::set`] or [`DnsMock::remove`], write the same name and type,
/// the later write replaces the earlier one. One source can be linked to several `DnsMock`s.
pub fn link(source: &impl ChangeSource, dns: &DnsMock, options: LinkOptions) -> Link {
    let changes = source.changes().clone();
    // The state served at once is the one after change number `start`; the task gets exactly
    // the changes after it, so none is replayed over a state that already holds it.
    let (start, rx, published) = start(source, &changes);
    let handle = dns.handle();
    for zone in &published.zones {
        handle.ensure_zone(zone);
    }
    let skipped = published
        .rrsets
        .iter()
        .map(|change| apply(&handle, change))
        .sum();
    let (progress, _) = watch::channel(());
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            held: options.held,
            received: start,
            applied: start,
            skipped,
            queue: VecDeque::new(),
        }),
        wake: Notify::new(),
        progress,
    });
    let task = tokio::spawn(run(shared.clone(), handle, rx, options.delay));
    Link {
        changes,
        shared,
        task,
    }
}

/// Subscribes to `source` and reads its state so that the two agree: the state is the one after
/// change number `start`, and the receiver gets every later change. A source that changes
/// meanwhile is read again, at most [`START_ATTEMPTS`] times; after the last attempt the state may
/// already hold some of the changes the receiver gets, which applied again end in the same
/// records.
///
/// A mock emits its changes while it holds the lock that guards its state, and
/// [`ChangeSource::published`] takes that lock. So when the hub's count after reading the state
/// still equals the count at the subscription, no change was made in between and the state is
/// exactly the one after change number `start`. The hub's lock is never held while the state is
/// read (the lock order of a mock is its state, then the hub).
fn start(
    source: &impl ChangeSource,
    changes: &Changes,
) -> (u64, mpsc::UnboundedReceiver<(u64, Change)>, Published) {
    let mut attempt = 1;
    loop {
        let (start, rx) = changes.subscribe_at();
        let published = source.published();
        if changes.emitted() == start || attempt >= START_ATTEMPTS {
            return (start, rx, published);
        }
        // The receiver is dropped here; the hub forgets it at the next subscription or emit,
        // and nothing sent to it reaches the link.
        drop(rx);
        attempt += 1;
    }
}

impl Link {
    /// Stops changes from reaching DNS: from now on they queue up in the link.
    pub fn hold(&self) {
        self.shared.state().held = true;
        self.shared.progress.send_replace(());
    }

    /// Ends a [`hold`](Link::hold): the queued changes are applied in order, each when its delay
    /// has passed.
    pub fn release(&self) {
        self.shared.state().held = false;
        self.shared.wake.notify_one();
        self.shared.progress.send_replace(());
    }

    /// Returns when every change the source emitted before this call has been applied to the
    /// [`DnsMock`], each after its delay. While the link is held, it returns as soon as those
    /// changes have reached the link's queue instead, without waiting for a release, so that a
    /// test can check what DNS answers before the release; it returns at once if the link is
    /// held when it is called and the changes have arrived.
    ///
    /// A change the link skips, wholly or in part ([`Link::skipped`]), counts as applied; check
    /// `skipped()` when a test needs every value in DNS.
    ///
    /// Call it on the runtime the link was made on: the link's task lives there, and once that
    /// runtime is gone nothing is applied any more and this never returns.
    pub async fn settled(&self) {
        let target = self.changes.emitted();
        let mut progress = self.shared.progress.subscribe();
        loop {
            {
                let state = self.shared.state();
                if state.applied >= target || (state.held && state.received >= target) {
                    return;
                }
            }
            if progress.changed().await.is_err() {
                return;
            }
        }
    }

    /// How many changes (of a type the link does not convert, or whose owner name cannot be
    /// written on the wire) and values (that could not be read, or would be over 65 535 octets on
    /// the wire) were skipped so far.
    pub fn skipped(&self) -> usize {
        self.shared.state().skipped
    }
}

/// The link's task: takes the changes of the source and applies them when they are due.
async fn run(
    shared: Arc<Shared>,
    dns: Handle,
    mut rx: mpsc::UnboundedReceiver<(u64, Change)>,
    delay: Option<Duration>,
) {
    let mut open = true;
    loop {
        let next_due = apply_due(&shared, &dns);
        shared.progress.send_replace(());
        let timer = async {
            match next_due {
                Some(due) => tokio::time::sleep_until(due).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            received = rx.recv(), if open => match received {
                Some((seq, change)) => {
                    // A delay too long to add to the current time means "never" in practice;
                    // adding it unchecked would panic and end the task.
                    let now = Instant::now();
                    let due = now
                        .checked_add(delay.unwrap_or_default())
                        .or_else(|| now.checked_add(FAR))
                        .unwrap_or(now);
                    let mut state = shared.state();
                    state.received = seq;
                    state.queue.push_back(Pending { seq, due, change });
                }
                None => open = false,
            },
            () = shared.wake.notified() => {}
            () = timer => {}
        }
    }
}

/// Applies the queued changes that are due, unless the link is held. Returns when the next
/// queued change is due, if one is and the link is not held.
fn apply_due(shared: &Shared, dns: &Handle) -> Option<Instant> {
    let mut state = shared.state();
    if state.held {
        return None;
    }
    let now = Instant::now();
    while let Some(front) = state.queue.front() {
        if front.due > now {
            return Some(front.due);
        }
        let Some(pending) = state.queue.pop_front() else {
            break;
        };
        state.skipped += apply(dns, &pending.change);
        state.applied = pending.seq;
    }
    None
}

/// Applies one change to the DNS mock; returns how much of it was skipped.
fn apply(dns: &Handle, change: &Change) -> usize {
    dns.ensure_zone(&change.zone);
    let Some(rtype) = type_code(&change.rtype) else {
        return 1;
    };
    let Some(rrset) = &change.rrset else {
        dns.set(&change.name, rtype, DEFAULT_TTL, Vec::new());
        return 0;
    };
    if !encodable(&change.name) {
        // No query can name it, and the DNS mock could not write it.
        return 1;
    }
    let mut skipped = 0;
    let mut values = Vec::new();
    for value in &rrset.values {
        match data(rtype, value) {
            Some(data) => values.push(data),
            None => skipped += 1,
        }
    }
    dns.set(
        &change.name,
        rtype,
        rrset.ttl.unwrap_or(DEFAULT_TTL),
        values,
    );
    skipped
}

/// The type code of a mnemonic the link converts.
fn type_code(rtype: &str) -> Option<u16> {
    Some(match rtype {
        "A" => TYPE_A,
        "AAAA" => TYPE_AAAA,
        "TXT" => TYPE_TXT,
        "CNAME" => TYPE_CNAME,
        "NS" => TYPE_NS,
        "MX" => TYPE_MX,
        "CAA" => TYPE_CAA,
        _ => return None,
    })
}

/// The RDATA of `text`, a value of type `rtype` in zone-file form; `None` when it cannot be read
/// or is over 65 535 octets, the most the RDLENGTH field of a record can say (RFC 1035 section
/// 3.2.1).
fn data(rtype: u16, text: &str) -> Option<Data> {
    let data = read(rtype, text)?;
    match &data {
        Data::Raw(octets) if octets.len() > usize::from(u16::MAX) => None,
        _ => Some(data),
    }
}

/// The RDATA of `text`, a value of type `rtype` in zone-file form; `None` when it cannot be read.
fn read(rtype: u16, text: &str) -> Option<Data> {
    let text = text.trim();
    match rtype {
        TYPE_A => text.parse::<Ipv4Addr>().ok().map(|a| Data::a(a.octets())),
        TYPE_AAAA => text.parse::<Ipv6Addr>().ok().map(Data::aaaa),
        TYPE_TXT => {
            let strings = character_strings(text, Some(255))?;
            let refs: Vec<&[u8]> = strings.iter().map(Vec::as_slice).collect();
            Some(Data::txt(&refs))
        }
        TYPE_CNAME | TYPE_NS => absolute(text).map(|name| Data::Name(name.to_owned())),
        TYPE_MX => {
            let (preference, exchange) = text.split_once(char::is_whitespace)?;
            let preference = preference.parse::<u16>().ok()?;
            let exchange = absolute(exchange.trim())?;
            Some(Data::Mx(preference, exchange.to_owned()))
        }
        TYPE_CAA => {
            // RFC 8659 section 4.1.1: `<flags> <tag> <value>`, the tag of ASCII letters and
            // digits, the value one character-string of any length.
            let (flags, rest) = text.split_once(char::is_whitespace)?;
            let flags = flags.parse::<u8>().ok()?;
            let (tag, value) = rest.trim_start().split_once(char::is_whitespace)?;
            if tag.is_empty() || tag.len() > 255 || !tag.bytes().all(|b| b.is_ascii_alphanumeric())
            {
                return None;
            }
            let mut value = character_strings(value, None)?;
            if value.len() != 1 {
                return None;
            }
            let value = value.pop()?;
            let mut out = vec![flags, u8::try_from(tag.len()).ok()?];
            out.extend_from_slice(tag.as_bytes());
            out.extend_from_slice(&value);
            Some(Data::Raw(out))
        }
        _ => None,
    }
}

/// A fully qualified name with the trailing dot, in the plain form the DNS mock writes: labels
/// of 1 to 63 octets without white space, quotes or escapes, at most 255 octets on the wire.
fn absolute(text: &str) -> Option<&str> {
    if text == "." {
        return Some(text);
    }
    let labels = text.strip_suffix('.')?;
    let plain = labels.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_graphic() && !matches!(b, b'\\' | b'"' | b'(' | b')' | b';'))
    });
    // With the trailing dot, a name of 254 characters is 255 octets on the wire (RFC 1035 section
    // 2.3.4).
    (plain && text.len() <= 254).then_some(text)
}

/// The character-strings of `text` in zone-file form (RFC 1035 section 5.1): quoted strings, in
/// which `\X` stands for `X` and `\DDD` for the octet with that decimal value, or unquoted words,
/// separated by white space. Each at most `limit` octets; at least one.
fn character_strings(text: &str, limit: Option<usize>) -> Option<Vec<Vec<u8>>> {
    let bytes = text.as_bytes();
    let mut at = 0;
    let mut out = Vec::new();
    loop {
        while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
            at += 1;
        }
        let Some(&first) = bytes.get(at) else {
            break;
        };
        let quoted = first == b'"';
        if quoted {
            at += 1;
        }
        let mut string = Vec::new();
        loop {
            let Some(&byte) = bytes.get(at) else {
                if quoted {
                    return None;
                }
                break;
            };
            if quoted && byte == b'"' {
                at += 1;
                break;
            }
            if !quoted && (byte.is_ascii_whitespace() || byte == b'"') {
                break;
            }
            if byte == b'\\' {
                let digits = bytes
                    .get(at + 1..at + 4)
                    .filter(|d| d.iter().all(u8::is_ascii_digit));
                if let Some(digits) = digits {
                    let value = std::str::from_utf8(digits).ok()?.parse::<u16>().ok()?;
                    string.push(u8::try_from(value).ok()?);
                    at += 4;
                } else {
                    string.push(*bytes.get(at + 1)?);
                    at += 2;
                }
            } else {
                string.push(byte);
                at += 1;
            }
        }
        if limit.is_some_and(|limit| string.len() > limit) {
            return None;
        }
        out.push(string);
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::changes::{ChangedRrset, Origin, Published};
    use crate::dns::Role;

    /// A source whose state and changes a test sets by hand.
    struct Source {
        changes: Changes,
        published: Published,
    }

    impl ChangeSource for Source {
        fn changes(&self) -> &Changes {
            &self.changes
        }

        fn published(&self) -> Published {
            self.published.clone()
        }
    }

    fn set(name: &str, rtype: &str, ttl: Option<u32>, values: &[&str]) -> Change {
        let values = values.iter().map(|v| (*v).to_owned()).collect();
        Change::new(
            "example.test",
            name,
            rtype,
            Some(ChangedRrset::new(ttl, values)),
            Origin::Api,
        )
    }

    fn removal(name: &str, rtype: &str) -> Change {
        Change::new("example.test", name, rtype, None, Origin::Api)
    }

    async fn setup(options: LinkOptions) -> (Source, DnsMock, Link) {
        let mut published = Published::new();
        published.zone("empty.test");
        published.rrset(
            "example.test",
            "seeded.example.test",
            "A",
            Some(300),
            vec!["192.0.2.1".into()],
        );
        let source = Source {
            changes: Changes::new(),
            published,
        };
        let dns = DnsMock::start(Role::Authoritative).await;
        let link = link(&source, &dns, options);
        (source, dns, link)
    }

    #[test]
    fn values_are_converted_from_text() {
        let raw = |rtype, text| match data(rtype, text) {
            Some(Data::Raw(octets)) => octets,
            other => panic!("{text}: {other:?}"),
        };
        assert_eq!(raw(TYPE_A, "192.0.2.1"), [192, 0, 2, 1]);
        assert_eq!(raw(TYPE_AAAA, "2001:db8::1").len(), 16);
        assert_eq!(raw(TYPE_TXT, "\"ab\" \"c d\""), b"\x02ab\x03c d");
        assert_eq!(raw(TYPE_TXT, "\"a\\\"b\\092\\\\\""), b"\x05a\"b\\\\");
        assert_eq!(raw(TYPE_TXT, "word \"\""), b"\x04word\x00");
        assert_eq!(
            raw(TYPE_CAA, "0 issue \"ca.example.net; account=1\""),
            b"\x00\x05issueca.example.net; account=1"
        );
        assert_eq!(raw(TYPE_CAA, "128 iodef mailto:a@example.test")[0], 128);
        assert_eq!(
            data(TYPE_CNAME, "target.example.net."),
            Some(Data::Name("target.example.net.".into()))
        );
        assert_eq!(
            data(TYPE_MX, "10 mail.example.test."),
            Some(Data::Mx(10, "mail.example.test.".into()))
        );
        assert_eq!(data(TYPE_MX, "0 ."), Some(Data::Mx(0, ".".into())));

        for (rtype, text) in [
            (TYPE_A, "192.0.2"),
            (TYPE_AAAA, "192.0.2.1"),
            (TYPE_TXT, "\"unterminated"),
            (TYPE_TXT, ""),
            (TYPE_CNAME, "relative.example"),
            (TYPE_CNAME, "a..example."),
            (TYPE_MX, "mail.example.test."),
            (TYPE_MX, "70000 mail.example.test."),
            (TYPE_CAA, "256 issue \"ca\""),
            (TYPE_CAA, "0 is-sue \"ca\""),
            (TYPE_CAA, "0 issue \"a\" \"b\""),
        ] {
            assert_eq!(data(rtype, text), None, "{text}");
        }
        let long = format!("\"{}\"", "x".repeat(256));
        assert_eq!(data(TYPE_TXT, &long), None);
    }

    #[tokio::test]
    async fn the_state_is_served_at_once_and_changes_after_settled() {
        let (source, dns, link) = setup(LinkOptions::new()).await;
        let handle = dns.handle();
        assert!(handle.serves("empty.test"));
        assert!(handle.serves("example.test"));
        assert_eq!(handle.rrset("seeded.example.test", TYPE_A)[0].ttl, 300);

        source.changes.emit(set(
            "_acme-challenge.example.test",
            "TXT",
            None,
            &["\"v1\"", "\"v2\""],
        ));
        source.changes.emit(removal("seeded.example.test", "A"));
        link.settled().await;
        let txt = handle.rrset("_acme-challenge.example.test", TYPE_TXT);
        assert_eq!(txt.len(), 2);
        assert_eq!(txt[0].ttl, DEFAULT_TTL);
        assert!(handle.rrset("seeded.example.test", TYPE_A).is_empty());

        // A zone first seen in a change is served.
        source.changes.emit(Change::new(
            "new.test",
            "new.test",
            "A",
            Some(ChangedRrset::new(Some(60), vec!["192.0.2.9".into()])),
            Origin::Control,
        ));
        link.settled().await;
        assert!(handle.serves("new.test"));
        assert_eq!(link.skipped(), 0);
    }

    #[tokio::test]
    async fn unconverted_types_and_unreadable_values_are_counted() {
        let (source, dns, link) = setup(LinkOptions::new()).await;
        source.changes.emit(set(
            "a.example.test",
            "SRV",
            None,
            &["0 0 443 x.example.test."],
        ));
        source.changes.emit(set(
            "a.example.test",
            "A",
            None,
            &["192.0.2.1", "nonsense", "192.0.2.2"],
        ));
        link.settled().await;
        assert_eq!(link.skipped(), 2);
        assert_eq!(dns.handle().rrset("a.example.test", TYPE_A).len(), 2);
    }

    #[tokio::test]
    async fn a_hold_queues_changes_until_release() {
        let (source, dns, link) = setup(LinkOptions::new().held(true)).await;
        let handle = dns.handle();
        // The initial state is served while held.
        assert_eq!(handle.rrset("seeded.example.test", TYPE_A).len(), 1);
        source
            .changes
            .emit(set("a.example.test", "A", None, &["192.0.2.1"]));
        source
            .changes
            .emit(set("a.example.test", "A", None, &["192.0.2.2"]));
        link.settled().await;
        assert!(handle.rrset("a.example.test", TYPE_A).is_empty());
        link.release();
        link.settled().await;
        assert_eq!(
            handle.rrset("a.example.test", TYPE_A)[0].data,
            Data::a([192, 0, 2, 2])
        );

        link.hold();
        source.changes.emit(removal("a.example.test", "A"));
        link.settled().await;
        assert_eq!(handle.rrset("a.example.test", TYPE_A).len(), 1);
        link.release();
        link.settled().await;
        assert!(handle.rrset("a.example.test", TYPE_A).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_delay_holds_each_change_back_under_a_paused_clock() {
        let delay = Duration::from_secs(30);
        let (source, dns, link) = setup(LinkOptions::new().delay(delay)).await;
        let handle = dns.handle();
        let start = Instant::now();
        source
            .changes
            .emit(set("a.example.test", "A", None, &["192.0.2.1"]));
        // Let the task take the change; the clock does not move while it is busy.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(handle.rrset("a.example.test", TYPE_A).is_empty());
        link.settled().await;
        assert!(start.elapsed() >= delay);
        assert_eq!(handle.rrset("a.example.test", TYPE_A).len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_delay_too_long_to_add_keeps_the_link_alive() {
        let (source, dns, link) = setup(LinkOptions::new().delay(Duration::MAX)).await;
        source
            .changes
            .emit(set("a.example.test", "TXT", None, &["\"v\""]));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!link.task.is_finished());
        assert_eq!(link.shared.state().received, 1);
        assert!(dns.handle().rrset("a.example.test", TYPE_TXT).is_empty());
    }

    /// A source whose `published()` emits two changes of `a.example.test` TXT before it reads
    /// its state: on the first call only, or on every call.
    struct Racing {
        changes: Changes,
        every_call: bool,
        calls: Mutex<u32>,
    }

    impl Racing {
        fn new(every_call: bool) -> Racing {
            Racing {
                changes: Changes::new(),
                every_call,
                calls: Mutex::new(0),
            }
        }

        fn calls(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
    }

    impl ChangeSource for Racing {
        fn changes(&self) -> &Changes {
            &self.changes
        }

        fn published(&self) -> Published {
            // Held while emitting and reading, like a mock's state lock.
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            if *calls == 1 || self.every_call {
                let last = 2 * *calls;
                for value in [last - 1, last] {
                    let value = format!("\"{value}\"");
                    self.changes
                        .emit(set("a.example.test", "TXT", None, &[value.as_str()]));
                }
            }
            let value = if self.every_call { 2 * *calls } else { 2 };
            let mut published = Published::new();
            published.rrset(
                "example.test",
                "a.example.test",
                "TXT",
                None,
                vec![format!("\"{value}\"")],
            );
            published
        }
    }

    fn txt_value(dns: &DnsMock) -> Vec<Data> {
        dns.handle()
            .rrset("a.example.test", TYPE_TXT)
            .into_iter()
            .map(|record| record.data)
            .collect()
    }

    #[tokio::test]
    async fn the_link_starts_from_a_state_that_matches_its_subscription() {
        let source = Racing::new(false);
        let dns = DnsMock::start(Role::Authoritative).await;
        let link = link(&source, &dns, LinkOptions::new().held(true));
        link.settled().await;
        assert!(link.shared.state().queue.is_empty());
        assert_eq!(source.calls(), 2);
        assert_eq!(txt_value(&dns), [Data::txt(&[b"2"])]);
        // The subscription given up is gone from the hub.
        assert!(format!("{:?}", source.changes).contains("subscribers: 1"));
    }

    #[tokio::test]
    async fn a_source_that_keeps_changing_is_read_a_bounded_number_of_times() {
        let source = Racing::new(true);
        let dns = DnsMock::start(Role::Authoritative).await;
        let link = link(&source, &dns, LinkOptions::new());
        assert_eq!(source.calls(), u32::try_from(START_ATTEMPTS).unwrap());
        link.settled().await;
        assert_eq!(txt_value(&dns), [Data::txt(&[b"16"])]);
        assert!(format!("{:?}", source.changes).contains("subscribers: 1"));
        // The link goes on receiving.
        source
            .changes
            .emit(set("a.example.test", "TXT", None, &["\"17\""]));
        link.settled().await;
        assert_eq!(txt_value(&dns), [Data::txt(&[b"17"])]);
    }

    #[test]
    fn an_absolute_name_is_at_most_255_octets_on_the_wire() {
        let label = "a".repeat(63);
        // 63 * 3 + 61 characters of labels and four dots: 254 characters, 255 octets on the wire.
        let name = format!("{label}.{label}.{label}.{}.", "b".repeat(61));
        assert_eq!(name.len(), 254);
        assert_eq!(absolute(&name), Some(name.as_str()));
        let name = format!("{label}.{label}.{label}.{}.", "b".repeat(62));
        assert_eq!(absolute(&name), None);
        assert_eq!(absolute(&format!("{}.test.", "a".repeat(64))), None);
    }

    #[tokio::test]
    async fn data_the_dns_mock_could_not_write_is_skipped() {
        let (source, dns, link) = setup(LinkOptions::new()).await;
        // An owner with a label of 64 octets.
        let owner = format!("{}.example.test", "a".repeat(64));
        source
            .changes
            .emit(set(&owner, "TXT", None, &["\"x\"", "\"y\""]));
        // TXT and CAA values whose RDATA would be over 65 535 octets.
        let strings = vec![format!("\"{}\"", "x".repeat(255)); 300].join(" ");
        let caa = format!("0 issue \"{}\"", "x".repeat(70_000));
        source.changes.emit(set(
            "b.example.test",
            "TXT",
            None,
            &[strings.as_str(), "\"ok\""],
        ));
        source
            .changes
            .emit(set("b.example.test", "CAA", None, &[caa.as_str()]));
        link.settled().await;
        assert_eq!(link.skipped(), 3);
        let handle = dns.handle();
        assert!(handle.rrset(&owner, TYPE_TXT).is_empty());
        assert_eq!(handle.rrset("b.example.test", TYPE_TXT).len(), 1);
        assert!(handle.rrset("b.example.test", TYPE_CAA).is_empty());
    }

    #[tokio::test]
    async fn dropping_the_link_keeps_the_records() {
        let (source, dns, link) = setup(LinkOptions::new()).await;
        source
            .changes
            .emit(set("a.example.test", "A", None, &["192.0.2.1"]));
        link.settled().await;
        drop(link);
        source.changes.emit(removal("a.example.test", "A"));
        assert_eq!(dns.handle().rrset("a.example.test", TYPE_A).len(), 1);
    }
}
