//! Mock of the OVHcloud API, version 1.0: the server time and the `/domain/zone` endpoints
//! (zones, records, refresh), with the request signature checked.
//!
//! Shapes follow the provider's documentation and its published clients, the same sources the
//! client cites, read on 2026-11-16:
//!
//! - the API schema <https://eu.api.ovh.com/1.0/domain.json>: `GET /domain/zone` answers the
//!   zones' names (`string[]`); `GET /domain/zone/{zone}` a zone (`name`, `nameServers`,
//!   `lastUpdate`, `dnssecSupported`, `hasDnsAnycast`); `GET /domain/zone/{zone}/record`
//!   answers the records' identifiers (`long[]`), filtered by `fieldType` ("like") and
//!   `subDomain` ("ilike"), both optional; `POST .../record` takes `fieldType` and `target`
//!   (required), `subDomain` and `ttl` (optional) and answers the record; `GET`, `PUT` and
//!   `DELETE .../record/{id}` read, change (`subDomain`, `target`, `ttl`, none required) and
//!   delete one record; every record change "applies after the zone is refreshed", and
//!   `POST .../refresh` "Applies the pending record changes to the zone". A record holds `id`,
//!   `zone`, `subDomain`, `fieldType`, `target` and `ttl`; the types are those of
//!   `domain.zone.RecordTypeEnum`.
//! - the schema <https://eu.api.ovh.com/1.0/auth.json>: `GET /auth/time`, the server's time in
//!   seconds since the Unix epoch, without authentication.
//! - go-ovh `ovh/ovh.go`: the headers `X-Ovh-Application`, `X-Ovh-Consumer`, `X-Ovh-Timestamp`
//!   and `X-Ovh-Signature`, the signature `"$1$" + hex(SHA1(AS+"+"+CK+"+"+METHOD+"+"+URL+"+"+
//!   BODY+"+"+TIMESTAMP))` over the full URL with its query string; `ovh/error.go`: error bodies
//!   with `class` and `message`.
//! - the guide on service accounts, the one error body the documentation shows:
//!   `403 {"class":"Client::Forbidden","message":"User not granted for this request"}`.
//! - the Terraform provider's `resource_domain_zone_record.go`: "The API silently quotes TXT
//!   fields, and splits long ones in 255 chars strings" (the mock stores a TXT `target` that does
//!   not start with a quote as quoted strings of at most 255 bytes, unless
//!   [`Control::set_txt_quoting`] turns that off); a create answer may lack the identifier
//!   ([`Control::set_create_without_id`]); a record read right after its create may answer `404`
//!   for a while ([`Control::set_read_lag`]).
//!
//! The mock holds every record twice: as staged and as published (what the last refresh of its
//! zone applied). Only the published records are reported as changes and served by a
//! [`link`](crate::link::link).
//!
//! Answers this mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading. A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - the record endpoints read and change the staged records, so a change that is stored but not
//!   refreshed reads as present (the documentation says only that a change "applies after the
//!   zone is refreshed");
//! - an unknown application key, a wrong consumer key, a timestamp more than 300 seconds away
//!   from the mock's clock, and a wrong or missing signature are `403` with the class
//!   `Client::Forbidden` (only the class and status of a permission refusal are documented),
//!   checked in that order;
//! - an unknown zone or record is `404` with the class `Client::NotFound`;
//! - `400` with the class `Client::BadRequest` for a body that is not a JSON object, a member
//!   the documented model does not have (also the read-only `id` and `zone`), a missing
//!   `fieldType` or `target`, a type outside the enumeration, a `ttl` that is not an integer or
//!   lies between 1 and 59 (the lower bound of the Terraform provider), and a `fieldType` filter
//!   outside the enumeration, an empty `target`, and a `subDomain` with a trailing dot or a
//!   space;
//! - a `subDomain` is stored in lower case;
//! - the filters are SQL patterns: `fieldType` LIKE (case-sensitive) and `subDomain` ILIKE
//!   (case-insensitive), `%` any text, `_` one character, `\` the escape; a record whose
//!   `subDomain` is the apex is stored as `""` and answered as `""`, or as `null` with
//!   [`Control::set_apex_null`]; `null` matches no `subDomain` filter;
//! - a record created without `ttl` stores none (answered `null`); `ttl` `0` or `null` is
//!   published with the zone's TTL of 3600;
//! - records of the types DKIM, DMARC and SPF are published under those type names, as the API
//!   names them (whether the name servers serve them as TXT is not established);
//! - a host name in `target` (CNAME, NS, MX, SRV) is published as absolute, a trailing dot
//!   added when missing;
//! - creating a record equal to an existing one is accepted (no source says otherwise);
//! - `PUT`, `DELETE` and the refresh answer `200` with the JSON body `null`; the refresh of a zone
//!   without staged changes succeeds;
//! - no rate limit, no paging, no rate-limit headers.
//!
//! Error texts are invented.
//!
//! A test holds an [`OvhMock`]. It dereferences to the [`MockServer`], so the request log and
//! the fault queue of the shared harness work as usual:
//!
//! ```text
//! let mock = OvhMock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("POST", "/1.0/domain/zone/*/refresh").status(500));
//! // ... drive the client against mock.base_url() ...
//! assert_eq!(mock.control().published_txt_values("_acme-challenge.example.org"), ["\"v1\""]);
//! ```
//!
//! The mock is a [`ChangeSource`]: it reports every change of its published records through
//! [`OvhMock::changes`], the records of one name and type grouped into one rrset (the TTL of the
//! set the smallest of its records), and a [`link`](crate::link::link) serves them over DNS. The
//! form of a value: TXT `target` when it starts with a quote, otherwise quoted strings of at most
//! 255 bytes; CNAME and NS the host name with a trailing dot; MX and SRV `target` with a
//! trailing dot on the host name; every other type `target` as it is. [`Control::reset`]
//! returns the mock to its seed.
//!
//! [`Control::hold_writes`] and [`Control::hold_refreshes`] keep record writes or refreshes from
//! being processed until the test releases them ([`Hold`]), so that a test can force the order in
//! which the requests of concurrent operations take effect, without timing.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::digest;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Map, Value, json};
use tokio::sync::watch;

use crate::changes::{ChangeSource, Changes, Origin, Published};
use crate::{Faults, MockServer, RequestLog};

/// Path of the API below the server's base URL.
pub const API_PATH: &str = "/1.0";

/// The record types of `domain.zone.RecordTypeEnum`.
const TYPES: &[&str] = &[
    "A", "AAAA", "CAA", "CNAME", "DKIM", "DMARC", "DNAME", "HTTPS", "LOC", "MX", "NAPTR", "NS",
    "PTR", "RP", "SPF", "SRV", "SSHFP", "SVCB", "TLSA", "TXT",
];

/// The largest distance between a request's timestamp and the mock's clock (invented).
const CLOCK_WINDOW: i64 = 300;

/// The TTL a record without one of its own is published with (invented).
const ZONE_TTL: u32 = 3600;

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The application key the API accepts.
    pub application_key: String,
    /// The application secret the signatures are checked with.
    pub application_secret: String,
    /// The consumer key the API accepts.
    pub consumer_key: String,
    /// The zones of the account, without a trailing dot.
    pub zones: Vec<String>,
}

impl Seed {
    /// The keys `test-only-ak`, `test-only-as` and `test-only-ck`, the zone `example.org`.
    pub fn standard() -> Self {
        Self {
            application_key: "test-only-ak".into(),
            application_secret: "test-only-as".into(),
            consumer_key: "test-only-ck".into(),
            zones: vec!["example.org".into()],
        }
    }
}

/// One record as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The record's identifier.
    pub id: u64,
    /// The zone, without a trailing dot.
    pub zone: String,
    /// The owner name relative to the zone, `""` for the apex.
    pub sub_domain: String,
    /// The record type.
    pub field_type: String,
    /// The value as stored (a TXT value quoted, see the module documentation).
    pub target: String,
    /// TTL in seconds; `None` is answered as `null`.
    pub ttl: Option<u64>,
}

#[derive(Debug)]
struct Inner {
    /// The seed the mock was started with, for [`Control::reset`].
    seed: Seed,
    changes: Changes,
    zones: Vec<String>,
    /// What the record endpoints read and change.
    staged: Vec<Record>,
    /// What the last refresh of each zone applied.
    live: Vec<Record>,
    next_id: u64,
    clock_offset: i64,
    txt_quoting: bool,
    apex_null: bool,
    create_without_id: bool,
    read_lag: u32,
    /// Records that answer `404` to a read this many more times.
    lagging: HashMap<u64, u32>,
    /// The hold of record writes, if any ([`Control::hold_writes`]).
    write_hold: Option<Arc<Gate>>,
    /// The hold of refreshes, if any ([`Control::hold_refreshes`]).
    refresh_hold: Option<Arc<Gate>>,
}

impl Inner {
    /// The state of a mock started with `seed`.
    fn new(seed: Seed, changes: Changes) -> Inner {
        Inner {
            zones: seed.zones.clone(),
            seed,
            changes,
            staged: Vec::new(),
            live: Vec::new(),
            next_id: 5_000_000_000,
            clock_offset: 0,
            txt_quoting: true,
            apex_null: false,
            create_without_id: false,
            read_lag: 0,
            lagging: HashMap::new(),
            write_hold: None,
            refresh_hold: None,
        }
    }

    fn has_zone(&self, zone: &str) -> bool {
        self.zones.iter().any(|z| z == zone)
    }

    /// The mock's clock, in seconds since the Unix epoch.
    fn now(&self) -> i64 {
        let local = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        local.saturating_add(self.clock_offset)
    }

    /// What a DNS server for the mock's zones would answer: the published records.
    fn published(&self) -> Published {
        let mut out = Published::new();
        for zone in &self.zones {
            out.zone(zone);
        }
        for record in &self.live {
            if !self.has_zone(&record.zone) {
                continue;
            }
            let ttl = record
                .ttl
                .and_then(|t| u32::try_from(t).ok())
                .filter(|t| *t > 0)
                .unwrap_or(ZONE_TTL);
            out.record(
                &record.zone,
                &absolute(&record.sub_domain, &record.zone),
                &record.field_type,
                Some(ttl),
                published_value(&record.field_type, &record.target),
            );
        }
        out
    }

    /// Reports every published rrset that differs from `before`. Called with the state locked,
    /// after a change.
    fn report(&self, before: &Published, origin: Origin) {
        self.changes.emit_diff(before, &self.published(), origin);
    }

    /// Publishes the staged records of `zone`.
    fn refresh(&mut self, zone: &str) {
        self.live.retain(|r| r.zone != zone);
        let staged: Vec<Record> = self
            .staged
            .iter()
            .filter(|r| r.zone == zone)
            .cloned()
            .collect();
        self.live.extend(staged);
    }

    /// `target` as the mock stores it.
    fn stored_target(&self, field_type: &str, target: &str) -> String {
        if field_type == "TXT" && self.txt_quoting && !target.starts_with('"') {
            quoted(target)
        } else {
            target.to_owned()
        }
    }

    fn record_json(&self, record: &Record) -> Value {
        let sub = if self.apex_null && record.sub_domain.is_empty() {
            Value::Null
        } else {
            Value::String(record.sub_domain.clone())
        };
        json!({
            "id": record.id, "zone": record.zone, "subDomain": sub,
            "fieldType": record.field_type, "target": record.target, "ttl": record.ttl
        })
    }
}

/// The value of a record in zone-file text (module documentation).
fn published_value(field_type: &str, target: &str) -> String {
    let host = |text: &str| {
        let text = text.trim();
        if text.ends_with('.') {
            text.to_owned()
        } else {
            format!("{text}.")
        }
    };
    match field_type {
        "TXT" if target.starts_with('"') => target.to_owned(),
        "TXT" => quoted(target),
        "CNAME" | "NS" => host(target),
        "MX" | "SRV" => {
            let mut fields: Vec<&str> = target.split_whitespace().collect();
            let last = fields.pop().map(host).unwrap_or_default();
            fields.push(&last);
            fields.join(" ")
        }
        _ => target.to_owned(),
    }
}

/// `text` as quoted character-strings of at most 255 bytes, `"` and `\` escaped.
fn quoted(text: &str) -> String {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return "\"\"".to_owned();
    }
    bytes
        .chunks(255)
        .map(|chunk| {
            let mut out = String::from("\"");
            for &byte in chunk {
                match byte {
                    b'"' | b'\\' => {
                        out.push('\\');
                        out.push(char::from(byte));
                    }
                    0x20..=0x7e => out.push(char::from(byte)),
                    _ => out.push_str(&format!("\\{byte:03}")),
                }
            }
            out.push('"');
            out
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// SQL `LIKE`: `%` any text, `_` one character, `\` escapes the next character.
fn like(pattern: &[char], text: &[char]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some(('%', rest)) => (0..=text.len()).any(|i| text.get(i..).is_some_and(|t| like(rest, t))),
        Some(('_', rest)) => text.split_first().is_some_and(|(_, t)| like(rest, t)),
        Some(('\\', rest)) => match rest.split_first() {
            Some((c, rest)) => text
                .split_first()
                .is_some_and(|(t0, t)| t0 == c && like(rest, t)),
            None => text
                .split_first()
                .is_some_and(|(t0, t)| *t0 == '\\' && t.is_empty()),
        },
        Some((c, rest)) => text
            .split_first()
            .is_some_and(|(t0, t)| t0 == c && like(rest, t)),
    }
}

fn like_str(pattern: &str, text: &str, case_insensitive: bool) -> bool {
    let fold = |s: &str| -> Vec<char> {
        if case_insensitive {
            s.to_lowercase().chars().collect()
        } else {
            s.chars().collect()
        }
    };
    like(&fold(pattern), &fold(text))
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The shared side of a [`Hold`]: how many more requests it takes, how many it took, and
/// whether it is released.
#[derive(Debug)]
struct Gate {
    remaining: Mutex<usize>,
    arrived: watch::Sender<usize>,
    released: watch::Sender<bool>,
}

impl Gate {
    fn new(count: usize) -> Gate {
        Gate {
            remaining: Mutex::new(count),
            arrived: watch::Sender::new(0),
            released: watch::Sender::new(false),
        }
    }

    /// Holds the calling request until the gate is released, when the gate still takes one.
    async fn pass(&self) {
        {
            let mut remaining = self
                .remaining
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *remaining == 0 || *self.released.borrow() {
                return;
            }
            *remaining -= 1;
        }
        self.arrived.send_modify(|n| *n += 1);
        let mut released = self.released.subscribe();
        // The sender lives in `self`, so the channel cannot close while this waits.
        let _ = released.wait_for(|r| *r).await;
    }
}

/// Holds the request of a handler at the gate `pick` chooses, if one is set.
async fn hold_at(state: &Shared, pick: fn(&Inner) -> &Option<Arc<Gate>>) {
    let gate = pick(&lock(state)).clone();
    if let Some(gate) = gate {
        gate.pass().await;
    }
}

/// Requests the mock keeps unprocessed until [`Hold::release`] is called or the hold is dropped
/// ([`Control::hold_writes`], [`Control::hold_refreshes`]).
///
/// A held request has been logged (the request log counts it on arrival) and has not been
/// authorized or applied: nothing of the mock's state changes until it is released. If the client
/// closes the connection meanwhile, whether the server still processes the request on release is
/// up to the HTTP server; a test must not rely on either.
#[derive(Debug)]
pub struct Hold {
    gate: Arc<Gate>,
}

impl Hold {
    /// The number of requests held so far (released ones included).
    pub fn arrived(&self) -> usize {
        *self.gate.arrived.borrow()
    }

    /// Waits until at least `count` requests have been held. Has no deadline of its own; a test
    /// puts one around it.
    pub async fn arrival(&self, count: usize) {
        let mut arrived = self.gate.arrived.subscribe();
        // The sender lives in `self.gate`, so the channel cannot close while this waits.
        let _ = arrived.wait_for(|n| *n >= count).await;
    }

    /// Lets every held request go on, and every later one pass without being held.
    pub fn release(&self) {
        self.gate.released.send_replace(true);
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.release();
    }
}

/// A running OVHcloud mock. Dereferences to its [`MockServer`] for the request log and the
/// fault queue; [`OvhMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct OvhMock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of an [`OvhMock`]. Cheap to clone, so that a fault hook
/// ([`Fault::run`](crate::Fault::run)) can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
    changes: Changes,
    log: RequestLog,
    faults: Faults,
}

impl Deref for OvhMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl OvhMock {
    /// Starts the mock with `seed` on `127.0.0.1` with an ephemeral port.
    pub async fn start(seed: Seed) -> Self {
        Self::start_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), seed).await
    }

    /// Starts the mock with `seed` on `addr` ([`MockServer::start_on`]). On an address other than
    /// loopback, for an isolated test network only.
    pub async fn start_on(addr: SocketAddr, seed: Seed) -> Self {
        let changes = Changes::new();
        let state = Arc::new(Mutex::new(Inner::new(seed, changes.clone())));
        let router = Router::new()
            .route("/1.0/auth/time", get(server_time))
            .route("/1.0/domain/zone", get(zones_list))
            .route("/1.0/domain/zone/{zone}", get(zone_get))
            .route(
                "/1.0/domain/zone/{zone}/record",
                get(records_list).post(record_create),
            )
            .route(
                "/1.0/domain/zone/{zone}/record/{id}",
                get(record_get).put(record_update).delete(record_delete),
            )
            .route("/1.0/domain/zone/{zone}/refresh", post(zone_refresh))
            .with_state(state.clone());
        let server = MockServer::start_on(addr, router).await;
        let control = Control {
            state,
            changes,
            log: server.log().clone(),
            faults: server.faults().clone(),
        };
        Self { server, control }
    }

    /// The API endpoint, for the client's `base_url`.
    pub fn base_url(&self) -> String {
        self.server.url(API_PATH)
    }

    /// The state control.
    pub fn control(&self) -> &Control {
        &self.control
    }
}

impl ChangeSource for OvhMock {
    fn changes(&self) -> &Changes {
        &self.control.changes
    }

    fn published(&self) -> Published {
        lock(&self.control.state).published()
    }
}

impl Control {
    /// Runs `f` on the locked state and reports what it changed, with [`Origin::Control`].
    fn change<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let mut inner = lock(&self.state);
        let before = inner.published();
        let out = f(&mut inner);
        inner.report(&before, Origin::Control);
        out
    }

    /// Returns the mock to the seed it was started with: its keys and zones, no records,
    /// identifiers counted from the start again, the documented answer forms, its own clock, an
    /// empty request log and no pending faults. Reports the removal of every rrset that was
    /// published.
    pub fn reset(&self) {
        self.faults.clear();
        self.change(|inner| {
            let seed = inner.seed.clone();
            *inner = Inner::new(seed, inner.changes.clone());
        });
        self.log.clear();
    }

    /// Every staged record, in creation order.
    pub fn records(&self) -> Vec<Record> {
        lock(&self.state).staged.clone()
    }

    /// Every published record.
    pub fn published_records(&self) -> Vec<Record> {
        lock(&self.state).live.clone()
    }

    /// The staged records of type `field_type` at `name` (absolute or relative to the first
    /// zone), in creation order.
    pub fn records_at(&self, name: &str, field_type: &str) -> Vec<Record> {
        let inner = lock(&self.state);
        at(&inner.staged, &inner.zones, name, field_type)
    }

    /// The `target` of the staged TXT records at `name`, in creation order.
    pub fn txt_values(&self, name: &str) -> Vec<String> {
        self.records_at(name, "TXT")
            .into_iter()
            .map(|r| r.target)
            .collect()
    }

    /// The `target` of the published TXT records at `name`, in creation order.
    pub fn published_txt_values(&self, name: &str) -> Vec<String> {
        let inner = lock(&self.state);
        at(&inner.live, &inner.zones, name, "TXT")
            .into_iter()
            .map(|r| r.target)
            .collect()
    }

    /// The zone has staged record changes that no refresh has published.
    pub fn pending(&self, zone: &str) -> bool {
        let inner = lock(&self.state);
        let of = |records: &[Record]| {
            let mut list: Vec<Record> =
                records.iter().filter(|r| r.zone == zone).cloned().collect();
            list.sort_by_key(|r| r.id);
            list
        };
        of(&inner.staged) != of(&inner.live)
    }

    /// Adds a published record directly, as another writer that refreshed the zone would.
    /// `name` is absolute or relative to the zone; `target` is stored as given. Returns the
    /// record's identifier.
    pub fn insert_record(
        &self,
        zone: &str,
        name: &str,
        field_type: &str,
        target: &str,
        ttl: Option<u64>,
    ) -> u64 {
        self.change(|inner| {
            let record = new_record(inner, zone, name, field_type, target, ttl);
            inner.staged.push(record.clone());
            inner.live.push(record.clone());
            record.id
        })
    }

    /// Adds a staged record directly, as another writer that did not refresh the zone would.
    pub fn stage_record(
        &self,
        zone: &str,
        name: &str,
        field_type: &str,
        target: &str,
        ttl: Option<u64>,
    ) -> u64 {
        self.change(|inner| {
            let record = new_record(inner, zone, name, field_type, target, ttl);
            inner.staged.push(record.clone());
            record.id
        })
    }

    /// Deletes the record `id` directly, staged and published, as another writer that refreshed
    /// the zone would.
    pub fn delete_record(&self, id: u64) {
        self.change(|inner| {
            inner.staged.retain(|r| r.id != id);
            inner.live.retain(|r| r.id != id);
        });
    }

    /// Publishes the staged records of `zone`, as a refresh by another writer would.
    pub fn refresh(&self, zone: &str) {
        self.change(|inner| inner.refresh(zone));
    }

    /// Adds a zone.
    pub fn insert_zone(&self, zone: &str) {
        self.change(|inner| inner.zones.push(zone.to_owned()));
    }

    /// Gives every record of `zone` a new identifier, staged and published, as a deletion and
    /// re-creation of the zone with the same records would.
    pub fn recreate_zone(&self, zone: &str) {
        let mut inner = lock(&self.state);
        let mut next = inner.next_id;
        let mut renamed = HashMap::new();
        for record in inner.staged.iter_mut().filter(|r| r.zone == zone) {
            next += 1;
            renamed.insert(record.id, next);
            record.id = next;
        }
        for record in inner.live.iter_mut().filter(|r| r.zone == zone) {
            if let Some(id) = renamed.get(&record.id) {
                record.id = *id;
            }
        }
        inner.next_id = next;
    }

    /// Moves the mock's clock by `seconds` against the local clock (for `/auth/time` and the
    /// timestamp check).
    pub fn set_clock_offset(&self, seconds: i64) {
        lock(&self.state).clock_offset = seconds;
    }

    /// Stores a TXT `target` that does not start with a quote quoted (the default, module
    /// documentation) or as written.
    pub fn set_txt_quoting(&self, quoting: bool) {
        lock(&self.state).txt_quoting = quoting;
    }

    /// Answers the `subDomain` of an apex record as `null` instead of `""`.
    pub fn set_apex_null(&self, null: bool) {
        lock(&self.state).apex_null = null;
    }

    /// Answers a create without the record's `id` (Terraform: "this is an API response BUG
    /// known by OVH team").
    pub fn set_create_without_id(&self, without: bool) {
        lock(&self.state).create_without_id = without;
    }

    /// Makes every record created from now on answer `404` to its first `reads` reads by
    /// identifier, while the listing already holds it.
    pub fn set_read_lag(&self, reads: u32) {
        lock(&self.state).read_lag = reads;
    }

    /// Holds the next `count` record writes (`POST .../record`, `PUT` and `DELETE`
    /// `.../record/{id}`) that reach the mock, before they are authorized or change anything,
    /// until the returned [`Hold`] is released or dropped. Later writes pass. A request the
    /// fault queue answers never reaches the hold.
    ///
    /// A new hold of writes replaces this one for requests that arrive after it, and
    /// [`Control::reset`] removes it for them; requests already held stay held until their own
    /// hold is released or dropped.
    pub fn hold_writes(&self, count: usize) -> Hold {
        let gate = Arc::new(Gate::new(count));
        lock(&self.state).write_hold = Some(gate.clone());
        Hold { gate }
    }

    /// The same as [`Control::hold_writes`] for the next `count` refreshes
    /// (`POST .../refresh`).
    pub fn hold_refreshes(&self, count: usize) -> Hold {
        let gate = Arc::new(Gate::new(count));
        lock(&self.state).refresh_hold = Some(gate.clone());
        Hold { gate }
    }
}

fn at(records: &[Record], zones: &[String], name: &str, field_type: &str) -> Vec<Record> {
    let first = zones.first().map_or("", String::as_str);
    let wanted = given(name, first);
    records
        .iter()
        .filter(|r| r.field_type == field_type && absolute(&r.sub_domain, &r.zone) == wanted)
        .cloned()
        .collect()
}

fn new_record(
    inner: &mut Inner,
    zone: &str,
    name: &str,
    field_type: &str,
    target: &str,
    ttl: Option<u64>,
) -> Record {
    inner.next_id += 1;
    Record {
        id: inner.next_id,
        zone: zone.to_owned(),
        sub_domain: relative(&given(name, zone), zone),
        field_type: field_type.to_owned(),
        target: target.to_owned(),
        ttl,
    }
}

/// The absolute name, lowercase, with a trailing dot, of `name` relative to `zone`.
fn absolute(name: &str, zone: &str) -> String {
    let name = name.trim().to_lowercase();
    let zone = zone.to_lowercase();
    if name.is_empty() {
        format!("{zone}.")
    } else {
        format!("{name}.{zone}.")
    }
}

/// The absolute name of a name a test gives: `""`, a name that is the zone or ends with it
/// (with or without a trailing dot) is taken as absolute, any other as relative.
fn given(name: &str, zone: &str) -> String {
    let lower = name.trim().to_lowercase();
    let bare = lower.strip_suffix('.').unwrap_or(&lower);
    let zone = zone.to_lowercase();
    if bare.is_empty() {
        format!("{zone}.")
    } else if bare == zone || bare.ends_with(&format!(".{zone}")) {
        format!("{bare}.")
    } else {
        format!("{bare}.{zone}.")
    }
}

/// `name`, absolute, relative to `zone` as the mock stores it: `""` for the zone itself.
fn relative(name: &str, zone: &str) -> String {
    let name = name.trim().to_lowercase();
    let name = name.strip_suffix('.').unwrap_or(&name);
    let zone = zone.to_lowercase();
    if name == zone {
        String::new()
    } else {
        name.strip_suffix(&format!(".{zone}"))
            .unwrap_or(name)
            .to_owned()
    }
}

/// An error answer in the shape of go-ovh `APIError`.
fn error(status: StatusCode, class: &str, message: &str) -> Response {
    (
        status,
        axum::Json(json!({ "class": class, "message": message })),
    )
        .into_response()
}

fn not_found(message: &str) -> Response {
    error(StatusCode::NOT_FOUND, "Client::NotFound", message)
}

fn bad_request(message: &str) -> Response {
    error(StatusCode::BAD_REQUEST, "Client::BadRequest", message)
}

fn forbidden(message: &str) -> Response {
    error(StatusCode::FORBIDDEN, "Client::Forbidden", message)
}

/// The answer of a write that returns nothing.
fn void() -> Response {
    axum::Json(Value::Null).into_response()
}

/// Checks the keys, the timestamp and the signature of a request (module documentation).
fn authorize(
    state: &Shared,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), Response> {
    let inner = lock(state);
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if header("x-ovh-application") != Some(inner.seed.application_key.as_str()) {
        return Err(forbidden("Invalid application key"));
    }
    if header("x-ovh-consumer") != Some(inner.seed.consumer_key.as_str()) {
        return Err(forbidden("This credential does not exist"));
    }
    let Some(timestamp) = header("x-ovh-timestamp").and_then(|t| t.parse::<i64>().ok()) else {
        return Err(forbidden("Missing or invalid timestamp"));
    };
    if (timestamp - inner.now()).abs() > CLOCK_WINDOW {
        return Err(forbidden("Query out of time"));
    }
    let host = header("host").unwrap_or("");
    let target = format!(
        "http://{host}{}",
        uri.path_and_query().map_or("", |p| p.as_str())
    );
    let mut signed = Vec::new();
    for part in [
        inner.seed.application_secret.as_bytes(),
        inner.seed.consumer_key.as_bytes(),
        method.as_str().as_bytes(),
        target.as_bytes(),
        body,
        timestamp.to_string().as_bytes(),
    ] {
        if !signed.is_empty() {
            signed.push(b'+');
        }
        signed.extend_from_slice(part);
    }
    let expected = format!(
        "$1${}",
        hex(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &signed).as_ref())
    );
    if header("x-ovh-signature") != Some(expected.as_str()) {
        return Err(forbidden("Invalid signature"));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn server_time(State(state): State<Shared>) -> Response {
    axum::Json(json!(lock(&state).now())).into_response()
}

async fn zones_list(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorize(&state, &method, &uri, &headers, b"") {
        return response;
    }
    axum::Json(json!(lock(&state).zones)).into_response()
}

async fn zone_get(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(zone): Path<String>,
) -> Response {
    if let Err(response) = authorize(&state, &method, &uri, &headers, b"") {
        return response;
    }
    let inner = lock(&state);
    if !inner.has_zone(&zone) {
        return not_found("This service does not exist");
    }
    axum::Json(json!({
        "name": zone, "nameServers": ["dns10.ovh.net", "ns10.ovh.net"], "lastUpdate": null,
        "dnssecSupported": true, "hasDnsAnycast": false
    }))
    .into_response()
}

fn query(uri: &Uri, key: &str) -> Option<String> {
    let query = uri.query()?;
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (k == key).then(|| percent_decode(v))
    })
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes.get(i) {
            Some(b'%') => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            Some(b'+') => {
                out.push(b' ');
                i += 1;
            }
            Some(&byte) => {
                out.push(byte);
                i += 1;
            }
            None => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn records_list(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(zone): Path<String>,
) -> Response {
    if let Err(response) = authorize(&state, &method, &uri, &headers, b"") {
        return response;
    }
    let field_type = query(&uri, "fieldType");
    if field_type.as_deref().is_some_and(|t| !TYPES.contains(&t)) {
        return bad_request("Invalid value for fieldType");
    }
    let sub_domain = query(&uri, "subDomain");
    let inner = lock(&state);
    if !inner.has_zone(&zone) {
        return not_found("This service does not exist");
    }
    let ids: Vec<u64> = inner
        .staged
        .iter()
        .filter(|r| r.zone == zone)
        .filter(|r| {
            field_type
                .as_deref()
                .is_none_or(|p| like_str(p, &r.field_type, false))
        })
        .filter(|r| {
            sub_domain.as_deref().is_none_or(|p| {
                // A `null` name (the apex answered as `null`) matches no pattern.
                !(inner.apex_null && r.sub_domain.is_empty()) && like_str(p, &r.sub_domain, true)
            })
        })
        .map(|r| r.id)
        .collect();
    axum::Json(json!(ids)).into_response()
}

async fn record_get(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path((zone, id)): Path<(String, String)>,
) -> Response {
    if let Err(response) = authorize(&state, &method, &uri, &headers, b"") {
        return response;
    }
    let mut inner = lock(&state);
    let Some(id) = id.parse::<u64>().ok() else {
        return not_found("The requested object does not exist");
    };
    if let Some(left) = inner.lagging.get_mut(&id)
        && *left > 0
    {
        *left -= 1;
        return not_found("The requested object does not exist");
    }
    match inner.staged.iter().find(|r| r.zone == zone && r.id == id) {
        Some(record) => axum::Json(inner.record_json(record)).into_response(),
        None => not_found("The requested object does not exist"),
    }
}

/// The members of a request body, refusing any the documented model does not have.
fn members(body: &[u8], allowed: &[&str]) -> Result<Map<String, Value>, Response> {
    let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(body) else {
        return Err(bad_request("The body is not a JSON object"));
    };
    if map.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(bad_request("The body holds an unknown member"));
    }
    Ok(map)
}

fn ttl_member(value: &Value) -> Result<Option<u64>, Response> {
    match value {
        Value::Null => Ok(None),
        other => match other.as_u64() {
            Some(0) => Ok(Some(0)),
            Some(t) if t >= 60 => Ok(Some(t)),
            _ => Err(bad_request("Invalid value for ttl")),
        },
    }
}

fn sub_domain_member(value: &Value) -> Result<String, Response> {
    match value {
        Value::Null => Ok(String::new()),
        Value::String(name) if !name.ends_with('.') && !name.contains(' ') => {
            Ok(name.to_lowercase())
        }
        _ => Err(bad_request("Invalid value for subDomain")),
    }
}

async fn record_create(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(zone): Path<String>,
    body: Bytes,
) -> Response {
    hold_at(&state, |inner| &inner.write_hold).await;
    if let Err(response) = authorize(&state, &method, &uri, &headers, &body) {
        return response;
    }
    let mut inner = lock(&state);
    if !inner.has_zone(&zone) {
        return not_found("This service does not exist");
    }
    let map = match members(&body, &["fieldType", "subDomain", "target", "ttl"]) {
        Ok(map) => map,
        Err(response) => return response,
    };
    let Some(field_type) = map.get("fieldType").and_then(Value::as_str) else {
        return bad_request("Missing parameter fieldType");
    };
    if !TYPES.contains(&field_type) {
        return bad_request("Invalid value for fieldType");
    }
    let Some(target) = map.get("target").and_then(Value::as_str) else {
        return bad_request("Missing parameter target");
    };
    if target.is_empty() {
        return bad_request("Invalid value for target");
    }
    let sub_domain = match map.get("subDomain").map(sub_domain_member) {
        None => String::new(),
        Some(Ok(sub)) => sub,
        Some(Err(response)) => return response,
    };
    let ttl = match map.get("ttl") {
        // `ttl` cannot be `null` in a create (`domain.zone.RecordCreate`).
        Some(Value::Null) => return bad_request("Invalid value for ttl"),
        Some(value) => match ttl_member(value) {
            Ok(ttl) => ttl,
            Err(response) => return response,
        },
        None => None,
    };
    inner.next_id += 1;
    let record = Record {
        id: inner.next_id,
        zone: zone.clone(),
        sub_domain,
        field_type: field_type.to_owned(),
        target: inner.stored_target(field_type, target),
        ttl,
    };
    let mut answer = inner.record_json(&record);
    if inner.create_without_id
        && let Some(object) = answer.as_object_mut()
    {
        object.remove("id");
    }
    if inner.read_lag > 0 {
        let lag = inner.read_lag;
        inner.lagging.insert(record.id, lag);
    }
    // A staged change: nothing published changes.
    inner.staged.push(record);
    axum::Json(answer).into_response()
}

async fn record_update(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path((zone, id)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    hold_at(&state, |inner| &inner.write_hold).await;
    if let Err(response) = authorize(&state, &method, &uri, &headers, &body) {
        return response;
    }
    let mut inner = lock(&state);
    let Some(index) = id.parse::<u64>().ok().and_then(|id| {
        inner
            .staged
            .iter()
            .position(|r| r.zone == zone && r.id == id)
    }) else {
        return not_found("The requested object does not exist");
    };
    let map = match members(&body, &["subDomain", "target", "ttl"]) {
        Ok(map) => map,
        Err(response) => return response,
    };
    let Some(mut updated) = inner.staged.get(index).cloned() else {
        return not_found("The requested object does not exist");
    };
    if let Some(value) = map.get("subDomain") {
        match sub_domain_member(value) {
            Ok(sub) => updated.sub_domain = sub,
            Err(response) => return response,
        }
    }
    if let Some(value) = map.get("target") {
        match value.as_str() {
            Some(target) if !target.is_empty() => {
                updated.target = inner.stored_target(&updated.field_type, target);
            }
            _ => return bad_request("Invalid value for target"),
        }
    }
    if let Some(value) = map.get("ttl") {
        match ttl_member(value) {
            Ok(ttl) => updated.ttl = ttl,
            Err(response) => return response,
        }
    }
    if let Some(slot) = inner.staged.get_mut(index) {
        *slot = updated;
    }
    void()
}

async fn record_delete(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path((zone, id)): Path<(String, String)>,
) -> Response {
    hold_at(&state, |inner| &inner.write_hold).await;
    if let Err(response) = authorize(&state, &method, &uri, &headers, b"") {
        return response;
    }
    let Ok(id) = id.parse::<u64>() else {
        return not_found("The requested object does not exist");
    };
    let mut inner = lock(&state);
    if !inner.staged.iter().any(|r| r.zone == zone && r.id == id) {
        return not_found("The requested object does not exist");
    }
    inner.staged.retain(|r| !(r.zone == zone && r.id == id));
    void()
}

async fn zone_refresh(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(zone): Path<String>,
    body: Bytes,
) -> Response {
    hold_at(&state, |inner| &inner.refresh_hold).await;
    if let Err(response) = authorize(&state, &method, &uri, &headers, &body) {
        return response;
    }
    let mut inner = lock(&state);
    if !inner.has_zone(&zone) {
        return not_found("This service does not exist");
    }
    let before = inner.published();
    inner.refresh(&zone);
    inner.report(&before, Origin::Api);
    void()
}

#[cfg(test)]
mod tests {
    use super::{absolute, given, like_str, published_value, quoted, relative};

    #[test]
    fn names_are_relative_to_the_zone() {
        assert_eq!(absolute("", "example.org"), "example.org.");
        assert_eq!(absolute("www", "example.org"), "www.example.org.");
        assert_eq!(given("www.example.org.", "example.org"), "www.example.org.");
        assert_eq!(given("www", "example.org"), "www.example.org.");
        assert_eq!(relative("example.org.", "example.org"), "");
        assert_eq!(relative("a.b.example.org.", "example.org"), "a.b");
    }

    #[test]
    fn filters_are_sql_patterns() {
        assert!(like_str("TXT", "TXT", false));
        assert!(!like_str("TXT", "txt", false));
        assert!(like_str("_acme-challenge", "xacme-challenge", true));
        assert!(like_str("WWW", "www", true));
        assert!(like_str("a%", "abc", true));
        assert!(!like_str("a", "ab", true));
        assert!(like_str("a\\_b", "a_b", true));
        assert!(!like_str("a\\_b", "axb", true));
        assert!(!like_str("x", "", true));
    }

    #[test]
    fn values_are_published_in_zone_file_text() {
        assert_eq!(quoted("v1"), "\"v1\"");
        let long = "x".repeat(300);
        assert_eq!(
            quoted(&long),
            format!("\"{}\" \"{}\"", "x".repeat(255), "x".repeat(45))
        );
        assert_eq!(published_value("TXT", "\"v1\""), "\"v1\"");
        assert_eq!(published_value("TXT", "v1"), "\"v1\"");
        assert_eq!(published_value("CNAME", "a.example.net"), "a.example.net.");
        assert_eq!(
            published_value("MX", "10 mail.example.org"),
            "10 mail.example.org."
        );
        assert_eq!(published_value("A", "192.0.2.1"), "192.0.2.1");
    }
}
