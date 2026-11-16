//! Mock of the nic.ru (RU-CENTER) DNS hosting API and its OAuth token endpoint. Written with
//! the `nicru` client.
//!
//! Shapes follow the provider's documentation, the same sources the client cites: the "API of
//! DNS hosting" request description (`API_DNS-hosting-en.pdf`, linked from
//! <https://www.nic.ru/help/api-of-dns-hosting_1579.html>; read through the Internet Archive copy
//! of 2024-09-13) and lego `providers/dns/nicru` with its test fixtures:
//!
//! - `POST /oauth/token` takes a form body with `grant_type=password`, `username`, `password`
//!   and `scope` (documentation section 2.2; a token without a scope "will not work"); the
//!   application's ID and secret come in an `Authorization: Basic` header (documentation) or as
//!   `client_id` and `client_secret` in the body (lego, `oauth2.AuthStyleInParams`); the answer
//!   is the JSON of lego's `auth.json` fixture (`access_token`, `token_type`, `expires_in`,
//!   `refresh_token`);
//! - every API answer is `<response><status>success</status>…</response>` or
//!   `<response><status>fail</status><errors><error code="…">text</error></errors></response>`;
//!   an unknown or expired token is code `4097`, "Access token expired or not found";
//! - `GET /dns-master/zones` lists every zone with the attributes `admin`, `enable`,
//!   `has-changes`, `has-primary`, `id`, `idn-name`, `name` (Punycode), `payer`, `service`;
//! - `GET /dns-master/services/{service}/zones/{zone}/records` answers one `zone` element (with
//!   `has-changes`) and its `rr` elements (`id` attribute; `name`, `idn-name`, `ttl`, `type` and
//!   the type's element of documentation section 4.6, for TXT `<txt><string>…</string>+</txt>`,
//!   with an `idn-name` next to every `name` inside it, as the listing example of 4.5.2 shows);
//! - `PUT …/records` takes `<request><rr-list><rr>…</rr>+</rr-list></request>` and answers the
//!   zone with the created records; `ttl` is optional, numeric or in BIND form (4.6); the type's
//!   element must be complete: an IPv4 address for A, an IPv6 address for AAAA, a name for
//!   CNAME, NS, PTR and DNAME, a 16-bit preference and a name for MX, three 16-bit numbers and a
//!   name for SRV, one to many strings of at most 255 bytes for TXT; the zone then has changes;
//! - `DELETE …/records/{id}` deletes one record (lego's fixture answers `success`);
//! - `POST …/commit` publishes every staged change of the zone; `POST …/rollback` discards them.
//!
//! Answers this mock invents because the documentation is silent. A test that depends on one of
//! them proves only how the client handles that answer, not that the provider gives it:
//!
//! - a `fail` answer has HTTP status 200 (the documentation says "HTTP with the error code" for
//!   most calls and "HTTP with the error code 200" for one; lego's tests serve its error fixture
//!   with 200);
//! - the record listing shows the staged state of the zone, including changes not committed;
//! - an unknown service or zone answers code `4026` "zone not found"; an unknown record `4030`
//!   "record not found"; a malformed or unsupported record `4004`;
//! - a refused token request answers `400` with `{"error":"invalid_grant"}` or
//!   `{"error":"invalid_scope"}` (the form of RFC 6749 section 5.2);
//! - a record name is stored relative to the zone, lowercase; an absolute name in a request is
//!   converted;
//! - the mock accepts A, AAAA, CNAME, NS, PTR, DNAME, MX, SRV and TXT records in a `PUT`
//!   (section 4.6 also shows SOA, HINFO, NAPTR and RP; the client does not send them); any other
//!   type is refused with `4004`; other types exist only through the control;
//! - the text of each field is stored as sent, trimmed, and listed as stored (a name keeps or
//!   lacks its trailing dot as sent).
//!
//! Error texts are invented.
//!
//! The mock is a [`ChangeSource`]: it reports every change of its published records through
//! [`NicruMock::changes`], the records of one name and type grouped into one rrset, and a
//! [`link`](crate::link::link) serves them over DNS. Only the committed state is published:
//! staging a record, deleting one and a rollback change nothing published and report nothing;
//! a commit reports the whole difference the zone's staged changes make. Every zone is
//! published. An owner name is read as a zone file reads it: `@` is the apex, a name with the
//! trailing dot is absolute, any other name is relative to the zone. The published form of a
//! value: TXT as its strings, each quoted, separated by spaces; A and AAAA as stored; a name in
//! a CNAME, NS, PTR, DNAME, MX or SRV value read the same way as an owner name and written
//! fully qualified; other types as their fields separated by spaces. The TTL of the set is the
//! smallest TTL of its records (a BIND-form TTL converted to seconds), none when no record has
//! one (the zone's default applies). Left out: the SOA record (the server that serves the zone
//! answers with its own) and records added through [`Control::insert_raw`], whose content the
//! documentation does not describe. [`Control::reset`] returns the mock to its seed.

// Handlers return finished HTTP answers as their error values and hand them straight to axum.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use base64::Engine as _;
use serde_json::json;

use crate::changes::{ChangeSource, Changes, Origin, Published};
use crate::{Fault, Faults, MockServer, RequestLog};

/// Path of the DNS API below the server's base URL.
pub const API_PATH: &str = "/dns-master";

/// Path of the token endpoint below the server's base URL.
pub const TOKEN_PATH: &str = "/oauth/token";

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The contract number used as the user name.
    pub username: String,
    /// The account's password.
    pub password: String,
    /// The OAuth application's ID.
    pub client_id: String,
    /// The OAuth application's secret.
    pub client_secret: String,
    /// The DNS-master service that holds the zones.
    pub service: String,
    /// Names of the zones.
    pub zones: Vec<String>,
}

impl Seed {
    /// The contract `123/NIC-REG`, synthetic application credentials, the service `zwservice`
    /// and the zone `example.org`.
    pub fn standard() -> Self {
        Self {
            username: "123/NIC-REG".into(),
            password: "test-only-password".into(),
            client_id: "0123456789abcdef0123456789abcdef".into(),
            client_secret: "test-only-client-secret".into(),
            service: "zwservice".into(),
            zones: vec!["example.org".into()],
        }
    }
}

/// A zone as the mock holds it.
#[derive(Clone, Debug)]
pub struct Zone {
    /// The numeric identifier.
    pub id: u64,
    /// The zone name, lowercase, without the trailing dot.
    pub name: String,
    /// The service the zone is placed under.
    pub service: String,
    /// True for a DNS-master service, false for a Secondary one.
    pub primary: bool,
    /// The zone has staged changes that are not committed.
    pub has_changes: bool,
}

/// A resource record as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The record's identifier.
    pub id: u64,
    /// The zone's identifier.
    pub zone_id: u64,
    /// The owner name relative to the zone (`@` for the apex), lowercase.
    pub name: String,
    /// The TTL as given, if any.
    pub ttl: Option<String>,
    /// The record type.
    pub rtype: String,
    /// For TXT, the character strings; for a type of section 4.6, the fields of its element in
    /// the order of the documentation; for another type, one string with its data.
    pub strings: Vec<String>,
    /// Content of the type's element as given to [`Control::insert_raw`], listed verbatim in
    /// place of `strings`.
    pub raw: Option<String>,
}

impl Record {
    /// The TXT value: the character strings joined.
    pub fn value(&self) -> String {
        self.strings.concat()
    }
}

#[derive(Debug)]
struct Inner {
    /// The seed the mock was started with, for [`Control::reset`]; `seed` below can be changed
    /// by [`Control::set_password`].
    initial: Seed,
    changes: Changes,
    seed: Seed,
    zones: Vec<Zone>,
    /// What the zone files hold now, staged changes included.
    staged: Vec<Record>,
    /// What was published by the last commit.
    published: Vec<Record>,
    tokens: Vec<String>,
    tokens_issued: u64,
    next_id: u64,
    /// How many of the next zone listings fail (see [`Control::fail_zone_listings`]).
    failing_listings: u32,
}

impl Inner {
    /// The state of a mock started with `seed`.
    fn new(seed: Seed, changes: Changes) -> Inner {
        let mut inner = Inner {
            initial: seed.clone(),
            changes,
            zones: Vec::new(),
            staged: Vec::new(),
            published: Vec::new(),
            tokens: Vec::new(),
            tokens_issued: 0,
            next_id: 227_000,
            failing_listings: 0,
            seed: seed.clone(),
        };
        for name in &seed.zones {
            let id = inner.new_id();
            inner.zones.push(Zone {
                id,
                name: normalize(name),
                service: seed.service.clone(),
                primary: true,
                has_changes: false,
            });
        }
        inner
    }

    /// What the name servers of the mock's zones answer: the committed records (module
    /// documentation).
    fn published(&self) -> Published {
        let mut out = Published::new();
        for zone in &self.zones {
            out.zone(&zone.name);
        }
        for record in &self.published {
            let Some(zone) = self.zones.iter().find(|z| z.id == record.zone_id) else {
                continue;
            };
            if record.raw.is_some() || record.rtype == "SOA" {
                continue;
            }
            let ttl = record.ttl.as_deref().and_then(ttl_seconds);
            out.record(
                &zone.name,
                &absolute(&record.name, &zone.name),
                &record.rtype,
                ttl,
                published_value(record, &zone.name),
            );
        }
        out
    }

    /// Reports every published rrset that differs from `before`. Called with the state locked,
    /// after a change.
    fn report(&self, before: &Published, origin: Origin) {
        self.changes.emit_diff(before, &self.published(), origin);
    }

    /// Publishes every staged change of zone `zone`.
    fn commit(&mut self, zone: u64) {
        let staged: Vec<Record> = self
            .staged
            .iter()
            .filter(|r| r.zone_id == zone)
            .cloned()
            .collect();
        self.published.retain(|r| r.zone_id != zone);
        self.published.extend(staged);
        for z in self.zones.iter_mut().filter(|z| z.id == zone) {
            z.has_changes = false;
        }
    }

    /// Stages a record of zone `zone_id` (see [`Control::stage_record`]); returns its identifier.
    fn stage(
        &mut self,
        zone_id: u64,
        name: &str,
        rtype: &str,
        data: &str,
        ttl: Option<&str>,
    ) -> u64 {
        let id = self.new_id();
        let strings = if rtype == "TXT" || shape(rtype).is_none() {
            vec![data.to_owned()]
        } else {
            data.split_whitespace().map(str::to_owned).collect()
        };
        self.staged.push(Record {
            id,
            zone_id,
            name: name.to_lowercase(),
            ttl: ttl.map(str::to_owned),
            rtype: rtype.to_owned(),
            strings,
            raw: None,
        });
        for z in self.zones.iter_mut().filter(|z| z.id == zone_id) {
            z.has_changes = true;
        }
        id
    }

    /// The identifier of zone `zone`.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    fn zone_id(&self, zone: &str) -> u64 {
        self.zone_by_name(zone)
            .map(|z| z.id)
            .unwrap_or_else(|| panic!("no zone {zone}"))
    }

    /// Adds a record published and staged alike (see [`Control::insert_record`]).
    fn insert(
        &mut self,
        zone: &str,
        name: &str,
        rtype: &str,
        data: &str,
        ttl: Option<&str>,
    ) -> u64 {
        let zone_id = self.zone_id(zone);
        let id = self.stage(zone_id, name, rtype, data, ttl);
        if let Some(record) = self.staged.iter().find(|r| r.id == id).cloned() {
            self.published.push(record);
        }
        for z in self.zones.iter_mut().filter(|z| z.id == zone_id) {
            z.has_changes = false;
        }
        id
    }

    fn new_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    fn zone_by_name(&self, name: &str) -> Option<&Zone> {
        let name = normalize(name);
        self.zones.iter().find(|z| z.name == name)
    }
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running nic.ru mock. Dereferences to its [`MockServer`] for the request log and the fault
/// queue; [`NicruMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct NicruMock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of a [`NicruMock`]. Cheap to clone, so that a fault hook can
/// change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
    changes: Changes,
    log: RequestLog,
    faults: Faults,
}

impl Deref for NicruMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl NicruMock {
    /// Starts the mock with `seed` on `127.0.0.1` with an ephemeral port.
    pub async fn start(seed: Seed) -> Self {
        Self::start_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), seed).await
    }

    /// Starts the mock with `seed` on `addr` ([`MockServer::start_on`]).
    pub async fn start_on(addr: SocketAddr, seed: Seed) -> Self {
        let changes = Changes::new();
        let state = Arc::new(Mutex::new(Inner::new(seed, changes.clone())));
        let router = Router::new()
            .route("/oauth/token", post(token))
            .route("/dns-master/zones", get(zones))
            .route(
                "/dns-master/services/{service}/zones/{zone}/records",
                get(records).put(add_records),
            )
            .route(
                "/dns-master/services/{service}/zones/{zone}/records/{id}",
                delete(delete_record),
            )
            .route(
                "/dns-master/services/{service}/zones/{zone}/commit",
                post(commit),
            )
            .route(
                "/dns-master/services/{service}/zones/{zone}/rollback",
                post(rollback),
            )
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

    /// The DNS API endpoint, for the client's `base_url`.
    pub fn base_url(&self) -> String {
        self.server.url(API_PATH)
    }

    /// The token endpoint, for the client's `token_url`.
    pub fn token_url(&self) -> String {
        self.server.url(TOKEN_PATH)
    }

    /// The state control.
    pub fn control(&self) -> &Control {
        &self.control
    }

    /// The next `times` commits are applied and then answered `502`, as commits whose answers
    /// are lost; each of them also makes the next `failing_listings` zone listings fail
    /// ([`Control::fail_zone_listings`]), so that a listing right after it fails as well.
    pub fn lose_commit_answers(&self, times: u32, failing_listings: u32) {
        let control = self.control.clone();
        self.server.faults().push(
            Fault::on("POST", "/dns-master/services/*/zones/*/commit")
                .times(times)
                .run(move || {
                    // The commit request itself is applied: an API change.
                    for zone in control.zone_names() {
                        control.commit_as(&zone, Origin::Api);
                    }
                    control.fail_zone_listings(failing_listings);
                })
                .status(502),
        );
    }

    /// The next `times` rollbacks are applied and then answered `502`, as rollbacks whose
    /// answers are lost; each of them also makes the next `failing_listings` zone listings fail.
    pub fn lose_rollback_answers(&self, times: u32, failing_listings: u32) {
        let control = self.control.clone();
        self.server.faults().push(
            Fault::on("POST", "/dns-master/services/*/zones/*/rollback")
                .times(times)
                .run(move || {
                    for zone in control.zone_names() {
                        control.rollback(&zone);
                    }
                    control.fail_zone_listings(failing_listings);
                })
                .status(502),
        );
    }

    /// The next `times` record stagings (`PUT …/records`) are answered `502` without being
    /// applied; each of them also makes the next `failing_listings` zone listings fail.
    pub fn fail_creates_unapplied(&self, times: u32, failing_listings: u32) {
        let control = self.control.clone();
        self.server.faults().push(
            Fault::on("PUT", "/dns-master/services/*/zones/*/records")
                .times(times)
                .run(move || control.fail_zone_listings(failing_listings))
                .status(502),
        );
    }
}

impl ChangeSource for NicruMock {
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

    /// Returns the mock to the seed it was started with: its credentials, its zones under their
    /// first identifiers without staged changes, no records, no tokens, no failing listings, an
    /// empty request log and no pending faults. Reports the removal of every rrset that was
    /// published.
    pub fn reset(&self) {
        self.faults.clear();
        self.change(|inner| {
            let seed = inner.initial.clone();
            *inner = Inner::new(seed, inner.changes.clone());
        });
        self.log.clear();
    }

    /// Every zone.
    pub fn zones(&self) -> Vec<Zone> {
        lock(&self.state).zones.clone()
    }

    /// Adds a zone under `service`; `primary` false makes it a zone of a Secondary service.
    pub fn insert_zone(&self, name: &str, service: &str, primary: bool) {
        self.change(|inner| {
            let id = inner.new_id();
            inner.zones.push(Zone {
                id,
                name: normalize(name),
                service: service.to_owned(),
                primary,
                has_changes: false,
            });
        });
    }

    /// Moves zone `name`, with its records, to service `service` under a new zone identifier.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn move_zone(&self, name: &str, service: &str) {
        let name = normalize(name);
        self.change(|inner| {
            let new_id = inner.new_id();
            let zone = inner
                .zones
                .iter_mut()
                .find(|z| z.name == name)
                .unwrap_or_else(|| panic!("no zone {name}"));
            let old_id = zone.id;
            zone.id = new_id;
            zone.service = service.to_owned();
            for record in inner
                .staged
                .iter_mut()
                .chain(inner.published.iter_mut())
                .filter(|r| r.zone_id == old_id)
            {
                record.zone_id = new_id;
            }
        });
    }

    /// True when zone `name` has staged changes that are not committed.
    pub fn has_changes(&self, zone: &str) -> bool {
        lock(&self.state)
            .zone_by_name(zone)
            .is_some_and(|z| z.has_changes)
    }

    /// Marks zone `zone` as having staged changes, as another writer's edit would.
    pub fn set_has_changes(&self, zone: &str) {
        let name = normalize(zone);
        for z in lock(&self.state)
            .zones
            .iter_mut()
            .filter(|z| z.name == name)
        {
            z.has_changes = true;
        }
    }

    /// Adds a record directly, published and staged alike, as another writer's committed
    /// change would. `name` is relative to the zone; `data` is the TXT value, or the fields of
    /// another type separated by whitespace. Returns the record's identifier.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn insert_record(
        &self,
        zone: &str,
        name: &str,
        rtype: &str,
        data: &str,
        ttl: Option<&str>,
    ) -> u64 {
        self.change(|inner| inner.insert(zone, name, rtype, data, ttl))
    }

    /// Stages a record without committing it, as another writer's edit would; the zone then
    /// has changes. Returns the record's identifier.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn stage_record(
        &self,
        zone: &str,
        name: &str,
        rtype: &str,
        data: &str,
        ttl: Option<&str>,
    ) -> u64 {
        // Staged only: nothing published changes, and the helper reports nothing.
        self.change(|inner| {
            let zone_id = inner.zone_id(zone);
            inner.stage(zone_id, name, rtype, data, ttl)
        })
    }

    /// Adds a published record of `rtype` at `name` (relative, as listed) whose type element is
    /// `element`, listed verbatim: content the documentation does not describe. Returns the
    /// record's identifier.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn insert_raw(
        &self,
        zone: &str,
        name: &str,
        rtype: &str,
        element: &str,
        ttl: Option<&str>,
    ) -> u64 {
        self.change(|inner| {
            let id = inner.insert(zone, name, rtype, "", ttl);
            for record in inner
                .staged
                .iter_mut()
                .chain(inner.published.iter_mut())
                .filter(|r| r.id == id)
            {
                record.name = name.to_owned();
                record.raw = Some(element.to_owned());
            }
            id
        })
    }

    /// Every published record of zone `zone`.
    pub fn published_all(&self, zone: &str) -> Vec<Record> {
        let inner = lock(&self.state);
        let Some(zone_id) = inner.zone_by_name(zone).map(|z| z.id) else {
            return Vec::new();
        };
        inner
            .published
            .iter()
            .filter(|r| r.zone_id == zone_id)
            .cloned()
            .collect()
    }

    /// Every staged record of zone `zone`, the records a commit would publish.
    pub fn staged_all(&self, zone: &str) -> Vec<Record> {
        let inner = lock(&self.state);
        let Some(zone_id) = inner.zone_by_name(zone).map(|z| z.id) else {
            return Vec::new();
        };
        inner
            .staged
            .iter()
            .filter(|r| r.zone_id == zone_id)
            .cloned()
            .collect()
    }

    /// Stages the deletion of the TXT records of `name` (relative) holding `value`, as an edit
    /// whose answer was lost would; the zone then has changes.
    pub fn stage_txt_deletion(&self, name: &str, value: &str) {
        let name = name.to_lowercase();
        // Staged only: nothing published changes, and the helper reports nothing.
        self.change(|inner| {
            let zones: Vec<u64> = inner
                .staged
                .iter()
                .filter(|r| r.name == name && r.rtype == "TXT" && r.value() == value)
                .map(|r| r.zone_id)
                .collect();
            inner
                .staged
                .retain(|r| !(r.name == name && r.rtype == "TXT" && r.value() == value));
            for z in inner.zones.iter_mut().filter(|z| zones.contains(&z.id)) {
                z.has_changes = true;
            }
        });
    }

    /// The staged records of `name` (relative, `@` for the apex) and `rtype`.
    pub fn staged(&self, name: &str, rtype: &str) -> Vec<Record> {
        let inner = lock(&self.state);
        of(&inner.staged, name, rtype)
    }

    /// The published records of `name` (relative) and `rtype`.
    pub fn published(&self, name: &str, rtype: &str) -> Vec<Record> {
        let inner = lock(&self.state);
        of(&inner.published, name, rtype)
    }

    /// The published TXT values of `name` (relative), in creation order.
    pub fn published_txt(&self, name: &str) -> Vec<String> {
        self.published(name, "TXT")
            .iter()
            .map(Record::value)
            .collect()
    }

    /// The staged TXT values of `name` (relative), in creation order.
    pub fn staged_txt(&self, name: &str) -> Vec<String> {
        self.staged(name, "TXT").iter().map(Record::value).collect()
    }

    /// Publishes every staged change of zone `zone`, as a commit request would; for a fault hook
    /// that applies a commit whose answer is then lost.
    pub fn commit(&self, zone: &str) {
        self.commit_as(zone, Origin::Control);
    }

    /// [`Control::commit`], reported with `origin`.
    fn commit_as(&self, zone: &str, origin: Origin) {
        let mut inner = lock(&self.state);
        let Some(id) = inner.zone_by_name(zone).map(|z| z.id) else {
            return;
        };
        let before = inner.published();
        inner.commit(id);
        inner.report(&before, origin);
    }

    /// Discards every staged change of zone `zone`, as a rollback request would; for a fault
    /// hook that applies a rollback whose answer is then lost.
    pub fn rollback(&self, zone: &str) {
        let mut inner = lock(&self.state);
        let Some(id) = inner.zone_by_name(zone).map(|z| z.id) else {
            return;
        };
        let published: Vec<Record> = inner
            .published
            .iter()
            .filter(|r| r.zone_id == id)
            .cloned()
            .collect();
        inner.staged.retain(|r| r.zone_id != id);
        inner.staged.extend(published);
        for z in inner.zones.iter_mut().filter(|z| z.id == id) {
            z.has_changes = false;
        }
    }

    /// The names of every zone.
    pub fn zone_names(&self) -> Vec<String> {
        lock(&self.state)
            .zones
            .iter()
            .map(|z| z.name.clone())
            .collect()
    }

    /// The next `n` zone listings (`GET /dns-master/zones`) are answered `503` with an empty
    /// body, replacing any count set before. A client's transport repeats an idempotent request
    /// up to three times, so `3` makes one listing of the client fail.
    pub fn fail_zone_listings(&self, n: u32) {
        lock(&self.state).failing_listings = n;
    }

    /// Invalidates every issued token, as an expiry would.
    pub fn expire_tokens(&self) {
        lock(&self.state).tokens.clear();
    }

    /// The number of tokens issued so far.
    pub fn tokens_issued(&self) -> u64 {
        lock(&self.state).tokens_issued
    }

    /// Changes the account's password; tokens issued before stay valid.
    pub fn set_password(&self, password: &str) {
        lock(&self.state).seed.password = password.to_owned();
    }
}

fn of(records: &[Record], name: &str, rtype: &str) -> Vec<Record> {
    let name = name.to_lowercase();
    records
        .iter()
        .filter(|r| r.name == name && r.rtype == rtype)
        .cloned()
        .collect()
}

/// A name of zone `zone` as a zone file reads it, fully qualified with the trailing dot: `@` or
/// an empty name is the apex, a name with the trailing dot is absolute, any other name is
/// relative to the zone.
fn absolute(name: &str, zone: &str) -> String {
    let name = name.trim();
    if name.is_empty() || name == "@" {
        format!("{zone}.")
    } else if name.ends_with('.') {
        name.to_owned()
    } else {
        format!("{name}.{zone}.")
    }
}

/// The value of `record` of zone `zone` in zone-file text (module documentation).
fn published_value(record: &Record, zone: &str) -> String {
    let field = |i: usize| record.strings.get(i).map(String::as_str).unwrap_or("");
    match record.rtype.as_str() {
        "TXT" => {
            let quoted: Vec<String> = record.strings.iter().map(|s| quote(s)).collect();
            quoted.join(" ")
        }
        "CNAME" | "NS" | "PTR" | "DNAME" => absolute(field(0), zone),
        "MX" => format!("{} {}", field(0), absolute(field(1), zone)),
        "SRV" => format!(
            "{} {} {} {}",
            field(0),
            field(1),
            field(2),
            absolute(field(3), zone)
        ),
        _ => record.strings.join(" "),
    }
}

/// `text` as one quoted character-string, `"` and `\` escaped.
fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        if matches!(c, '"' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// A TTL in seconds from its numeric or BIND form ([`valid_ttl`]); `None` for anything else.
fn ttl_seconds(ttl: &str) -> Option<u32> {
    if let Ok(seconds) = ttl.parse::<u32>() {
        return Some(seconds);
    }
    if !valid_ttl(ttl) {
        return None;
    }
    let mut total: u64 = 0;
    let mut number: u64 = 0;
    for c in ttl.chars() {
        if let Some(digit) = c.to_digit(10) {
            number = number.saturating_mul(10).saturating_add(u64::from(digit));
        } else {
            let unit = match c.to_ascii_lowercase() {
                'w' => 604_800,
                'd' => 86_400,
                'h' => 3600,
                'm' => 60,
                _ => 1,
            };
            total = total.saturating_add(number.saturating_mul(unit));
            number = 0;
        }
    }
    u32::try_from(total).ok()
}

fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_lowercase()
}

/// XML escaping of text and attribute values.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn xml(body: String) -> Response {
    (
        StatusCode::OK,
        [("content-type", "text/xml; charset=UTF-8")],
        body,
    )
        .into_response()
}

const HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n";

/// A `fail` answer with one error.
fn fail(code: &str, text: &str) -> Response {
    xml(format!(
        "{HEAD}<response>\n  <status>fail</status>\n  <errors>\n    <error code=\"{code}\">{}</error>\n  </errors>\n</response>\n",
        esc(text)
    ))
}

/// A `success` answer with `data` inside `<data>`, or without `<data>` for `None`.
fn success(data: Option<&str>) -> Response {
    match data {
        Some(data) => xml(format!(
            "{HEAD}<response>\n  <status>success</status>\n  <data>{data}</data>\n</response>\n"
        )),
        None => xml(format!(
            "{HEAD}<response>\n  <status>success</status>\n</response>\n"
        )),
    }
}

async fn token(State(state): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let form: HashMap<String, String> = form_pairs(&body);
    let mut inner = lock(&state);
    let seed = inner.seed.clone();
    // The application's credentials: a Basic header (documentation) or the body (lego).
    let basic = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .and_then(|b| String::from_utf8(b).ok());
    let (client_id, client_secret) = match &basic {
        Some(pair) => match pair.split_once(':') {
            Some((id, secret)) => (Some(id.to_owned()), Some(secret.to_owned())),
            None => (None, None),
        },
        None => (
            form.get("client_id").cloned(),
            form.get("client_secret").cloned(),
        ),
    };
    let refuse = |error: &str| {
        (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "error": error })),
        )
            .into_response()
    };
    if form.get("scope").is_none_or(String::is_empty) {
        return refuse("invalid_scope");
    }
    let granted = form.get("grant_type").map(String::as_str) == Some("password")
        && form.get("username") == Some(&seed.username)
        && form.get("password") == Some(&seed.password)
        && client_id.as_deref() == Some(seed.client_id.as_str())
        && client_secret.as_deref() == Some(seed.client_secret.as_str());
    if !granted {
        return refuse("invalid_grant");
    }
    inner.tokens_issued += 1;
    let access = format!("nic-test-token-{}", inner.tokens_issued);
    inner.tokens.push(access.clone());
    axum::Json(json!({
        "token_type": "Bearer",
        "expires_in": 7600,
        "access_token": access,
        "refresh_token": "",
    }))
    .into_response()
}

/// Decodes a form body (WHATWG `application/x-www-form-urlencoded`).
fn form_pairs(body: &[u8]) -> HashMap<String, String> {
    fn decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'+' => out.push(b' '),
                b'%' if i + 2 < bytes.len() => {
                    let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                    match u8::from_str_radix(hex, 16) {
                        Ok(b) => {
                            out.push(b);
                            i += 2;
                        }
                        Err(_) => out.push(b'%'),
                    }
                }
                b => out.push(b),
            }
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
    String::from_utf8_lossy(body)
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (decode(k), decode(v)),
            None => (decode(pair), String::new()),
        })
        .collect()
}

/// Checks the bearer token; a missing or unknown one is the documented `4097`.
fn authorize(inner: &Inner, headers: &HeaderMap) -> Result<(), Response> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match token {
        Some(t) if inner.tokens.iter().any(|known| known == t) => Ok(()),
        _ => Err(fail("4097", "Access token expired or not found")),
    }
}

fn zone_element(zone: &Zone, admin: &str, children: &str) -> String {
    format!(
        "<zone admin=\"{}\" enable=\"true\" has-changes=\"{}\" has-primary=\"{}\" id=\"{}\" idn-name=\"{}\" name=\"{}\" payer=\"{}\" service=\"{}\">{children}</zone>",
        esc(admin),
        zone.has_changes,
        zone.primary,
        zone.id,
        esc(&zone.name),
        esc(&zone.name),
        esc(admin),
        esc(&zone.service),
    )
}

async fn zones(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let mut inner = lock(&state);
    if let Err(r) = authorize(&inner, &headers) {
        return r;
    }
    if inner.failing_listings > 0 {
        inner.failing_listings -= 1;
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let mut data = String::new();
    for zone in &inner.zones {
        data.push_str("\n    ");
        data.push_str(&zone_element(zone, &inner.seed.username, ""));
    }
    data.push_str("\n  ");
    success(Some(&data))
}

/// The zone `zone` under `service`, by name, case-insensitively (the documentation's examples
/// write zone names in upper case).
fn find_zone(inner: &Inner, service: &str, zone: &str) -> Result<Zone, Response> {
    let name = normalize(zone);
    inner
        .zones
        .iter()
        .find(|z| z.name == name && z.service.eq_ignore_ascii_case(service))
        .cloned()
        .ok_or_else(|| fail("4026", "zone not found"))
}

/// The element of each record type of documentation section 4.6 other than TXT, and the path
/// of each of its fields; an empty path is the element's own text.
const SHAPES: &[(&str, &str, &[&[&str]])] = &[
    ("A", "a", &[&[]]),
    ("AAAA", "aaaa", &[&[]]),
    ("CNAME", "cname", &[&["name"]]),
    ("NS", "ns", &[&["name"]]),
    ("PTR", "ptr", &[&["name"]]),
    ("DNAME", "dname", &[&["name"]]),
    ("MX", "mx", &[&["preference"], &["exchange", "name"]]),
    (
        "SRV",
        "srv",
        &[&["priority"], &["weight"], &["port"], &["target", "name"]],
    ),
    (
        "SOA",
        "soa",
        &[
            &["mname", "name"],
            &["rname", "name"],
            &["serial"],
            &["refresh"],
            &["retry"],
            &["expire"],
            &["minimum"],
        ],
    ),
    ("HINFO", "hinfo", &[&["hardware"], &["os"]]),
    (
        "NAPTR",
        "naptr",
        &[
            &["order"],
            &["preference"],
            &["flags"],
            &["service"],
            &["regexp"],
            &["replacement", "name"],
        ],
    ),
    (
        "RP",
        "rp",
        &[&["mbox-dname", "name"], &["txt-dname", "name"]],
    ),
];

/// The element and field paths of `rtype`.
fn shape(rtype: &str) -> Option<(&'static str, &'static [&'static [&'static str]])> {
    SHAPES
        .iter()
        .find(|(t, _, _)| *t == rtype)
        .map(|(_, element, fields)| (*element, *fields))
}

/// The types a `PUT` accepts.
const WRITABLE: &[&str] = &[
    "A", "AAAA", "CNAME", "NS", "PTR", "DNAME", "MX", "SRV", "TXT",
];

fn rr_element(record: &Record) -> String {
    let mut out = format!(
        "\n      <rr id=\"{}\">\n        <name>{}</name>\n        <idn-name>{}</idn-name>\n",
        record.id,
        esc(&record.name),
        esc(&record.name)
    );
    if let Some(ttl) = &record.ttl {
        let _ = writeln!(out, "        <ttl>{}</ttl>", esc(ttl));
    }
    let _ = writeln!(out, "        <type>{}</type>", esc(&record.rtype));
    if let Some(raw) = &record.raw {
        let _ = writeln!(out, "        {raw}");
    } else if record.rtype == "TXT" {
        out.push_str("        <txt>\n");
        for s in &record.strings {
            let _ = writeln!(out, "          <string>{}</string>", esc(s));
        }
        out.push_str("        </txt>\n");
    } else if let Some((element, fields)) = shape(&record.rtype) {
        let _ = write!(out, "        <{element}>");
        for (path, value) in fields.iter().zip(&record.strings) {
            for tag in *path {
                let _ = write!(out, "<{tag}>");
            }
            out.push_str(&esc(value));
            for tag in path.iter().rev() {
                let _ = write!(out, "</{tag}>");
                if *tag == "name" {
                    let _ = write!(out, "<idn-name>{}</idn-name>", esc(value));
                }
            }
        }
        let _ = writeln!(out, "</{element}>");
    } else {
        let _ = writeln!(
            out,
            "        <{0}>{1}</{0}>",
            record.rtype.to_lowercase(),
            esc(&record.value())
        );
    }
    out.push_str("      </rr>");
    out
}

async fn records(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((service, zone)): Path<(String, String)>,
) -> Response {
    let inner = lock(&state);
    if let Err(r) = authorize(&inner, &headers) {
        return r;
    }
    let zone = match find_zone(&inner, &service, &zone) {
        Ok(zone) => zone,
        Err(r) => return r,
    };
    let rrs: String = inner
        .staged
        .iter()
        .filter(|r| r.zone_id == zone.id)
        .map(rr_element)
        .collect();
    let data = format!(
        "\n    {}\n  ",
        zone_element(&zone, &inner.seed.username, &format!("{rrs}\n    "))
    );
    success(Some(&data))
}

/// The text of the child element `tag` of `node`.
fn child_text(node: roxmltree::Node<'_, '_>, tag: &str) -> Option<String> {
    node.children()
        .find(|c| c.is_element() && c.tag_name().name() == tag)
        .map(|c| c.text().unwrap_or("").trim().to_owned())
}

async fn add_records(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((service, zone)): Path<(String, String)>,
    body: String,
) -> Response {
    let mut inner = lock(&state);
    if let Err(r) = authorize(&inner, &headers) {
        return r;
    }
    let zone = match find_zone(&inner, &service, &zone) {
        Ok(zone) => zone,
        Err(r) => return r,
    };
    let Ok(doc) = roxmltree::Document::parse(&body) else {
        return fail("4004", "the request is not XML");
    };
    let root = doc.root_element();
    if root.tag_name().name() != "request" {
        return fail("4004", "the request element is missing");
    }
    let Some(list) = root
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == "rr-list")
    else {
        return fail("4004", "rr-list is missing");
    };
    let rrs: Vec<_> = list
        .children()
        .filter(|c| c.is_element() && c.tag_name().name() == "rr")
        .collect();
    if rrs.is_empty() {
        return fail("4004", "rr-list holds no rr");
    }
    let mut created = Vec::new();
    for rr in rrs {
        let (Some(name), Some(rtype)) = (child_text(rr, "name"), child_text(rr, "type")) else {
            return fail("4004", "an rr lacks name or type");
        };
        let rtype = rtype.to_uppercase();
        if !WRITABLE.contains(&rtype.as_str()) {
            return fail("4004", "unsupported record type");
        }
        let strings = match record_fields(rr, &rtype) {
            Ok(strings) => strings,
            Err(text) => return fail("4004", text),
        };
        let ttl = child_text(rr, "ttl").filter(|t| !t.is_empty());
        if ttl.as_deref().is_some_and(|t| !valid_ttl(t)) {
            return fail("4004", "the ttl is not a number");
        }
        let name = relative(&name, &zone.name);
        let id = inner.new_id();
        created.push(Record {
            id,
            zone_id: zone.id,
            name,
            ttl,
            rtype,
            strings,
            raw: None,
        });
    }
    inner.staged.extend(created.iter().cloned());
    let mut zone = zone;
    for z in inner.zones.iter_mut().filter(|z| z.id == zone.id) {
        z.has_changes = true;
    }
    zone.has_changes = true;
    let rrs: String = created.iter().map(rr_element).collect();
    let data = format!(
        "\n    {}\n  ",
        zone_element(&zone, &inner.seed.username, &format!("{rrs}\n    "))
    );
    success(Some(&data))
}

/// The fields of record `rr` of type `rtype` (one of [`WRITABLE`]), validated as the
/// documentation describes them; the text of an error otherwise.
fn record_fields(rr: roxmltree::Node<'_, '_>, rtype: &str) -> Result<Vec<String>, &'static str> {
    fn child<'a, 'i>(node: roxmltree::Node<'a, 'i>, tag: &str) -> Option<roxmltree::Node<'a, 'i>> {
        node.children()
            .find(|c| c.is_element() && c.tag_name().name() == tag)
    }
    if rtype == "TXT" {
        let txt = child(rr, "txt").ok_or("a TXT rr lacks txt")?;
        // The raw text of each string, as sent.
        let strings: Vec<String> = txt
            .children()
            .filter(|c| c.is_element() && c.tag_name().name() == "string")
            .map(|c| c.text().unwrap_or("").to_owned())
            .collect();
        if strings.is_empty() || strings.iter().any(|s| s.len() > 255) {
            return Err("a TXT string is missing or longer than 255 bytes");
        }
        return Ok(strings);
    }
    let (element, paths) = shape(rtype).ok_or("unsupported record type")?;
    let node = child(rr, element).ok_or("the rr lacks the element of its type")?;
    let mut fields = Vec::new();
    for path in paths {
        let mut at = node;
        for tag in *path {
            at = child(at, tag).ok_or("a field of the record is missing")?;
        }
        fields.push(at.text().unwrap_or("").trim().to_owned());
    }
    let number = |i: usize| fields.get(i).is_some_and(|f| f.parse::<u16>().is_ok());
    let name = |i: usize| {
        fields
            .get(i)
            .is_some_and(|f| !f.is_empty() && !f.contains(' '))
    };
    let valid = match rtype {
        "A" => fields
            .first()
            .is_some_and(|f| f.parse::<std::net::Ipv4Addr>().is_ok()),
        "AAAA" => fields
            .first()
            .is_some_and(|f| f.parse::<std::net::Ipv6Addr>().is_ok()),
        "MX" => number(0) && name(1),
        "SRV" => number(0) && number(1) && number(2) && name(3),
        _ => name(0),
    };
    if !valid {
        return Err("a field of the record is not valid for its type");
    }
    Ok(fields)
}

/// A TTL in numeric form or in BIND's form of numbers with `w`, `d`, `h`, `m` or `s`
/// (documentation section 4.6).
fn valid_ttl(ttl: &str) -> bool {
    if ttl.parse::<u32>().is_ok() {
        return true;
    }
    let mut digits = false;
    for c in ttl.chars() {
        if c.is_ascii_digit() {
            digits = true;
        } else if "wdhmsWDHMS".contains(c) && digits {
            digits = false;
        } else {
            return false;
        }
    }
    !ttl.is_empty() && !digits
}

/// A record name relative to `zone`: `@` for the apex; an absolute name (with a trailing dot)
/// below the zone loses the zone's suffix.
fn relative(name: &str, zone: &str) -> String {
    let lower = name.to_lowercase();
    let Some(absolute) = lower.strip_suffix('.') else {
        return lower;
    };
    if absolute == zone {
        return "@".to_owned();
    }
    match absolute.strip_suffix(&format!(".{zone}")) {
        Some(rest) => rest.to_owned(),
        None => lower,
    }
}

async fn delete_record(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((service, zone, id)): Path<(String, String, String)>,
) -> Response {
    let mut inner = lock(&state);
    if let Err(r) = authorize(&inner, &headers) {
        return r;
    }
    let zone = match find_zone(&inner, &service, &zone) {
        Ok(zone) => zone,
        Err(r) => return r,
    };
    let before = inner.staged.len();
    inner
        .staged
        .retain(|r| !(r.zone_id == zone.id && r.id.to_string() == id));
    if inner.staged.len() == before {
        return fail("4030", "record not found");
    }
    for z in inner.zones.iter_mut().filter(|z| z.id == zone.id) {
        z.has_changes = true;
    }
    success(None)
}

async fn commit(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((service, zone)): Path<(String, String)>,
) -> Response {
    let mut inner = lock(&state);
    if let Err(r) = authorize(&inner, &headers) {
        return r;
    }
    let zone = match find_zone(&inner, &service, &zone) {
        Ok(zone) => zone,
        Err(r) => return r,
    };
    let before = inner.published();
    inner.commit(zone.id);
    inner.report(&before, Origin::Api);
    success(None)
}

async fn rollback(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((service, zone)): Path<(String, String)>,
) -> Response {
    let mut inner = lock(&state);
    if let Err(r) = authorize(&inner, &headers) {
        return r;
    }
    let zone = match find_zone(&inner, &service, &zone) {
        Ok(zone) => zone,
        Err(r) => return r,
    };
    let published: Vec<Record> = inner
        .published
        .iter()
        .filter(|r| r.zone_id == zone.id)
        .cloned()
        .collect();
    inner.staged.retain(|r| r.zone_id != zone.id);
    inner.staged.extend(published);
    for z in inner.zones.iter_mut().filter(|z| z.id == zone.id) {
        z.has_changes = false;
    }
    success(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_bodies_decode() {
        let pairs = form_pairs(b"a=1+2&b=%2F%3a&c=&d");
        assert_eq!(pairs["a"], "1 2");
        assert_eq!(pairs["b"], "/:");
        assert_eq!(pairs["c"], "");
        assert_eq!(pairs["d"], "");
    }

    #[test]
    fn ttls_are_numeric_or_bind_units() {
        for good in ["30", "1h", "1h30m", "2W"] {
            assert!(valid_ttl(good), "{good}");
        }
        for bad in ["", "h", "1h3", "-1", "1x"] {
            assert!(!valid_ttl(bad), "{bad}");
        }
    }

    #[test]
    fn bind_ttls_convert_to_seconds() {
        assert_eq!(ttl_seconds("300"), Some(300));
        assert_eq!(ttl_seconds("1h30m"), Some(5400));
        assert_eq!(ttl_seconds("2W"), Some(1_209_600));
        assert_eq!(ttl_seconds("1x"), None);
    }

    #[test]
    fn names_are_read_as_a_zone_file_reads_them() {
        assert_eq!(absolute("@", "example.org"), "example.org.");
        assert_eq!(absolute("www", "example.org"), "www.example.org.");
        assert_eq!(absolute("x.example.net.", "example.org"), "x.example.net.");
    }

    #[test]
    fn names_become_relative() {
        assert_eq!(
            relative("_acme-challenge", "example.org"),
            "_acme-challenge"
        );
        assert_eq!(relative("A.Example.Org.", "example.org"), "a");
        assert_eq!(relative("example.org.", "example.org"), "@");
        assert_eq!(relative("x.other.net.", "example.org"), "x.other.net.");
    }
}
