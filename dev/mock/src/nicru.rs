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

// Handlers return finished HTTP answers as their error values and hand them straight to axum.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::fmt::Write as _;
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

use crate::MockServer;

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
    seed: Seed,
    zones: Vec<Zone>,
    /// What the zone files hold now, staged changes included.
    staged: Vec<Record>,
    /// What was published by the last commit.
    published: Vec<Record>,
    tokens: Vec<String>,
    tokens_issued: u64,
    next_id: u64,
}

impl Inner {
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
}

impl Deref for NicruMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl NicruMock {
    /// Starts the mock with `seed`.
    pub async fn start(seed: Seed) -> Self {
        let mut inner = Inner {
            zones: Vec::new(),
            staged: Vec::new(),
            published: Vec::new(),
            tokens: Vec::new(),
            tokens_issued: 0,
            next_id: 227_000,
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
        let state = Arc::new(Mutex::new(inner));
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
        Self {
            server: MockServer::start(router).await,
            control: Control { state },
        }
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
}

impl Control {
    /// Every zone.
    pub fn zones(&self) -> Vec<Zone> {
        lock(&self.state).zones.clone()
    }

    /// Adds a zone under `service`; `primary` false makes it a zone of a Secondary service.
    pub fn insert_zone(&self, name: &str, service: &str, primary: bool) {
        let mut inner = lock(&self.state);
        let id = inner.new_id();
        inner.zones.push(Zone {
            id,
            name: normalize(name),
            service: service.to_owned(),
            primary,
            has_changes: false,
        });
    }

    /// Moves zone `name`, with its records, to service `service` under a new zone identifier.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn move_zone(&self, name: &str, service: &str) {
        let name = normalize(name);
        let mut inner = lock(&self.state);
        let new_id = inner.new_id();
        let zone = inner
            .zones
            .iter_mut()
            .find(|z| z.name == name)
            .unwrap_or_else(|| panic!("no zone {name}"));
        let old_id = zone.id;
        zone.id = new_id;
        zone.service = service.to_owned();
        let inner = &mut *inner;
        for record in inner
            .staged
            .iter_mut()
            .chain(inner.published.iter_mut())
            .filter(|r| r.zone_id == old_id)
        {
            record.zone_id = new_id;
        }
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
        let id = self.stage_record(zone, name, rtype, data, ttl);
        let mut inner = lock(&self.state);
        if let Some(record) = inner.staged.iter().find(|r| r.id == id).cloned() {
            inner.published.push(record);
        }
        let zone_id = record_zone(&inner, id);
        for z in inner.zones.iter_mut().filter(|z| Some(z.id) == zone_id) {
            z.has_changes = false;
        }
        id
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
        let mut inner = lock(&self.state);
        let zone_id = inner
            .zone_by_name(zone)
            .map(|z| z.id)
            .unwrap_or_else(|| panic!("no zone {zone}"));
        let id = inner.new_id();
        let strings = if rtype == "TXT" || shape(rtype).is_none() {
            vec![data.to_owned()]
        } else {
            data.split_whitespace().map(str::to_owned).collect()
        };
        inner.staged.push(Record {
            id,
            zone_id,
            name: name.to_lowercase(),
            ttl: ttl.map(str::to_owned),
            rtype: rtype.to_owned(),
            strings,
            raw: None,
        });
        for z in inner.zones.iter_mut().filter(|z| z.id == zone_id) {
            z.has_changes = true;
        }
        id
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
        let id = self.insert_record(zone, name, rtype, "", ttl);
        let mut inner = lock(&self.state);
        let inner = &mut *inner;
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
        let mut inner = lock(&self.state);
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
        let mut inner = lock(&self.state);
        let Some(id) = inner.zone_by_name(zone).map(|z| z.id) else {
            return;
        };
        let staged: Vec<Record> = inner
            .staged
            .iter()
            .filter(|r| r.zone_id == id)
            .cloned()
            .collect();
        inner.published.retain(|r| r.zone_id != id);
        inner.published.extend(staged);
        for z in inner.zones.iter_mut().filter(|z| z.id == id) {
            z.has_changes = false;
        }
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

fn record_zone(inner: &Inner, id: u64) -> Option<u64> {
    inner.staged.iter().find(|r| r.id == id).map(|r| r.zone_id)
}

fn of(records: &[Record], name: &str, rtype: &str) -> Vec<Record> {
    let name = name.to_lowercase();
    records
        .iter()
        .filter(|r| r.name == name && r.rtype == rtype)
        .cloned()
        .collect()
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
    let inner = lock(&state);
    if let Err(r) = authorize(&inner, &headers) {
        return r;
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
    let staged: Vec<Record> = inner
        .staged
        .iter()
        .filter(|r| r.zone_id == zone.id)
        .cloned()
        .collect();
    inner.published.retain(|r| r.zone_id != zone.id);
    inner.published.extend(staged);
    for z in inner.zones.iter_mut().filter(|z| z.id == zone.id) {
        z.has_changes = false;
    }
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
