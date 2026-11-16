//! Mock of the Gandi LiveDNS API (v5).
//!
//! Shapes follow the sources the client cites: the LiveDNS API reference
//! <https://api.gandi.net/docs/livedns/>, the general reference
//! <https://api.gandi.net/docs/reference/>, the authentication page
//! <https://api.gandi.net/docs/authentication/>, lego `providers/dns/gandiv5` and dns-update
//! `src/providers/gandiv5.rs`.
//!
//! What the documentation says and the mock does:
//!
//! - every path is below `/v5/livedns`; the client's `base_url` is [`GandiMock::base_url`];
//! - `Authorization: Bearer <token>` with a token of the seed; a bearer token the mock does not
//!   know is `403` ("In case the bearer token has expired, does not have enought permission or
//!   does not exists");
//! - domains and rrsets are listed as JSON arrays in pages (`page` from 1, `per_page`), with the
//!   headers `Total-Count` and `Filtered-Count`; a page beyond the last is an empty list; the
//!   domain listing shows the domains of the personal organization, or with `sharing_id` those
//!   of that organization;
//! - an rrset is addressed by domain (`fqdn` without the trailing dot), owner name relative to
//!   the domain (`@` for the apex) and type, one of the reference's enumeration; it holds
//!   `rrset_values` (strings) and an optional `rrset_ttl` of 300 to 2592000;
//! - a read of a missing name/type pair is `404`;
//! - a create (`POST`) is `201`; of an rrset that exists, `200` when its values are the same and
//!   `409` otherwise;
//! - a replacement (`PUT`) is `201`;
//! - a value-level change (`PATCH` with `add_rrset_values` / `remove_rrset_values` and an
//!   optional `rrset_ttl`) answers `200` with the rrset, or `204` when no value is left, and the
//!   rrset is then gone; each value is printable ASCII of at most 16384 characters;
//! - a delete is `204`;
//! - error bodies carry `cause`, `code`, `message` and `object`.
//!
//! Answers the mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading:
//!
//! - a missing domain is `404` on every route below it, the domain itself included;
//! - a request without a bearer token is `401`;
//! - a `PATCH` or a `DELETE` of a missing rrset is `404`; a `PATCH` that adds a value the rrset
//!   holds, or removes one it does not hold, changes nothing for that value; a `PATCH` without
//!   `rrset_ttl` keeps the rrset's TTL;
//! - a `PUT` of a missing rrset creates it (lego relies on that; the reference says only
//!   "Overwrites");
//! - an rrset written without `rrset_ttl` gets 10800, the TTL of the reference's examples;
//! - a body with a member the call does not document, an empty `rrset_values`, a TTL outside
//!   300 to 2592000, a value outside printable ASCII or longer than 16384 characters, a value
//!   that does not have the form of its type (below), and an owner name with a trailing dot
//!   are `400`; a value the rrset already holds is accepted as it is, so that the provider's own
//!   data written back unchanged is never refused;
//! - a write to the SOA rrset is `400`;
//! - `page` below 1 or not a number is `400`; the default and largest page is
//!   [`Seed::page_size`] (100 unless set); `Total-Count` is the total of the listing unless
//!   [`Control::set_paging`] says otherwise ([`Paging`]: the count of the page, or a server that
//!   ignores `page`), readings the client must survive;
//! - owner names are compared without regard to ASCII case and kept in lowercase.
//!
//! Value forms per type, as the reference's examples and dns-update write them: A and AAAA one
//! address; CNAME, NS, PTR, DNAME and ALIAS one name; MX a preference and a name; SRV priority,
//! weight, port and a name; TXT any text. Any other type is checked only for being non-empty.
//! A name has non-empty labels and may end with a dot.
//!
//! Published state ([`ChangeSource`]): every value in zone-file text with names fully
//! qualified. A name without the trailing dot inside a value is taken as absolute (invented: the
//! documentation spells names both ways and does not say), and a TXT value that does not start
//! with `"` is the value itself, written quoted.
//!
//! Error texts are invented.
//!
//! A test holds a [`GandiMock`]. It dereferences to the [`MockServer`], so the request log and
//! the fault queue of the shared harness work as usual:
//!
//! ```text
//! let mock = GandiMock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("PATCH", "/v5/livedns/domains/*/records/*/TXT").status(500));
//! // ... drive the client against mock.base_url() ...
//! assert_eq!(mock.control().values("example.org", "_acme-challenge", "TXT"), ["\"v1\""]);
//! ```
//!
//! [`Control::reset`] returns the mock to its seed.

// Handlers return finished HTTP answers as their error values and hand them straight to axum;
// boxing them would only add noise.
#![allow(clippy::result_large_err)]

use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Map, Value, json};

use crate::changes::{ChangeSource, Changes, Origin, Published};
use crate::{Faults, MockServer, RequestLog};

/// Path of the LiveDNS API below the server's base URL.
pub const API_PATH: &str = "/v5/livedns";

/// The record types of the reference's `rrset_type` enumeration.
const TYPES: &[&str] = &[
    "A",
    "AAAA",
    "ALIAS",
    "CAA",
    "CDS",
    "CNAME",
    "DNAME",
    "DS",
    "HTTPS",
    "KEY",
    "LOC",
    "MX",
    "NAPTR",
    "NS",
    "OPENPGPKEY",
    "PTR",
    "RP",
    "SOA",
    "SPF",
    "SRV",
    "SSHFP",
    "SVCB",
    "TLSA",
    "TXT",
    "WKS",
];

/// TTL range of `rrset_ttl` (the reference).
const TTL_MIN: u64 = 300;
const TTL_MAX: u64 = 2_592_000;

/// TTL of an rrset written without one (invented).
const DEFAULT_TTL: u32 = 10_800;

/// Longest value of a `PATCH` body (the reference); the mock applies it to every write.
const MAX_VALUE: usize = 16_384;

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// Personal access tokens the API accepts.
    pub tokens: Vec<String>,
    /// Domains of the personal organization, in listing order.
    pub zones: Vec<String>,
    /// The default and largest page of a listing.
    pub page_size: usize,
}

impl Seed {
    /// The token `test-only-token` and the domain `example.org`, pages of 100.
    pub fn standard() -> Self {
        Self {
            tokens: vec!["test-only-token".into()],
            zones: vec!["example.org".into()],
            page_size: 100,
        }
    }
}

/// A domain as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Zone {
    /// The domain name, lowercase, without the trailing dot.
    pub fqdn: String,
    /// The organization the domain belongs to; `None` for the personal organization.
    pub sharing_id: Option<String>,
}

/// An rrset as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rrset {
    /// The domain, without the trailing dot.
    pub zone: String,
    /// The owner name relative to the domain, lowercase, `@` for the apex.
    pub name: String,
    /// The record type.
    pub rtype: String,
    /// `rrset_ttl`; `None`: the answers leave it out.
    pub ttl: Option<u32>,
    /// `rrset_values`, as written.
    pub values: Vec<String>,
}

/// How a listing pages: the documented reading and two readings the client must survive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Paging {
    /// `page` is honored and `Total-Count` is the number of items of the whole listing.
    #[default]
    Total,
    /// `page` is honored and `Total-Count` is the number of items of the page answered.
    PageCount,
    /// `page` is ignored: every request answers the first page, with the whole total.
    IgnorePage,
}

#[derive(Debug)]
struct Inner {
    original: Seed,
    seed: Seed,
    zones: Vec<Zone>,
    rrsets: Vec<Rrset>,
    paging: Paging,
    changes: Changes,
}

impl Inner {
    fn new(seed: Seed, changes: Changes) -> Inner {
        Inner {
            original: seed.clone(),
            zones: seed
                .zones
                .iter()
                .map(|name| Zone {
                    fqdn: plain(name),
                    sharing_id: None,
                })
                .collect(),
            seed,
            rrsets: Vec::new(),
            paging: Paging::Total,
            changes,
        }
    }

    /// What a DNS server for the mock's domains would answer: every rrset, in zone-file text.
    fn published(&self) -> Published {
        let mut out = Published::new();
        for zone in &self.zones {
            out.zone(&zone.fqdn);
        }
        for rrset in &self.rrsets {
            let owner = if rrset.name == "@" {
                format!("{}.", rrset.zone)
            } else {
                format!("{}.{}.", rrset.name, rrset.zone)
            };
            let values = rrset
                .values
                .iter()
                .map(|value| zone_file_text(&rrset.rtype, value))
                .collect();
            out.rrset(&rrset.zone, &owner, &rrset.rtype, rrset.ttl, values);
        }
        out
    }

    fn report(&self, before: &Published, origin: Origin) {
        self.changes.emit_diff(before, &self.published(), origin);
    }

    fn zone(&self, fqdn: &str) -> Option<&Zone> {
        self.zones.iter().find(|z| z.fqdn == fqdn)
    }

    fn position(&self, zone: &str, name: &str, rtype: &str) -> Option<usize> {
        self.rrsets
            .iter()
            .position(|r| r.zone == zone && r.name == name && r.rtype == rtype)
    }
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Reads and changes the state of a mock. Cheap to clone, so that a fault hook
/// ([`Fault::run`](crate::Fault::run)) can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
    changes: Changes,
    log: RequestLog,
    faults: Faults,
}

/// A running Gandi mock. Dereferences to its [`MockServer`] for the request log and the fault
/// queue; [`GandiMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct GandiMock {
    server: MockServer,
    control: Control,
}

impl Deref for GandiMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl GandiMock {
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
            .route("/v5/livedns/domains", get(domains_list))
            .route("/v5/livedns/domains/{fqdn}", get(domain_get))
            .route("/v5/livedns/domains/{fqdn}/records", get(records_list))
            .route(
                "/v5/livedns/domains/{fqdn}/records/{name}/{rtype}",
                get(rrset_get)
                    .post(rrset_create)
                    .put(rrset_replace)
                    .patch(rrset_patch)
                    .delete(rrset_delete),
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

    /// The API endpoint, for the client's `base_url`.
    pub fn base_url(&self) -> String {
        self.server.url(API_PATH)
    }

    /// The state control.
    pub fn control(&self) -> &Control {
        &self.control
    }
}

impl ChangeSource for GandiMock {
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

    /// Returns the mock to the seed it was started with: its domains, no rrsets, the documented
    /// paging, an empty request log and no pending faults. Reports the removal of every rrset
    /// that was published.
    pub fn reset(&self) {
        self.faults.clear();
        self.change(|inner| {
            let seed = inner.original.clone();
            *inner = Inner::new(seed, inner.changes.clone());
        });
        self.log.clear();
    }

    /// Every domain.
    pub fn zones(&self) -> Vec<Zone> {
        lock(&self.state).zones.clone()
    }

    /// Adds an empty domain of the personal organization.
    pub fn insert_zone(&self, fqdn: &str) {
        self.insert_zone_of(None, fqdn);
    }

    /// Adds an empty domain of the organization `sharing_id` (`None`: the personal one).
    pub fn insert_zone_of(&self, sharing_id: Option<&str>, fqdn: &str) {
        self.change(|inner| {
            inner.zones.push(Zone {
                fqdn: plain(fqdn),
                sharing_id: sharing_id.map(str::to_owned),
            });
        });
    }

    /// Removes domain `fqdn` and its rrsets.
    pub fn remove_zone(&self, fqdn: &str) {
        let fqdn = plain(fqdn);
        self.change(|inner| {
            inner.zones.retain(|z| z.fqdn != fqdn);
            inner.rrsets.retain(|r| r.zone != fqdn);
        });
    }

    /// How listings page from now on ([`Paging`]).
    pub fn set_paging(&self, paging: Paging) {
        lock(&self.state).paging = paging;
    }

    /// The default and largest page of a listing from now on.
    pub fn set_page_size(&self, size: usize) {
        lock(&self.state).seed.page_size = size;
    }

    /// Every rrset.
    pub fn rrsets(&self) -> Vec<Rrset> {
        lock(&self.state).rrsets.clone()
    }

    /// The rrset of `name` (relative, `@` for the apex) and `rtype` in domain `zone`, if any.
    pub fn rrset(&self, zone: &str, name: &str, rtype: &str) -> Option<Rrset> {
        let (zone, name) = (plain(zone), name.to_lowercase());
        let inner = lock(&self.state);
        inner
            .position(&zone, &name, rtype)
            .and_then(|at| inner.rrsets.get(at).cloned())
    }

    /// The values of `name` and `rtype` in domain `zone`, in rrset order; empty when there is no
    /// such rrset.
    pub fn values(&self, zone: &str, name: &str, rtype: &str) -> Vec<String> {
        self.rrset(zone, name, rtype)
            .map(|r| r.values)
            .unwrap_or_default()
    }

    /// Creates or replaces an rrset directly, as another writer would. `name` is relative to the
    /// domain, `@` for the apex; the values are stored exactly as given.
    ///
    /// # Panics
    ///
    /// If there is no such domain.
    pub fn insert_rrset(
        &self,
        zone: &str,
        name: &str,
        rtype: &str,
        ttl: Option<u32>,
        values: &[&str],
    ) {
        let (zone, name) = (plain(zone), name.to_lowercase());
        self.change(|inner| {
            assert!(inner.zone(&zone).is_some(), "no domain {zone}");
            let rrset = Rrset {
                zone: zone.clone(),
                name: name.clone(),
                rtype: rtype.to_owned(),
                ttl,
                values: values.iter().map(|v| (*v).to_owned()).collect(),
            };
            match inner.position(&zone, &name, rtype) {
                Some(at) => inner.rrsets[at] = rrset,
                None => inner.rrsets.push(rrset),
            }
        });
    }

    /// Deletes the rrset of `name` and `rtype` in domain `zone` directly, as another writer would.
    pub fn delete_rrset(&self, zone: &str, name: &str, rtype: &str) {
        let (zone, name) = (plain(zone), name.to_lowercase());
        self.change(|inner| {
            inner
                .rrsets
                .retain(|r| !(r.zone == zone && r.name == name && r.rtype == rtype));
        });
    }

    /// Changes the rrset of `name` and `rtype` in domain `zone` with `f`, as another writer would.
    ///
    /// # Panics
    ///
    /// If there is no such rrset.
    pub fn edit_rrset(&self, zone: &str, name: &str, rtype: &str, f: impl FnOnce(&mut Rrset)) {
        let (zone, name) = (plain(zone), name.to_lowercase());
        self.change(|inner| {
            let at = inner
                .position(&zone, &name, rtype)
                .unwrap_or_else(|| panic!("no rrset {name} {rtype} in {zone}"));
            f(&mut inner.rrsets[at]);
        });
    }
}

/// `name` lowercase without a trailing dot.
fn plain(name: &str) -> String {
    let name = name.trim().to_lowercase();
    name.strip_suffix('.').map(str::to_owned).unwrap_or(name)
}

/// An error answer in the documented shape.
fn error(status: StatusCode, text: &str) -> Response {
    let body = json!({
        "cause": status.canonical_reason().unwrap_or("Error"),
        "code": status.as_u16(),
        "message": text,
        "object": "HTTPError",
    });
    (status, axum::Json(body)).into_response()
}

fn bad_request(text: &str) -> Response {
    error(StatusCode::BAD_REQUEST, text)
}

fn not_found(text: &str) -> Response {
    error(StatusCode::NOT_FOUND, text)
}

/// A confirmation in the documented shape (`message`).
fn message(status: StatusCode, text: &str) -> Response {
    (status, axum::Json(json!({ "message": text }))).into_response()
}

/// Checks `Authorization: Bearer <token>`.
fn authorize(state: &Shared, headers: &HeaderMap) -> Result<(), Response> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    if lock(state).seed.tokens.iter().any(|t| t == token) {
        Ok(())
    } else {
        Err(error(
            StatusCode::FORBIDDEN,
            "the bearer token has expired, does not have enough permission or does not exist",
        ))
    }
}

fn query<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// One page of `all` as a JSON array, with `Total-Count` and `Filtered-Count` as `paging` says.
fn listing(
    all: Vec<Value>,
    pairs: &[(String, String)],
    page_size: usize,
    paging: Paging,
) -> Response {
    let number = |key: &str| match query(pairs, key).map(str::parse::<usize>) {
        None => Ok(None),
        Some(Ok(n)) if n >= 1 => Ok(Some(n)),
        Some(_) => Err(bad_request(
            "page and per_page must be integers of at least 1",
        )),
    };
    let (page, per_page) = match (number("page"), number("per_page")) {
        (Ok(page), Ok(per_page)) => (page.unwrap_or(1), per_page),
        (Err(response), _) | (_, Err(response)) => return response,
    };
    let page = if paging == Paging::IgnorePage {
        1
    } else {
        page
    };
    let size = per_page.unwrap_or(page_size).min(page_size).max(1);
    let total = all.len();
    let items: Vec<Value> = all
        .into_iter()
        .skip((page - 1).saturating_mul(size))
        .take(size)
        .collect();
    let stated_total = match paging {
        Paging::PageCount => items.len(),
        _ => total,
    };
    let mut response = axum::Json(Value::Array(items.clone())).into_response();
    let headers = response.headers_mut();
    headers.insert("total-count", HeaderValue::from(stated_total));
    headers.insert("filtered-count", HeaderValue::from(items.len()));
    response
}

fn domain_json(zone: &Zone) -> Value {
    json!({
        "fqdn": zone.fqdn,
        "domain_href": format!("https://api.test/v5/livedns/domains/{}", zone.fqdn),
        "domain_records_href": format!("https://api.test/v5/livedns/domains/{}/records", zone.fqdn),
    })
}

fn rrset_json(rrset: &Rrset) -> Value {
    let mut out = json!({
        "rrset_name": rrset.name,
        "rrset_type": rrset.rtype,
        "rrset_values": rrset.values,
        "rrset_href": format!(
            "https://api.test/v5/livedns/domains/{}/records/{}/{}",
            rrset.zone,
            rrset.name.replace('@', "%40"),
            rrset.rtype
        ),
    });
    if let Some(ttl) = rrset.ttl {
        out["rrset_ttl"] = json!(ttl);
    }
    out
}

async fn domains_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let sharing_id = query(&pairs, "sharing_id");
    let inner = lock(&state);
    let all: Vec<Value> = inner
        .zones
        .iter()
        .filter(|z| z.sharing_id.as_deref() == sharing_id)
        .map(domain_json)
        .collect();
    let (page_size, paging) = (inner.seed.page_size, inner.paging);
    drop(inner);
    listing(all, &pairs, page_size, paging)
}

async fn domain_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(fqdn): Path<String>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let found = lock(&state).zone(&fqdn).cloned();
    match found {
        None => not_found("domain not found"),
        Some(zone) => {
            let mut body = domain_json(&zone);
            body["domain_keys_href"] = json!(format!(
                "https://api.test/v5/livedns/domains/{}/keys",
                zone.fqdn
            ));
            body["automatic_snapshots"] = json!(true);
            axum::Json(body).into_response()
        }
    }
}

async fn records_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(fqdn): Path<String>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let inner = lock(&state);
    if inner.zone(&fqdn).is_none() {
        return not_found("domain not found");
    }
    // `sort_by` defaults to `rrset_name` (the reference).
    let mut all: Vec<&Rrset> = inner.rrsets.iter().filter(|r| r.zone == fqdn).collect();
    all.sort_by(|a, b| a.name.cmp(&b.name).then(a.rtype.cmp(&b.rtype)));
    let all: Vec<Value> = all.iter().map(|r| rrset_json(r)).collect();
    let (page_size, paging) = (inner.seed.page_size, inner.paging);
    drop(inner);
    listing(all, &pairs, page_size, paging)
}

/// The domain, owner name and type of a path, checked: the domain exists, the name has no
/// trailing dot, the type is one of the enumeration. The name is returned in lowercase.
fn address(inner: &Inner, fqdn: &str, name: &str, rtype: &str) -> Result<String, Response> {
    if inner.zone(fqdn).is_none() {
        return Err(not_found("domain not found"));
    }
    if name.is_empty() || name.ends_with('.') {
        return Err(bad_request(
            "the record name must be relative to the domain, without the trailing dot",
        ));
    }
    if !TYPES.contains(&rtype) {
        return Err(bad_request("unknown record type"));
    }
    Ok(name.to_lowercase())
}

async fn rrset_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((fqdn, name, rtype)): Path<(String, String, String)>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let inner = lock(&state);
    let name = match address(&inner, &fqdn, &name, &rtype) {
        Ok(name) => name,
        Err(response) => return response,
    };
    match inner
        .position(&fqdn, &name, &rtype)
        .and_then(|at| inner.rrsets.get(at))
    {
        Some(rrset) => axum::Json(rrset_json(rrset)).into_response(),
        None => not_found("record not found"),
    }
}

/// A JSON object body with only the `allowed` members.
fn object(bytes: &[u8], allowed: &[&str]) -> Result<Map<String, Value>, Response> {
    let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(bytes) else {
        return Err(bad_request("malformed request body"));
    };
    if body.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(bad_request("unexpected member in the request body"));
    }
    Ok(body)
}

/// `rrset_ttl` of a body, checked; `None` when absent.
fn ttl(body: &Map<String, Value>) -> Result<Option<u32>, Response> {
    match body.get("rrset_ttl") {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .filter(|ttl| (TTL_MIN..=TTL_MAX).contains(ttl))
            .and_then(|ttl| u32::try_from(ttl).ok())
            .map(Some)
            .ok_or_else(|| bad_request("rrset_ttl must be an integer from 300 to 2592000")),
    }
}

/// A list of values under `key`, each checked against `rtype` unless `held` has it.
fn values(
    body: &Map<String, Value>,
    key: &str,
    rtype: &str,
    held: &[String],
) -> Result<Vec<String>, Response> {
    let items = match body.get(key) {
        None => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => return Err(bad_request("the values must be an array")),
    };
    let mut out = Vec::new();
    for item in items {
        let Value::String(text) = item else {
            return Err(bad_request("a value must be a string"));
        };
        let printable = !text.is_empty()
            && text.len() <= MAX_VALUE
            && text.bytes().all(|b| (0x20..=0x7e).contains(&b));
        if !printable {
            return Err(bad_request(
                "a value must be 1 to 16384 printable ASCII characters",
            ));
        }
        if !held.contains(text) && !value_valid(rtype, text) {
            return Err(bad_request("a value does not match the record type"));
        }
        out.push(text.clone());
    }
    Ok(out)
}

/// The body of a create or a replacement, checked: the values (at least one) and the TTL.
fn rrset_body(
    rtype: &str,
    bytes: &[u8],
    held: &[String],
) -> Result<(Vec<String>, Option<u32>), Response> {
    let body = object(bytes, &["rrset_values", "rrset_ttl"])?;
    if !matches!(body.get("rrset_values"), Some(Value::Array(_))) {
        return Err(bad_request("rrset_values is required"));
    }
    let list = values(&body, "rrset_values", rtype, held)?;
    if list.is_empty() {
        return Err(bad_request("rrset_values must not be empty"));
    }
    Ok((list, ttl(&body)?))
}

fn sorted(values: &[String]) -> Vec<String> {
    let mut out = values.to_vec();
    out.sort();
    out
}

async fn rrset_create(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((fqdn, name, rtype)): Path<(String, String, String)>,
    bytes: Bytes,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    let name = match address(&inner, &fqdn, &name, &rtype) {
        Ok(name) => name,
        Err(response) => return response,
    };
    if rtype == "SOA" {
        return bad_request("the SOA record cannot be written");
    }
    let (list, ttl) = match rrset_body(&rtype, &bytes, &[]) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Some(at) = inner.position(&fqdn, &name, &rtype) {
        return if sorted(&inner.rrsets[at].values) == sorted(&list) {
            message(
                StatusCode::OK,
                "Same record already exists. Nothing was changed",
            )
        } else {
            error(
                StatusCode::CONFLICT,
                "A record with that name / type pair already exists",
            )
        };
    }
    let before = inner.published();
    inner.rrsets.push(Rrset {
        zone: fqdn,
        name,
        rtype,
        ttl: Some(ttl.unwrap_or(DEFAULT_TTL)),
        values: list,
    });
    inner.report(&before, Origin::Api);
    message(StatusCode::CREATED, "DNS Record Created")
}

async fn rrset_replace(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((fqdn, name, rtype)): Path<(String, String, String)>,
    bytes: Bytes,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    let name = match address(&inner, &fqdn, &name, &rtype) {
        Ok(name) => name,
        Err(response) => return response,
    };
    if rtype == "SOA" {
        return bad_request("the SOA record cannot be written");
    }
    let at = inner.position(&fqdn, &name, &rtype);
    let held = at
        .map(|at| inner.rrsets[at].values.clone())
        .unwrap_or_default();
    let (list, ttl) = match rrset_body(&rtype, &bytes, &held) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let before = inner.published();
    let rrset = Rrset {
        zone: fqdn,
        name,
        rtype,
        ttl: Some(ttl.unwrap_or(DEFAULT_TTL)),
        values: list,
    };
    match at {
        Some(at) => inner.rrsets[at] = rrset,
        None => inner.rrsets.push(rrset),
    }
    inner.report(&before, Origin::Api);
    message(StatusCode::CREATED, "DNS Record Created")
}

async fn rrset_patch(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((fqdn, name, rtype)): Path<(String, String, String)>,
    bytes: Bytes,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    let name = match address(&inner, &fqdn, &name, &rtype) {
        Ok(name) => name,
        Err(response) => return response,
    };
    if rtype == "SOA" {
        return bad_request("the SOA record cannot be written");
    }
    let Some(at) = inner.position(&fqdn, &name, &rtype) else {
        return not_found("record not found");
    };
    let held = inner.rrsets[at].values.clone();
    let parsed = object(
        &bytes,
        &["add_rrset_values", "remove_rrset_values", "rrset_ttl"],
    )
    .and_then(|body| {
        Ok((
            values(&body, "add_rrset_values", &rtype, &held)?,
            values(&body, "remove_rrset_values", &rtype, &held)?,
            ttl(&body)?,
        ))
    });
    let (add, remove, ttl) = match parsed {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    let before = inner.published();
    let rrset = &mut inner.rrsets[at];
    rrset.values.retain(|v| !remove.contains(v));
    for value in add {
        if !rrset.values.contains(&value) {
            rrset.values.push(value);
        }
    }
    if let Some(ttl) = ttl {
        rrset.ttl = Some(ttl);
    }
    let answer = if rrset.values.is_empty() {
        inner.rrsets.remove(at);
        StatusCode::NO_CONTENT.into_response()
    } else {
        axum::Json(rrset_json(rrset)).into_response()
    };
    inner.report(&before, Origin::Api);
    answer
}

async fn rrset_delete(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((fqdn, name, rtype)): Path<(String, String, String)>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    let name = match address(&inner, &fqdn, &name, &rtype) {
        Ok(name) => name,
        Err(response) => return response,
    };
    if rtype == "SOA" {
        return bad_request("the SOA record cannot be deleted");
    }
    let Some(at) = inner.position(&fqdn, &name, &rtype) else {
        return not_found("record not found");
    };
    let before = inner.published();
    inner.rrsets.remove(at);
    inner.report(&before, Origin::Api);
    StatusCode::NO_CONTENT.into_response()
}

/// A name inside a value: non-empty labels, an optional trailing dot, no whitespace.
fn is_name(text: &str) -> bool {
    let text = text.strip_suffix('.').unwrap_or(text);
    !text.is_empty()
        && !text.chars().any(char::is_whitespace)
        && text.split('.').all(|label| !label.is_empty())
}

fn is_u16(text: &str) -> bool {
    text.parse::<u16>().is_ok()
}

/// The value has the form of `rtype` (module documentation).
fn value_valid(rtype: &str, text: &str) -> bool {
    let fields: Vec<&str> = text.split_whitespace().collect();
    match (rtype, fields.as_slice()) {
        ("A", [address]) => address.parse::<Ipv4Addr>().is_ok(),
        ("AAAA", [address]) => address.parse::<std::net::Ipv6Addr>().is_ok(),
        ("CNAME" | "NS" | "PTR" | "DNAME" | "ALIAS", [target]) => is_name(target),
        ("MX", [preference, host]) => is_u16(preference) && is_name(host),
        ("SRV", [priority, weight, port, target]) => {
            is_u16(priority) && is_u16(weight) && is_u16(port) && is_name(target)
        }
        ("TXT", _) => true,
        ("A" | "AAAA" | "CNAME" | "NS" | "PTR" | "DNAME" | "ALIAS" | "MX" | "SRV", _) => false,
        _ => !fields.is_empty(),
    }
}

/// A value as zone-file text (RFC 1035 section 5.1), names fully qualified.
fn zone_file_text(rtype: &str, text: &str) -> String {
    let absolute = |name: &str| {
        if name.ends_with('.') {
            name.to_owned()
        } else {
            format!("{name}.")
        }
    };
    let fields: Vec<&str> = text.split_whitespace().collect();
    match (rtype, fields.as_slice()) {
        ("TXT", _) if text.trim_start().starts_with('"') => text.trim().to_owned(),
        ("TXT", _) => quoted(text),
        ("CNAME" | "NS" | "PTR" | "DNAME" | "ALIAS", [target]) => absolute(target),
        ("MX", [preference, host]) => format!("{preference} {}", absolute(host)),
        ("SRV", [priority, weight, port, target]) => {
            format!("{priority} {weight} {port} {}", absolute(target))
        }
        _ => text.trim().to_owned(),
    }
}

/// Text as one or more quoted character-strings of zone-file text.
fn quoted(text: &str) -> String {
    text.as_bytes()
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

#[cfg(test)]
mod tests {
    use super::{value_valid, zone_file_text};

    #[test]
    fn values_are_checked_per_type() {
        for (rtype, text) in [
            ("A", "192.0.2.1"),
            ("AAAA", "2001:db8::1"),
            ("CNAME", "www.example.net."),
            ("CNAME", "www.example.net"),
            ("MX", "10 spool.mail.gandi.net."),
            ("SRV", "10 20 5060 sip.example.org."),
            ("TXT", "\"v=spf1 -all\""),
            ("CAA", "0 issue \"ca.example.net\""),
        ] {
            assert!(value_valid(rtype, text), "{rtype} {text}");
        }
        for (rtype, text) in [
            ("A", "192.0.2"),
            ("A", "192.0.2.1 192.0.2.2"),
            ("MX", "spool.mail.gandi.net."),
            ("SRV", "10 20 sip.example.org."),
            ("CNAME", "a..b"),
        ] {
            assert!(!value_valid(rtype, text), "{rtype} {text}");
        }
    }

    #[test]
    fn zone_file_text_is_fully_qualified() {
        assert_eq!(
            zone_file_text("MX", "10 mail.example.org"),
            "10 mail.example.org."
        );
        assert_eq!(zone_file_text("CNAME", "a.example.net."), "a.example.net.");
        assert_eq!(zone_file_text("TXT", "\"a b\""), "\"a b\"");
        assert_eq!(zone_file_text("TXT", "token"), "\"token\"");
        assert_eq!(zone_file_text("A", "192.0.2.1"), "192.0.2.1");
    }
}
