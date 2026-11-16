//! Mock of the deSEC DNS API.
//!
//! Sources, read 2026-11-16: the deSEC documentation, <https://desec.readthedocs.io/en/latest/>
//! (`dns/domains`, `dns/rrsets`, `rate-limits`, `auth/tokens`; the sources of those pages are in
//! `docs/` of `github.com/desec-io/desec-stack`), the Go client lego uses
//! (`github.com/nrdcg/desec`) and lego `providers/dns/desec/desec.go`.
//!
//! What the documentation says and the mock does:
//!
//! - every path is below `/api/v1` and ends with `/`; the client's `base_url` is
//!   [`DesecMock::base_url`]; the token is sent as `Authorization: Token <token>`;
//! - domains: `GET /domains/` (with `owns_qname`), `GET /domains/{name}/` (`404` for a domain the
//!   account does not own);
//! - rrsets of a domain, identified by `subname` and `type`: `GET …/rrsets/` (filters `type` and
//!   `subname`), `POST …/rrsets/` (`201`), `GET`, `PATCH`, `PUT` and `DELETE` on
//!   `…/rrsets/{subname}/{type}/`, the apex as `@` in a path and `""` in a body; `PATCH` and
//!   `PUT` with `"records": []` delete the rrset (`204`); `DELETE` answers `204` also when the
//!   rrset is not there; every call on a domain the account does not own is `404`;
//! - listings in reverse order of creation, at most [`Seed::page_size`] items (500 unless set)
//!   per page; a listing longer than that without the `cursor` parameter is `400` with a
//!   `Link: <…>; rel="first"` header; with `cursor` (empty for the first page) the answer
//!   carries a `Link` header with `first`, `prev` (not on the first page) and `next` (not on
//!   the last page), with opaque cursors;
//! - a create of an rrset that exists is `400`, and so are an unknown or lowercase type, a TTL
//!   below the domain's `minimum_ttl` ([`Seed::minimum_ttl`], 3600 unless set) or above 86400, a
//!   missing mandatory field, more than 4091 records, content that does not have the form of its
//!   type, a CNAME at the apex, with more than one value or next to other data at its name,
//!   ALIAS and ANAME, and an SOA rrset; the DNSSEC types the provider manages (CDS, NSEC3PARAM,
//!   RRSIG) are `403`; DNSKEY, DS and CDNSKEY are accepted at the apex only;
//! - content is checked and brought into canonical form per type: an A or AAAA address in its
//!   canonical text (`0:0000::1` becomes `::1`); CNAME, DNAME, NS and PTR one name and MX
//!   (priority) and SRV (priority, weight, port) names that end with a dot; CAA flags, tag and a
//!   quoted value; TXT one or more quoted strings with `\X` and `\DDD` escapes, strings longer
//!   than 255 octets split, written back with `"` and `\` escaped and every byte outside
//!   printable ASCII as `\DDD`; other types any text without control characters. Content an rrset
//!   holds already is accepted as it is (another writer's data written back unchanged);
//! - a throttled request is `429` with `Retry-After` and a body that says how long to wait
//!   ([`Control::set_throttled`]).
//!
//! What the mock invents because the documentation is silent, chosen so that a client cannot
//! rely on a lenient reading:
//!
//! - a request without a valid token is `401` with `{"detail": …}`;
//! - a `PATCH` or `PUT` of an rrset that does not exist is `404` (the documentation gives the
//!   answer only for the bulk form, which creates);
//! - a wildcard subname arrives percent-encoded in a path (`%2A`) and is decoded before the
//!   rrset is looked up, as a web framework decodes a path segment;
//! - a body member that is not a field of the rrset object, and a read-only one (`name`,
//!   `domain`, `created`, `touched`), is `400`; so is a `subname` or `type` in a `PATCH` or
//!   `PUT` body that differs from the path (both are write-once);
//! - error bodies are `{"detail": …}` for a whole request and keyed by field
//!   (`{"records": […]}`, `{"non_field_errors": […]}`) for a refused rrset; error texts are
//!   invented;
//! - a new domain gets an apex NS rrset with [`Seed::apex_ns`] (the documentation says deSEC's
//!   name servers are set up for a new domain, without the values), TTL 3600;
//! - the cursors are `p<offset>`; [`Control::set_paging`] makes the listing page in ways the
//!   documentation does not exclude ([`Paging`]), for tests of a client's end rule, among
//!   them the `Link` header as one field line per link.
//!
//! Not modeled: bulk writes (an array body is `400`), the `…` subname syntax of a path, token
//! management and policies, `allowed_subnets`, the zone file export, the SOA rrset and the DNSSEC
//! records the provider manages, and the rate limits themselves beyond the throttled answer.
//!
//! The mock is a [`ChangeSource`]: it reports every change of its published records (every
//! rrset, in every domain) through [`DesecMock::changes`], and a [`link`](crate::link::link)
//! serves them over DNS. [`Control::reset`] returns the mock to its seed.

// Handlers return finished HTTP answers as their error values and hand them straight to axum;
// boxing them would only add noise.
#![allow(clippy::result_large_err)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Map, Value, json};

use crate::MockServer;
use crate::changes::{ChangeSource, Changes, Origin, Published};

/// Path of the API below the server's base URL.
pub const API_PATH: &str = "/api/v1";

/// The largest TTL the API accepts.
const TTL_MAX: u64 = 86_400;

/// The most records of one rrset.
const MAX_RECORDS: usize = 4091;

/// The longest subname.
const SUBNAME_MAX: usize = 178;

/// Types the documentation lists as supported ("at least"), besides the managed DNSSEC types.
const TYPES: &[&str] = &[
    "A",
    "AAAA",
    "AFSDB",
    "APL",
    "CAA",
    "CDNSKEY",
    "CERT",
    "CNAME",
    "DHCID",
    "DNAME",
    "DNSKEY",
    "DLV",
    "DS",
    "EUI48",
    "EUI64",
    "HINFO",
    "HTTPS",
    "KX",
    "L32",
    "L64",
    "LOC",
    "LP",
    "MX",
    "NAPTR",
    "NID",
    "NS",
    "OPENPGPKEY",
    "PTR",
    "RP",
    "SMIMEA",
    "SPF",
    "SRV",
    "SSHFP",
    "SVCB",
    "TLSA",
    "TXT",
    "URI",
];

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// API tokens the API accepts.
    pub tokens: Vec<String>,
    /// Domains, oldest first.
    pub zones: Vec<String>,
    /// The largest page of a listing.
    pub page_size: usize,
    /// The `minimum_ttl` of every domain.
    pub minimum_ttl: u32,
    /// The values of the apex NS rrset a new domain gets; none when empty.
    pub apex_ns: Vec<String>,
}

impl Seed {
    /// The token `test-only-token`, the domain `example.org` with an apex NS rrset of
    /// `ns1.desec.io.` and `ns2.desec.org.`, pages of 500, a minimum TTL of 3600.
    pub fn standard() -> Self {
        Self {
            tokens: vec!["test-only-token".into()],
            zones: vec!["example.org".into()],
            page_size: 500,
            minimum_ttl: 3600,
            apex_ns: vec!["ns1.desec.io.".into(), "ns2.desec.org.".into()],
        }
    }
}

/// An rrset as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rrset {
    /// The domain, without the trailing dot.
    pub zone: String,
    /// The owner relative to the domain; `""` at the apex.
    pub subname: String,
    /// The record type.
    pub rtype: String,
    /// TTL in seconds.
    pub ttl: u32,
    /// The record contents, in presentation format.
    pub records: Vec<String>,
    /// The order of creation.
    pub created: u64,
}

impl Rrset {
    /// The owner name, fully qualified, without the trailing dot.
    pub fn name(&self) -> String {
        owner(&self.zone, &self.subname)
    }
}

/// A domain as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Zone {
    /// The domain name, lowercase, without the trailing dot.
    pub name: String,
    /// The smallest TTL an rrset of the domain may have.
    pub minimum_ttl: u32,
}

/// How a listing pages: the documented reading and readings a client must not loop on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Paging {
    /// As documented: the cursor is honored, and `next` points to the following page.
    #[default]
    Documented,
    /// The cursor is ignored: every request answers the first page, with a `next` link.
    IgnoreCursor,
    /// The `next` link carries the cursor of the request itself.
    RepeatCursor,
    /// The `next` link carries no `cursor` parameter.
    NoCursorInLink,
    /// As documented, with each link of the `Link` header in a field line of its own (RFC 9110
    /// section 5.3 allows a list-valued header to be split so; the documentation prints the
    /// links on three lines).
    SplitLinkFields,
}

#[derive(Debug)]
struct Inner {
    original: Seed,
    seed: Seed,
    zones: Vec<Zone>,
    rrsets: Vec<Rrset>,
    paging: Paging,
    throttled: Option<u32>,
    next_created: u64,
    changes: Changes,
}

impl Inner {
    fn new(seed: Seed, changes: Changes) -> Inner {
        let mut inner = Inner {
            original: seed.clone(),
            zones: Vec::new(),
            rrsets: Vec::new(),
            paging: Paging::Documented,
            throttled: None,
            next_created: 0,
            changes,
            seed: seed.clone(),
        };
        for zone in &seed.zones {
            inner.add_zone(zone);
        }
        inner
    }

    fn add_zone(&mut self, name: &str) {
        let name = plain(name);
        self.zones.push(Zone {
            name: name.clone(),
            minimum_ttl: self.seed.minimum_ttl,
        });
        if !self.seed.apex_ns.is_empty() {
            let created = self.created();
            self.rrsets.push(Rrset {
                zone: name,
                subname: String::new(),
                rtype: "NS".into(),
                ttl: 3600,
                records: self.seed.apex_ns.clone(),
                created,
            });
        }
    }

    fn created(&mut self) -> u64 {
        self.next_created += 1;
        self.next_created
    }

    /// What a DNS server for the mock's domains would answer: every rrset of every domain.
    fn published(&self) -> Published {
        let mut out = Published::new();
        for zone in &self.zones {
            out.zone(&zone.name);
        }
        for rrset in &self.rrsets {
            out.rrset(
                &rrset.zone,
                &format!("{}.", rrset.name()),
                &rrset.rtype,
                Some(rrset.ttl),
                rrset.records.clone(),
            );
        }
        out
    }

    fn report(&self, before: &Published, origin: Origin) {
        self.changes.emit_diff(before, &self.published(), origin);
    }

    fn zone(&self, name: &str) -> Option<&Zone> {
        self.zones.iter().find(|z| z.name == name)
    }

    fn find(&self, zone: &str, subname: &str, rtype: &str) -> Option<usize> {
        self.rrsets
            .iter()
            .position(|r| r.zone == zone && r.subname == subname && r.rtype == rtype)
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
    server: Arc<ServerParts>,
}

/// The request log and the fault queue of the server, for [`Control::reset`].
#[derive(Debug)]
struct ServerParts {
    log: crate::RequestLog,
    faults: crate::Faults,
}

/// A running deSEC mock. Dereferences to its [`MockServer`] for the request log and the fault
/// queue; [`DesecMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct DesecMock {
    server: MockServer,
    control: Control,
}

impl Deref for DesecMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl DesecMock {
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
            .route("/api/v1/domains/", get(domains_list))
            .route("/api/v1/domains/{zone}/", get(domain_get))
            .route(
                "/api/v1/domains/{zone}/rrsets/",
                get(rrsets_list).post(rrset_create),
            )
            .route(
                "/api/v1/domains/{zone}/rrsets/{subname}/{rtype}/",
                get(rrset_get)
                    .patch(rrset_patch)
                    .put(rrset_put)
                    .delete(rrset_delete),
            )
            .with_state(state.clone());
        let server = MockServer::start_on(addr, router).await;
        let control = Control {
            state,
            changes,
            server: Arc::new(ServerParts {
                log: server.log().clone(),
                faults: server.faults().clone(),
            }),
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

impl ChangeSource for DesecMock {
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

    /// Returns the mock to the seed it was started with: its domains with their apex NS rrsets,
    /// no other rrset, documented paging, no throttling, an empty request log and no pending
    /// faults. Reports the removal of every rrset that was published.
    pub fn reset(&self) {
        self.server.faults.clear();
        self.change(|inner| {
            let seed = inner.original.clone();
            *inner = Inner::new(seed, inner.changes.clone());
        });
        self.server.log.clear();
    }

    /// Every domain.
    pub fn zones(&self) -> Vec<Zone> {
        lock(&self.state).zones.clone()
    }

    /// Adds a domain, with an apex NS rrset as the seed says.
    pub fn insert_zone(&self, name: &str) {
        self.change(|inner| inner.add_zone(name));
    }

    /// Removes domain `name` and its rrsets.
    pub fn remove_zone(&self, name: &str) {
        let name = plain(name);
        self.change(|inner| {
            inner.zones.retain(|z| z.name != name);
            inner.rrsets.retain(|r| r.zone != name);
        });
    }

    /// The `minimum_ttl` of every domain from now on.
    pub fn set_minimum_ttl(&self, seconds: u32) {
        let mut inner = lock(&self.state);
        inner.seed.minimum_ttl = seconds;
        for zone in &mut inner.zones {
            zone.minimum_ttl = seconds;
        }
    }

    /// How listings page from now on ([`Paging`]).
    pub fn set_paging(&self, paging: Paging) {
        lock(&self.state).paging = paging;
    }

    /// The largest page of a listing from now on.
    pub fn set_page_size(&self, size: usize) {
        lock(&self.state).seed.page_size = size;
    }

    /// With `Some(seconds)`, every request is answered `429 Too Many Requests` with
    /// `Retry-After: <seconds>` until this is called with `None`.
    pub fn set_throttled(&self, retry_after: Option<u32>) {
        lock(&self.state).throttled = retry_after;
    }

    /// Every rrset.
    pub fn rrsets(&self) -> Vec<Rrset> {
        lock(&self.state).rrsets.clone()
    }

    /// The rrset of owner `name` (fully qualified, with or without the trailing dot) and
    /// `rtype`, if any.
    pub fn rrset(&self, name: &str, rtype: &str) -> Option<Rrset> {
        let name = plain(name);
        lock(&self.state)
            .rrsets
            .iter()
            .find(|r| r.name() == name && r.rtype == rtype)
            .cloned()
    }

    /// The record contents of `name` and `rtype`, in rrset order; empty when there is no such
    /// rrset.
    pub fn records(&self, name: &str, rtype: &str) -> Vec<String> {
        self.rrset(name, rtype)
            .map(|r| r.records)
            .unwrap_or_default()
    }

    /// Creates an rrset in domain `zone` directly, as another writer would, with `records`
    /// stored exactly as given (unchecked), or replaces the one of that name and type.
    ///
    /// # Panics
    ///
    /// If there is no such domain, or `name` is not within it.
    pub fn insert_rrset(&self, zone: &str, name: &str, rtype: &str, ttl: u32, records: &[&str]) {
        let zone = plain(zone);
        let name = plain(name);
        self.change(|inner| {
            assert!(inner.zone(&zone).is_some(), "no domain {zone}");
            let subname = relative(&name, &zone)
                .unwrap_or_else(|| panic!("{name} is not within {zone}"))
                .to_owned();
            let records: Vec<String> = records.iter().map(|r| (*r).to_owned()).collect();
            match inner.find(&zone, &subname, rtype) {
                Some(at) => {
                    inner.rrsets[at].ttl = ttl;
                    inner.rrsets[at].records = records;
                }
                None => {
                    let created = inner.created();
                    inner.rrsets.push(Rrset {
                        zone,
                        subname,
                        rtype: rtype.to_owned(),
                        ttl,
                        records,
                        created,
                    });
                }
            }
        });
    }

    /// Deletes the rrset of `name` and `rtype` directly, as another writer would.
    pub fn delete_rrset(&self, name: &str, rtype: &str) {
        let name = plain(name);
        self.change(|inner| {
            inner
                .rrsets
                .retain(|r| !(r.name() == name && r.rtype == rtype));
        });
    }

    /// Changes the rrset of `name` and `rtype` with `f`, as another writer would.
    ///
    /// # Panics
    ///
    /// If there is no such rrset.
    pub fn edit_rrset(&self, name: &str, rtype: &str, f: impl FnOnce(&mut Rrset)) {
        let name = plain(name);
        self.change(|inner| {
            let rrset = inner
                .rrsets
                .iter_mut()
                .find(|r| r.name() == name && r.rtype == rtype)
                .unwrap_or_else(|| panic!("no rrset {name} {rtype}"));
            f(rrset);
        });
    }
}

/// `name` lowercase without a trailing dot.
fn plain(name: &str) -> String {
    let name = name.trim().to_lowercase();
    name.strip_suffix('.').map(str::to_owned).unwrap_or(name)
}

/// The owner of `subname` in `zone`, without the trailing dot.
fn owner(zone: &str, subname: &str) -> String {
    if subname.is_empty() {
        zone.to_owned()
    } else {
        format!("{subname}.{zone}")
    }
}

/// `name` relative to `zone`; `None` outside it.
fn relative<'a>(name: &'a str, zone: &str) -> Option<&'a str> {
    if name == zone {
        return Some("");
    }
    name.strip_suffix(zone)?.strip_suffix('.')
}

fn detail(status: StatusCode, text: &str) -> Response {
    (status, axum::Json(json!({ "detail": text }))).into_response()
}

/// A refusal of the rrset in the request, keyed by `field`.
fn field_error(field: &str, text: &str) -> Response {
    let mut body = Map::new();
    body.insert(field.to_owned(), json!([text]));
    (StatusCode::BAD_REQUEST, axum::Json(Value::Object(body))).into_response()
}

fn not_found() -> Response {
    detail(StatusCode::NOT_FOUND, "Not found.")
}

/// Checks `Authorization: Token <token>` and the throttle.
fn admit(state: &Shared, headers: &HeaderMap) -> Result<(), Response> {
    let inner = lock(state);
    if let Some(wait) = inner.throttled {
        let mut response = detail(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("Request was throttled. Expected available in {wait} seconds."),
        );
        response
            .headers_mut()
            .insert("retry-after", HeaderValue::from(wait));
        return Err(response);
    }
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Token "));
    match token {
        Some(token) if inner.seed.tokens.iter().any(|t| t == token) => Ok(()),
        _ => Err(detail(StatusCode::UNAUTHORIZED, "Invalid token.")),
    }
}

fn query<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// The absolute URL of the listing at `path` with the filters of `pairs` and `cursor`.
fn page_url(headers: &HeaderMap, path: &str, pairs: &[(String, String)], cursor: &str) -> String {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1");
    let mut query: Vec<String> = pairs
        .iter()
        .filter(|(k, _)| k != "cursor")
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect();
    query.push(format!("cursor={}", encode(cursor)));
    format!("http://{host}{path}?{}", query.join("&"))
}

fn encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~:".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// One page of `all` by the request's `cursor`, with the `Link` header (module documentation).
fn listing(
    inner: &Inner,
    headers: &HeaderMap,
    path: &str,
    pairs: &[(String, String)],
    all: Vec<Value>,
) -> Response {
    let size = inner.seed.page_size.max(1);
    let first = page_url(headers, path, pairs, "");
    let Some(cursor) = query(pairs, "cursor") else {
        if all.len() > size {
            let mut response = detail(
                StatusCode::BAD_REQUEST,
                "Pagination required. Please use the `first` page link (see Link header).",
            );
            if let Ok(link) = HeaderValue::from_str(&format!("<{first}>; rel=\"first\"")) {
                response.headers_mut().insert("link", link);
            }
            return response;
        }
        return axum::Json(Value::Array(all)).into_response();
    };
    let offset = match (inner.paging, cursor) {
        (Paging::IgnoreCursor, _) | (_, "") => 0,
        (_, cursor) => match cursor
            .strip_prefix('p')
            .and_then(|n| n.parse::<usize>().ok())
        {
            Some(offset) => offset,
            None => return detail(StatusCode::BAD_REQUEST, "Invalid cursor."),
        },
    };
    let total = all.len();
    let items: Vec<Value> = all.into_iter().skip(offset).take(size).collect();
    let mut links = vec![format!("<{first}>; rel=\"first\"")];
    if offset > 0 {
        let prev = format!("p{}", offset.saturating_sub(size));
        links.push(format!(
            "<{}>; rel=\"prev\"",
            page_url(headers, path, pairs, &prev)
        ));
    }
    if offset + size < total {
        let next = match inner.paging {
            Paging::RepeatCursor => cursor.to_owned(),
            _ => format!("p{}", offset + size),
        };
        let url = match inner.paging {
            Paging::NoCursorInLink => {
                let host = headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("127.0.0.1");
                format!("http://{host}{path}")
            }
            _ => page_url(headers, path, pairs, &next),
        };
        links.push(format!("<{url}>; rel=\"next\""));
    }
    let mut response = axum::Json(Value::Array(items)).into_response();
    if inner.paging == Paging::SplitLinkFields {
        for link in &links {
            if let Ok(link) = HeaderValue::from_str(link) {
                response.headers_mut().append("link", link);
            }
        }
    } else if let Ok(link) = HeaderValue::from_str(&links.join(", ")) {
        response.headers_mut().insert("link", link);
    }
    response
}

const TIMESTAMP: &str = "2026-01-01T00:00:00.000000Z";

fn zone_json(zone: &Zone, keys: bool) -> Value {
    let mut out = json!({
        "created": TIMESTAMP,
        "minimum_ttl": zone.minimum_ttl,
        "name": zone.name,
        "published": TIMESTAMP,
        "status": {
            "checked": null,
            "nameserver_status": null,
            "nameservers": [],
            "secure_since": null,
            "security_status": null
        },
        "touched": TIMESTAMP,
    });
    if keys {
        out["keys"] = json!([]);
    }
    out
}

fn rrset_json(rrset: &Rrset) -> Value {
    json!({
        "created": TIMESTAMP,
        "domain": rrset.zone,
        "subname": rrset.subname,
        "name": format!("{}.", rrset.name()),
        "type": rrset.rtype,
        "records": rrset.records,
        "ttl": rrset.ttl,
        "touched": TIMESTAMP,
    })
}

async fn domains_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    if let Err(response) = admit(&state, &headers) {
        return response;
    }
    let inner = lock(&state);
    let mut zones: Vec<&Zone> = inner.zones.iter().rev().collect();
    if let Some(qname) = query(&pairs, "owns_qname") {
        let qname = plain(qname);
        let best = zones
            .iter()
            .filter(|z| relative(&qname, &z.name).is_some())
            .max_by_key(|z| z.name.len())
            .copied();
        zones = best.into_iter().collect();
    }
    let all: Vec<Value> = zones.iter().map(|z| zone_json(z, false)).collect();
    listing(&inner, &headers, "/api/v1/domains/", &pairs, all)
}

async fn domain_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(zone): Path<String>,
) -> Response {
    if let Err(response) = admit(&state, &headers) {
        return response;
    }
    match lock(&state).zone(&zone) {
        Some(zone) => axum::Json(zone_json(zone, true)).into_response(),
        None => not_found(),
    }
}

async fn rrsets_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(zone): Path<String>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    if let Err(response) = admit(&state, &headers) {
        return response;
    }
    let inner = lock(&state);
    if inner.zone(&zone).is_none() {
        return not_found();
    }
    let rtype = query(&pairs, "type");
    let subname = query(&pairs, "subname");
    let mut all: Vec<&Rrset> = inner
        .rrsets
        .iter()
        .filter(|r| r.zone == zone)
        .filter(|r| rtype.is_none_or(|t| r.rtype == t))
        .filter(|r| subname.is_none_or(|s| r.subname == s))
        .collect();
    all.sort_by_key(|r| std::cmp::Reverse(r.created));
    let all: Vec<Value> = all.into_iter().map(rrset_json).collect();
    let path = format!("/api/v1/domains/{zone}/rrsets/");
    listing(&inner, &headers, &path, &pairs, all)
}

/// The subname of a path: `@` is the apex.
fn path_subname(subname: &str) -> &str {
    if subname == "@" { "" } else { subname }
}

async fn rrset_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((zone, subname, rtype)): Path<(String, String, String)>,
) -> Response {
    if let Err(response) = admit(&state, &headers) {
        return response;
    }
    let inner = lock(&state);
    if inner.zone(&zone).is_none() {
        return not_found();
    }
    match inner.find(&zone, path_subname(&subname), &rtype) {
        Some(at) => axum::Json(rrset_json(&inner.rrsets[at])).into_response(),
        None => not_found(),
    }
}

/// A write body, checked: the fields given.
struct Body {
    subname: Option<String>,
    rtype: Option<String>,
    ttl: Option<u32>,
    records: Option<Vec<String>>,
}

/// Parses a write body: one object (a bulk array is not modeled) whose members are writable
/// fields of the rrset object.
fn parse_body(bytes: &[u8]) -> Result<Body, Response> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| detail(StatusCode::BAD_REQUEST, "JSON parse error."))?;
    let Value::Object(object) = value else {
        return Err(detail(
            StatusCode::BAD_REQUEST,
            "Expected a single RRset object.",
        ));
    };
    for key in object.keys() {
        if !matches!(key.as_str(), "subname" | "type" | "ttl" | "records") {
            return Err(field_error(key, "This field is not writable or unknown."));
        }
    }
    let text = |key: &str| -> Result<Option<String>, Response> {
        match object.get(key) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(field_error(key, "Not a valid string.")),
        }
    };
    let ttl = match object.get("ttl") {
        None => None,
        Some(value) => Some(
            value
                .as_u64()
                .and_then(|t| u32::try_from(t).ok())
                .ok_or_else(|| field_error("ttl", "A valid integer is required."))?,
        ),
    };
    let records = match object.get("records") {
        None => None,
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .map(|item| item.as_str().map(str::to_owned))
                .collect::<Option<Vec<String>>>()
                .ok_or_else(|| field_error("records", "Not a valid string."))?,
        ),
        Some(_) => return Err(field_error("records", "Expected a list of items.")),
    };
    Ok(Body {
        subname: text("subname")?,
        rtype: text("type")?,
        ttl,
        records,
    })
}

/// Checks a subname: lowercase alphanumerics, `-`, `_` and `.`, a `*` only as the whole first
/// label, at most 178 characters.
fn subname_valid(subname: &str) -> bool {
    if subname.len() > SUBNAME_MAX {
        return false;
    }
    if subname.is_empty() {
        return true;
    }
    let rest = match subname.strip_prefix('*') {
        Some("") => return true,
        Some(rest) => match rest.strip_prefix('.') {
            Some(rest) => rest,
            None => return false,
        },
        None => subname,
    };
    !rest.is_empty()
        && rest.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b))
        })
}

/// Checks the type for an rrset at `subname`: uppercase, supported, not refused.
fn type_check(rtype: &str, subname: &str) -> Result<(), Response> {
    match rtype {
        "CDS" | "NSEC3PARAM" | "RRSIG" => Err(detail(
            StatusCode::FORBIDDEN,
            "You cannot tinker with the automatically managed DNSSEC records.",
        )),
        "SOA" => Err(field_error(
            "type",
            "You cannot tinker with the SOA RR set.",
        )),
        "ALIAS" | "ANAME" => Err(field_error("type", "This record type is not supported.")),
        "DNSKEY" | "DS" | "CDNSKEY" if !subname.is_empty() => Err(field_error(
            "type",
            "This record type is allowed at the zone apex only.",
        )),
        _ if TYPES.contains(&rtype) => Ok(()),
        _ => Err(field_error("type", "Unknown or unsupported record type.")),
    }
}

/// Checks and canonicalizes the records of an rrset of `rtype` at `subname` in `zone`. `held`
/// are the contents the rrset holds now: those are accepted as they are.
fn records_check(
    inner: &Inner,
    zone: &str,
    subname: &str,
    rtype: &str,
    records: &[String],
    held: &[String],
) -> Result<Vec<String>, Response> {
    if records.len() > MAX_RECORDS {
        return Err(field_error(
            "records",
            "Ensure this field has no more than 4091 elements.",
        ));
    }
    let mut out: Vec<String> = Vec::new();
    for record in records {
        let canonical = if held.contains(record) {
            record.clone()
        } else {
            canonical(rtype, record)
                .ok_or_else(|| field_error("records", "Record content is malformed."))?
        };
        if !out.contains(&canonical) {
            out.push(canonical);
        }
    }
    if rtype == "CNAME" {
        if subname.is_empty() {
            return Err(field_error(
                "type",
                "CNAME RRset cannot have empty subname.",
            ));
        }
        if out.len() > 1 {
            return Err(field_error(
                "records",
                "CNAME RRset cannot have multiple records.",
            ));
        }
    }
    // CNAME exclusivity: a CNAME and other data at one name.
    let mut others = inner
        .rrsets
        .iter()
        .filter(|r| r.zone == zone && r.subname == subname && r.rtype != rtype);
    let conflict = others.any(|r| rtype == "CNAME" || r.rtype == "CNAME");
    if conflict && !out.is_empty() {
        return Err(field_error(
            "non_field_errors",
            "RRset with conflicting type present: CNAME and other data at one name.",
        ));
    }
    Ok(out)
}

/// The TTL checked against the domain's minimum and the maximum.
fn ttl_check(inner: &Inner, zone: &str, ttl: u32) -> Result<u32, Response> {
    let minimum = inner.zone(zone).map_or(1, |z| z.minimum_ttl);
    if ttl < minimum {
        return Err(field_error(
            "ttl",
            &format!("Ensure this value is greater than or equal to {minimum}."),
        ));
    }
    if u64::from(ttl) > TTL_MAX {
        return Err(field_error(
            "ttl",
            "Ensure this value is less than or equal to 86400.",
        ));
    }
    Ok(ttl)
}

async fn rrset_create(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(zone): Path<String>,
    bytes: Bytes,
) -> Response {
    if let Err(response) = admit(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    if inner.zone(&zone).is_none() {
        return not_found();
    }
    let body = match parse_body(&bytes) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let subname = body.subname.unwrap_or_default();
    let (Some(rtype), Some(ttl), Some(records)) = (body.rtype, body.ttl, body.records) else {
        return field_error("non_field_errors", "type, ttl and records are required.");
    };
    if !subname_valid(&subname) {
        return field_error("subname", "Subname is invalid.");
    }
    if let Err(response) = type_check(&rtype, &subname) {
        return response;
    }
    if inner.find(&zone, &subname, &rtype).is_some() {
        return field_error(
            "non_field_errors",
            "Another RRset with the same subdomain and type exists for this domain.",
        );
    }
    let ttl = match ttl_check(&inner, &zone, ttl) {
        Ok(ttl) => ttl,
        Err(response) => return response,
    };
    if records.is_empty() {
        return field_error("records", "This list may not be empty.");
    }
    let records = match records_check(&inner, &zone, &subname, &rtype, &records, &[]) {
        Ok(records) => records,
        Err(response) => return response,
    };
    let before = inner.published();
    let created = inner.created();
    let rrset = Rrset {
        zone,
        subname,
        rtype,
        ttl,
        records,
        created,
    };
    let answer = rrset_json(&rrset);
    inner.rrsets.push(rrset);
    inner.report(&before, Origin::Api);
    (StatusCode::CREATED, axum::Json(answer)).into_response()
}

/// `PATCH` (`partial`) and `PUT` on one rrset.
fn rrset_update(
    state: &Shared,
    headers: &HeaderMap,
    zone: &str,
    subname: &str,
    rtype: &str,
    bytes: &[u8],
    partial: bool,
) -> Response {
    if let Err(response) = admit(state, headers) {
        return response;
    }
    let mut inner = lock(state);
    if inner.zone(zone).is_none() {
        return not_found();
    }
    let subname = path_subname(subname);
    let body = match parse_body(bytes) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if body.subname.as_deref().is_some_and(|s| s != subname)
        || body.rtype.as_deref().is_some_and(|t| t != rtype)
    {
        return field_error("non_field_errors", "subname and type cannot be changed.");
    }
    if !partial && (body.subname.is_none() || body.rtype.is_none() || body.ttl.is_none()) {
        return field_error("non_field_errors", "PUT requires every field of the RRset.");
    }
    if !partial && body.records.is_none() {
        return field_error("records", "This field is required.");
    }
    let Some(at) = inner.find(zone, subname, rtype) else {
        return not_found();
    };
    let held = inner.rrsets[at].records.clone();
    let ttl = match body.ttl {
        Some(ttl) => match ttl_check(&inner, zone, ttl) {
            Ok(ttl) => ttl,
            Err(response) => return response,
        },
        None => inner.rrsets[at].ttl,
    };
    let records = match body.records {
        Some(records) => match records_check(&inner, zone, subname, rtype, &records, &held) {
            Ok(records) => records,
            Err(response) => return response,
        },
        None => held,
    };
    let before = inner.published();
    if records.is_empty() {
        inner.rrsets.remove(at);
        inner.report(&before, Origin::Api);
        return StatusCode::NO_CONTENT.into_response();
    }
    inner.rrsets[at].ttl = ttl;
    inner.rrsets[at].records = records;
    let answer = rrset_json(&inner.rrsets[at]);
    inner.report(&before, Origin::Api);
    axum::Json(answer).into_response()
}

async fn rrset_patch(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((zone, subname, rtype)): Path<(String, String, String)>,
    bytes: Bytes,
) -> Response {
    rrset_update(&state, &headers, &zone, &subname, &rtype, &bytes, true)
}

async fn rrset_put(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((zone, subname, rtype)): Path<(String, String, String)>,
    bytes: Bytes,
) -> Response {
    rrset_update(&state, &headers, &zone, &subname, &rtype, &bytes, false)
}

async fn rrset_delete(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((zone, subname, rtype)): Path<(String, String, String)>,
) -> Response {
    if let Err(response) = admit(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    if inner.zone(&zone).is_none() {
        return not_found();
    }
    let before = inner.published();
    if let Some(at) = inner.find(&zone, path_subname(&subname), &rtype) {
        inner.rrsets.remove(at);
        inner.report(&before, Origin::Api);
    }
    StatusCode::NO_CONTENT.into_response()
}

// ---- Content -----------------------------------------------------------------------------------

/// A name inside content: non-empty labels, ending with the dot, no whitespace.
fn is_name(text: &str) -> bool {
    let Some(bare) = text.strip_suffix('.') else {
        return false;
    };
    !bare.is_empty()
        && !bare.chars().any(|c| c.is_whitespace() || c.is_control())
        && bare.split('.').all(|label| !label.is_empty())
}

fn is_u16(text: &str) -> bool {
    text.parse::<u16>().is_ok()
}

/// The canonical form of a record's content of `rtype`, or `None` when it does not have the form
/// of its type (module documentation).
fn canonical(rtype: &str, content: &str) -> Option<String> {
    let fields: Vec<&str> = content.split_ascii_whitespace().collect();
    match (rtype, fields.as_slice()) {
        ("A", [address]) => address.parse::<Ipv4Addr>().ok().map(|a| a.to_string()),
        ("AAAA", [address]) => address.parse::<Ipv6Addr>().ok().map(|a| a.to_string()),
        ("CNAME" | "DNAME" | "NS" | "PTR", [target]) => {
            is_name(target).then(|| target.to_lowercase())
        }
        ("MX", [priority, host]) => (is_u16(priority) && is_name(host))
            .then(|| format!("{priority} {}", host.to_lowercase())),
        ("SRV", [priority, weight, port, target]) => {
            (is_u16(priority) && is_u16(weight) && is_u16(port) && is_name(target))
                .then(|| format!("{priority} {weight} {port} {}", target.to_lowercase()))
        }
        ("CAA", [flags, tag, ..]) => {
            let value = content.trim_start().strip_prefix(flags)?.trim_start();
            let value = value.strip_prefix(tag)?.trim_start();
            let parsed = txt_strings(value)?;
            let ok = flags.parse::<u8>().is_ok()
                && !tag.is_empty()
                && tag.bytes().all(|b| b.is_ascii_alphanumeric())
                && parsed.len() == 1;
            ok.then(|| format!("{flags} {} {}", tag.to_lowercase(), quote(&parsed[0])))
        }
        ("TXT", _) => {
            let strings = txt_strings(content)?;
            let chunks: Vec<String> = strings
                .iter()
                .flat_map(|s| {
                    if s.is_empty() {
                        vec![quote(&[])]
                    } else {
                        s.chunks(255).map(quote).collect()
                    }
                })
                .collect();
            Some(chunks.join(" "))
        }
        ("A" | "AAAA" | "CNAME" | "DNAME" | "NS" | "PTR" | "MX" | "SRV" | "CAA", _) => None,
        (_, []) => None,
        _ => (!content.chars().any(char::is_control)).then(|| content.trim().to_owned()),
    }
}

/// The quoted strings of TXT content, unescaped; `None` for text outside quotes, an
/// unterminated quote, a bad escape or a control character.
fn txt_strings(content: &str) -> Option<Vec<Vec<u8>>> {
    let bytes = content.trim().as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b' ' | b'\t' => at += 1,
            b'"' => {
                at += 1;
                let mut string = Vec::new();
                loop {
                    let byte = *bytes.get(at)?;
                    at += 1;
                    match byte {
                        b'"' => break,
                        b'\\' => {
                            let next = *bytes.get(at)?;
                            if next.is_ascii_digit() {
                                let digits = bytes.get(at..at + 3)?;
                                let text = std::str::from_utf8(digits).ok()?;
                                let value: u8 = text.parse().ok()?;
                                string.push(value);
                                at += 3;
                            } else {
                                string.push(next);
                                at += 1;
                            }
                        }
                        byte if byte < 0x20 || byte == 0x7f => return None,
                        byte => string.push(byte),
                    }
                }
                out.push(string);
            }
            _ => return None,
        }
    }
    (!out.is_empty()).then_some(out)
}

/// A character-string in quotes, `"` and `\` escaped, bytes outside printable ASCII as `\DDD`.
fn quote(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for &byte in bytes {
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
}

#[cfg(test)]
mod tests {
    use super::{canonical, subname_valid};

    #[test]
    fn content_is_checked_and_canonicalized() {
        for (rtype, content, expected) in [
            ("A", "192.0.2.1", "192.0.2.1"),
            ("AAAA", "0:0000::1", "::1"),
            ("CNAME", "Target.example.net.", "target.example.net."),
            ("MX", "10  mail.a4a.de.", "10 mail.a4a.de."),
            (
                "SRV",
                "10 20 5060 sip.example.org.",
                "10 20 5060 sip.example.org.",
            ),
            (
                "CAA",
                "0 issue \"letsencrypt.org\"",
                "0 issue \"letsencrypt.org\"",
            ),
            ("TXT", "\"test value1\"", "\"test value1\""),
            ("TXT", "\"a\" \"b\"", "\"a\" \"b\""),
            ("TXT", "\"\\013\\\"\"", "\"\\013\\\"\""),
            (
                "TXT",
                "\"ключ\"",
                "\"\\208\\186\\208\\187\\209\\142\\209\\135\"",
            ),
            ("TLSA", "3 1 1 0a1b", "3 1 1 0a1b"),
        ] {
            assert_eq!(
                canonical(rtype, content).as_deref(),
                Some(expected),
                "{rtype} {content}"
            );
        }
        let long = format!("\"{}\"", "x".repeat(300));
        let split = canonical("TXT", &long).unwrap();
        assert_eq!(
            split,
            format!("\"{}\" \"{}\"", "x".repeat(255), "x".repeat(45))
        );
        for (rtype, content) in [
            ("A", "192.0.2"),
            ("CNAME", "target.example.net"),
            ("MX", "10 mail"),
            ("MX", "mail.example.org."),
            ("TXT", "unquoted"),
            ("TXT", "\"open"),
            ("TXT", "\"a\" b"),
            ("CAA", "256 issue \"x\""),
            ("TLSA", ""),
        ] {
            assert_eq!(canonical(rtype, content), None, "{rtype} {content}");
        }
    }

    #[test]
    fn subnames_are_checked() {
        for ok in [
            "",
            "www",
            "_acme-challenge.www",
            "*",
            "*.sub",
            "xn--e1afmkfd",
        ] {
            assert!(subname_valid(ok), "{ok}");
        }
        for bad in ["WWW", "a..b", "a.*", "*x", "a b", ".a"] {
            assert!(!subname_valid(bad), "{bad}");
        }
    }
}
