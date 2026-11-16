//! The core of the Gcore and EdgeCenter mocks: the DNS API v2 that Gcore serves and EdgeCenter
//! serves in a fork of its own. Each public mock ([`crate::gcore`], [`crate::edgecenter`]) starts
//! this core with the answers of its provider's specification ([`Flavor`]) and re-exports its
//! types.
//!
//! Shapes follow the sources the clients cite:
//!
//! - Gcore: <https://docs.gcore.com/api-reference/dns> and the Swagger document
//!   <https://api.gcore.com/dns/docs/swagger.yaml>;
//! - EdgeCenter: the Swagger document <https://api.edgecenter.ru/dns/docs/swagger-en.yaml> and the
//!   provider's Go SDK `github.com/Edge-Center/edgecenter-dns-sdk-go`;
//! - both: lego `providers/dns/internal/gcore` and its fixtures.
//!
//! What both specifications document and the mock does: the paths below `/dns/v2`; the header
//! `Authorization: APIKey <token>`; zones and rrsets listed in `{…, "total_amount"}` pages with
//! `offset` and `limit`; an rrset addressed by zone name, owner name and type, each a fully
//! qualified name without the trailing dot; `content` as an array with one element per field of
//! the record; `enabled` defaulting to true; `ttl` defaulting to 300; `PUT` replacing the whole
//! rrset, its selection (`pickers` at Gcore, `filters` at EdgeCenter) and its `meta` included;
//! error bodies `{"error": "…"}` (lego and the SDK read that shape).
//!
//! Answers the mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading:
//!
//! - a missing zone and a missing rrset are both `404` (documented by EdgeCenter, inferred for
//!   Gcore from lego's "Support DELETE idempotence");
//! - a request without the right token is `401` (documented by EdgeCenter only);
//! - at Gcore a create of an rrset that exists is `400` (only `400` is documented); at
//!   EdgeCenter it is `409`, which its spec lists for a create without a meaning;
//! - a `PUT` of an rrset that does not exist is `404`: the specs call `PUT` "Update" (Gcore's
//!   prose says "Create/update"), and neither client uses it to create;
//! - an owner name in the path with a trailing dot, outside the zone, or in upper case is `400`;
//!   so is a body with a member the input form does not have (an rrset `id`, a record `id`), an
//!   empty `resource_records`, a TTL below the plan's minimum (`min_ttl` of the limits, 1 unless
//!   set with [`Control::set_min_ttl`]), and content that does not have the form of its type
//!   (below), except content the rrset already holds: the provider's own data written back
//!   unchanged is accepted as it is;
//! - a write to the SOA rrset or to the NS rrset at the apex is `400`;
//! - the default page size is [`Seed::page_size`] (100 unless set), and `limit` is capped there;
//!   `total_amount` is the total of the listing unless [`Control::set_paging`] says otherwise
//!   ([`Paging`]: the count of the page, or a server that ignores `offset`), readings the Gcore
//!   spec, which describes neither member, does not exclude;
//! - `filter_set_id` is answered only when a test sets it ([`Rrset::filter_set_id`]).
//!
//! Content per type, as dns-update and the EdgeCenter SDK write it: A and AAAA one address;
//! CNAME and NS one name (DNAME and PTR alike, where a provider accepts the type); MX a priority (a number, 0 to 65535) and a name; SRV priority,
//! weight and port (numbers) and a name; CAA flags (0 to 255), a tag and a value (strings); TXT
//! one string. A name has non-empty labels and may end with a dot. Any other type is checked only
//! for being a non-empty array.
//!
//! Error texts are invented.

// Handlers return finished HTTP answers as their error values and hand them straight to axum;
// boxing them would only add noise.
#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Map, Value, json};

use crate::changes::{Changes, Origin, Published};
use crate::{Faults, MockServer, RequestLog};

/// Path of the DNS API below the server's base URL.
pub const API_PATH: &str = "/dns";

/// What differs between the providers that serve this API.
#[derive(Debug)]
pub(crate) struct Flavor {
    /// The member of an rrset that selects answers per query.
    pub(crate) selection: &'static str,
    /// The answer to a create of an rrset that exists.
    pub(crate) create_exists: StatusCode,
    /// The answer to a delete: `200` with `{}` (Gcore) or `204` (EdgeCenter).
    pub(crate) delete_status: StatusCode,
    /// The zone's answer is wrapped in `{"zone": …}` (EdgeCenter) rather than flat (Gcore).
    pub(crate) zone_wrapped: bool,
    /// The record types the API accepts.
    pub(crate) types: &'static [&'static str],
}

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// Permanent API tokens the API accepts.
    pub tokens: Vec<String>,
    /// Zones, in listing order.
    pub zones: Vec<String>,
    /// The default and largest page of a listing.
    pub page_size: usize,
}

impl Seed {
    /// The token `test-only-token` and the zone `example.org`, pages of 100.
    pub fn standard() -> Self {
        Self {
            tokens: vec!["test-only-token".into()],
            zones: vec!["example.org".into()],
            page_size: 100,
        }
    }
}

/// One record of an rrset, in the API's form.
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    /// The record's identifier.
    pub id: u64,
    /// One element per field of the record.
    pub content: Vec<Value>,
    /// A disabled record is kept but not published.
    pub enabled: bool,
    /// Per-record metadata, if any.
    pub meta: Option<Map<String, Value>>,
}

/// An rrset as the mock holds it.
#[derive(Clone, Debug, PartialEq)]
pub struct Rrset {
    /// The rrset's identifier.
    pub id: u64,
    /// The zone, without the trailing dot.
    pub zone: String,
    /// The owner name, fully qualified, without the trailing dot.
    pub name: String,
    /// The record type.
    pub rtype: String,
    /// TTL in seconds.
    pub ttl: u32,
    /// The records.
    pub records: Vec<Record>,
    /// Rrset metadata (failover checks, a GeoDNS link); empty for a plain rrset.
    pub meta: Map<String, Value>,
    /// The selection of answers per query (`pickers` or `filters`); empty for a plain rrset.
    pub selection: Vec<Value>,
    /// `filter_set_id`, answered only when set: the specs list it without a meaning ("For
    /// internal use", the EdgeCenter spec).
    pub filter_set_id: Option<u64>,
}

/// A zone as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Zone {
    /// The zone name, lowercase, without the trailing dot.
    pub name: String,
    /// A disabled zone is listed with `"enabled": false`.
    pub enabled: bool,
}

#[derive(Debug)]
struct Inner {
    original: Seed,
    seed: Seed,
    zones: Vec<Zone>,
    rrsets: Vec<Rrset>,
    min_ttl: u32,
    paging: Paging,
    next_id: u64,
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
                    name: plain(name),
                    enabled: true,
                })
                .collect(),
            seed,
            rrsets: Vec::new(),
            min_ttl: 1,
            paging: Paging::Total,
            next_id: 0,
            changes,
        }
    }

    fn new_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// What a DNS server for the mock's zones would answer: the enabled records, of every zone.
    fn published(&self) -> Published {
        let mut out = Published::new();
        for zone in &self.zones {
            out.zone(&zone.name);
        }
        for rrset in &self.rrsets {
            let values = rrset
                .records
                .iter()
                .filter(|r| r.enabled)
                .filter_map(|r| zone_file_text(&rrset.rtype, &r.content))
                .collect();
            out.rrset(
                &rrset.zone,
                &format!("{}.", rrset.name),
                &rrset.rtype,
                Some(rrset.ttl),
                values,
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

    fn rrset_mut(&mut self, zone: &str, name: &str, rtype: &str) -> Option<&mut Rrset> {
        self.rrsets
            .iter_mut()
            .find(|r| r.zone == zone && r.name == name && r.rtype == rtype)
    }
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Clone)]
struct App {
    state: Shared,
    flavor: &'static Flavor,
}

/// Reads and changes the state of a mock. Cheap to clone, so that a fault hook
/// ([`Fault::run`](crate::Fault::run)) can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
    pub(crate) changes: Changes,
    log: RequestLog,
    faults: Faults,
}

/// Starts the core with `flavor` on `addr`.
pub(crate) async fn start(
    addr: SocketAddr,
    seed: Seed,
    flavor: &'static Flavor,
) -> (MockServer, Control) {
    let changes = Changes::new();
    let state = Arc::new(Mutex::new(Inner::new(seed, changes.clone())));
    let app = App {
        state: state.clone(),
        flavor,
    };
    let router = Router::new()
        .route("/dns/v2/zones", get(zones_list))
        .route("/dns/v2/zones/{zone}", get(zone_get))
        .route("/dns/v2/zones/{zone}/rrsets", get(rrsets_list))
        .route(
            "/dns/v2/zones/{zone}/{name}/{rtype}",
            get(rrset_get)
                .post(rrset_create)
                .put(rrset_replace)
                .delete(rrset_delete),
        )
        .with_state(app);
    let server = MockServer::start_on(addr, router).await;
    let control = Control {
        state,
        changes,
        log: server.log().clone(),
        faults: server.faults().clone(),
    };
    (server, control)
}

/// The published state of the mock behind `control`.
pub(crate) fn published(control: &Control) -> Published {
    lock(&control.state).published()
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

    /// Returns the mock to the seed it was started with: its zones, no rrsets, a plan minimum
    /// TTL of 1, an empty request log and no pending faults. Reports the removal of every rrset
    /// that was published.
    pub fn reset(&self) {
        self.faults.clear();
        self.change(|inner| {
            let seed = inner.original.clone();
            *inner = Inner::new(seed, inner.changes.clone());
        });
        self.log.clear();
    }

    /// Every zone.
    pub fn zones(&self) -> Vec<Zone> {
        lock(&self.state).zones.clone()
    }

    /// Adds an empty zone.
    pub fn insert_zone(&self, name: &str) {
        self.change(|inner| {
            inner.zones.push(Zone {
                name: plain(name),
                enabled: true,
            });
        });
    }

    /// Removes zone `name` and its rrsets.
    pub fn remove_zone(&self, name: &str) {
        let name = plain(name);
        self.change(|inner| {
            inner.zones.retain(|z| z.name != name);
            inner.rrsets.retain(|r| r.zone != name);
        });
    }

    /// Marks zone `name` disabled or enabled.
    pub fn set_zone_enabled(&self, name: &str, enabled: bool) {
        let name = plain(name);
        for zone in lock(&self.state)
            .zones
            .iter_mut()
            .filter(|z| z.name == name)
        {
            zone.enabled = enabled;
        }
    }

    /// The smallest TTL the API accepts from now on (the plan's `min_ttl`).
    pub fn set_min_ttl(&self, seconds: u32) {
        lock(&self.state).min_ttl = seconds;
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

    /// The rrset of `name` and `rtype`, if any.
    pub fn rrset(&self, name: &str, rtype: &str) -> Option<Rrset> {
        let name = plain(name);
        lock(&self.state)
            .rrsets
            .iter()
            .find(|r| r.name == name && r.rtype == rtype)
            .cloned()
    }

    /// Creates an rrset in zone `zone` directly, as another writer would: each element of
    /// `contents` is the `content` array of one enabled record.
    ///
    /// # Panics
    ///
    /// If there is no such zone, or an element of `contents` is not an array.
    pub fn insert_rrset(&self, zone: &str, name: &str, rtype: &str, ttl: u32, contents: &[Value]) {
        let zone = plain(zone);
        let name = plain(name);
        self.change(|inner| {
            assert!(inner.zone(&zone).is_some(), "no zone {zone}");
            let records = contents
                .iter()
                .map(|content| {
                    let Value::Array(content) = content else {
                        panic!("content must be an array: {content}");
                    };
                    Record {
                        id: inner.new_id(),
                        content: content.clone(),
                        enabled: true,
                        meta: None,
                    }
                })
                .collect();
            let id = inner.new_id();
            inner.rrsets.push(Rrset {
                id,
                zone,
                name,
                rtype: rtype.to_owned(),
                ttl,
                records,
                meta: Map::new(),
                selection: Vec::new(),
                filter_set_id: None,
            });
        });
    }

    /// Deletes the rrset of `name` and `rtype` directly, as another writer would.
    pub fn delete_rrset(&self, name: &str, rtype: &str) {
        let name = plain(name);
        self.change(|inner| {
            inner
                .rrsets
                .retain(|r| !(r.name == name && r.rtype == rtype));
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
                .find(|r| r.name == name && r.rtype == rtype)
                .unwrap_or_else(|| panic!("no rrset {name} {rtype}"));
            f(rrset);
        });
    }

    /// Disables or enables the records of `name` and `rtype` whose content is `content`.
    pub fn set_enabled(&self, name: &str, rtype: &str, content: &Value, enabled: bool) {
        let name = plain(name);
        self.change(|inner| {
            for rrset in inner
                .rrsets
                .iter_mut()
                .filter(|r| r.name == name && r.rtype == rtype)
            {
                for record in rrset
                    .records
                    .iter_mut()
                    .filter(|r| Value::Array(r.content.clone()) == *content)
                {
                    record.enabled = enabled;
                }
            }
        });
    }

    /// The `content` of each record of `name` and `rtype`, in rrset order, with its `enabled`
    /// flag; empty when there is no such rrset.
    pub fn contents(&self, name: &str, rtype: &str) -> Vec<(Value, bool)> {
        self.rrset(name, rtype)
            .map(|r| {
                r.records
                    .into_iter()
                    .map(|record| (Value::Array(record.content), record.enabled))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The TXT strings of `name`, in rrset order, disabled records included: the one string of
    /// each record's content, or its JSON text when the content is in another form.
    pub fn txt_values(&self, name: &str) -> Vec<String> {
        self.rrset(name, "TXT")
            .map(|r| {
                r.records
                    .iter()
                    .map(|record| match record.content.as_slice() {
                        [Value::String(text)] => text.clone(),
                        other => Value::Array(other.to_vec()).to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// `name` lowercase without a trailing dot.
fn plain(name: &str) -> String {
    let name = name.trim().to_lowercase();
    name.strip_suffix('.').map(str::to_owned).unwrap_or(name)
}

/// An error answer in the shape lego and the SDK read.
fn error(status: StatusCode, text: &str) -> Response {
    (status, axum::Json(json!({ "error": text }))).into_response()
}

fn bad_request(text: &str) -> Response {
    error(StatusCode::BAD_REQUEST, text)
}

fn not_found(text: &str) -> Response {
    error(StatusCode::NOT_FOUND, text)
}

/// Checks `Authorization: APIKey <token>`.
fn authorize(app: &App, headers: &HeaderMap) -> Result<(), Response> {
    let refused = || error(StatusCode::UNAUTHORIZED, "invalid or missing API token");
    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(refused)?;
    let token = header.strip_prefix("APIKey ").ok_or_else(refused)?;
    if lock(&app.state).seed.tokens.iter().any(|t| t == token) {
        Ok(())
    } else {
        Err(refused())
    }
}

fn query<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// How a listing pages: the documented reading and two readings the documentation does not
/// exclude, for tests of a client's end rule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Paging {
    /// `offset` is honored and `total_amount` is the number of items of the whole listing.
    #[default]
    Total,
    /// `offset` is honored and `total_amount` is the number of items of the page answered.
    PageCount,
    /// `offset` is ignored: every request answers the first page, with the whole total.
    IgnoreOffset,
}

/// The answer of a listing: one page of `all` under `key`, with `total_amount` as `paging`
/// says.
fn listing(
    key: &str,
    all: Vec<Value>,
    pairs: &[(String, String)],
    page_size: usize,
    paging: Paging,
) -> Response {
    let total = all.len();
    let pairs: Vec<(String, String)> = match paging {
        Paging::IgnoreOffset => pairs
            .iter()
            .filter(|(k, _)| k != "offset")
            .cloned()
            .collect(),
        _ => pairs.to_vec(),
    };
    match page(all, &pairs, page_size) {
        Ok(items) => {
            let total = match paging {
                Paging::PageCount => items.len(),
                _ => total,
            };
            let mut body = serde_json::Map::new();
            body.insert(key.to_owned(), Value::Array(items));
            body.insert("total_amount".to_owned(), json!(total));
            axum::Json(Value::Object(body)).into_response()
        }
        Err(response) => response,
    }
}

/// The items of one page by `offset` and `limit`, the limit capped at the page size.
fn page<T>(
    items: Vec<T>,
    pairs: &[(String, String)],
    page_size: usize,
) -> Result<Vec<T>, Response> {
    let number = |key: &str| match query(pairs, key).map(str::parse::<usize>) {
        None => Ok(None),
        Some(Ok(n)) => Ok(Some(n)),
        Some(Err(_)) => Err(bad_request(
            "offset and limit must be non-negative integers",
        )),
    };
    let offset = number("offset")?.unwrap_or(0);
    let limit = match number("limit")? {
        Some(0) | None => page_size,
        Some(limit) => limit.min(page_size),
    };
    Ok(items.into_iter().skip(offset).take(limit).collect())
}

fn zone_json(zone: &Zone) -> Value {
    json!({
        "name": zone.name,
        "enabled": zone.enabled,
        "contact": "hostmaster@example.org",
        "serial": 1,
        "nx_ttl": 300,
        "meta": {}
    })
}

fn rrset_json(rrset: &Rrset, flavor: &Flavor) -> Value {
    let records: Vec<Value> = rrset
        .records
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "content": r.content,
                "enabled": r.enabled,
                "meta": r.meta.clone().unwrap_or_default(),
            })
        })
        .collect();
    let mut out = json!({
        "id": rrset.id,
        "name": rrset.name,
        "type": rrset.rtype,
        "ttl": rrset.ttl,
        "resource_records": records,
        "meta": rrset.meta,
        "updated_at": 1_767_225_600,
    });
    out[flavor.selection] = Value::Array(rrset.selection.clone());
    if let Some(id) = rrset.filter_set_id {
        out["filter_set_id"] = json!(id);
    }
    out
}

async fn zones_list(
    State(app): State<App>,
    headers: HeaderMap,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    if let Err(response) = authorize(&app, &headers) {
        return response;
    }
    let inner = lock(&app.state);
    let all: Vec<Value> = inner.zones.iter().map(zone_json).collect();
    let (page_size, paging) = (inner.seed.page_size, inner.paging);
    drop(inner);
    listing("zones", all, &pairs, page_size, paging)
}

async fn zone_get(
    State(app): State<App>,
    headers: HeaderMap,
    Path(zone): Path<String>,
) -> Response {
    if let Err(response) = authorize(&app, &headers) {
        return response;
    }
    let found = lock(&app.state).zone(&zone).cloned();
    match found {
        None => not_found("zone not found"),
        Some(zone) if app.flavor.zone_wrapped => {
            axum::Json(json!({ "zone": zone_json(&zone) })).into_response()
        }
        Some(zone) => axum::Json(zone_json(&zone)).into_response(),
    }
}

async fn rrsets_list(
    State(app): State<App>,
    headers: HeaderMap,
    Path(zone): Path<String>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    if let Err(response) = authorize(&app, &headers) {
        return response;
    }
    let inner = lock(&app.state);
    if inner.zone(&zone).is_none() {
        return not_found("zone not found");
    }
    let mut all: Vec<&Rrset> = inner.rrsets.iter().filter(|r| r.zone == zone).collect();
    all.sort_by(|a, b| a.name.cmp(&b.name).then(a.rtype.cmp(&b.rtype)));
    let all: Vec<Value> = all.iter().map(|r| rrset_json(r, app.flavor)).collect();
    let (page_size, paging) = (inner.seed.page_size, inner.paging);
    drop(inner);
    listing("rrsets", all, &pairs, page_size, paging)
}

/// The zone and owner name of a path, checked: the zone exists, the name is lowercase, has no
/// trailing dot and is inside the zone.
fn address(inner: &Inner, zone: &str, name: &str) -> Result<(), Response> {
    if inner.zone(zone).is_none() {
        return Err(not_found("zone not found"));
    }
    if name.ends_with('.') || name.to_lowercase() != name {
        return Err(bad_request(
            "the rrset name must be the full name without the trailing dot",
        ));
    }
    if name != zone && !name.ends_with(&format!(".{zone}")) {
        return Err(bad_request("the rrset name is outside the zone"));
    }
    Ok(())
}

async fn rrset_get(
    State(app): State<App>,
    headers: HeaderMap,
    Path((zone, name, rtype)): Path<(String, String, String)>,
) -> Response {
    if let Err(response) = authorize(&app, &headers) {
        return response;
    }
    let inner = lock(&app.state);
    if let Err(response) = address(&inner, &zone, &name) {
        return response;
    }
    match inner
        .rrsets
        .iter()
        .find(|r| r.zone == zone && r.name == name && r.rtype == rtype)
    {
        Some(rrset) => axum::Json(rrset_json(rrset, app.flavor)).into_response(),
        None => not_found("rrset not found"),
    }
}

/// The rrset is the provider's: SOA, and NS at the apex.
fn protected(zone: &str, name: &str, rtype: &str) -> bool {
    rtype == "SOA" || (rtype == "NS" && name == zone)
}

/// One record of a write body: its content, `enabled` and `meta`.
type BodyRecord = (Vec<Value>, bool, Option<Map<String, Value>>);

/// A write body, checked: `ttl`, the records and the rrset's `meta` and selection.
struct Body {
    ttl: u32,
    records: Vec<BodyRecord>,
    meta: Map<String, Value>,
    selection: Vec<Value>,
}

/// Parses and checks a create or replacement body. `held` are the contents the rrset holds now
/// (none for a create): a record with one of them is the provider's own data written back and is
/// not checked against the content rules.
fn body(
    app: &App,
    min_ttl: u32,
    rtype: &str,
    bytes: &[u8],
    held: &[Vec<Value>],
) -> Result<Body, Response> {
    let Ok(Value::Object(request)) = serde_json::from_slice::<Value>(bytes) else {
        return Err(bad_request("malformed request body"));
    };
    let allowed = ["ttl", "resource_records", "meta", app.flavor.selection];
    if request.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(bad_request("unexpected field in the rrset"));
    }
    let ttl = match request.get("ttl") {
        None => 300,
        Some(value) => value
            .as_u64()
            .and_then(|ttl| u32::try_from(ttl).ok())
            .ok_or_else(|| bad_request("ttl must be an unsigned 32-bit integer"))?,
    };
    if ttl < min_ttl {
        return Err(bad_request("ttl is below the minimum of the plan"));
    }
    let Some(Value::Array(items)) = request.get("resource_records") else {
        return Err(bad_request("resource_records is required"));
    };
    if items.is_empty() {
        return Err(bad_request("resource_records must not be empty"));
    }
    let mut records = Vec::new();
    for item in items {
        let Value::Object(item) = item else {
            return Err(bad_request("a resource record must be an object"));
        };
        if item
            .keys()
            .any(|k| !matches!(k.as_str(), "content" | "enabled" | "meta"))
        {
            return Err(bad_request("unexpected field in a resource record"));
        }
        let Some(Value::Array(content)) = item.get("content") else {
            return Err(bad_request("content is required and must be an array"));
        };
        if !held.contains(content) && !content_valid(rtype, content) {
            return Err(bad_request("content does not match the record type"));
        }
        let enabled = match item.get("enabled") {
            None => true,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => return Err(bad_request("enabled must be a boolean")),
        };
        let meta = match item.get("meta") {
            None | Some(Value::Null) => None,
            Some(Value::Object(meta)) => Some(meta.clone()),
            Some(_) => return Err(bad_request("meta must be an object")),
        };
        records.push((content.clone(), enabled, meta));
    }
    let meta = match request.get("meta") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(meta)) => meta.clone(),
        Some(_) => return Err(bad_request("meta must be an object")),
    };
    let selection = match request.get(app.flavor.selection) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(list)) => list.clone(),
        Some(_) => return Err(bad_request("the selection must be an array")),
    };
    Ok(Body {
        ttl,
        records,
        meta,
        selection,
    })
}

async fn rrset_create(
    State(app): State<App>,
    headers: HeaderMap,
    Path((zone, name, rtype)): Path<(String, String, String)>,
    bytes: Bytes,
) -> Response {
    if let Err(response) = authorize(&app, &headers) {
        return response;
    }
    let mut inner = lock(&app.state);
    if let Err(response) = address(&inner, &zone, &name) {
        return response;
    }
    if !app.flavor.types.contains(&rtype.as_str()) {
        return bad_request("unsupported record type");
    }
    if protected(&zone, &name, &rtype) {
        return bad_request("this record set cannot be created");
    }
    let body = match body(&app, inner.min_ttl, &rtype, &bytes, &[]) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if inner.rrset_mut(&zone, &name, &rtype).is_some() {
        return error(app.flavor.create_exists, "rrset already exists");
    }
    let before = inner.published();
    let records = body
        .records
        .into_iter()
        .map(|(content, enabled, meta)| Record {
            id: inner.new_id(),
            content,
            enabled,
            meta,
        })
        .collect();
    let rrset = Rrset {
        id: inner.new_id(),
        zone,
        name,
        rtype,
        ttl: body.ttl,
        records,
        meta: body.meta,
        selection: body.selection,
        filter_set_id: None,
    };
    let answer = rrset_json(&rrset, app.flavor);
    inner.rrsets.push(rrset);
    inner.report(&before, Origin::Api);
    axum::Json(answer).into_response()
}

async fn rrset_replace(
    State(app): State<App>,
    headers: HeaderMap,
    Path((zone, name, rtype)): Path<(String, String, String)>,
    bytes: Bytes,
) -> Response {
    if let Err(response) = authorize(&app, &headers) {
        return response;
    }
    let mut inner = lock(&app.state);
    if let Err(response) = address(&inner, &zone, &name) {
        return response;
    }
    if protected(&zone, &name, &rtype) {
        return bad_request("this record set cannot be edited");
    }
    let min_ttl = inner.min_ttl;
    let Some(held) = inner.rrset_mut(&zone, &name, &rtype).map(|r| {
        r.records
            .iter()
            .map(|rec| rec.content.clone())
            .collect::<Vec<_>>()
    }) else {
        return not_found("rrset not found");
    };
    let body = match body(&app, min_ttl, &rtype, &bytes, &held) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let before = inner.published();
    let records: Vec<Record> = body
        .records
        .into_iter()
        .map(|(content, enabled, meta)| Record {
            id: inner.new_id(),
            content,
            enabled,
            meta,
        })
        .collect();
    let answer = {
        let Some(rrset) = inner.rrset_mut(&zone, &name, &rtype) else {
            return not_found("rrset not found");
        };
        rrset.ttl = body.ttl;
        rrset.records = records;
        rrset.meta = body.meta;
        rrset.selection = body.selection;
        rrset_json(rrset, app.flavor)
    };
    inner.report(&before, Origin::Api);
    axum::Json(answer).into_response()
}

async fn rrset_delete(
    State(app): State<App>,
    headers: HeaderMap,
    Path((zone, name, rtype)): Path<(String, String, String)>,
) -> Response {
    if let Err(response) = authorize(&app, &headers) {
        return response;
    }
    let mut inner = lock(&app.state);
    if let Err(response) = address(&inner, &zone, &name) {
        return response;
    }
    if protected(&zone, &name, &rtype) {
        return bad_request("this record set cannot be deleted");
    }
    let before = inner.published();
    let count = inner.rrsets.len();
    inner
        .rrsets
        .retain(|r| !(r.zone == zone && r.name == name && r.rtype == rtype));
    if inner.rrsets.len() == count {
        return not_found("rrset not found");
    }
    inner.report(&before, Origin::Api);
    if app.flavor.delete_status == StatusCode::NO_CONTENT {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (app.flavor.delete_status, axum::Json(json!({}))).into_response()
    }
}

/// A name inside content: non-empty labels, an optional trailing dot, no whitespace.
fn is_name(value: &Value) -> bool {
    let Some(text) = value.as_str() else {
        return false;
    };
    let text = text.strip_suffix('.').unwrap_or(text);
    !text.is_empty()
        && !text.chars().any(char::is_whitespace)
        && text.split('.').all(|label| !label.is_empty())
}

fn is_number(value: &Value, max: u64) -> bool {
    value.as_u64().is_some_and(|n| n <= max)
}

/// The content has the form of `rtype` (module documentation).
fn content_valid(rtype: &str, content: &[Value]) -> bool {
    match (rtype, content) {
        ("A", [address]) => address
            .as_str()
            .is_some_and(|a| a.parse::<std::net::Ipv4Addr>().is_ok()),
        ("AAAA", [address]) => address
            .as_str()
            .is_some_and(|a| a.parse::<std::net::Ipv6Addr>().is_ok()),
        ("CNAME" | "NS" | "DNAME" | "PTR", [target]) => is_name(target),
        ("MX", [priority, host]) => is_number(priority, 65_535) && is_name(host),
        ("SRV", [priority, weight, port, target]) => {
            is_number(priority, 65_535)
                && is_number(weight, 65_535)
                && is_number(port, 65_535)
                && is_name(target)
        }
        ("CAA", [flags, Value::String(tag), Value::String(_)]) => {
            is_number(flags, 255) && !tag.is_empty()
        }
        ("TXT", [Value::String(_)]) => true,
        ("A" | "AAAA" | "CNAME" | "NS" | "DNAME" | "PTR" | "MX" | "SRV" | "CAA" | "TXT", _) => {
            false
        }
        _ => !content.is_empty(),
    }
}

/// A TXT or CAA string as a quoted character-string of zone-file text.
fn quoted(text: &str) -> String {
    let mut out = String::from("\"");
    for byte in text.bytes() {
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

/// A name of content, fully qualified with the trailing dot.
fn fqdn(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    Some(if text.ends_with('.') {
        text.to_owned()
    } else {
        format!("{text}.")
    })
}

/// A record's content as zone-file text (RFC 1035 section 5.1), names fully qualified; `None`
/// for content the mock cannot render.
fn zone_file_text(rtype: &str, content: &[Value]) -> Option<String> {
    let number = |value: &Value| value.as_u64().map(|n| n.to_string());
    match (rtype, content) {
        ("TXT", [Value::String(text)]) => {
            let chunks: Vec<String> = text
                .as_bytes()
                .chunks(255)
                .map(|chunk| quoted(&String::from_utf8_lossy(chunk)))
                .collect();
            Some(if chunks.is_empty() {
                "\"\"".to_owned()
            } else {
                chunks.join(" ")
            })
        }
        ("CAA", [flags, Value::String(tag), Value::String(value)]) => {
            Some(format!("{} {tag} {}", number(flags)?, quoted(value)))
        }
        ("CNAME" | "NS" | "DNAME" | "PTR", [target]) => fqdn(target),
        ("MX", [priority, host]) => Some(format!("{} {}", number(priority)?, fqdn(host)?)),
        ("SRV", [priority, weight, port, target]) => Some(format!(
            "{} {} {} {}",
            number(priority)?,
            number(weight)?,
            number(port)?,
            fqdn(target)?
        )),
        ("A" | "AAAA", [Value::String(address)]) => Some(address.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{content_valid, zone_file_text};

    fn items(value: Value) -> Vec<Value> {
        match value {
            Value::Array(items) => items,
            other => panic!("not an array: {other}"),
        }
    }

    #[test]
    fn content_is_checked_per_type() {
        for (rtype, content) in [
            ("A", json!(["192.0.2.1"])),
            ("AAAA", json!(["2001:db8::1"])),
            ("CNAME", json!(["target.example.org"])),
            ("CNAME", json!(["target.example.org."])),
            ("MX", json!([10, "mail.example.org"])),
            ("SRV", json!([10, 20, 5060, "sip.example.org"])),
            ("CAA", json!([0, "issue", "ca.example.net"])),
            ("TXT", json!(["anything at all"])),
            ("HTTPS", json!([1, ".", ["alpn", "h2"]])),
        ] {
            assert!(
                content_valid(rtype, &items(content.clone())),
                "{rtype} {content}"
            );
        }
        for (rtype, content) in [
            ("A", json!(["192.0.2"])),
            ("A", json!(["192.0.2.1", "192.0.2.2"])),
            ("MX", json!(["mail.example.org"])),
            ("MX", json!(["10", "mail.example.org"])),
            ("SRV", json!([10, 20, "sip.example.org"])),
            ("CAA", json!([256, "issue", "ca"])),
            ("TXT", json!(["a", "b"])),
            ("CNAME", json!(["a..b"])),
            ("HTTPS", json!([])),
        ] {
            assert!(
                !content_valid(rtype, &items(content.clone())),
                "{rtype} {content}"
            );
        }
    }

    #[test]
    fn zone_file_text_is_fully_qualified() {
        for (rtype, content, text) in [
            (
                "MX",
                json!([10, "mail.example.org"]),
                "10 mail.example.org.",
            ),
            ("TXT", json!(["say \"hi\""]), "\"say \\\"hi\\\"\""),
            (
                "CAA",
                json!([0, "issue", "ca.example.net"]),
                "0 issue \"ca.example.net\"",
            ),
            ("A", json!(["192.0.2.1"]), "192.0.2.1"),
        ] {
            assert_eq!(
                zone_file_text(rtype, &items(content)).as_deref(),
                Some(text),
                "{rtype}"
            );
        }
        assert_eq!(zone_file_text("MX", &items(json!(["x"]))), None);
    }
}
