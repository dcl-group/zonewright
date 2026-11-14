//! Mock of the Cloudflare API v4 (DNS records and zones).
//!
//! Shapes follow the provider's documentation, the same sources the client cites: the API
//! reference <https://developers.cloudflare.com/api/> and the OpenAPI document
//! <https://github.com/cloudflare/api-schemas>:
//!
//! - every answer is the envelope `{success, errors[{code, message}], messages, result}`, and
//!   listings add `result_info {page, per_page, count, total_count, total_pages}`;
//! - `GET /zones` takes `name` (equal), `status`, `per_page` (5 to 50, default 20) and `page`;
//!   a zone has `id` (at most 32 characters), `name` and `status`
//!   (`initializing`, `pending`, `active`, `moved`);
//! - `GET /zones/{zone}/dns_records` takes `type`, `name` (the exact name, an alias of
//!   `name.exact`, case-insensitive), `per_page` (1 to 5000000, default 100) and `page`;
//! - `POST /zones/{zone}/dns_records` takes `type`, `name`, `content`, `ttl` (`1` is automatic,
//!   otherwise 60 to 86400) and answers `200` with the record; TXT `content` must consist of
//!   quoted character strings of at most 255 bytes each; names are in Punycode;
//! - `DELETE /zones/{zone}/dns_records/{record}` answers `200` with `result: {id}`;
//! - the identifiers are 32 characters at most.
//!
//! Answers this mock invents because the documentation is silent (the schema names only the
//! failure class `4XX` for every call). A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - a missing or wrong token answers `401`, code `10000`;
//! - an unknown zone answers `404`, code `7003` (the code and text are the schema's example of
//!   a failure; the status is invented), on every zone path;
//! - a delete of an unknown record answers `404`, code `81044`;
//! - a create of a record that exists (same zone, name, type and content) answers `400`, code
//!   `81058` (the client does not read the code: it reads again after any refused create);
//! - a create that breaks the documented rules (name outside the zone, bad TTL, unquoted or
//!   over-long TXT content, a missing field) answers `400`, code `9000`;
//! - a `per_page` outside the documented range answers `400`, code `9000`;
//! - the page count of an empty listing is `0`;
//! - a zone that is not `active` is listed with its status and its record paths answer as
//!   usual.
//!
//! Error texts are invented.
//!
//! A test holds a [`CloudflareMock`]. It dereferences to the [`MockServer`], so the request log
//! and the fault queue of the shared harness work as usual:
//!
//! ```text
//! let mock = CloudflareMock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("POST", "/client/v4/zones/*/dns_records").status(500));
//! // ... drive the client against mock.base_url() ...
//! assert_eq!(mock.control().txt_values("_acme-challenge.example.org"), ["v1"]);
//! ```

// Handlers return finished HTTP answers as their error values and hand them straight to axum;
// boxing them would only add noise.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Value, json};

use crate::MockServer;

/// Path of the API below the server's base URL.
pub const API_PATH: &str = "/client/v4";

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The API token the mock accepts.
    pub token: String,
    /// Names of the zones, all `active`.
    pub zones: Vec<String>,
}

impl Seed {
    /// The token `cf-test-token` and the zone `example.org`.
    pub fn standard() -> Self {
        Self {
            token: "cf-test-token".into(),
            zones: vec!["example.org".into()],
        }
    }
}

/// A zone as the mock holds it.
#[derive(Clone, Debug)]
pub struct Zone {
    /// The zone's identifier.
    pub id: String,
    /// The zone name, lowercase, without the trailing dot.
    pub name: String,
    /// `active`, `pending`, `initializing` or `moved`.
    pub status: String,
}

/// A DNS record as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The record's identifier.
    pub id: String,
    /// The zone's identifier.
    pub zone_id: String,
    /// The owner name, lowercase, without the trailing dot.
    pub name: String,
    /// The record type.
    pub rtype: String,
    /// The content as stored; TXT content is quoted.
    pub content: String,
    /// TTL in seconds; `1` is automatic.
    pub ttl: u32,
}

#[derive(Debug)]
struct Inner {
    token: String,
    zones: Vec<Zone>,
    records: Vec<Record>,
    next_id: u64,
    /// When set, no page holds more items than this, whatever `per_page` says.
    page_cap: Option<usize>,
}

impl Inner {
    /// A new identifier in the 32-character form the provider uses.
    fn new_id(&mut self) -> String {
        self.next_id += 1;
        format!("{:032x}", self.next_id)
    }

    fn zone(&self, id: &str) -> Option<&Zone> {
        self.zones.iter().find(|z| z.id == id)
    }
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running Cloudflare mock. Dereferences to its [`MockServer`] for the request log and the
/// fault queue; [`CloudflareMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct CloudflareMock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of a [`CloudflareMock`]. Cheap to clone, so that a fault hook
/// ([`Fault::run`](crate::Fault::run)) can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
}

impl Deref for CloudflareMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl CloudflareMock {
    /// Starts the mock with `seed`.
    pub async fn start(seed: Seed) -> Self {
        let mut inner = Inner {
            token: seed.token.clone(),
            zones: Vec::new(),
            records: Vec::new(),
            next_id: 0,
            page_cap: None,
        };
        for name in &seed.zones {
            let id = inner.new_id();
            inner.zones.push(Zone {
                id,
                name: normalize(name),
                status: "active".into(),
            });
        }
        let state = Arc::new(Mutex::new(inner));
        let router = Router::new()
            .route("/client/v4/zones", get(zones_list))
            .route(
                "/client/v4/zones/{zone}/dns_records",
                get(records_list).post(record_create),
            )
            .route(
                "/client/v4/zones/{zone}/dns_records/{record}",
                axum::routing::delete(record_delete),
            )
            .with_state(state.clone());
        Self {
            server: MockServer::start(router).await,
            control: Control { state },
        }
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

impl Control {
    /// Every zone.
    pub fn zones(&self) -> Vec<Zone> {
        lock(&self.state).zones.clone()
    }

    /// The identifier of zone `name`.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn zone_id(&self, name: &str) -> String {
        let name = normalize(name);
        lock(&self.state)
            .zones
            .iter()
            .find(|z| z.name == name)
            .map(|z| z.id.clone())
            .unwrap_or_else(|| panic!("no zone {name}"))
    }

    /// Adds an `active` zone and returns its identifier.
    pub fn insert_zone(&self, name: &str) -> String {
        let mut inner = lock(&self.state);
        let id = inner.new_id();
        inner.zones.push(Zone {
            id: id.clone(),
            name: normalize(name),
            status: "active".into(),
        });
        id
    }

    /// Sets the status of zone `name`.
    pub fn set_zone_status(&self, name: &str, status: &str) {
        let name = normalize(name);
        for zone in lock(&self.state)
            .zones
            .iter_mut()
            .filter(|z| z.name == name)
        {
            zone.status = status.to_owned();
        }
    }

    /// Deletes zone `name` and creates it again under a new identifier, with the same records
    /// (under new record identifiers). Returns the new zone identifier.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn recreate_zone(&self, name: &str) -> String {
        let name = normalize(name);
        let mut inner = lock(&self.state);
        let new_id = inner.new_id();
        let old_id = inner
            .zones
            .iter()
            .find(|z| z.name == name)
            .map(|z| z.id.clone())
            .unwrap_or_else(|| panic!("no zone {name}"));
        for zone in inner.zones.iter_mut().filter(|z| z.id == old_id) {
            zone.id = new_id.clone();
        }
        for i in 0..inner.records.len() {
            if inner.records[i].zone_id == old_id {
                let record_id = inner.new_id();
                let record = &mut inner.records[i];
                record.zone_id = new_id.clone();
                record.id = record_id;
            }
        }
        new_id
    }

    /// Limits every page to `n` items, whatever `per_page` says (forces paging).
    pub fn set_page_cap(&self, n: usize) {
        lock(&self.state).page_cap = Some(n);
    }

    /// Every record.
    pub fn records(&self) -> Vec<Record> {
        lock(&self.state).records.clone()
    }

    /// The records of `name` and `rtype`.
    pub fn records_of(&self, name: &str, rtype: &str) -> Vec<Record> {
        let name = normalize(name);
        lock(&self.state)
            .records
            .iter()
            .filter(|r| r.name == name && r.rtype == rtype)
            .cloned()
            .collect()
    }

    /// The TXT values at `name` without their outer quotes, in creation order.
    pub fn txt_values(&self, name: &str) -> Vec<String> {
        self.records_of(name, "TXT")
            .iter()
            .map(|r| r.content.trim_matches('"').to_owned())
            .collect()
    }

    /// Creates a record in zone `zone` directly, as another writer would. `content` is the
    /// API's text. Returns the record's identifier.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn insert_record(
        &self,
        zone: &str,
        name: &str,
        rtype: &str,
        content: &str,
        ttl: u32,
    ) -> String {
        let zone_id = self.zone_id(zone);
        let mut inner = lock(&self.state);
        let id = inner.new_id();
        inner.records.push(Record {
            id: id.clone(),
            zone_id,
            name: normalize(name),
            rtype: rtype.to_owned(),
            content: content.to_owned(),
            ttl,
        });
        id
    }

    /// Deletes the records of `name` and `rtype`, as another writer would.
    pub fn delete_records(&self, name: &str, rtype: &str) {
        let name = normalize(name);
        lock(&self.state)
            .records
            .retain(|r| !(r.name == name && r.rtype == rtype));
    }
}

fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_lowercase()
}

/// An error answer in the documented envelope.
fn failure(status: StatusCode, code: i64, message: &str) -> Response {
    (
        status,
        axum::Json(json!({
            "success": false,
            "errors": [{"code": code, "message": message}],
            "messages": [],
            "result": null,
        })),
    )
        .into_response()
}

fn bad_request(message: &str) -> Response {
    failure(StatusCode::BAD_REQUEST, 9000, message)
}

fn unknown_zone() -> Response {
    failure(StatusCode::NOT_FOUND, 7003, "No route for the URI")
}

/// A success answer; `info` is the `result_info` of a listing.
fn success(result: Value, info: Option<Value>) -> Response {
    let mut body = json!({"success": true, "errors": [], "messages": [], "result": result});
    if let Some(info) = info {
        body["result_info"] = info;
    }
    axum::Json(body).into_response()
}

/// Checks the token.
fn authenticate(inner: &Inner, headers: &HeaderMap) -> Result<(), Response> {
    let want = format!("Bearer {}", inner.token);
    match headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
    {
        Some(got) if got == want => Ok(()),
        _ => Err(failure(
            StatusCode::UNAUTHORIZED,
            10000,
            "Authentication error",
        )),
    }
}

/// Paging parameters: `per_page` within `min..=max` (default `default`), `page` from 1.
fn paging(
    query: &HashMap<String, String>,
    cap: Option<usize>,
    (min, max, default): (usize, usize, usize),
) -> Result<(usize, usize), Response> {
    let per_page = match query.get("per_page") {
        None => default,
        Some(text) => text
            .parse::<usize>()
            .ok()
            .filter(|n| (min..=max).contains(n))
            .ok_or_else(|| bad_request("per_page is out of range"))?,
    };
    let page = match query.get("page") {
        None => 1,
        Some(text) => text
            .parse::<usize>()
            .ok()
            .filter(|&n| n >= 1)
            .ok_or_else(|| bad_request("page is out of range"))?,
    };
    Ok((cap.map_or(per_page, |cap| per_page.min(cap)), page))
}

/// One page of `items` and its `result_info`.
fn page_of(items: &[Value], per_page: usize, page: usize) -> (Vec<Value>, Value) {
    let total_pages = items.len().div_ceil(per_page);
    let slice: Vec<Value> = items
        .iter()
        .skip((page - 1).saturating_mul(per_page))
        .take(per_page)
        .cloned()
        .collect();
    let info = json!({
        "page": page,
        "per_page": per_page,
        "count": slice.len(),
        "total_count": items.len(),
        "total_pages": total_pages,
    });
    (slice, info)
}

async fn zones_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let inner = lock(&state);
    if let Err(response) = authenticate(&inner, &headers) {
        return response;
    }
    let (per_page, page) = match paging(&query, inner.page_cap, (5, 50, 20)) {
        Ok(paging) => paging,
        Err(response) => return response,
    };
    let all: Vec<Value> = inner
        .zones
        .iter()
        .filter(|z| {
            query
                .get("name")
                .is_none_or(|name| z.name == normalize(name))
        })
        .filter(|z| query.get("status").is_none_or(|status| z.status == *status))
        .map(|z| json!({"id": z.id, "name": z.name, "status": z.status}))
        .collect();
    let (items, info) = page_of(&all, per_page, page);
    success(json!(items), Some(info))
}

async fn records_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(zone): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let inner = lock(&state);
    if let Err(response) = authenticate(&inner, &headers) {
        return response;
    }
    if inner.zone(&zone).is_none() {
        return unknown_zone();
    }
    let (per_page, page) = match paging(&query, inner.page_cap, (1, 5_000_000, 100)) {
        Ok(paging) => paging,
        Err(response) => return response,
    };
    let name_filter = query
        .get("name")
        .or_else(|| query.get("name.exact"))
        .map(|name| normalize(name));
    let all: Vec<Value> = inner
        .records
        .iter()
        .filter(|r| r.zone_id == zone)
        .filter(|r| query.get("type").is_none_or(|t| *t == r.rtype))
        .filter(|r| name_filter.as_ref().is_none_or(|name| *name == r.name))
        .map(|r| {
            json!({
                "id": r.id,
                "zone_id": zone,
                "type": r.rtype,
                "name": r.name,
                "content": r.content,
                "ttl": r.ttl,
            })
        })
        .collect();
    let (items, info) = page_of(&all, per_page, page);
    success(json!(items), Some(info))
}

/// TXT content must consist of quoted character strings of at most 255 bytes each.
fn valid_txt_content(content: &str) -> bool {
    let mut rest = content.trim();
    if rest.is_empty() {
        return false;
    }
    while !rest.is_empty() {
        let Some(after) = rest.strip_prefix('"') else {
            return false;
        };
        let mut bytes = 0;
        let mut escaped = false;
        let mut end = None;
        for (i, c) in after.char_indices() {
            if escaped {
                escaped = false;
                bytes += c.len_utf8();
            } else if c == '\\' {
                escaped = true;
                bytes += 1;
            } else if c == '"' {
                end = Some(i);
                break;
            } else {
                bytes += c.len_utf8();
            }
        }
        let Some(end) = end else {
            return false;
        };
        if bytes > 255 {
            return false;
        }
        rest = after[end + 1..].trim_start();
    }
    true
}

async fn record_create(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(zone): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let mut inner = lock(&state);
    if let Err(response) = authenticate(&inner, &headers) {
        return response;
    }
    let Some(zone_name) = inner.zone(&zone).map(|z| z.name.clone()) else {
        return unknown_zone();
    };
    let Ok(body) = serde_json::from_slice::<Value>(&body) else {
        return bad_request("the body is not JSON");
    };
    let (Some(rtype), Some(name), Some(content), Some(ttl)) = (
        body["type"].as_str(),
        body["name"].as_str(),
        body["content"].as_str(),
        body["ttl"].as_u64(),
    ) else {
        return bad_request("type, name, content and ttl are required");
    };
    let name = normalize(name);
    if name != zone_name && !name.ends_with(&format!(".{zone_name}")) {
        return bad_request("the name is outside the zone");
    }
    if !name.is_ascii() {
        return bad_request("names are in Punycode");
    }
    let Ok(ttl) = u32::try_from(ttl) else {
        return bad_request("invalid ttl");
    };
    if ttl != 1 && !(60..=86_400).contains(&ttl) {
        return bad_request("invalid ttl");
    }
    if rtype == "TXT" && !valid_txt_content(content) {
        return bad_request("TXT content must be quoted character strings of up to 255 bytes");
    }
    if inner
        .records
        .iter()
        .any(|r| r.zone_id == zone && r.name == name && r.rtype == rtype && r.content == content)
    {
        return failure(
            StatusCode::BAD_REQUEST,
            81058,
            "An identical record already exists.",
        );
    }
    let id = inner.new_id();
    let record = Record {
        id,
        zone_id: zone.clone(),
        name,
        rtype: rtype.to_owned(),
        content: content.to_owned(),
        ttl,
    };
    let answer = json!({
        "id": record.id,
        "zone_id": zone,
        "type": record.rtype,
        "name": record.name,
        "content": record.content,
        "ttl": record.ttl,
    });
    inner.records.push(record);
    success(answer, None)
}

async fn record_delete(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((zone, record)): Path<(String, String)>,
) -> Response {
    let mut inner = lock(&state);
    if let Err(response) = authenticate(&inner, &headers) {
        return response;
    }
    if inner.zone(&zone).is_none() {
        return unknown_zone();
    }
    let before = inner.records.len();
    inner
        .records
        .retain(|r| !(r.zone_id == zone && r.id == record));
    if inner.records.len() == before {
        return failure(StatusCode::NOT_FOUND, 81044, "Record does not exist.");
    }
    success(json!({"id": record}), None)
}
