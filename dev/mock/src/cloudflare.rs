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
//! - `PATCH /zones/{zone}/dns_records/{record}` changes the fields it names and answers `200`
//!   with the record;
//! - A and AAAA take an address in `content`, CNAME, NS and PTR a host name, MX a host name and
//!   `priority` (0 to 65535, required); CAA, SRV and TLSA take `data` (`flags`/`tag`/`value`,
//!   `priority`/`weight`/`port`/`target`, `usage`/`selector`/`matching_type`/`certificate`) and
//!   their `content` is read-only;
//! - "A/AAAA records cannot exist on the same name as CNAME records. NS records cannot exist on
//!   the same name as any other record type";
//! - a record carries `proxied` (default false), `settings`, `comment` and `tags`, and A and AAAA
//!   `private_routing`; a proxied record's TTL is automatic and cannot be edited;
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
//!   usual;
//! - a host name in `content` or `data.target` must be lowercase letters, digits, `-`, `_` and
//!   `*` in dot-separated labels, without a trailing dot (stricter than "a valid hostname"); a
//!   TLSA `certificate` must be non-empty hex; a request that sends `content` for CAA, SRV or
//!   TLSA, a record type other than A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, TLSA and TXT, a
//!   `proxied: true` on a type other than A, AAAA and CNAME, a TTL other than `1` on a proxied
//!   record, a second CNAME at a name, or a `PATCH` that names another type answers `400`, code
//!   `9000`;
//! - the formatted `content` of a CAA record is `<flags> <tag> "<value>"`, of a TLSA record
//!   `<usage> <selector> <matching type> <certificate>` (the SRV form, `<weight> <port>
//!   <target>`, is the one of the provider's record type reference);
//! - a listed record carries `data` only for the types that take it;
//! - a `PATCH` of an unknown record answers `404`, code `81044`.
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
    /// The MX preference.
    pub priority: Option<u16>,
    /// The components of a CAA, SRV or TLSA record.
    pub data: Option<Value>,
    /// Proxied.
    pub proxied: bool,
    /// Private routing (A and AAAA).
    pub private_routing: bool,
    /// The settings object.
    pub settings: Value,
    /// The comment.
    pub comment: Option<String>,
    /// The tags.
    pub tags: Vec<String>,
}

impl Record {
    /// A record with every optional field at its default; the caller sets the rest.
    fn bare() -> Record {
        Record {
            id: String::new(),
            zone_id: String::new(),
            name: String::new(),
            rtype: String::new(),
            content: String::new(),
            ttl: 1,
            priority: None,
            data: None,
            proxied: false,
            private_routing: false,
            settings: json!({}),
            comment: None,
            tags: Vec::new(),
        }
    }

    /// The record as the API lists it.
    fn to_json(&self) -> Value {
        let mut out = json!({
            "id": self.id,
            "zone_id": self.zone_id,
            "type": self.rtype,
            "name": self.name,
            "content": self.content,
            "ttl": self.ttl,
            "proxied": self.proxied,
            "proxiable": matches!(self.rtype.as_str(), "A" | "AAAA" | "CNAME"),
            "settings": self.settings,
            "comment": self.comment,
            "tags": self.tags,
        });
        if let Some(priority) = self.priority {
            out["priority"] = json!(priority);
        }
        if let Some(data) = &self.data {
            out["data"] = data.clone();
        }
        if matches!(self.rtype.as_str(), "A" | "AAAA") {
            out["private_routing"] = json!(self.private_routing);
        }
        out
    }
}

#[derive(Debug)]
struct Inner {
    token: String,
    zones: Vec<Zone>,
    records: Vec<Record>,
    next_id: u64,
    /// When set, no page holds more items than this, whatever `per_page` says.
    page_cap: Option<usize>,
    /// When set, the record listing ignores its `name` and `type` filters.
    ignore_filters: bool,
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
            ignore_filters: false,
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
                axum::routing::delete(record_delete).patch(record_update),
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

    /// Makes the record listing ignore its `name` and `type` filters and return every record of
    /// the zone (a test switch for a filter looser than documented, not an invented answer).
    pub fn set_ignore_filters(&self, ignore: bool) {
        lock(&self.state).ignore_filters = ignore;
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
            ..Record::bare()
        });
        id
    }

    /// Creates a record in zone `zone` directly from a JSON object in the API's form (`type`,
    /// `name`, and any of `content`, `priority`, `data`, `ttl`, `proxied`, `private_routing`,
    /// `settings`, `comment`, `tags`), as another writer would. Nothing is validated; a missing
    /// `content` is computed for CAA, SRV and TLSA. Returns the record's identifier.
    ///
    /// # Panics
    ///
    /// If there is no such zone, or `type` or `name` is missing.
    pub fn insert_json(&self, zone: &str, record: &Value) -> String {
        let zone_id = self.zone_id(zone);
        let mut inner = lock(&self.state);
        let id = inner.new_id();
        let rtype = record["type"].as_str().expect("type").to_owned();
        let data = record.get("data").cloned();
        let content = record["content"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| data.as_ref().and_then(|d| formatted(&rtype, d)))
            .unwrap_or_default();
        inner.records.push(Record {
            id: id.clone(),
            zone_id,
            name: normalize(record["name"].as_str().expect("name")),
            rtype,
            content,
            ttl: record["ttl"]
                .as_u64()
                .and_then(|t| u32::try_from(t).ok())
                .unwrap_or(1),
            priority: record["priority"]
                .as_u64()
                .and_then(|p| u16::try_from(p).ok()),
            data,
            proxied: record["proxied"].as_bool().unwrap_or(false),
            private_routing: record["private_routing"].as_bool().unwrap_or(false),
            settings: record.get("settings").cloned().unwrap_or_else(|| json!({})),
            comment: record["comment"].as_str().map(str::to_owned),
            tags: record["tags"]
                .as_array()
                .map(|tags| {
                    tags.iter()
                        .filter_map(|t| t.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
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
        .map(|name| normalize(name))
        .filter(|_| !inner.ignore_filters);
    let type_filter = query.get("type").filter(|_| !inner.ignore_filters);
    let all: Vec<Value> = inner
        .records
        .iter()
        .filter(|r| r.zone_id == zone)
        .filter(|r| type_filter.is_none_or(|t| *t == r.rtype))
        .filter(|r| name_filter.as_ref().is_none_or(|name| *name == r.name))
        .map(Record::to_json)
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

/// The record types this mock accepts in a write.
const WRITABLE: &[&str] = &[
    "A", "AAAA", "CAA", "CNAME", "MX", "NS", "PTR", "SRV", "TLSA", "TXT",
];

/// A host name as this mock accepts it (see the module documentation).
fn valid_host(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_*".contains(&b))
        })
}

/// A number field of `data` within `0..=max`.
fn data_number(data: &Value, key: &str, max: u64) -> Option<u64> {
    data.get(key).and_then(Value::as_u64).filter(|n| *n <= max)
}

/// The formatted content of a record with `data`, or `None` when `data` is not valid for the
/// type.
fn formatted(rtype: &str, data: &Value) -> Option<String> {
    match rtype {
        "CAA" => {
            let flags = data_number(data, "flags", 255)?;
            let tag = data.get("tag").and_then(Value::as_str)?;
            let value = data.get("value").and_then(Value::as_str)?;
            (!tag.is_empty()).then(|| format!("{flags} {tag} \"{value}\""))
        }
        "SRV" => {
            data_number(data, "priority", 65_535)?;
            let weight = data_number(data, "weight", 65_535)?;
            let port = data_number(data, "port", 65_535)?;
            let target = data.get("target").and_then(Value::as_str)?;
            valid_host(target).then(|| format!("{weight} {port} {target}"))
        }
        "TLSA" => {
            let usage = data_number(data, "usage", 255)?;
            let selector = data_number(data, "selector", 255)?;
            let matching = data_number(data, "matching_type", 255)?;
            let certificate = data.get("certificate").and_then(Value::as_str)?;
            (!certificate.is_empty()
                && certificate.len() % 2 == 0
                && certificate.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| format!("{usage} {selector} {matching} {certificate}"))
        }
        _ => None,
    }
}

/// Checks the per-type fields of `record` (type, content, priority, data, TTL, proxied) and
/// fills in the formatted content of the types with `data`.
fn validate_fields(record: &mut Record) -> Result<(), Response> {
    let rtype = record.rtype.as_str();
    if !WRITABLE.contains(&rtype) {
        return Err(bad_request("this record type is not supported by the mock"));
    }
    if record.ttl != 1 && !(60..=86_400).contains(&record.ttl) {
        return Err(bad_request("invalid ttl"));
    }
    if record.proxied {
        if !matches!(rtype, "A" | "AAAA" | "CNAME") {
            return Err(bad_request("this record type cannot be proxied"));
        }
        if record.ttl != 1 {
            return Err(bad_request("the TTL of a proxied record is automatic"));
        }
    }
    let content = record.content.as_str();
    let valid = match rtype {
        "A" => content.parse::<std::net::Ipv4Addr>().is_ok(),
        "AAAA" => content.parse::<std::net::Ipv6Addr>().is_ok(),
        "CNAME" | "NS" | "PTR" => valid_host(content),
        "MX" => valid_host(content) && record.priority.is_some(),
        "TXT" => valid_txt_content(content),
        _ => true,
    };
    if !valid {
        return Err(bad_request("the content is not valid for the record type"));
    }
    if matches!(rtype, "CAA" | "SRV" | "TLSA") {
        let Some(content) = record.data.as_ref().and_then(|d| formatted(rtype, d)) else {
            return Err(bad_request("the data is not valid for the record type"));
        };
        record.content = content;
    } else if record.data.is_some() {
        return Err(bad_request("this record type takes no data"));
    }
    Ok(())
}

/// Checks the rules between records of one name, for `record` replacing the record with the
/// same identifier, if any.
fn validate_neighbors(inner: &Inner, record: &Record) -> Result<(), Response> {
    let others: Vec<&Record> = inner
        .records
        .iter()
        .filter(|r| r.zone_id == record.zone_id && r.name == record.name && r.id != record.id)
        .collect();
    let rtype = record.rtype.as_str();
    let clash = others.iter().any(|r| {
        let other = r.rtype.as_str();
        (rtype == "CNAME" && matches!(other, "A" | "AAAA" | "CNAME"))
            || (other == "CNAME" && matches!(rtype, "A" | "AAAA"))
            || (rtype == "NS" && other != "NS")
            || (other == "NS" && rtype != "NS")
    });
    if clash {
        return Err(bad_request(
            "the record cannot exist next to the other records of the name",
        ));
    }
    if others.iter().any(|r| {
        r.rtype == record.rtype
            && r.content == record.content
            && r.priority == record.priority
            && r.data == record.data
    }) {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            81058,
            "An identical record already exists.",
        ));
    }
    Ok(())
}

/// The fields of a write body that the client may send, applied to `record`.
fn apply_body(record: &mut Record, body: &Value) -> Result<(), Response> {
    let object = body
        .as_object()
        .ok_or_else(|| bad_request("the body is not an object"))?;
    for (key, value) in object {
        match key.as_str() {
            "type" | "name" => {}
            "content" => {
                if matches!(record.rtype.as_str(), "CAA" | "SRV" | "TLSA") {
                    return Err(bad_request("content is read-only for this record type"));
                }
                record.content = value
                    .as_str()
                    .ok_or_else(|| bad_request("content must be a string"))?
                    .to_owned();
            }
            "ttl" => {
                record.ttl = value
                    .as_u64()
                    .and_then(|t| u32::try_from(t).ok())
                    .ok_or_else(|| bad_request("invalid ttl"))?;
            }
            "priority" => {
                record.priority = Some(
                    value
                        .as_u64()
                        .and_then(|p| u16::try_from(p).ok())
                        .ok_or_else(|| bad_request("invalid priority"))?,
                );
            }
            "data" => record.data = Some(value.clone()),
            "proxied" => {
                record.proxied = value
                    .as_bool()
                    .ok_or_else(|| bad_request("proxied must be a boolean"))?;
            }
            "private_routing" => {
                if !matches!(record.rtype.as_str(), "A" | "AAAA") {
                    return Err(bad_request("private_routing is for A and AAAA records"));
                }
                record.private_routing = value
                    .as_bool()
                    .ok_or_else(|| bad_request("private_routing must be a boolean"))?;
            }
            "settings" => {
                if !value.is_object() {
                    return Err(bad_request("settings must be an object"));
                }
                record.settings = value.clone();
            }
            "comment" => record.comment = value.as_str().map(str::to_owned),
            "tags" => {
                record.tags = value
                    .as_array()
                    .ok_or_else(|| bad_request("tags must be an array"))?
                    .iter()
                    .filter_map(|t| t.as_str().map(str::to_owned))
                    .collect();
            }
            _ => return Err(bad_request("unknown field")),
        }
    }
    Ok(())
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
    let (Some(rtype), Some(name), Some(_)) = (
        body["type"].as_str(),
        body["name"].as_str(),
        body["ttl"].as_u64(),
    ) else {
        return bad_request("type, name and ttl are required");
    };
    if !matches!(rtype, "CAA" | "SRV" | "TLSA") && body["content"].as_str().is_none() {
        return bad_request("content is required");
    }
    let name = normalize(name);
    if name != zone_name && !name.ends_with(&format!(".{zone_name}")) {
        return bad_request("the name is outside the zone");
    }
    if !name.is_ascii() {
        return bad_request("names are in Punycode");
    }
    let mut record = Record {
        zone_id: zone.clone(),
        name,
        rtype: rtype.to_owned(),
        ..Record::bare()
    };
    if let Err(response) = apply_body(&mut record, &body)
        .and_then(|()| validate_fields(&mut record))
        .and_then(|()| validate_neighbors(&inner, &record))
    {
        return response;
    }
    record.id = inner.new_id();
    let answer = record.to_json();
    inner.records.push(record);
    success(answer, None)
}

async fn record_update(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((zone, id)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Response {
    let mut inner = lock(&state);
    if let Err(response) = authenticate(&inner, &headers) {
        return response;
    }
    if inner.zone(&zone).is_none() {
        return unknown_zone();
    }
    let Some(index) = inner
        .records
        .iter()
        .position(|r| r.zone_id == zone && r.id == id)
    else {
        return failure(StatusCode::NOT_FOUND, 81044, "Record does not exist.");
    };
    let Ok(body) = serde_json::from_slice::<Value>(&body) else {
        return bad_request("the body is not JSON");
    };
    let mut record = inner.records[index].clone();
    if body
        .get("type")
        .is_some_and(|t| t.as_str() != Some(record.rtype.as_str()))
    {
        return bad_request("the type of a record cannot change");
    }
    if body
        .get("name")
        .is_some_and(|n| n.as_str().map(normalize).as_deref() != Some(record.name.as_str()))
    {
        return bad_request("the mock does not rename records");
    }
    if let Err(response) = apply_body(&mut record, &body)
        .and_then(|()| validate_fields(&mut record))
        .and_then(|()| validate_neighbors(&inner, &record))
    {
        return response;
    }
    let answer = record.to_json();
    inner.records[index] = record;
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
