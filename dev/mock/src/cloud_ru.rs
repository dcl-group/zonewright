//! Mock of the Cloud.ru Evolution DNS public API and of the token service in front of it.
//!
//! Shapes follow the provider's documentation, the same sources the client cites:
//!
//! - The Evolution DNS OpenAPI specification
//!   (<https://cloud.ru/docs/api/specs/evolution-dns/ug/_specs/openapi.yaml>):
//!   `GET /v1/publicZonesSole` (`projectId` required, `pageSize` default 100, `pageToken`;
//!   `{zones, nextPageToken}`), `GET /v1/publicRecordsSole` (`publicZoneId` required, same
//!   paging; `{records, nextPageToken}`), `POST /v1/publicRecordsSole` (`publicZoneId`, `name`,
//!   `type`, `values`, `ttl` required; `type` one of `a, aaaa, srv, cname, mx, ns, spf, txt,
//!   caa`), `PATCH` and `DELETE /v1/publicRecordsSole/{publicRecordId}` (the update body has
//!   `values`, `ttl`, `description`, `tags`, `gslbData` only), `GET /v1/operations/{operationId}`;
//!   every write answers `200` with a `dnsv1Operation` (`id`, `done`, `error`); error answers
//!   carry an `rpcStatus` (`code`, `message`, `details`) with a `google.rpc.Code`.
//! - Authentication (<https://cloud.ru/docs/console_api/ug/topics/guides__auth_api>): `POST
//!   /api/v1/auth/token` with `{"keyId", "secret"}` answers with `access_token`, `expires_in`
//!   (3600) and `token_type` `Bearer`; requests carry `Authorization: Bearer <access_token>`.
//! - Limitations (<https://cloud.ru/docs/evolution-dns/ug/topics/overview__limitations>): one
//!   record per name and type in a zone, holding several values; TTL 60 to 86400 seconds.
//! - Proto3 JSON (<https://protobuf.dev/programming-guides/json/>): an int64 (`ttl`) is written
//!   as a string.
//!
//! Answers this mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading. A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - status codes: the specification documents `200` and a `default` error answer only. The mock
//!   answers a wrong access key `401` (code 16), a missing or revoked token `401` (code 16), a
//!   project other than the configured one `403` (code 7), an unknown zone, record or operation
//!   `404` (code 5), a create of a name and type that exists `409` (code 6), a malformed request
//!   `400` (code 3), and a write to a read-only record `400` (code 9);
//! - the form of a record's `name`: the mock accepts the name relative to the zone, `@` for the
//!   zone itself, or absolute with a trailing dot, and returns it relative (or absolute with or
//!   without the trailing dot, with [`Control::set_name_style`]);
//! - an update replaces the description and the tags with the ones it carries (none when
//!   absent), the values with the ones it carries (which are required), and the TTL when it
//!   carries one;
//! - a write is applied when it is accepted (unless the operation is set to fail, see
//!   [`Control::fail_next_operation`]); its operation reports `done: false` in the answer and
//!   `done: true` on the first poll (configurable with [`Control::set_operation_polls`]);
//! - page tokens are opaque strings; the last page has no `nextPageToken`; the list field is
//!   present on every page, empty or not;
//! - the zone listing lists the configured project's zones only.
//!
//! Error texts are invented.
//!
//! A test holds a [`CloudRuMock`]. It dereferences to the [`MockServer`], so the request log and
//! the fault queue of the shared harness work as usual.

// Handlers return finished HTTP answers as their error values and hand them straight to axum;
// boxing them would only add noise.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Map, Value, json};

use crate::MockServer;

/// Path of the token endpoint below the server's base URL.
pub const IAM_PATH: &str = "/api/v1/auth/token";

/// Record types the API accepts (the OpenAPI, `v1CreatePublicRecordSoleRequest.type`).
const TYPES: [&str; 9] = ["a", "aaaa", "srv", "cname", "mx", "ns", "spf", "txt", "caa"];

/// Default page size (the OpenAPI, `pageSize`).
const DEFAULT_PAGE_SIZE: usize = 100;

/// TTL range (the limitations page).
const TTL_MIN: u64 = 60;
const TTL_MAX: u64 = 86_400;

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The project the access key may use.
    pub project_id: String,
    /// The access key's ID.
    pub key_id: String,
    /// The access key's secret.
    pub secret: String,
    /// Public zones of the project, in listing order.
    pub zones: Vec<String>,
    /// `expires_in` of an issued token, in seconds.
    pub token_expires_in: u64,
}

impl Seed {
    /// Project `0f1e2d3c-0000-4000-8000-000000000001`, access key `zw-test-key-id` /
    /// `test-only-secret`, and the zone `example.org.`. Tokens state one hour, as the provider's
    /// do.
    pub fn standard() -> Self {
        Self {
            project_id: "0f1e2d3c-0000-4000-8000-000000000001".into(),
            key_id: "zw-test-key-id".into(),
            secret: "test-only-secret".into(),
            zones: vec!["example.org.".into()],
            token_expires_in: 3600,
        }
    }
}

/// A zone as the mock holds it.
#[derive(Clone, Debug)]
pub struct Zone {
    /// The zone's identifier.
    pub id: String,
    /// The project that owns it.
    pub project_id: String,
    /// The domain, lowercase, with the trailing dot.
    pub domain: String,
    /// A read-only zone is listed with `"readOnly": true`.
    pub read_only: bool,
}

/// A record as the mock holds it: one per zone, owner name and type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The record's identifier.
    pub id: String,
    /// The zone's identifier.
    pub zone_id: String,
    /// The owner name, absolute, lowercase, with the trailing dot.
    pub owner: String,
    /// The type, lowercase.
    pub rtype: String,
    /// The values in the API's text form.
    pub values: Vec<String>,
    /// TTL in seconds.
    pub ttl: u64,
    /// A read-only record refuses writes.
    pub read_only: bool,
    /// The description, if any.
    pub description: Option<String>,
    /// The tags.
    pub tags: Vec<String>,
}

/// How the mock spells a record's `name`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NameStyle {
    /// Relative to the zone, `@` for the zone itself.
    #[default]
    Relative,
    /// Absolute, with the trailing dot.
    Absolute,
    /// Absolute, without the trailing dot.
    AbsoluteNoDot,
}

#[derive(Debug)]
struct Operation {
    polls_left: u32,
    error: Option<String>,
}

#[derive(Debug)]
struct Inner {
    seed: Seed,
    zones: Vec<Zone>,
    records: Vec<Record>,
    tokens: HashMap<String, bool>,
    issued: Vec<String>,
    operations: HashMap<String, Operation>,
    polls_before_done: u32,
    fail_next: Option<String>,
    name_style: NameStyle,
    page_size_cap: Option<usize>,
    next_id: u64,
}

impl Inner {
    /// A new identifier in the UUID form the provider uses.
    fn new_id(&mut self) -> String {
        self.next_id += 1;
        format!("00000000-0000-4000-8000-{:012x}", self.next_id)
    }

    fn zone(&self, id: &str) -> Option<&Zone> {
        self.zones.iter().find(|z| z.id == id)
    }

    /// Starts the operation of a write; `error` is the message it finishes with, if it fails.
    fn operation(&mut self, error: Option<String>) -> Value {
        let id = self.new_id();
        if self.polls_before_done == 0 {
            return finished(&id, error.as_deref());
        }
        self.operations.insert(
            id.clone(),
            Operation {
                polls_left: self.polls_before_done,
                error,
            },
        );
        json!({"id": id, "resourceName": "urn:cloud:dns", "done": false})
    }
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running Cloud.ru mock. Dereferences to its [`MockServer`] for the request log and the fault
/// queue; [`CloudRuMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct CloudRuMock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of a [`CloudRuMock`]. Cheap to clone, so that a fault hook
/// ([`Fault::run`](crate::Fault::run)) can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
}

impl Deref for CloudRuMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl CloudRuMock {
    /// Starts the mock with `seed`.
    pub async fn start(seed: Seed) -> Self {
        let mut inner = Inner {
            seed: seed.clone(),
            zones: Vec::new(),
            records: Vec::new(),
            tokens: HashMap::new(),
            issued: Vec::new(),
            operations: HashMap::new(),
            polls_before_done: 1,
            fail_next: None,
            name_style: NameStyle::Relative,
            page_size_cap: None,
            next_id: 0,
        };
        for zone in &seed.zones {
            let id = inner.new_id();
            inner.zones.push(Zone {
                id,
                project_id: seed.project_id.clone(),
                domain: fqdn(zone),
                read_only: false,
            });
        }
        let state = Arc::new(Mutex::new(inner));
        let router = Router::new()
            .route(IAM_PATH, post(token))
            .route("/v1/publicZonesSole", get(zones_list))
            .route(
                "/v1/publicRecordsSole",
                get(records_list).post(record_create),
            )
            .route(
                "/v1/publicRecordsSole/{id}",
                get(record_get).patch(record_update).delete(record_delete),
            )
            .route("/v1/operations/{id}", get(operation_get))
            .with_state(state.clone());
        Self {
            server: MockServer::start(router).await,
            control: Control { state },
        }
    }

    /// The DNS API endpoint, for the client's `dns_url`.
    pub fn dns_url(&self) -> String {
        self.server.base_url()
    }

    /// The token endpoint, for the client's `iam_url`.
    pub fn iam_url(&self) -> String {
        self.server.url(IAM_PATH)
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

    /// The identifier of zone `domain`.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn zone_id(&self, domain: &str) -> String {
        let domain = fqdn(domain);
        lock(&self.state)
            .zones
            .iter()
            .find(|z| z.domain == domain)
            .map(|z| z.id.clone())
            .unwrap_or_else(|| panic!("no zone {domain}"))
    }

    /// Adds a zone of `project_id`. Returns its identifier.
    pub fn insert_zone(&self, domain: &str, project_id: &str) -> String {
        let mut inner = lock(&self.state);
        let id = inner.new_id();
        inner.zones.push(Zone {
            id: id.clone(),
            project_id: project_id.to_owned(),
            domain: fqdn(domain),
            read_only: false,
        });
        id
    }

    /// Marks zone `domain` read-only or writable.
    pub fn set_zone_read_only(&self, domain: &str, read_only: bool) {
        let domain = fqdn(domain);
        for zone in lock(&self.state)
            .zones
            .iter_mut()
            .filter(|z| z.domain == domain)
        {
            zone.read_only = read_only;
        }
    }

    /// Deletes zone `domain` and creates it again under a new identifier, with the same records
    /// (under new record identifiers). Returns the new zone identifier.
    pub fn recreate_zone(&self, domain: &str) -> String {
        let old_id = self.zone_id(domain);
        let mut inner = lock(&self.state);
        let new_id = inner.new_id();
        for zone in inner.zones.iter_mut().filter(|z| z.id == old_id) {
            zone.id = new_id.clone();
        }
        let moved: Vec<usize> = (0..inner.records.len())
            .filter(|&i| inner.records[i].zone_id == old_id)
            .collect();
        for i in moved {
            let record_id = inner.new_id();
            let record = &mut inner.records[i];
            record.zone_id = new_id.clone();
            record.id = record_id;
        }
        new_id
    }

    /// Every record.
    pub fn records(&self) -> Vec<Record> {
        lock(&self.state).records.clone()
    }

    /// The record of owner `name` and type `rtype` (lowercase), if any.
    pub fn record(&self, name: &str, rtype: &str) -> Option<Record> {
        let owner = fqdn(name);
        lock(&self.state)
            .records
            .iter()
            .find(|r| r.owner == owner && r.rtype == rtype)
            .cloned()
    }

    /// Creates a record in zone `zone` directly, as another writer would. Returns its
    /// identifier.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn insert_record(
        &self,
        zone: &str,
        name: &str,
        rtype: &str,
        ttl: u64,
        values: &[&str],
    ) -> String {
        let zone_id = self.zone_id(zone);
        let mut inner = lock(&self.state);
        let id = inner.new_id();
        inner.records.push(Record {
            id: id.clone(),
            zone_id,
            owner: fqdn(name),
            rtype: rtype.to_owned(),
            values: values.iter().map(|v| (*v).to_owned()).collect(),
            ttl,
            read_only: false,
            description: None,
            tags: Vec::new(),
        });
        id
    }

    /// Appends `value` to the TXT record of `name`, or creates the record (TTL 3600) in the zone
    /// that contains `name`, as another writer would.
    ///
    /// # Panics
    ///
    /// If no zone contains `name`.
    pub fn append_txt(&self, name: &str, value: &str) {
        let owner = fqdn(name);
        {
            let mut inner = lock(&self.state);
            if let Some(record) = inner
                .records
                .iter_mut()
                .find(|r| r.owner == owner && r.rtype == "txt")
            {
                record.values.push(value.to_owned());
                return;
            }
        }
        let zone = self
            .zones()
            .into_iter()
            .filter(|z| owner == z.domain || owner.ends_with(&format!(".{}", z.domain)))
            .max_by_key(|z| z.domain.len())
            .unwrap_or_else(|| panic!("no zone contains {owner}"));
        self.insert_record(&zone.domain, name, "txt", 3600, &[value]);
    }

    /// Marks the record of `name` and `rtype` read-only or writable.
    pub fn set_read_only(&self, name: &str, rtype: &str, read_only: bool) {
        self.edit(name, rtype, |r| r.read_only = read_only);
    }

    /// Sets the description and the tags of the record of `name` and `rtype`.
    pub fn set_attributes(
        &self,
        name: &str,
        rtype: &str,
        description: Option<&str>,
        tags: &[&str],
    ) {
        self.edit(name, rtype, |r| {
            r.description = description.map(str::to_owned);
            r.tags = tags.iter().map(|t| (*t).to_owned()).collect();
        });
    }

    fn edit(&self, name: &str, rtype: &str, change: impl Fn(&mut Record)) {
        let owner = fqdn(name);
        for record in lock(&self.state)
            .records
            .iter_mut()
            .filter(|r| r.owner == owner && r.rtype == rtype)
        {
            change(record);
        }
    }

    /// Deletes the record of `name` and `rtype` directly, as another writer would.
    pub fn delete_record(&self, name: &str, rtype: &str) {
        let owner = fqdn(name);
        lock(&self.state)
            .records
            .retain(|r| !(r.owner == owner && r.rtype == rtype));
    }

    /// The values of the TXT record of `name`, in order; empty when there is none.
    pub fn txt_values(&self, name: &str) -> Vec<String> {
        self.record(name, "txt")
            .map(|r| r.values)
            .unwrap_or_default()
    }

    /// Revokes every token issued so far: requests with them answer `401`.
    pub fn revoke_tokens(&self) {
        for revoked in lock(&self.state).tokens.values_mut() {
            *revoked = true;
        }
    }

    /// `expires_in` stated for tokens issued from now on. The mock does not enforce it; revoke
    /// tokens to make the API refuse them.
    pub fn set_token_expires_in(&self, seconds: u64) {
        lock(&self.state).seed.token_expires_in = seconds;
    }

    /// Every token issued so far, in order.
    pub fn issued_tokens(&self) -> Vec<String> {
        lock(&self.state).issued.clone()
    }

    /// Number of tokens issued so far.
    pub fn tokens_issued(&self) -> usize {
        lock(&self.state).issued.len()
    }

    /// Number of polls after which an operation started from now on reports `done: true`; `0`
    /// for an operation that is done in the write's answer already.
    pub fn set_operation_polls(&self, polls: u32) {
        lock(&self.state).polls_before_done = polls;
    }

    /// The next write is not applied, and its operation finishes with an error (code 9) whose
    /// message is `message`.
    pub fn fail_next_operation(&self, message: &str) {
        lock(&self.state).fail_next = Some(message.to_owned());
    }

    /// How record names are spelled in listings.
    pub fn set_name_style(&self, style: NameStyle) {
        lock(&self.state).name_style = style;
    }

    /// Caps the page size of every listing, to force several pages.
    pub fn set_page_size_cap(&self, cap: usize) {
        lock(&self.state).page_size_cap = Some(cap.max(1));
    }
}

/// `name` lowercase with exactly one trailing dot.
fn fqdn(name: &str) -> String {
    let name = name.trim().to_lowercase();
    if name.ends_with('.') {
        name
    } else {
        format!("{name}.")
    }
}

/// An error answer: an `rpcStatus` with `code`.
fn error(status: StatusCode, code: i64, message: &str) -> Response {
    (
        status,
        axum::Json(json!({"code": code, "message": message, "details": []})),
    )
        .into_response()
}

fn bad_request(message: &str) -> Response {
    error(StatusCode::BAD_REQUEST, 3, message)
}

fn not_found(message: &str) -> Response {
    error(StatusCode::NOT_FOUND, 5, message)
}

async fn token(State(state): State<Shared>, body: Bytes) -> Response {
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return bad_request("malformed request body");
    };
    let mut inner = lock(&state);
    let accepted = request["keyId"].as_str() == Some(inner.seed.key_id.as_str())
        && request["secret"].as_str() == Some(inner.seed.secret.as_str());
    if !accepted {
        return error(StatusCode::UNAUTHORIZED, 16, "invalid access key");
    }
    let n = inner.issued.len() + 1;
    let token = format!("eyJ-mock-access-token-{n:04}");
    inner.tokens.insert(token.clone(), false);
    inner.issued.push(token.clone());
    axum::Json(json!({
        "access_token": token,
        "id_token": "eyJ-mock-id-token",
        "refresh_token": "",
        "expires_in": inner.seed.token_expires_in,
        "refresh_expires_in": 0,
        "scopes": ["openid profile email roles"],
        "token_type": "Bearer",
        "not_before": 0
    }))
    .into_response()
}

/// `Ok` for a request with a valid token, or the `401` answer.
fn authorize(state: &Shared, headers: &HeaderMap) -> Result<(), Response> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match token.and_then(|t| lock(state).tokens.get(t).copied()) {
        Some(false) => Ok(()),
        _ => Err(error(StatusCode::UNAUTHORIZED, 16, "unauthenticated")),
    }
}

/// The zone `zone_id`: `404` when there is none, `403` when it belongs to another project.
fn own_zone(state: &Shared, zone_id: &str) -> Result<Zone, Response> {
    let inner = lock(state);
    match inner.zone(zone_id) {
        None => Err(not_found("public zone not found")),
        Some(zone) if zone.project_id != inner.seed.project_id => Err(error(
            StatusCode::FORBIDDEN,
            7,
            "permission denied for the zone",
        )),
        Some(zone) => Ok(zone.clone()),
    }
}

/// One page of `items` by `pageSize` and `pageToken`, under `key`.
fn paginate(
    state: &Shared,
    key: &str,
    items: Vec<Value>,
    query: &HashMap<String, String>,
) -> Response {
    let cap = lock(state).page_size_cap;
    let size = match query.get("pageSize").map(|s| s.parse::<usize>()) {
        None => DEFAULT_PAGE_SIZE,
        Some(Ok(size)) if size >= 1 => size,
        Some(_) => return bad_request("pageSize must be a positive integer"),
    };
    let size = cap.map_or(size, |cap| size.min(cap));
    let start = match query.get("pageToken").map(String::as_str) {
        None | Some("") => 0,
        Some(token) => match token.strip_prefix("pg-").map(str::parse::<usize>) {
            Some(Ok(start)) => start,
            _ => return bad_request("invalid page token"),
        },
    };
    let total = items.len();
    let page: Vec<Value> = items.into_iter().skip(start).take(size).collect();
    let mut body = Map::new();
    body.insert(key.to_owned(), Value::Array(page));
    if start.saturating_add(size) < total {
        body.insert(
            "nextPageToken".into(),
            Value::String(format!("pg-{}", start + size)),
        );
    }
    axum::Json(Value::Object(body)).into_response()
}

fn zone_json(zone: &Zone) -> Value {
    json!({
        "id": zone.id,
        "createAt": "2026-01-10T12:00:00Z",
        "updatedAt": "2026-01-10T12:00:00Z",
        "projectId": zone.project_id,
        "name": zone.domain.trim_end_matches('.'),
        "domain": zone.domain,
        "readOnly": zone.read_only,
        "state": "ok",
        "confirmState": "delegated"
    })
}

async fn zones_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let Some(project) = query.get("projectId") else {
        return bad_request("projectId is required");
    };
    let zones: Vec<Value> = {
        let inner = lock(&state);
        if *project != inner.seed.project_id {
            return error(
                StatusCode::FORBIDDEN,
                7,
                "permission denied for the project",
            );
        }
        inner
            .zones
            .iter()
            .filter(|z| z.project_id == *project)
            .map(zone_json)
            .collect()
    };
    paginate(&state, "zones", zones, &query)
}

/// The record's `name` in the configured style.
fn name_text(record: &Record, zone: &Zone, style: NameStyle) -> String {
    match style {
        NameStyle::Absolute => record.owner.clone(),
        NameStyle::AbsoluteNoDot => record.owner.trim_end_matches('.').to_owned(),
        NameStyle::Relative if record.owner == zone.domain => "@".to_owned(),
        NameStyle::Relative => record
            .owner
            .strip_suffix(&format!(".{}", zone.domain))
            .unwrap_or(&record.owner)
            .to_owned(),
    }
}

fn record_json(record: &Record, zone: &Zone, style: NameStyle) -> Value {
    let mut value = json!({
        "id": record.id,
        "publicZoneId": record.zone_id,
        "createAt": "2026-01-10T12:00:00Z",
        "updatedAt": "2026-01-10T12:00:00Z",
        "name": name_text(record, zone, style),
        "type": record.rtype,
        "values": record.values,
        // Proto3 JSON writes an int64 as a string.
        "ttl": record.ttl.to_string(),
        "readOnly": record.read_only,
        "wildcard": false,
        "tags": record.tags,
    });
    if let Some(description) = &record.description {
        value["description"] = json!(description);
    }
    value
}

async fn records_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let Some(zone_id) = query.get("publicZoneId") else {
        return bad_request("publicZoneId is required");
    };
    let zone = match own_zone(&state, zone_id) {
        Ok(zone) => zone,
        Err(response) => return response,
    };
    let records: Vec<Value> = {
        let inner = lock(&state);
        inner
            .records
            .iter()
            .filter(|r| r.zone_id == zone.id)
            .map(|r| record_json(r, &zone, inner.name_style))
            .collect()
    };
    paginate(&state, "records", records, &query)
}

async fn record_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let inner = lock(&state);
    let Some(record) = inner.records.iter().find(|r| r.id == id) else {
        return not_found("record not found");
    };
    let Some(zone) = inner.zone(&record.zone_id) else {
        return not_found("public zone not found");
    };
    axum::Json(record_json(record, zone, inner.name_style)).into_response()
}

/// The absolute owner name of `name` in `zone`: `@`, a relative name, or an absolute one with a
/// trailing dot inside the zone.
fn owner_of(name: &str, zone: &Zone) -> Option<String> {
    let name = name.trim().to_lowercase();
    let owner = if name == "@" {
        zone.domain.clone()
    } else if name.ends_with('.') {
        name
    } else if name.is_empty() {
        return None;
    } else {
        format!("{name}.{}", zone.domain)
    };
    (owner == zone.domain || owner.ends_with(&format!(".{}", zone.domain))).then_some(owner)
}

/// `values` as a non-empty list of strings.
fn string_list(value: Option<&Value>) -> Option<Vec<String>> {
    let list = value?.as_array()?;
    let strings: Option<Vec<String>> = list.iter().map(|v| v.as_str().map(str::to_owned)).collect();
    strings.filter(|s| !s.is_empty())
}

/// An int64 as a number or a decimal string (Proto3 JSON accepts both on input), within the TTL
/// range.
fn ttl_of(value: Option<&Value>) -> Result<u64, Response> {
    let ttl = match value {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    };
    match ttl {
        Some(ttl) if (TTL_MIN..=TTL_MAX).contains(&ttl) => Ok(ttl),
        _ => Err(bad_request("ttl must be between 60 and 86400")),
    }
}

async fn record_create(State(state): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return bad_request("malformed request body");
    };
    let Some(zone_id) = request["publicZoneId"].as_str() else {
        return bad_request("publicZoneId is required");
    };
    let zone = match own_zone(&state, zone_id) {
        Ok(zone) => zone,
        Err(response) => return response,
    };
    let Some(owner) = request["name"].as_str().and_then(|n| owner_of(n, &zone)) else {
        return bad_request("name is required and must be inside the zone");
    };
    let rtype = request["type"].as_str().unwrap_or("");
    if !TYPES.contains(&rtype) {
        return bad_request("type must be one of a, aaaa, srv, cname, mx, ns, spf, txt, caa");
    }
    let Some(values) = string_list(request.get("values")) else {
        return bad_request("values are required");
    };
    let ttl = match ttl_of(request.get("ttl")) {
        Ok(ttl) => ttl,
        Err(response) => return response,
    };
    let mut inner = lock(&state);
    if inner
        .records
        .iter()
        .any(|r| r.zone_id == zone.id && r.owner == owner && r.rtype == rtype)
    {
        return error(
            StatusCode::CONFLICT,
            6,
            "a record with this name and type already exists",
        );
    }
    let fail = inner.fail_next.take();
    if fail.is_none() {
        let id = inner.new_id();
        inner.records.push(Record {
            id,
            zone_id: zone.id,
            owner,
            rtype: rtype.to_owned(),
            values,
            ttl,
            read_only: false,
            description: request["description"].as_str().map(str::to_owned),
            tags: Vec::new(),
        });
    }
    axum::Json(inner.operation(fail)).into_response()
}

async fn record_update(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let Ok(Value::Object(request)) = serde_json::from_slice::<Value>(&body) else {
        return bad_request("malformed request body");
    };
    // The update body has these fields only (`v1PublicRecordSoleServiceUpdateBody`).
    if request.keys().any(|k| {
        !matches!(
            k.as_str(),
            "values" | "ttl" | "description" | "tags" | "gslbData"
        )
    }) {
        return bad_request("unexpected field");
    }
    let Some(values) = string_list(request.get("values")) else {
        return bad_request("values are required");
    };
    let ttl = match request.get("ttl") {
        None => None,
        Some(value) => match ttl_of(Some(value)) {
            Ok(ttl) => Some(ttl),
            Err(response) => return response,
        },
    };
    let mut inner = lock(&state);
    let Some(index) = inner.records.iter().position(|r| r.id == id) else {
        return not_found("record not found");
    };
    if inner.records[index].read_only {
        return error(StatusCode::BAD_REQUEST, 9, "the record is read-only");
    }
    let fail = inner.fail_next.take();
    if fail.is_none() {
        let record = &mut inner.records[index];
        record.values = values;
        if let Some(ttl) = ttl {
            record.ttl = ttl;
        }
        record.description = request
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_owned);
        record.tags = string_list(request.get("tags")).unwrap_or_default();
    }
    axum::Json(inner.operation(fail)).into_response()
}

async fn record_delete(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    let Some(index) = inner.records.iter().position(|r| r.id == id) else {
        return not_found("record not found");
    };
    if inner.records[index].read_only {
        return error(StatusCode::BAD_REQUEST, 9, "the record is read-only");
    }
    let fail = inner.fail_next.take();
    if fail.is_none() {
        inner.records.remove(index);
    }
    axum::Json(inner.operation(fail)).into_response()
}

async fn operation_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    let Some(operation) = inner.operations.get_mut(&id) else {
        return not_found("operation not found");
    };
    operation.polls_left = operation.polls_left.saturating_sub(1);
    if operation.polls_left > 0 {
        return axum::Json(json!({"id": id, "done": false})).into_response();
    }
    axum::Json(finished(&id, operation.error.as_deref())).into_response()
}

/// A finished operation, with an error (code 9) when `error` is given.
fn finished(id: &str, error: Option<&str>) -> Value {
    match error {
        None => json!({"id": id, "done": true}),
        Some(message) => json!({
            "id": id,
            "done": true,
            "error": {"code": 9, "message": message, "details": []}
        }),
    }
}
