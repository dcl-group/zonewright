//! Mock of the Timeweb Cloud API (domains and their DNS records, `v1`).
//!
//! Shapes follow the provider's public API description, <https://timeweb.cloud/api-docs> (the
//! OpenAPI document it is rendered from), the same source the client cites:
//!
//! - `GET /api/v1/domains`: `limit` (integer, default 100), `offset` (integer, default 0); the
//!   answer holds `meta.total` and `domains` with `fqdn`.
//! - `GET /api/v1/domains/{fqdn}/dns-records`: `limit`, `offset`; the answer holds `meta.total`
//!   and `dns_records` with `type`, `id` (a number, nullable), `ttl` and `data` (`subdomain`,
//!   `value`); documented errors `400`, `401`, `404`, `429`, `500`.
//! - `POST /api/v1/domains/{fqdn}/dns-records`: `type` (one of `TXT`, `SRV`, `CNAME`, `AAAA`,
//!   `MX`, `A`) and `value` required, `subdomain`, `priority` and `ttl` optional; `201` with a
//!   `dns_record`.
//! - `DELETE /api/v1/domains/{fqdn}/dns-records/{record_id}`: `204`.
//! - Every error body is `{status_code, error_code, message, response_id}`; `Authorization:
//!   Bearer <token>` is required.
//!
//! Answers this mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading. A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - the form in which a listing states a record's `subdomain`: relative to the domain with
//!   `null` for the apex (the default), or the full name ([`SubdomainForm`]);
//! - the `subdomain` of a created record is read as the full name when it equals the domain or
//!   ends with `.<domain>`, and otherwise as a name relative to the domain; a missing or empty
//!   one is the apex;
//! - `limit` above 100 or below 1, an `offset` below 0, and a `limit` or `offset` that is not an
//!   integer are refused with `400`; `meta.total` counts all the records of the domain;
//! - a `ttl` that is not a non-negative integer is refused with `400`; a record created without
//!   `ttl` is listed without one (`null`);
//! - the text and `error_code` of every error, and the status of a delete of a missing record
//!   (`404`);
//! - a record can be listed with `id` as a whole float (`1001.0`, [`Control::set_float_ids`]) or
//!   with a `null` id ([`Control::set_null_id`]), both allowed by the schema's `number`,
//!   `nullable`.
//!
//! Error texts are invented.
//!
//! ```text
//! let mock = TimewebCloudMock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("POST", "/api/v1/domains/*/dns-records").status(500));
//! // ... drive the client against mock.base_url() ...
//! assert_eq!(mock.control().txt_values("_acme-challenge.example.org"), ["v1"]);
//! ```

// Reason: handlers return an axum `Response` as the error of a `Result` to answer early;
// boxing them would only add noise.
#![allow(clippy::result_large_err)]

use std::collections::HashSet;
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
pub const API_PATH: &str = "/api";

/// Largest `limit` the mock accepts (invented; the documentation states the default only).
const MAX_LIMIT: u64 = 100;

/// Record types the create accepts.
const TYPES: [&str; 6] = ["TXT", "SRV", "CNAME", "AAAA", "MX", "A"];

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The API token the mock accepts.
    pub token: String,
    /// The domains of the account, without a trailing dot.
    pub domains: Vec<String>,
}

impl Seed {
    /// Token `test-only-token` and the domain `example.org`.
    pub fn standard() -> Self {
        Self {
            token: "test-only-token".into(),
            domains: vec!["example.org".into()],
        }
    }
}

/// The form in which a listing states a record's `subdomain`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubdomainForm {
    /// Relative to the domain; `null` for the apex.
    Relative,
    /// The full name without a trailing dot, the zone's own name for the apex.
    Full,
}

/// One record as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The record's identifier.
    pub id: u64,
    /// The domain, without a trailing dot.
    pub domain: String,
    /// The owner name relative to the domain; empty for the apex.
    pub subdomain: String,
    /// The record type.
    pub rtype: String,
    /// The value.
    pub value: String,
    /// TTL in seconds; `None` when none was given.
    pub ttl: Option<u64>,
}

#[derive(Debug)]
struct Inner {
    token: String,
    domains: Vec<String>,
    records: Vec<Record>,
    next_id: u64,
    /// Caps `limit`, to force small pages.
    page_cap: Option<u64>,
    form: SubdomainForm,
    float_ids: bool,
    /// Records the listing shows with a `null` id.
    null_ids: HashSet<u64>,
    /// Records the listing leaves out.
    hidden: HashSet<u64>,
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running Timeweb Cloud mock. Dereferences to its [`MockServer`] for the request log and the
/// fault queue; [`TimewebCloudMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct TimewebCloudMock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of a [`TimewebCloudMock`]. Cheap to clone, so that a fault hook
/// ([`Fault::run`](crate::Fault::run)) can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
}

impl Deref for TimewebCloudMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl TimewebCloudMock {
    /// Starts the mock with `seed`.
    pub async fn start(seed: Seed) -> Self {
        let state = Arc::new(Mutex::new(Inner {
            token: seed.token,
            domains: seed.domains,
            records: Vec::new(),
            next_id: 1000,
            page_cap: None,
            form: SubdomainForm::Relative,
            float_ids: false,
            null_ids: HashSet::new(),
            hidden: HashSet::new(),
        }));
        let router = Router::new()
            .route("/api/v1/domains", get(domains_list))
            .route(
                "/api/v1/domains/{fqdn}/dns-records",
                get(records_list).post(record_create),
            )
            .route(
                "/api/v1/domains/{fqdn}/dns-records/{id}",
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
    /// Every record, in creation order.
    pub fn records(&self) -> Vec<Record> {
        lock(&self.state).records.clone()
    }

    /// The values of the TXT records at `name` (absolute, or relative to the first domain), in
    /// creation order.
    pub fn txt_values(&self, name: &str) -> Vec<String> {
        self.txt_records(name)
            .into_iter()
            .map(|r| r.value)
            .collect()
    }

    /// The TXT records at `name`.
    pub fn txt_records(&self, name: &str) -> Vec<Record> {
        let inner = lock(&self.state);
        let domain = inner.domains.first().map_or("", String::as_str);
        let wanted = relative(name, domain);
        inner
            .records
            .iter()
            .filter(|r| r.rtype == "TXT" && r.subdomain == wanted)
            .cloned()
            .collect()
    }

    /// Adds a record directly, as another writer would. `name` is absolute or relative to the
    /// domain. Returns the record's identifier.
    pub fn insert_record(
        &self,
        domain: &str,
        name: &str,
        rtype: &str,
        value: &str,
        ttl: Option<u64>,
    ) -> u64 {
        let mut inner = lock(&self.state);
        inner.next_id += 1;
        let id = inner.next_id;
        inner.records.push(Record {
            id,
            domain: domain.to_owned(),
            subdomain: relative(name, domain),
            rtype: rtype.to_owned(),
            value: value.to_owned(),
            ttl,
        });
        id
    }

    /// Deletes the record `id` directly, as another writer would.
    pub fn delete_record(&self, id: u64) {
        lock(&self.state).records.retain(|r| r.id != id);
    }

    /// Changes the record `id` in place, keeping its identifier, as another writer would with
    /// the documented `PATCH /api/v1/domains/{fqdn}/dns-records/{record_id}`. `name` is
    /// absolute or relative to the record's domain.
    pub fn update_record(&self, id: u64, name: &str, value: &str) {
        let mut inner = lock(&self.state);
        if let Some(record) = inner.records.iter_mut().find(|r| r.id == id) {
            record.subdomain = relative(name, &record.domain);
            record.value = value.to_owned();
        }
    }

    /// Adds a domain.
    pub fn insert_domain(&self, domain: &str) {
        lock(&self.state).domains.push(domain.to_owned());
    }

    /// Deletes `domain` with its records and creates it again with the same records under new
    /// identifiers.
    pub fn recreate_domain(&self, domain: &str) {
        let mut inner = lock(&self.state);
        let mut next = inner.next_id;
        for record in inner.records.iter_mut().filter(|r| r.domain == domain) {
            next += 1;
            record.id = next;
        }
        inner.next_id = next;
    }

    /// Caps `limit` at `cap`, so that listings come in small pages.
    pub fn set_page_cap(&self, cap: u64) {
        lock(&self.state).page_cap = Some(cap.max(1));
    }

    /// The form in which listings state a record's `subdomain`.
    pub fn set_subdomain_form(&self, form: SubdomainForm) {
        lock(&self.state).form = form;
    }

    /// Lists identifiers as whole floats (`1001.0`).
    pub fn set_float_ids(&self, floats: bool) {
        lock(&self.state).float_ids = floats;
    }

    /// The listing shows the record `id` with a `null` identifier.
    pub fn set_null_id(&self, id: u64) {
        lock(&self.state).null_ids.insert(id);
    }

    /// The listing leaves the record `id` out (it still exists and can be deleted by `id`).
    pub fn hide_from_list(&self, id: u64) {
        lock(&self.state).hidden.insert(id);
    }
}

/// `name` relative to `domain`, lowercase, without dots at the ends; empty for the domain
/// itself. A name that does not end with the domain is taken as relative already.
fn relative(name: &str, domain: &str) -> String {
    let name = name.trim().to_lowercase();
    let name = name.strip_suffix('.').unwrap_or(&name);
    let domain = domain.to_lowercase();
    if name == domain || name == "@" {
        String::new()
    } else {
        name.strip_suffix(&format!(".{domain}"))
            .unwrap_or(name)
            .to_owned()
    }
}

/// An error answer in the documented shape.
fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        axum::Json(json!({
            "status_code": status.as_u16(),
            "error_code": code,
            "message": message,
            "response_id": "00000000-0000-0000-0000-00000000mock",
        })),
    )
        .into_response()
}

fn bad_request(message: &str) -> Response {
    error(StatusCode::BAD_REQUEST, "bad_request", message)
}

fn not_found(message: &str) -> Response {
    error(StatusCode::NOT_FOUND, "not_found", message)
}

/// `Ok` when the request carries the token of the seed.
fn authorize(state: &Shared, headers: &HeaderMap) -> Result<(), Response> {
    let want = format!("Bearer {}", lock(state).token);
    if headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(want.as_str()) {
        Ok(())
    } else {
        Err(error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Unauthorized",
        ))
    }
}

/// `limit` and `offset` of a listing.
fn paging(state: &Shared, pairs: &[(String, String)]) -> Result<(u64, u64), Response> {
    let get = |key: &str, default: u64| -> Result<u64, Response> {
        match pairs.iter().find(|(k, _)| k == key) {
            None => Ok(default),
            Some((_, v)) => v
                .parse::<u64>()
                .map_err(|_| bad_request(&format!("{key} must be a non-negative integer"))),
        }
    };
    let limit = get("limit", MAX_LIMIT)?;
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(bad_request("limit must be between 1 and 100"));
    }
    let offset = get("offset", 0)?;
    let limit = lock(state).page_cap.map_or(limit, |cap| limit.min(cap));
    Ok((limit, offset))
}

fn take_page(items: Vec<Value>, limit: u64, offset: u64) -> Vec<Value> {
    items
        .into_iter()
        .skip(usize::try_from(offset).unwrap_or(usize::MAX))
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .collect()
}

async fn domains_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let (limit, offset) = match paging(&state, &pairs) {
        Ok(paging) => paging,
        Err(response) => return response,
    };
    let items: Vec<Value> = lock(&state)
        .domains
        .iter()
        .enumerate()
        .map(|(i, d)| json!({"id": i + 1, "fqdn": d, "subdomains": [], "linked_ip": null}))
        .collect();
    let total = items.len();
    axum::Json(json!({
        "meta": {"total": total},
        "domains": take_page(items, limit, offset),
        "response_id": "00000000-0000-0000-0000-00000000mock",
    }))
    .into_response()
}

fn id_json(inner: &Inner, id: u64) -> Value {
    if inner.null_ids.contains(&id) {
        Value::Null
    } else if inner.float_ids {
        // `serde_json` renders a whole float with its fraction: `1001.0`.
        json!(id as f64)
    } else {
        json!(id)
    }
}

fn record_json(inner: &Inner, record: &Record) -> Value {
    let subdomain = match (inner.form, record.subdomain.is_empty()) {
        (SubdomainForm::Relative, true) => Value::Null,
        (SubdomainForm::Relative, false) => json!(record.subdomain),
        (SubdomainForm::Full, true) => json!(record.domain),
        (SubdomainForm::Full, false) => json!(format!("{}.{}", record.subdomain, record.domain)),
    };
    json!({
        "id": id_json(inner, record.id),
        "type": record.rtype,
        "ttl": record.ttl,
        "data": {"subdomain": subdomain, "value": record.value},
    })
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
    let (limit, offset) = match paging(&state, &pairs) {
        Ok(paging) => paging,
        Err(response) => return response,
    };
    let inner = lock(&state);
    if !inner.domains.contains(&fqdn) {
        return not_found("Domain not found");
    }
    let items: Vec<Value> = inner
        .records
        .iter()
        .filter(|r| r.domain == fqdn && !inner.hidden.contains(&r.id))
        .map(|r| record_json(&inner, r))
        .collect();
    let total = items.len();
    axum::Json(json!({
        "meta": {"total": total},
        "dns_records": take_page(items, limit, offset),
        "response_id": "00000000-0000-0000-0000-00000000mock",
    }))
    .into_response()
}

async fn record_create(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(fqdn): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    if !inner.domains.contains(&fqdn) {
        return not_found("Domain not found");
    }
    let Ok(body) = serde_json::from_slice::<Value>(&body) else {
        return bad_request("the body is not JSON");
    };
    let Some(rtype) = body["type"].as_str().filter(|t| TYPES.contains(t)) else {
        return bad_request("type is required and must be one of the record types");
    };
    let Some(value) = body["value"].as_str() else {
        return bad_request("value is required");
    };
    let subdomain = match body.get("subdomain") {
        None | Some(Value::Null) => "",
        Some(Value::String(s)) => s.as_str(),
        Some(_) => return bad_request("subdomain must be a string"),
    };
    let ttl = match body.get("ttl") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_u64() {
            Some(ttl) => Some(ttl),
            None => return bad_request("ttl must be a non-negative integer"),
        },
    };
    inner.next_id += 1;
    let record = Record {
        id: inner.next_id,
        domain: fqdn.clone(),
        subdomain: relative(subdomain, &fqdn),
        rtype: rtype.to_owned(),
        value: value.to_owned(),
        ttl,
    };
    let created = record_json(&inner, &record);
    inner.records.push(record);
    (
        StatusCode::CREATED,
        axum::Json(json!({
            "dns_record": created,
            "response_id": "00000000-0000-0000-0000-00000000mock",
        })),
    )
        .into_response()
}

async fn record_delete(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((fqdn, id)): Path<(String, String)>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    if !inner.domains.contains(&fqdn) {
        return not_found("Domain not found");
    }
    let Ok(id) = id.parse::<u64>() else {
        return bad_request("record_id must be an integer");
    };
    let before = inner.records.len();
    inner.records.retain(|r| !(r.domain == fqdn && r.id == id));
    if inner.records.len() == before {
        return not_found("DNS record not found");
    }
    StatusCode::NO_CONTENT.into_response()
}
