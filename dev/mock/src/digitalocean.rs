//! Mock of the DigitalOcean API v2 (domains and domain records).
//!
//! Shapes follow the provider's documentation, the same sources the client cites:
//!
//! - Domains: <https://docs.digitalocean.com/reference/api/reference/domains/>: `GET /v2/domains`
//!   (`per_page` 1 to 200, default 20; `page` from 1; the answer holds `domains`, `links` and a
//!   required `meta` with `total`) and `GET /v2/domains/{domain_name}` (`404` `not_found`).
//! - Domain Records: <https://docs.digitalocean.com/reference/api/reference/domain-records/>: list
//!   (`name` is a fully qualified record name, `type`, `per_page`, `page`; `404` documented),
//!   create (`type` required, and for TXT also `name` and `data`, per the OpenAPI description's
//!   `domain_record_txt`; `ttl` optional; answers `201` with a `domain_record` that has the
//!   generated `id`; `404` documented), delete (`204` with an empty body, `404` when missing),
//!   error bodies `{id, message, request_id}` with the ids `unauthorized`, `not_found`,
//!   `too_many_requests`, `server_error`; answers state record names relative to the domain,
//!   `@` for the apex (the reference's examples).
//! - DNS limits: <https://docs.digitalocean.com/products/networking/dns/details/limits/>: "All
//!   DNS records require a minimum TTL value of 30 seconds".
//! - Account: <https://docs.digitalocean.com/reference/api/reference/account/>: `GET /v2/account`
//!   answers `{"account": {...}}`, `401` for a token that is not accepted.
//!
//! Answers this mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading. A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - the `name` of a record in an answer can be switched to the absolute form with a trailing
//!   dot ([`NameForm::Absolute`]); the default, [`NameForm::Relative`], is the documented one;
//! - the `name` of a created record is read as in a zone file: `@` is the apex, a name with a
//!   trailing dot is absolute and must lie within the domain, any other name is relative (lego
//!   sends the absolute form; the reference's example the relative one);
//! - the `name` filter of the record listing compares the record's absolute name with the filter
//!   exactly, ignoring case and a trailing dot; with [`Control::set_loose_filter`] it matches by
//!   substring instead, so that a listing returns "noisy" neighbors the client must skip;
//! - `meta.total` counts the records under the filters; `links.pages.next` is present on every
//!   page but the last and points at a foreign host, which a client must not request;
//! - the status of a refused create: a record without `type`, a TXT record without `name` or
//!   `data`, and a `ttl` that is not an integer of at least 30 are refused with `422`; a record
//!   created without `ttl` gets 1800;
//! - a `per_page` outside 1 to 200 or a `page` below 1 is refused with `422`;
//! - the `ratelimit-*` headers are not sent.
//!
//! Error texts are invented.
//!
//! A test holds a [`DigitalOceanMock`]. It dereferences to the [`MockServer`], so the request log
//! and the fault queue of the shared harness work as usual:
//!
//! ```text
//! let mock = DigitalOceanMock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("POST", "/v2/domains/*/records").status(500));
//! // ... drive the client against mock.base_url() ...
//! assert_eq!(mock.control().txt_values("_acme-challenge.example.org"), ["v1"]);
//! ```

#![allow(clippy::result_large_err)]

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
pub const API_PATH: &str = "/v2";

/// Largest `per_page` the API accepts.
const MAX_PER_PAGE: usize = 200;

/// Default `per_page`.
const DEFAULT_PER_PAGE: usize = 20;

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The personal access token the API accepts.
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

/// The form in which an answer states a record's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameForm {
    /// Relative to the domain, `@` for the apex.
    Relative,
    /// Absolute, with a trailing dot.
    Absolute,
}

/// One record as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The record's identifier.
    pub id: u64,
    /// The domain, without a trailing dot.
    pub domain: String,
    /// The owner name relative to the domain, `@` for the apex.
    pub name: String,
    /// The record type.
    pub rtype: String,
    /// The value.
    pub data: String,
    /// TTL in seconds.
    pub ttl: u32,
}

#[derive(Debug)]
struct Inner {
    token: String,
    domains: Vec<String>,
    records: Vec<Record>,
    next_id: u64,
    /// Caps `per_page`, to force small pages.
    page_cap: Option<usize>,
    name_form: NameForm,
    loose_filter: bool,
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running DigitalOcean mock. Dereferences to its [`MockServer`] for the request log and the
/// fault queue; [`DigitalOceanMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct DigitalOceanMock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of a [`DigitalOceanMock`]. Cheap to clone, so that a fault hook
/// ([`Fault::run`](crate::Fault::run)) can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
}

impl Deref for DigitalOceanMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl DigitalOceanMock {
    /// Starts the mock with `seed`.
    pub async fn start(seed: Seed) -> Self {
        let state = Arc::new(Mutex::new(Inner {
            token: seed.token,
            domains: seed.domains,
            records: Vec::new(),
            next_id: 1000,
            page_cap: None,
            name_form: NameForm::Relative,
            loose_filter: false,
        }));
        let router = Router::new()
            .route("/v2/account", get(account))
            .route("/v2/domains", get(domains_list))
            .route("/v2/domains/{domain}", get(domain_get))
            .route(
                "/v2/domains/{domain}/records",
                get(records_list).post(record_create),
            )
            .route(
                "/v2/domains/{domain}/records/{id}",
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

    /// The values of the TXT records at `name` (absolute or relative to the first domain), in
    /// creation order.
    pub fn txt_values(&self, name: &str) -> Vec<String> {
        self.txt_records(name).into_iter().map(|r| r.data).collect()
    }

    /// The TXT records at `name`.
    pub fn txt_records(&self, name: &str) -> Vec<Record> {
        let inner = lock(&self.state);
        let wanted = given(name, inner.domains.first().map_or("", String::as_str));
        inner
            .records
            .iter()
            .filter(|r| r.rtype == "TXT" && absolute(&r.name, &r.domain) == wanted)
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
        data: &str,
        ttl: u32,
    ) -> u64 {
        let mut inner = lock(&self.state);
        inner.next_id += 1;
        let id = inner.next_id;
        inner.records.push(Record {
            id,
            domain: domain.to_owned(),
            name: relative(&given(name, domain), domain),
            rtype: rtype.to_owned(),
            data: data.to_owned(),
            ttl,
        });
        id
    }

    /// Deletes the record `id` directly, as another writer would.
    pub fn delete_record(&self, id: u64) {
        lock(&self.state).records.retain(|r| r.id != id);
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

    /// Caps `per_page` at `cap`, so that listings come in small pages.
    pub fn set_page_cap(&self, cap: usize) {
        lock(&self.state).page_cap = Some(cap.max(1));
    }

    /// The form in which answers state a record's name.
    pub fn set_name_form(&self, form: NameForm) {
        lock(&self.state).name_form = form;
    }

    /// Makes the `name` filter of the record listing match by substring.
    pub fn set_loose_filter(&self, loose: bool) {
        lock(&self.state).loose_filter = loose;
    }
}

/// The absolute name, lowercase, with a trailing dot, of `name` in `domain`: `@` is the domain,
/// a name with a trailing dot is absolute, any other is relative.
fn absolute(name: &str, domain: &str) -> String {
    let name = name.trim().to_lowercase();
    let domain = domain.to_lowercase();
    if name == "@" || name.is_empty() {
        format!("{domain}.")
    } else if name.ends_with('.') {
        name
    } else {
        format!("{name}.{domain}.")
    }
}

/// The absolute name of a name a test gives: `@`, a name that is the domain or ends with it
/// (with or without a trailing dot) is taken as absolute, any other as relative.
fn given(name: &str, domain: &str) -> String {
    let lower = name.trim().to_lowercase();
    let bare = lower.strip_suffix('.').unwrap_or(&lower);
    let domain = domain.to_lowercase();
    if bare == "@" {
        format!("{domain}.")
    } else if bare == domain || bare.ends_with(&format!(".{domain}")) {
        format!("{bare}.")
    } else {
        format!("{bare}.{domain}.")
    }
}

/// `name`, absolute, relative to `domain` as the mock stores it: `@` for the domain itself.
fn relative(name: &str, domain: &str) -> String {
    let name = name.trim().to_lowercase();
    let name = name.strip_suffix('.').unwrap_or(&name);
    let domain = domain.to_lowercase();
    if name == domain {
        "@".to_owned()
    } else {
        name.strip_suffix(&format!(".{domain}"))
            .unwrap_or(name)
            .to_owned()
    }
}

/// An error answer in the documented shape.
fn error(status: StatusCode, id: &str, message: &str) -> Response {
    (
        status,
        axum::Json(json!({"id": id, "message": message, "request_id": "00000000-mock"})),
    )
        .into_response()
}

fn unprocessable(message: &str) -> Response {
    error(
        StatusCode::UNPROCESSABLE_ENTITY,
        "unprocessable_entity",
        message,
    )
}

fn not_found() -> Response {
    error(
        StatusCode::NOT_FOUND,
        "not_found",
        "The resource you requested could not be found.",
    )
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
            "Unable to authenticate you.",
        ))
    }
}

fn query<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// One page of `items` by `per_page` and `page`, with `links` and `meta`.
fn paginate(
    state: &Shared,
    key: &str,
    items: Vec<Value>,
    pairs: &[(String, String)],
    link: &str,
) -> Response {
    let per_page = match query(pairs, "per_page").map(str::parse::<usize>) {
        None => DEFAULT_PER_PAGE,
        Some(Ok(n)) if (1..=MAX_PER_PAGE).contains(&n) => n,
        Some(_) => return unprocessable("per_page must be between 1 and 200"),
    };
    let page = match query(pairs, "page").map(str::parse::<usize>) {
        None => 1,
        Some(Ok(n)) if n >= 1 => n,
        Some(_) => return unprocessable("page must be at least 1"),
    };
    let per_page = lock(state)
        .page_cap
        .map_or(per_page, |cap| per_page.min(cap));
    let total = items.len();
    let shown: Vec<Value> = items
        .into_iter()
        .skip((page - 1) * per_page)
        .take(per_page)
        .collect();
    let mut pages = json!({});
    if page * per_page < total {
        // A link to a foreign host: a client must take the next page number, never this URL.
        pages["next"] = json!(format!("https://evil.example.test{link}?page={}", page + 1));
    }
    let mut body = json!({"links": {"pages": pages}, "meta": {"total": total}});
    body[key] = Value::Array(shown);
    axum::Json(body).into_response()
}

async fn account(State(state): State<Shared>, headers: HeaderMap) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    axum::Json(json!({"account": {"uuid": "00000000-mock", "status": "active"}})).into_response()
}

fn domain_json(name: &str) -> Value {
    json!({"name": name, "ttl": 1800, "zone_file": null})
}

async fn domains_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let items: Vec<Value> = lock(&state)
        .domains
        .iter()
        .map(|d| domain_json(d))
        .collect();
    paginate(&state, "domains", items, &pairs, "/v2/domains")
}

async fn domain_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    if !lock(&state).domains.contains(&domain) {
        return not_found();
    }
    axum::Json(json!({"domain": domain_json(&domain)})).into_response()
}

fn record_json(record: &Record, form: NameForm) -> Value {
    let name = match form {
        NameForm::Relative => record.name.clone(),
        NameForm::Absolute => absolute(&record.name, &record.domain),
    };
    json!({
        "id": record.id, "type": record.rtype, "name": name, "data": record.data,
        "priority": null, "port": null, "ttl": record.ttl, "weight": null, "flags": null,
        "tag": null
    })
}

async fn records_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(domain): Path<String>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let (items, link) = {
        let inner = lock(&state);
        if !inner.domains.contains(&domain) {
            return not_found();
        }
        let filter = query(&pairs, "name").map(str::to_lowercase);
        let filter = filter.as_deref().map(|f| f.strip_suffix('.').unwrap_or(f));
        let items: Vec<Value> = inner
            .records
            .iter()
            .filter(|r| r.domain == domain)
            .filter(|r| query(&pairs, "type").is_none_or(|t| t == r.rtype))
            .filter(|r| {
                let full = absolute(&r.name, &r.domain);
                let full = full.strip_suffix('.').unwrap_or(&full);
                filter.is_none_or(|f| {
                    if inner.loose_filter {
                        full.contains(f)
                    } else {
                        full == f
                    }
                })
            })
            .map(|r| record_json(r, inner.name_form))
            .collect();
        (items, format!("/v2/domains/{domain}/records"))
    };
    paginate(&state, "domain_records", items, &pairs, &link)
}

async fn record_create(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(domain): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    if !inner.domains.contains(&domain) {
        return not_found();
    }
    let Ok(body) = serde_json::from_slice::<Value>(&body) else {
        return unprocessable("the body is not JSON");
    };
    let Some(rtype) = body["type"].as_str() else {
        return unprocessable("type is required");
    };
    // `name` and `data` are required for TXT (OpenAPI `domain_record_txt`).
    let name = match body["name"].as_str().filter(|n| !n.is_empty()) {
        Some(name) => name,
        None if rtype == "TXT" => return unprocessable("name is required"),
        None => "@",
    };
    let Some(data) = body["data"].as_str().filter(|d| !d.is_empty()) else {
        return unprocessable("data is required");
    };
    let ttl = match body.get("ttl") {
        None | Some(Value::Null) => 1800,
        // The documented minimum is 30 seconds.
        Some(value) => match value
            .as_u64()
            .filter(|&t| t >= 30 && t <= u64::from(u32::MAX))
        {
            Some(ttl) => ttl as u32,
            None => return unprocessable("ttl must be an integer of at least 30"),
        },
    };
    if name.ends_with('.') {
        let absolute_name = name.to_lowercase();
        let domain_dot = format!("{}.", domain.to_lowercase());
        if absolute_name != domain_dot && !absolute_name.ends_with(&format!(".{domain_dot}")) {
            return unprocessable("name is outside the domain");
        }
    }
    inner.next_id += 1;
    let record = Record {
        id: inner.next_id,
        domain: domain.clone(),
        name: relative(&absolute(name, &domain), &domain),
        rtype: rtype.to_owned(),
        data: data.to_owned(),
        ttl,
    };
    let created = record_json(&record, inner.name_form);
    inner.records.push(record);
    (
        StatusCode::CREATED,
        axum::Json(json!({"domain_record": created})),
    )
        .into_response()
}

async fn record_delete(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((domain, id)): Path<(String, String)>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let Ok(id) = id.parse::<u64>() else {
        return not_found();
    };
    let mut inner = lock(&state);
    let before = inner.records.len();
    inner
        .records
        .retain(|r| !(r.domain == domain && r.id == id));
    if inner.records.len() == before {
        return not_found();
    }
    StatusCode::NO_CONTENT.into_response()
}
