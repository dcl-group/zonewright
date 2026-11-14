//! Mock of the Timeweb Cloud API: domains, their subdomains and DNS records, with the `v2`
//! record create, update and delete, the `v1` listings and the `v1` domain answer.
//!
//! Shapes follow the provider's public API description, <https://timeweb.cloud/api-docs> (the
//! OpenAPI document it is rendered from), the same source the client cites:
//!
//! - `GET /api/v1/domains` (`getDomains`): `limit` (integer, default 100), `offset` (integer,
//!   default 0); the answer holds `meta.total` and `domains`, each with `fqdn` and `subdomains`
//!   (each with `fqdn`, `id`, `linked_ip`).
//! - `GET /api/v1/domains/{fqdn}/dns-records` (`getDomainDNSRecords`): `fqdn` is the full name of
//!   a domain or a subdomain; `limit`, `offset`; the answer holds `meta.total` and `dns_records`
//!   with `type`, `id` (a number, nullable), `ttl` and `data` (`subdomain`, `value`); documented
//!   errors `400`, `401`, `404`, `429`, `500`.
//! - `POST /api/v2/domains/{fqdn}/dns-records` (`createDomainDNSRecordV2`): `fqdn` is the domain
//!   for a record at the apex, else the full name of the subdomain. The body is one of the
//!   documented per-type objects: `type` and `value` required for `A`, `AAAA`, `TXT`, `CNAME`;
//!   `type`, `value` and `priority` for `MX`; `type`, `service`, `protocol`, `priority`, `port`
//!   and `host` for `SRV`; `ttl` optional everywhere, `app_id` optional for `A`. `201` with a
//!   `dns_record` (`id`, `type`, `fqdn` of the main domain, `data` with `value` and the
//!   `subdomain` relative to the main domain, absent at the apex, `ttl`); documented errors
//!   `400`, `401`, `404`, `409`, `429`, `500`.
//! - `DELETE /api/v2/domains/{fqdn}/dns-records/{record_id}` (`deleteDomainDNSRecordV2`):
//!   `record_id` an integer; `204`; documented errors `400`, `401`, `404`, `429`, `500`.
//! - `PATCH /api/v2/domains/{fqdn}/dns-records/{record_id}` (`updateDomainDNSRecordV2`): the
//!   body is the create's per-type object, checked the same way; `200` with `dns_record`;
//!   documented errors `400`, `401`, `404`, `409`, `429`, `500`.
//! - `GET /api/v1/domains/{fqdn}` (`getDomain`): `domain` with `fqdn`, `id` and `subdomains`
//!   (each with `fqdn`, the full name, `id` and `linked_ip`), plus `response_id`; `404` for a name
//!   that is not a domain of the account.
//! - Values per type: A an IPv4 address, AAAA an IPv6 address (the create objects' descriptions);
//!   the listing states `data.priority` for a record that has one (the `dns-record` schema).
//! - Every error body is `{status_code, error_code, message, response_id}`; `Authorization:
//!   Bearer <token>` is required.
//!
//! The deprecated `v1` create and delete are not served: a client that sends them gets `405` (the
//! listing's path exists for `GET` only) or `404`.
//!
//! Answers this mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading. A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - the form in which a listing states a record's `subdomain`: relative to the main domain with
//!   `null` for the apex (the default, as the `v2` record schema describes it), or the full name
//!   ([`SubdomainForm`]);
//! - which records a listing holds: the listing of a domain holds every record of the domain,
//!   subdomains included; the listing of a subdomain holds the records at that name and at every
//!   name below it; a listing of a name that is neither a domain of the account nor a subdomain
//!   of one is `404`;
//! - a create at a name that is not yet a subdomain creates the subdomain (lego creates records
//!   at challenge names without creating a subdomain first), unless
//!   [`Control::set_require_subdomain`] makes it `404`, as the documentation's "created
//!   beforehand" could mean; a subdomain stays when its last record is deleted;
//! - a delete names the record at the name it is at: another name, even of the same domain, is
//!   `404`;
//! - a body key that the type's documented object does not have is refused with `400`;
//! - `limit` above 100 or below 1, an `offset` below 0, and a `limit` or `offset` that is not an
//!   integer are refused with `400`; `meta.total` counts all the records of the listing;
//! - a `ttl` that is not a non-negative integer is refused with `400`; a record created without
//!   `ttl` is listed without one (`null`);
//! - a `priority` that is not an integer from 0 to 65535 is refused with `400`;
//! - an update replaces the record's value, priority and TTL with those of the body: a body
//!   without `ttl` leaves the record without one (the strict reading of "the record will be
//!   updated with the information provided"); an update whose `type` differs from the record's,
//!   or that names the record at another name, is `400` and `404`;
//! - how an SRV record is listed: `value` holds the `host`, `priority` the priority, and the
//!   other fields are not listed (the listing's schema has no field for them);
//! - with [`Control::set_domain_listing_scope`] the listing of a domain holds only the records at
//!   the domain itself, the other reading of "all records of a domain or subdomain";
//! - the text and `error_code` of every error, the status of a delete of a missing record
//!   (`404`), and that the mock never answers `409`;
//! - a record can be listed with `id` as a whole float (`1001.0`, [`Control::set_float_ids`]) or
//!   with a `null` id ([`Control::set_null_id`]), both allowed by the schema's `number`,
//!   `nullable`.
//!
//! Error texts are invented.
//!
//! ```text
//! let mock = TimewebCloudMock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("POST", "/api/v2/domains/*/dns-records").status(500));
//! // ... drive the client against mock.base_url() ...
//! assert_eq!(mock.control().txt_values("_acme-challenge.example.org"), ["v1"]);
//! ```

// Reason: handlers return an axum `Response` as the error of a `Result` to answer early;
// boxing them would only add noise.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeSet, HashSet};
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde_json::{Map, Value, json};

use crate::MockServer;

/// Path of the API below the server's base URL.
pub const API_PATH: &str = "/api";

/// Largest `limit` the mock accepts (invented; the documentation states the default only).
const MAX_LIMIT: u64 = 100;

/// The documented create objects: type, required keys, optional keys.
const SHAPES: [(&str, &[&str], &[&str]); 6] = [
    ("A", &["type", "value"], &["ttl", "app_id"]),
    ("AAAA", &["type", "value"], &["ttl"]),
    ("TXT", &["type", "value"], &["ttl"]),
    ("CNAME", &["type", "value"], &["ttl"]),
    ("MX", &["type", "value", "priority"], &["ttl"]),
    (
        "SRV",
        &["type", "service", "protocol", "priority", "port", "host"],
        &["ttl"],
    ),
];

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
    /// Relative to the main domain; `null` for the apex.
    Relative,
    /// The full name without a trailing dot, the domain's own name for the apex.
    Full,
}

/// Which records the listing of a domain holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListingScope {
    /// Every record of the domain, those of its subdomains included (the default).
    Everything,
    /// Only the records at the domain itself.
    OwnName,
}

/// One record as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The record's identifier.
    pub id: u64,
    /// The main domain, without a trailing dot.
    pub domain: String,
    /// The owner name relative to the domain; empty for the apex.
    pub subdomain: String,
    /// The record type.
    pub rtype: String,
    /// The value (for `SRV`, the `host`).
    pub value: String,
    /// TTL in seconds; `None` when none was given.
    pub ttl: Option<u64>,
    /// The MX or SRV priority; `None` for the other types.
    pub priority: Option<u64>,
}

#[derive(Debug)]
struct Inner {
    token: String,
    domains: Vec<String>,
    /// Subdomains: (domain, name relative to it).
    subdomains: BTreeSet<(String, String)>,
    records: Vec<Record>,
    next_id: u64,
    /// Caps `limit`, to force small pages.
    page_cap: Option<u64>,
    form: SubdomainForm,
    float_ids: bool,
    /// Records the listing shows with a `null` id.
    null_ids: HashSet<u64>,
    /// A create at a name that is not a subdomain yet is `404`.
    require_subdomain: bool,
    scope: ListingScope,
}

impl Inner {
    /// The domain of the account that `fqdn` is, or is below, and the name relative to it
    /// (empty for the domain itself). The longest matching domain wins.
    fn locate(&self, fqdn: &str) -> Option<(String, String)> {
        let fqdn = fqdn.to_lowercase();
        self.domains
            .iter()
            .filter_map(|domain| {
                let domain = domain.to_lowercase();
                if fqdn == domain {
                    Some((domain, String::new()))
                } else {
                    fqdn.strip_suffix(&format!(".{domain}"))
                        .map(|rel| (domain.clone(), rel.to_owned()))
                }
            })
            .max_by_key(|(domain, _)| domain.len())
    }
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
            subdomains: BTreeSet::new(),
            records: Vec::new(),
            next_id: 1000,
            page_cap: None,
            form: SubdomainForm::Relative,
            float_ids: false,
            null_ids: HashSet::new(),
            require_subdomain: false,
            scope: ListingScope::Everything,
        }));
        let router = Router::new()
            .route("/api/v1/domains", get(domains_list))
            .route("/api/v1/domains/{fqdn}", get(domain_get))
            .route("/api/v1/domains/{fqdn}/dns-records", get(records_list))
            .route("/api/v2/domains/{fqdn}/dns-records", post(record_create))
            .route(
                "/api/v2/domains/{fqdn}/dns-records/{id}",
                delete(record_delete).patch(record_update),
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

    /// The records of `rtype` at `name` (absolute, or relative to the first domain), in creation
    /// order.
    pub fn records_at(&self, name: &str, rtype: &str) -> Vec<Record> {
        let inner = lock(&self.state);
        let domain = inner.domains.first().map_or("", String::as_str);
        let wanted = relative(name, domain);
        inner
            .records
            .iter()
            .filter(|r| r.rtype == rtype && r.subdomain == wanted)
            .cloned()
            .collect()
    }

    /// The full names of the subdomains, sorted.
    pub fn subdomains(&self) -> Vec<String> {
        lock(&self.state)
            .subdomains
            .iter()
            .map(|(domain, rel)| format!("{rel}.{domain}"))
            .collect()
    }

    /// Adds a record directly, as another writer would. `name` is absolute or relative to the
    /// domain; a name below the domain becomes a subdomain. Returns the record's identifier.
    pub fn insert_record(
        &self,
        domain: &str,
        name: &str,
        rtype: &str,
        value: &str,
        ttl: Option<u64>,
    ) -> u64 {
        self.insert_record_with(domain, name, rtype, value, ttl, None)
    }

    /// [`Control::insert_record`] with a priority.
    pub fn insert_record_with(
        &self,
        domain: &str,
        name: &str,
        rtype: &str,
        value: &str,
        ttl: Option<u64>,
        priority: Option<u64>,
    ) -> u64 {
        let mut inner = lock(&self.state);
        inner.next_id += 1;
        let id = inner.next_id;
        let subdomain = relative(name, domain);
        if !subdomain.is_empty() {
            inner
                .subdomains
                .insert((domain.to_owned(), subdomain.clone()));
        }
        inner.records.push(Record {
            id,
            domain: domain.to_owned(),
            subdomain,
            rtype: rtype.to_owned(),
            value: value.to_owned(),
            ttl,
            priority,
        });
        id
    }

    /// Adds a subdomain of `domain` (`name` absolute or relative), as the documented
    /// `POST /api/v1/domains/{fqdn}/subdomains/{subdomain}` would.
    pub fn insert_subdomain(&self, domain: &str, name: &str) {
        let subdomain = relative(name, domain);
        lock(&self.state)
            .subdomains
            .insert((domain.to_owned(), subdomain));
    }

    /// Which records the listing of a domain holds.
    pub fn set_domain_listing_scope(&self, scope: ListingScope) {
        lock(&self.state).scope = scope;
    }

    /// Deletes the record `id` directly, as another writer would.
    pub fn delete_record(&self, id: u64) {
        lock(&self.state).records.retain(|r| r.id != id);
    }

    /// Changes the record `id` in place, keeping its identifier, as another writer would with
    /// the documented `PATCH /api/v2/domains/{fqdn}/dns-records/{record_id}`.
    pub fn update_record(&self, id: u64, value: &str) {
        let mut inner = lock(&self.state);
        if let Some(record) = inner.records.iter_mut().find(|r| r.id == id) {
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

    /// A create at a name that is not a subdomain yet is answered `404` instead of creating the
    /// subdomain.
    pub fn set_require_subdomain(&self, require: bool) {
        lock(&self.state).require_subdomain = require;
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
    let inner = lock(&state);
    let items: Vec<Value> = inner
        .domains
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let subdomains: Vec<Value> = inner
                .subdomains
                .iter()
                .filter(|(domain, _)| domain == d)
                .enumerate()
                .map(|(j, (_, rel))| {
                    json!({"id": 5000 + j, "fqdn": format!("{rel}.{d}"), "linked_ip": null})
                })
                .collect();
            json!({"id": i + 1, "fqdn": d, "subdomains": subdomains, "linked_ip": null})
        })
        .collect();
    drop(inner);
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

/// A record as a listing states it.
fn record_json(inner: &Inner, record: &Record) -> Value {
    let subdomain = match (inner.form, record.subdomain.is_empty()) {
        (SubdomainForm::Relative, true) => Value::Null,
        (SubdomainForm::Relative, false) => json!(record.subdomain),
        (SubdomainForm::Full, true) => json!(record.domain),
        (SubdomainForm::Full, false) => json!(format!("{}.{}", record.subdomain, record.domain)),
    };
    let mut data = Map::new();
    data.insert("subdomain".into(), subdomain);
    data.insert("value".into(), json!(record.value));
    if let Some(priority) = record.priority {
        data.insert("priority".into(), json!(priority));
    }
    json!({
        "id": id_json(inner, record.id),
        "type": record.rtype,
        "ttl": record.ttl,
        "data": data,
    })
}

/// A record as the `v2` create states it: the main domain in `fqdn`, the name relative to it
/// in `data.subdomain`, absent at the apex.
fn created_json(record: &Record) -> Value {
    let mut data = Map::new();
    data.insert("value".into(), json!(record.value));
    if let Some(priority) = record.priority {
        data.insert("priority".into(), json!(priority));
    }
    if !record.subdomain.is_empty() {
        data.insert("subdomain".into(), json!(record.subdomain));
    }
    json!({
        "id": record.id,
        "type": record.rtype,
        "fqdn": record.domain,
        "data": data,
        "ttl": record.ttl,
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
    let Some((domain, rel)) = inner.locate(&fqdn) else {
        return not_found("Domain not found");
    };
    if !rel.is_empty() && !inner.subdomains.contains(&(domain.clone(), rel.clone())) {
        return not_found("Subdomain not found");
    }
    let below = format!(".{rel}");
    let own_only = inner.scope == ListingScope::OwnName;
    let items: Vec<Value> = inner
        .records
        .iter()
        .filter(|r| {
            r.domain == domain
                && if rel.is_empty() {
                    !own_only || r.subdomain.is_empty()
                } else {
                    r.subdomain == rel || r.subdomain.ends_with(&below)
                }
        })
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

/// The fields of a create or update body, checked against the documented object of its type.
struct Fields {
    rtype: String,
    value: String,
    ttl: Option<u64>,
    priority: Option<u64>,
}

/// The fields of a create or update body, checked against the documented object of its type.
fn create_fields(body: &[u8]) -> Result<Fields, Response> {
    let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(body) else {
        return Err(bad_request("the body is not a JSON object"));
    };
    let rtype = body.get("type").and_then(Value::as_str).unwrap_or("");
    let Some((_, required, optional)) = SHAPES.iter().find(|(t, _, _)| *t == rtype) else {
        return Err(bad_request(
            "type is required and must be one of the record types",
        ));
    };
    for key in *required {
        if body.get(*key).is_none_or(Value::is_null) {
            return Err(bad_request(&format!("{key} is required")));
        }
    }
    if let Some(key) = body
        .keys()
        .find(|k| !required.contains(&k.as_str()) && !optional.contains(&k.as_str()))
    {
        return Err(bad_request(&format!("{key} is not a field of this type")));
    }
    let text = |key: &str| body.get(key).and_then(Value::as_str).map(str::to_owned);
    let value = if rtype == "SRV" {
        text("host")
    } else {
        text("value")
    };
    let Some(value) = value else {
        return Err(bad_request("value must be a string"));
    };
    let valid = match rtype {
        "A" => value.parse::<std::net::Ipv4Addr>().is_ok(),
        "AAAA" => value.parse::<std::net::Ipv6Addr>().is_ok(),
        _ => !value.is_empty(),
    };
    if !valid {
        return Err(bad_request("value is not valid for the record type"));
    }
    let priority = match body.get("priority") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_u64().filter(|p| *p <= 65_535) {
            Some(priority) => Some(priority),
            None => return Err(bad_request("priority must be an integer from 0 to 65535")),
        },
    };
    let ttl = match body.get("ttl") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_u64() {
            Some(ttl) => Some(ttl),
            None => return Err(bad_request("ttl must be a non-negative integer")),
        },
    };
    Ok(Fields {
        rtype: rtype.to_owned(),
        value,
        ttl,
        priority,
    })
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
    let Some((domain, rel)) = inner.locate(&fqdn) else {
        return not_found("Domain not found");
    };
    let Fields {
        rtype,
        value,
        ttl,
        priority,
    } = match create_fields(&body) {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    if !rel.is_empty() {
        let key = (domain.clone(), rel.clone());
        if !inner.subdomains.contains(&key) {
            if inner.require_subdomain {
                return not_found("Subdomain not found");
            }
            inner.subdomains.insert(key);
        }
    }
    inner.next_id += 1;
    let record = Record {
        id: inner.next_id,
        domain,
        subdomain: rel,
        rtype,
        value,
        ttl,
        priority,
    };
    let created = created_json(&record);
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
    let Some((domain, rel)) = inner.locate(&fqdn) else {
        return not_found("Domain not found");
    };
    let Ok(id) = id.parse::<u64>() else {
        return bad_request("record_id must be an integer");
    };
    let before = inner.records.len();
    inner
        .records
        .retain(|r| !(r.domain == domain && r.subdomain == rel && r.id == id));
    if inner.records.len() == before {
        return not_found("DNS record not found");
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn record_update(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((fqdn, id)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    let Some((domain, rel)) = inner.locate(&fqdn) else {
        return not_found("Domain not found");
    };
    let Ok(id) = id.parse::<u64>() else {
        return bad_request("record_id must be an integer");
    };
    let fields = match create_fields(&body) {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let Some(record) = inner
        .records
        .iter_mut()
        .find(|r| r.domain == domain && r.subdomain == rel && r.id == id)
    else {
        return not_found("DNS record not found");
    };
    if record.rtype != fields.rtype {
        return bad_request("the type of a record cannot be changed");
    }
    record.value = fields.value;
    record.ttl = fields.ttl;
    record.priority = fields.priority;
    let updated = created_json(record);
    axum::Json(json!({
        "dns_record": updated,
        "response_id": "00000000-0000-0000-0000-00000000mock",
    }))
    .into_response()
}

async fn domain_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(fqdn): Path<String>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let inner = lock(&state);
    let fqdn = fqdn.to_lowercase();
    let Some((index, domain)) = inner
        .domains
        .iter()
        .enumerate()
        .find(|(_, d)| d.to_lowercase() == fqdn)
    else {
        return not_found("Domain not found");
    };
    let subdomains: Vec<Value> = inner
        .subdomains
        .iter()
        .filter(|(d, _)| d == domain)
        .enumerate()
        .map(|(j, (_, rel))| {
            json!({"id": 5000 + j, "fqdn": format!("{rel}.{domain}"), "linked_ip": null})
        })
        .collect();
    axum::Json(json!({
        "domain": {"id": index + 1, "fqdn": domain, "subdomains": subdomains, "linked_ip": null},
        "response_id": "00000000-0000-0000-0000-00000000mock",
    }))
    .into_response()
}
