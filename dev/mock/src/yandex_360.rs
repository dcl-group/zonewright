//! Mock of the Yandex 360 API (`DomainDNSService` and the domain listing).
//!
//! Shapes follow the provider's documentation, the same sources the client cites:
//!
//! - Create: <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Create>:
//!   `POST /directory/v1/org/{orgId}/domains/{domain}/dns` with `type`, `name` and `ttl`
//!   required (and `text` for a TXT record); `200` with the record and its `recordId`; `400`,
//!   `401`, `403`, `404`, `500` with the body `{code, message, details}`.
//! - List: <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_List>:
//!   `GET` on the same path with `page` (default 1) and `perPage` (default 50); the answer holds
//!   `records`, `page`, `pages`, `perPage`, `total`.
//! - Delete: <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Delete>:
//!   `DELETE …/dns/{recordId}`, `200` with `{}`.
//! - Domains: <https://yandex.ru/dev/api360/doc/ru/ref/DomainService/DomainService_List>:
//!   `GET /directory/v1/org/{orgId}/domains` with `page` and `perPage` (maximum 10); the answer
//!   holds `domains` (each with `name` and `delegated`), `page`, `pages`, `perPage`, `total`.
//! - Access: <https://yandex.ru/dev/api360/doc/ru/access.md>: `Authorization: OAuth <token>`.
//!
//! Answers this mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading. A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - the answer to a request for a domain of another organization is `403`, and for a domain the
//!   organization does not have `404` (the documentation lists both statuses without saying
//!   when);
//! - the DNS endpoints refuse a domain that is not delegated with `400` (the documentation does
//!   not say what they answer);
//! - the `name` of a created record is read as relative to the domain, as lego sends it; `@` and
//!   an empty name are refused with `400`, since nothing documents the spelling of the apex; a
//!   record the test inserts at the apex is stated as `@` ([`NameForm::Relative`]) or as the
//!   domain's full name ([`NameForm::Full`]), and the full form is the one the listing page's
//!   field description names;
//! - a `ttl` that is not a positive integer is refused with `400`; no range is enforced, as
//!   none is documented;
//! - the listing has no filter, so `type` and `name` in the query are ignored;
//! - a `page` or `perPage` below 1 is refused with `400`; the records listing has no maximum
//!   `perPage` here, the domain listing has the documented 10;
//! - `pages` is at least 1, also for an empty listing;
//! - a `recordId` in a path that is not a number is `400`, an unknown one `404`.
//!
//! Error texts are invented.
//!
//! A test holds a [`Yandex360Mock`]. It dereferences to the [`MockServer`], so the request log
//! and the fault queue of the shared harness work as usual:
//!
//! ```text
//! let mock = Yandex360Mock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("POST", "/directory/v1/org/*/domains/*/dns").status(500));
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

/// The organization the standard seed accepts.
pub const ORG_ID: &str = "7654321";

/// Largest `perPage` of the domain listing.
const MAX_DOMAINS_PER_PAGE: usize = 10;

/// Default `perPage` of the record listing.
const DEFAULT_RECORDS_PER_PAGE: usize = 50;

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The organization the token belongs to.
    pub org_id: String,
    /// The OAuth token the API accepts.
    pub token: String,
    /// The domains of the organization, without a trailing dot, with whether each is delegated
    /// to Yandex name servers.
    pub domains: Vec<(String, bool)>,
}

impl Seed {
    /// Organization `7654321`, token `test-only-token` and the delegated domain `example.org`.
    pub fn standard() -> Self {
        Self {
            org_id: ORG_ID.into(),
            token: "test-only-token".into(),
            domains: vec![("example.org".into(), true)],
        }
    }
}

/// The form in which a listing states a record's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameForm {
    /// Relative to the domain, `@` for the apex.
    Relative,
    /// The full name, without a trailing dot.
    Full,
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
    pub text: String,
    /// TTL in seconds.
    pub ttl: u32,
}

#[derive(Debug)]
struct Inner {
    org_id: String,
    token: String,
    domains: Vec<(String, bool)>,
    records: Vec<Record>,
    next_id: u64,
    /// Caps `perPage`, to force small pages.
    page_cap: Option<usize>,
    name_form: NameForm,
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running Yandex 360 mock. Dereferences to its [`MockServer`] for the request log and the
/// fault queue; [`Yandex360Mock::control`] reads and changes the state.
#[derive(Debug)]
pub struct Yandex360Mock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of a [`Yandex360Mock`]. Cheap to clone, so that a fault hook
/// ([`Fault::run`](crate::Fault::run)) can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
}

impl Deref for Yandex360Mock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl Yandex360Mock {
    /// Starts the mock with `seed`.
    pub async fn start(seed: Seed) -> Self {
        let state = Arc::new(Mutex::new(Inner {
            org_id: seed.org_id,
            token: seed.token,
            domains: seed.domains,
            records: Vec::new(),
            next_id: 1000,
            page_cap: None,
            name_form: NameForm::Relative,
        }));
        let router = Router::new()
            .route("/directory/v1/org/{org}/domains", get(domains_list))
            .route(
                "/directory/v1/org/{org}/domains/{domain}/dns",
                get(records_list).post(record_create),
            )
            .route(
                "/directory/v1/org/{org}/domains/{domain}/dns/{id}",
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
        self.server.url("")
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
        self.txt_records(name).into_iter().map(|r| r.text).collect()
    }

    /// The TXT records at `name`.
    pub fn txt_records(&self, name: &str) -> Vec<Record> {
        let inner = lock(&self.state);
        let domain = inner.domains.first().map_or("", |d| d.0.as_str());
        let wanted = relative(name, domain);
        inner
            .records
            .iter()
            .filter(|r| r.rtype == "TXT" && r.domain == domain && r.name == wanted)
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
        text: &str,
        ttl: u32,
    ) -> u64 {
        let mut inner = lock(&self.state);
        inner.next_id += 1;
        let id = inner.next_id;
        inner.records.push(Record {
            id,
            domain: domain.to_owned(),
            name: relative(name, domain),
            rtype: rtype.to_owned(),
            text: text.to_owned(),
            ttl,
        });
        id
    }

    /// Deletes the record `id` directly, as another writer would.
    pub fn delete_record(&self, id: u64) {
        lock(&self.state).records.retain(|r| r.id != id);
    }

    /// Adds a domain, delegated or not.
    pub fn insert_domain(&self, domain: &str, delegated: bool) {
        lock(&self.state)
            .domains
            .push((domain.to_owned(), delegated));
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

    /// Caps `perPage` at `cap`, so that listings come in small pages.
    pub fn set_page_cap(&self, cap: usize) {
        lock(&self.state).page_cap = Some(cap.max(1));
    }

    /// The form in which listings state a record's name.
    pub fn set_name_form(&self, form: NameForm) {
        lock(&self.state).name_form = form;
    }
}

/// `name` relative to `domain` as the mock stores it: `@` for the domain itself. A name that is
/// the domain or ends with it is absolute (with or without a trailing dot); any other is
/// relative already.
fn relative(name: &str, domain: &str) -> String {
    let name = name.trim().to_lowercase();
    let name = name.strip_suffix('.').unwrap_or(&name);
    let domain = domain.to_lowercase();
    if name == domain || name.is_empty() || name == "@" {
        "@".to_owned()
    } else {
        name.strip_suffix(&format!(".{domain}"))
            .unwrap_or(name)
            .to_owned()
    }
}

/// An error answer in the documented shape.
fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        axum::Json(json!({"code": status.as_u16(), "message": message, "details": []})),
    )
        .into_response()
}

fn bad_request(message: &str) -> Response {
    error(StatusCode::BAD_REQUEST, message)
}

fn not_found() -> Response {
    error(StatusCode::NOT_FOUND, "the resource was not found")
}

/// `Ok` when the request carries the token of the seed and names the seed's organization.
fn authorize(inner: &Inner, headers: &HeaderMap, org: &str) -> Result<(), Response> {
    let want = format!("OAuth {}", inner.token);
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(want.as_str()) {
        return Err(error(StatusCode::UNAUTHORIZED, "not authorized"));
    }
    if org != inner.org_id {
        return Err(error(
            StatusCode::FORBIDDEN,
            "no access to the organization",
        ));
    }
    Ok(())
}

fn query<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// One page of `items` by `perPage` and `page`, with `pages` and `total`.
fn paginate(
    inner: &Inner,
    key: &str,
    items: Vec<Value>,
    pairs: &[(String, String)],
    default_per_page: usize,
    max_per_page: Option<usize>,
) -> Response {
    let per_page = match query(pairs, "perPage").map(str::parse::<usize>) {
        None => default_per_page,
        Some(Ok(n)) if n >= 1 && max_per_page.is_none_or(|max| n <= max) => n,
        Some(_) => return bad_request("perPage is out of range"),
    };
    let page = match query(pairs, "page").map(str::parse::<usize>) {
        None => 1,
        Some(Ok(n)) if n >= 1 => n,
        Some(_) => return bad_request("page must be at least 1"),
    };
    let per_page = inner.page_cap.map_or(per_page, |cap| per_page.min(cap));
    let total = items.len();
    let pages = total.div_ceil(per_page).max(1);
    let shown: Vec<Value> = items
        .into_iter()
        .skip((page - 1) * per_page)
        .take(per_page)
        .collect();
    let mut body = json!({"page": page, "pages": pages, "perPage": per_page, "total": total});
    body[key] = Value::Array(shown);
    axum::Json(body).into_response()
}

async fn domains_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(org): Path<String>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let inner = lock(&state);
    if let Err(response) = authorize(&inner, &headers, &org) {
        return response;
    }
    let items: Vec<Value> = inner
        .domains
        .iter()
        .map(|(name, delegated)| {
            json!({
                "name": name, "country": "RU", "delegated": delegated, "master": true,
                "mx": false, "verified": true
            })
        })
        .collect();
    paginate(
        &inner,
        "domains",
        items,
        &pairs,
        MAX_DOMAINS_PER_PAGE,
        Some(MAX_DOMAINS_PER_PAGE),
    )
}

/// Authorizes and finds the domain; `Err` is the answer to give.
fn domain_of(inner: &Inner, headers: &HeaderMap, org: &str, domain: &str) -> Result<(), Response> {
    authorize(inner, headers, org)?;
    match inner.domains.iter().find(|(name, _)| name == domain) {
        None => Err(not_found()),
        Some((_, false)) => Err(bad_request("the domain is not delegated")),
        Some(_) => Ok(()),
    }
}

fn record_json(record: &Record, form: NameForm) -> Value {
    let name = match (form, record.name.as_str()) {
        (NameForm::Relative, name) => name.to_owned(),
        (NameForm::Full, "@") => record.domain.clone(),
        (NameForm::Full, name) => format!("{name}.{}", record.domain),
    };
    json!({
        "recordId": record.id, "type": record.rtype, "name": name, "ttl": record.ttl,
        "text": record.text
    })
}

async fn records_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((org, domain)): Path<(String, String)>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let inner = lock(&state);
    if let Err(response) = domain_of(&inner, &headers, &org, &domain) {
        return response;
    }
    let items: Vec<Value> = inner
        .records
        .iter()
        .filter(|r| r.domain == domain)
        .map(|r| record_json(r, inner.name_form))
        .collect();
    paginate(
        &inner,
        "records",
        items,
        &pairs,
        DEFAULT_RECORDS_PER_PAGE,
        None,
    )
}

async fn record_create(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((org, domain)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Response {
    let mut inner = lock(&state);
    if let Err(response) = domain_of(&inner, &headers, &org, &domain) {
        return response;
    }
    let Ok(body) = serde_json::from_slice::<Value>(&body) else {
        return bad_request("the body is not JSON");
    };
    // `type`, `name` and `ttl` are required; `text` carries a TXT record's value.
    let Some(rtype) = body["type"].as_str() else {
        return bad_request("type is required");
    };
    let Some(name) = body["name"].as_str() else {
        return bad_request("name is required");
    };
    if name.is_empty() || name == "@" {
        return bad_request("the name is empty");
    }
    let Some(ttl) = body["ttl"]
        .as_u64()
        .filter(|&t| t >= 1 && t <= u64::from(u32::MAX))
    else {
        return bad_request("ttl is required and must be a positive integer");
    };
    let Some(text) = body["text"].as_str().filter(|t| !t.is_empty()) else {
        return bad_request("text is required for a TXT record");
    };
    inner.next_id += 1;
    let record = Record {
        id: inner.next_id,
        domain: domain.clone(),
        // Relative to the domain, as lego sends it: stored as given.
        name: name.to_lowercase(),
        rtype: rtype.to_owned(),
        text: text.to_owned(),
        ttl: ttl as u32,
    };
    let created = record_json(&record, inner.name_form);
    inner.records.push(record);
    axum::Json(created).into_response()
}

async fn record_delete(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((org, domain, id)): Path<(String, String, String)>,
) -> Response {
    let mut inner = lock(&state);
    if let Err(response) = domain_of(&inner, &headers, &org, &domain) {
        return response;
    }
    let Ok(id) = id.parse::<u64>() else {
        return bad_request("recordId is not a number");
    };
    let before = inner.records.len();
    inner
        .records
        .retain(|r| !(r.domain == domain && r.id == id));
    if inner.records.len() == before {
        return not_found();
    }
    axum::Json(json!({})).into_response()
}
