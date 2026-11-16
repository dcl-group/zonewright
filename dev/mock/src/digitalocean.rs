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
//!   generated `id`; `404` documented), update by PATCH (`200` with the `domain_record`, `404`
//!   documented; the body's schema requires only `type`), delete (`204` with an empty body,
//!   `404` when missing),
//!   error bodies `{id, message, request_id}` with the ids `unauthorized`, `not_found`,
//!   `too_many_requests`, `server_error`; answers state record names relative to the domain,
//!   `@` for the apex (the reference's examples).
//! - Record fields per type (OpenAPI `models/domain_record.yml` and
//!   `models/domain_record_types.yml`, commit `9981928`): `data` and `name` required for A, AAAA,
//!   CNAME, TXT, NS, SRV and CAA; `priority` required for MX and SRV, `port` for SRV, `flags`
//!   and `tag` for CAA; `flags` "between 0-255"; `tag` "issue", "issuewild" or "iodef"; fields
//!   that do not apply are `null` in answers. SOA "Can only have ttl changed, cannot be deleted"
//!   (the API's record type table).
//! - CAA (DNS limits page): neither `;` as the value nor name-value parameters after the CA name
//!   are supported.
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
//! - the status of a refused create or update: `422` for a record without `type`, a type outside
//!   the documented list, a missing required field, an A or AAAA `data` that is not an address,
//!   a CAA field outside the documented values, a `priority`, `port` or `weight` outside 0 to
//!   65535, a `ttl` that is not an integer of at least 30, a create of SOA, an update that
//!   changes the type or anything of an SOA record but its `ttl`; a record created without `ttl`
//!   gets 1800;
//! - leniency where the documentation is stricter than observed use: the OpenAPI lists `flags`
//!   and `tag` as required (nullable) for NS, SRV and TXT too, but lego creates TXT records
//!   without them; the mock does not require them for any type but CAA, and a test that relies
//!   on this proves nothing about the provider;
//! - `name` is not required for MX (its schema does not list it) and defaults to `@`;
//! - `data` is stored and answered exactly as sent (host names keep or lack their trailing dot);
//!   with [`Control::set_apex_target_as_at`], the `data` of a CNAME, MX, NS or SRV record that
//!   names the domain itself (with or without a trailing dot) is answered as `@`, the form
//!   DigitalOcean's Terraform provider expects (`digitalocean/domain/resource_record.go`, the
//!   read, at commit `5c5eea1`); the reference shows no example of it;
//! - [`Control::insert_zone_defaults`] seeds an SOA record whose `data` is `1800` and three NS
//!   records at the apex; the SOA's `data` form is not documented;
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
//!
//! The mock is a [`ChangeSource`]: it reports every change of its published records through
//! [`DigitalOceanMock::changes`], the records of one name and type grouped into one rrset (the
//! TTL of the set the smallest of its records), and a [`link`](crate::link::link) serves them
//! over DNS. Published are the records of the account's domains, each at its absolute name. The
//! form of a value: A and AAAA `data`; TXT `data`, the value itself, as one quoted
//! character-string (split every 255 bytes); CNAME and NS `data` with the trailing dot added (a
//! host name in `data` is absolute, `@` the domain itself); MX as `<priority> <host>.`; SRV as
//! `<priority> <weight> <port> <target>.`; CAA as `<flags> <tag> "<data>"`. Left out: SOA records
//! (a DNS server for the zone has its own) and records of a domain that is not on the account.
//! The answer switches ([`Control::set_name_form`], [`Control::set_apex_target_as_at`]) change
//! only the API's answers, not what is published. [`Control::reset`] returns the mock to its
//! seed.

#![allow(clippy::result_large_err)]

use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Value, json};

use crate::changes::{ChangeSource, Changes, Origin, Published};
use crate::{Faults, MockServer, RequestLog};

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

/// The fields of a record beyond `data`, `null` when absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fields {
    /// MX and SRV priority.
    pub priority: Option<u64>,
    /// SRV port.
    pub port: Option<u64>,
    /// SRV weight.
    pub weight: Option<u64>,
    /// CAA flags.
    pub flags: Option<u64>,
    /// CAA tag.
    pub tag: Option<String>,
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
    /// The fields beyond `data`.
    pub fields: Fields,
}

#[derive(Debug)]
struct Inner {
    /// The seed the mock was started with, for [`Control::reset`].
    seed: Seed,
    changes: Changes,
    token: String,
    domains: Vec<String>,
    records: Vec<Record>,
    next_id: u64,
    /// Caps `per_page`, to force small pages.
    page_cap: Option<usize>,
    name_form: NameForm,
    loose_filter: bool,
    apex_target_as_at: bool,
}

impl Inner {
    /// The state of a mock started with `seed`.
    fn new(seed: Seed, changes: Changes) -> Inner {
        Inner {
            seed: seed.clone(),
            changes,
            token: seed.token,
            domains: seed.domains,
            records: Vec::new(),
            next_id: 1000,
            page_cap: None,
            name_form: NameForm::Relative,
            loose_filter: false,
            apex_target_as_at: false,
        }
    }

    /// What a DNS server for the mock's domains would answer (module documentation).
    fn published(&self) -> Published {
        let mut out = Published::new();
        for domain in &self.domains {
            out.zone(domain);
        }
        for record in &self.records {
            if !self.domains.contains(&record.domain) {
                continue;
            }
            let host = |data: &str| {
                if data.trim() == "@" {
                    format!("{}.", record.domain.to_lowercase())
                } else {
                    format!("{}.", data.trim().trim_end_matches('.'))
                }
            };
            let f = &record.fields;
            let n = |v: Option<u64>| v.unwrap_or(0);
            let value = match record.rtype.as_str() {
                "TXT" => quoted(&record.data),
                "CNAME" | "NS" => host(&record.data),
                "MX" => format!("{} {}", n(f.priority), host(&record.data)),
                "SRV" => format!(
                    "{} {} {} {}",
                    n(f.priority),
                    n(f.weight),
                    n(f.port),
                    host(&record.data)
                ),
                "CAA" => format!(
                    "{} {} {}",
                    n(f.flags),
                    f.tag.as_deref().unwrap_or_default(),
                    quoted(&record.data)
                ),
                // A DNS server for the zone answers its own SOA.
                "SOA" => continue,
                _ => record.data.clone(),
            };
            out.record(
                &record.domain,
                &absolute(&record.name, &record.domain),
                &record.rtype,
                Some(record.ttl),
                value,
            );
        }
        out
    }

    /// Reports every published rrset that differs from `before`. Called with the state locked,
    /// after a change.
    fn report(&self, before: &Published, origin: Origin) {
        self.changes.emit_diff(before, &self.published(), origin);
    }
}

/// `text` as quoted character-strings of at most 255 bytes, `"` and `\` escaped.
fn quoted(text: &str) -> String {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return "\"\"".to_owned();
    }
    bytes
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
    changes: Changes,
    log: RequestLog,
    faults: Faults,
}

impl Deref for DigitalOceanMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl DigitalOceanMock {
    /// Starts the mock with `seed` on `127.0.0.1` with an ephemeral port.
    pub async fn start(seed: Seed) -> Self {
        Self::start_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), seed).await
    }

    /// Starts the mock with `seed` on `addr` ([`MockServer::start_on`]).
    pub async fn start_on(addr: SocketAddr, seed: Seed) -> Self {
        let changes = Changes::new();
        let state = Arc::new(Mutex::new(Inner::new(seed, changes.clone())));
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
                axum::routing::delete(record_delete).patch(record_update),
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

impl ChangeSource for DigitalOceanMock {
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

    /// Returns the mock to the seed it was started with: its token and domains, no records,
    /// identifiers counted from the start again, the default answer forms and filter, no page
    /// cap, an empty request log and no pending faults. Reports the removal of every rrset that
    /// was published.
    pub fn reset(&self) {
        self.faults.clear();
        self.change(|inner| {
            let seed = inner.seed.clone();
            *inner = Inner::new(seed, inner.changes.clone());
        });
        self.log.clear();
    }

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

    /// The records of type `rtype` at `name` (absolute or relative to the first domain), in
    /// creation order.
    pub fn records_at(&self, name: &str, rtype: &str) -> Vec<Record> {
        let inner = lock(&self.state);
        let wanted = given(name, inner.domains.first().map_or("", String::as_str));
        inner
            .records
            .iter()
            .filter(|r| r.rtype == rtype && absolute(&r.name, &r.domain) == wanted)
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
        self.insert_record_with(domain, name, rtype, data, ttl, Fields::default())
    }

    /// [`Control::insert_record`] with the fields beyond `data`.
    pub fn insert_record_with(
        &self,
        domain: &str,
        name: &str,
        rtype: &str,
        data: &str,
        ttl: u32,
        fields: Fields,
    ) -> u64 {
        self.change(|inner| {
            inner.next_id += 1;
            let id = inner.next_id;
            inner.records.push(Record {
                id,
                domain: domain.to_owned(),
                name: relative(&given(name, domain), domain),
                rtype: rtype.to_owned(),
                data: data.to_owned(),
                ttl,
                fields,
            });
            id
        })
    }

    /// Seeds what the provider creates with a domain: an SOA record and three NS records at the
    /// apex (the SOA's `data` is invented, see the module documentation).
    pub fn insert_zone_defaults(&self, domain: &str) {
        self.insert_record(domain, "@", "SOA", "1800", 1800);
        for ns in [
            "ns1.digitalocean.com",
            "ns2.digitalocean.com",
            "ns3.digitalocean.com",
        ] {
            self.insert_record(domain, "@", "NS", ns, 1800);
        }
    }

    /// Deletes the record `id` directly, as another writer would.
    pub fn delete_record(&self, id: u64) {
        self.change(|inner| inner.records.retain(|r| r.id != id));
    }

    /// Adds a domain.
    pub fn insert_domain(&self, domain: &str) {
        self.change(|inner| inner.domains.push(domain.to_owned()));
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

    /// Answers a CNAME, MX, NS or SRV `data` that names the domain itself as `@`.
    pub fn set_apex_target_as_at(&self, at: bool) {
        lock(&self.state).apex_target_as_at = at;
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

fn record_json(record: &Record, inner: &Inner) -> Value {
    let name = match inner.name_form {
        NameForm::Relative => record.name.clone(),
        NameForm::Absolute => absolute(&record.name, &record.domain),
    };
    let host = matches!(record.rtype.as_str(), "CNAME" | "MX" | "NS" | "SRV");
    let apex = record.data.strip_suffix('.').unwrap_or(&record.data);
    let data = if inner.apex_target_as_at && host && apex.eq_ignore_ascii_case(&record.domain) {
        "@".to_owned()
    } else {
        record.data.clone()
    };
    let f = &record.fields;
    json!({
        "id": record.id, "type": record.rtype, "name": name, "data": data,
        "priority": f.priority, "port": f.port, "ttl": record.ttl, "weight": f.weight,
        "flags": f.flags, "tag": f.tag
    })
}

/// The documented record types.
const TYPES: &[&str] = &["A", "AAAA", "CAA", "CNAME", "MX", "NS", "SOA", "SRV", "TXT"];

/// The documented CAA tags.
const CAA_TAGS: &[&str] = &["issue", "issuewild", "iodef"];

/// An optional integer field of a request body: `Ok(None)` when absent or `null`.
fn integer(body: &Value, key: &str, max: u64) -> Result<Option<u64>, Response> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => match value.as_u64().filter(|&n| n <= max) {
            Some(n) => Ok(Some(n)),
            None => Err(unprocessable(&format!("{key} is out of range"))),
        },
    }
}

/// An optional TTL of a request body: an integer of at least 30 (the documented minimum).
fn ttl_field(body: &Value) -> Result<Option<u32>, Response> {
    match body.get("ttl") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => match value
            .as_u64()
            .filter(|&t| t >= 30)
            .and_then(|t| u32::try_from(t).ok())
        {
            Some(ttl) => Ok(Some(ttl)),
            None => Err(unprocessable("ttl must be an integer of at least 30")),
        },
    }
}

/// The fields beyond `data` that a request body gives.
fn body_fields(body: &Value, base: Fields) -> Result<Fields, Response> {
    let mut fields = base;
    if body.get("priority").is_some() {
        fields.priority = integer(body, "priority", 65_535)?;
    }
    if body.get("port").is_some() {
        fields.port = integer(body, "port", 65_535)?;
    }
    if body.get("weight").is_some() {
        fields.weight = integer(body, "weight", 65_535)?;
    }
    if body.get("flags").is_some() {
        fields.flags = integer(body, "flags", 255)?;
    }
    if let Some(tag) = body.get("tag") {
        fields.tag = match tag {
            Value::Null => None,
            Value::String(tag) => Some(tag.clone()),
            _ => return Err(unprocessable("tag must be a string")),
        };
    }
    Ok(fields)
}

/// The per-type rules of the documentation for a record as it would be stored.
fn validate(record: &Record) -> Result<(), Response> {
    let f = &record.fields;
    if record.data.is_empty() {
        return Err(unprocessable("data is required"));
    }
    match record.rtype.as_str() {
        "A" if record.data.parse::<std::net::Ipv4Addr>().is_err() => {
            Err(unprocessable("data must be an IPv4 address"))
        }
        "AAAA" if record.data.parse::<std::net::Ipv6Addr>().is_err() => {
            Err(unprocessable("data must be an IPv6 address"))
        }
        "MX" if f.priority.is_none() => Err(unprocessable("priority is required")),
        "SRV" if f.priority.is_none() || f.port.is_none() => {
            Err(unprocessable("priority and port are required"))
        }
        "CAA" => {
            if f.flags.is_none() {
                return Err(unprocessable("flags is required"));
            }
            if !f.tag.as_deref().is_some_and(|t| CAA_TAGS.contains(&t)) {
                return Err(unprocessable("tag must be issue, issuewild or iodef"));
            }
            if record.data.contains(';') {
                return Err(unprocessable("CAA values with ';' are not supported"));
            }
            Ok(())
        }
        _ => Ok(()),
    }
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
            .map(|r| record_json(r, &inner))
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
    if !TYPES.contains(&rtype) {
        return unprocessable("unsupported record type");
    }
    if rtype == "SOA" {
        return unprocessable("SOA records cannot be created");
    }
    // `name` is required for every documented type but MX (OpenAPI `domain_record_types.yml`).
    let name = match body["name"].as_str().filter(|n| !n.is_empty()) {
        Some(name) => name,
        None if rtype != "MX" => return unprocessable("name is required"),
        None => "@",
    };
    let Some(data) = body["data"].as_str().filter(|d| !d.is_empty()) else {
        return unprocessable("data is required");
    };
    let ttl = match ttl_field(&body) {
        Ok(ttl) => ttl.unwrap_or(1800),
        Err(response) => return response,
    };
    let fields = match body_fields(&body, Fields::default()) {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    if name.ends_with('.') {
        let absolute_name = name.to_lowercase();
        let domain_dot = format!("{}.", domain.to_lowercase());
        if absolute_name != domain_dot && !absolute_name.ends_with(&format!(".{domain_dot}")) {
            return unprocessable("name is outside the domain");
        }
    }
    let record = Record {
        id: inner.next_id + 1,
        domain: domain.clone(),
        name: relative(&absolute(name, &domain), &domain),
        rtype: rtype.to_owned(),
        data: data.to_owned(),
        ttl,
        fields,
    };
    if let Err(response) = validate(&record) {
        return response;
    }
    inner.next_id += 1;
    let created = record_json(&record, &inner);
    let before = inner.published();
    inner.records.push(record);
    inner.report(&before, Origin::Api);
    (
        StatusCode::CREATED,
        axum::Json(json!({"domain_record": created})),
    )
        .into_response()
}

async fn record_update(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((domain, id)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    let Some(index) = id.parse::<u64>().ok().and_then(|id| {
        inner
            .records
            .iter()
            .position(|r| r.domain == domain && r.id == id)
    }) else {
        return not_found();
    };
    let Ok(body) = serde_json::from_slice::<Value>(&body) else {
        return unprocessable("the body is not JSON");
    };
    let Some(current) = inner.records.get(index).cloned() else {
        return not_found();
    };
    // `type` is the one required field of the update's schema.
    let Some(rtype) = body["type"].as_str() else {
        return unprocessable("type is required");
    };
    if rtype != current.rtype {
        return unprocessable("the type of a record cannot change");
    }
    let ttl = match ttl_field(&body) {
        Ok(ttl) => ttl.unwrap_or(current.ttl),
        Err(response) => return response,
    };
    let given = |key: &str| body.get(key).is_some_and(|v| !v.is_null());
    if rtype == "SOA"
        && ["name", "data", "priority", "port", "weight", "flags", "tag"]
            .iter()
            .any(|k| given(k))
    {
        return unprocessable("only the ttl of an SOA record can change");
    }
    let fields = match body_fields(&body, current.fields.clone()) {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let name = match body["name"].as_str().filter(|n| !n.is_empty()) {
        Some(name) => relative(&absolute(name, &domain), &domain),
        None => current.name.clone(),
    };
    let data = body["data"]
        .as_str()
        .map_or(current.data.clone(), str::to_owned);
    let updated = Record {
        name,
        data,
        ttl,
        fields,
        ..current
    };
    if let Err(response) = validate(&updated) {
        return response;
    }
    let answer = record_json(&updated, &inner);
    let before = inner.published();
    if let Some(slot) = inner.records.get_mut(index) {
        *slot = updated;
    }
    inner.report(&before, Origin::Api);
    axum::Json(json!({"domain_record": answer})).into_response()
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
    let published = inner.published();
    let before = inner.records.len();
    inner
        .records
        .retain(|r| !(r.domain == domain && r.id == id));
    if inner.records.len() == before {
        return not_found();
    }
    inner.report(&published, Origin::Api);
    StatusCode::NO_CONTENT.into_response()
}
