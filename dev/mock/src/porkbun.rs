//! Mock of the Porkbun API v3 (credentials check, domain listing and DNS records).
//!
//! Shapes follow the provider's documentation, the same sources the client cites: the OpenAPI
//! description, <https://porkbun.com/api/json/v3/spec>, version 3.79, and the page generated from
//! it, <https://porkbun.com/llms/dns>, both read 2026-11-16:
//!
//! - authentication: `apikey` and `secretapikey` in the JSON body, or the headers `X-API-Key`
//!   and `X-Secret-API-Key`; "Header auth takes effect only when no body credentials are
//!   present". No key at all is `API_KEY_REQUIRED`, a wrong pair `INVALID_API_KEYS_001`. The
//!   headers are declared as parameters of the `GET` operations only, and the request schemas of
//!   the DNS writes (`CreateDnsRequest`, `EditDnsRequest`) list the body keys as required; so by
//!   default ([`WriteAuth::Body`]) the writes (`/dns/create`, `/dns/edit`, `/dns/delete`) take
//!   the keys from the body only and answer a write without them `API_KEY_REQUIRED`, whatever
//!   headers it carries. [`WriteAuth::BodyOrHeaders`] takes the general reading for the writes as
//!   well;
//! - every refusal is HTTP 400 with `{"status":"ERROR","code":…,"message":…}` ("Every refusal
//!   now returns HTTP 400 with a proper code", changelog v3.20); `INVALID_DOMAIN` and
//!   `API_ACCESS_DISABLED` name the account in `account`;
//! - `GET|POST /ping`: without keys the caller's IP only; with valid keys also
//!   `credentialsValid: true`, `account` and `scopes`;
//! - `GET|POST /domain/listAll`: `start` (zero-based offset), pages of up to 1000 domains with
//!   `count`, the exact filter `domain` ("Returns 0 or 1 result") and the filter `apiAccess`
//!   (`yes`/`no`); each domain with `apiAccess` and `notLocal` as integers 1 or 0;
//! - `GET|POST /dns/retrieve/{domain}`: every record but the provider's default NS records
//!   (and SOA, which the mock does not hold): `id`, `ttl` and `prio` as strings (`prio` `null`
//!   where it does not apply), `name` fully qualified, `notes`;
//! - `POST /dns/create/{domain}`: `type` (one of the documented types) and `content` required,
//!   `name` relative to the domain ("Do not include the domain name itself", blank for the apex,
//!   `*` for a wildcard), `ttl` ("Defaults to the account minimum if omitted or 0"; the account
//!   minimum here is 600), `prio` ("Defaults to 0 if omitted", for MX and SRV), `notes`,
//!   `dryRun`; answers `{"status":"SUCCESS","id":<number>}`, with `warnings` for a domain whose
//!   name servers are not the provider's (`notLocal`); refuses an exact duplicate with
//!   `DUPLICATE_RECORD` and `existingId` (a string), a CNAME next to other data with
//!   `RECORD_CONFLICT` and `conflictingRecords`, a record past 2,500 in a zone with
//!   `ZONE_RECORD_LIMIT`;
//! - `POST /dns/edit/{domain}/{id}`: only the fields sent change ("any field left out keeps its
//!   current value", `"name": ""` moves the record to the apex, `notes` `""` clears them); an
//!   edit to the current values succeeds; a record that is not there is `INVALID_RECORD_ID`;
//! - `POST /dns/delete/{domain}/{id}`: `INVALID_RECORD_ID` when the record is not there;
//! - a `POST` without a JSON object as its body is `INVALID_OR_EMPTY_JSON`.
//!
//! Answers this mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading. A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - a member of a request body that the operation's schema does not list is refused with
//!   `INVALID_INPUT`;
//! - a `ttl` below the account minimum (600) is refused with `INVALID_INPUT` (the documentation
//!   does not say whether it is refused or raised; `/dns/import` raises it); `ttl` and `prio`
//!   are taken as a JSON number or a string of digits (the spec's quickstart sends `"ttl":"600"`,
//!   its schema an integer);
//! - an A or AAAA `content` that is not an address is refused with `INVALID_INPUT`;
//! - a `name` that includes the domain is refused with `INVALID_INPUT`;
//! - a duplicate is the same name, type and `content`, compared exactly; `prio` plays no role;
//! - `start` beyond the last domain answers an empty page; with [`Paging::IgnoreStart`] the
//!   listing answers the first page for every `start`;
//! - `name` in answers is lowercase; `content` is stored and answered exactly as sent;
//! - the `X-RateLimit-*` headers are not sent; rate limits come only from faults.
//!
//! Not modeled: the operations by name and type (`retrieveByNameType`, `editByNameType`,
//! `deleteByNameType`), DNSSEC, history, import, `Idempotency-Key`, key scopes and IP or domain
//! allowlists (their 403 answers come from faults), SPF and other content checks, Cloudflare
//! connections. Error texts are invented.
//!
//! A test holds a [`PorkbunMock`]. It dereferences to the [`MockServer`], so the request log and
//! the fault queue of the shared harness work as usual:
//!
//! ```text
//! let mock = PorkbunMock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("POST", "/api/json/v3/dns/create/*").status(500));
//! // ... drive the client against mock.base_url() ...
//! assert_eq!(mock.control().txt_values("_acme-challenge.example.org"), ["v1"]);
//! ```
//!
//! The mock is a [`ChangeSource`]: it reports every change of its published records through
//! [`PorkbunMock::changes`](ChangeSource::changes), the records of one name and type grouped
//! into one rrset (the TTL of the set the smallest of its records), and a
//! [`link`](crate::link::link) serves them over DNS. Published are the records of the account's
//! domains, the default NS records of [`Control::insert_zone_defaults`] included, each at its
//! absolute name. The form of a value: A and AAAA `content`; TXT `content`, the value itself, as
//! one quoted character-string (split every 255 bytes); CNAME, ALIAS and NS `content` with the
//! trailing dot added; MX as `<prio> <host>.`; SRV as `<prio> <weight> <port> <target>.` from a
//! `content` of `weight port target`; every other type `content` as it is. [`Control::reset`]
//! returns the mock to its seed.

#![allow(clippy::result_large_err)]

use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Map, Value, json};

use crate::changes::{ChangeSource, Changes, Origin, Published};
use crate::{Faults, MockServer, RequestLog};

/// Path of the API below the server's base URL.
pub const API_PATH: &str = "/api/json/v3";

/// Most domains on one page of `/domain/listAll`.
pub const PAGE_SIZE: usize = 1000;

/// Most records one zone holds (`ZONE_RECORD_LIMIT`).
pub const ZONE_RECORD_LIMIT: usize = 2500;

/// The account's minimum TTL, which a record created without `ttl` gets.
pub const MIN_TTL: u32 = 600;

/// The documented record types (`CreateDnsRequest.type`).
const TYPES: &[&str] = &[
    "A", "AAAA", "MX", "CNAME", "ALIAS", "TXT", "NS", "SRV", "TLSA", "CAA", "SSHFP", "HTTPS",
    "SVCB", "DS",
];

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The API key the API accepts.
    pub api_key: String,
    /// The secret API key the API accepts.
    pub secret_api_key: String,
    /// The account's user name, named in some error answers.
    pub account: String,
    /// The domains of the account, without a trailing dot, all opted in to API access.
    pub domains: Vec<String>,
}

impl Seed {
    /// Keys `pk1_test-only-key` and `sk1_test-only-secret`, account `zw-test-account` and the
    /// domain `example.org`.
    pub fn standard() -> Self {
        Self {
            api_key: "pk1_test-only-key".into(),
            secret_api_key: "sk1_test-only-secret".into(),
            account: "zw-test-account".into(),
            domains: vec!["example.org".into()],
        }
    }
}

/// How `/domain/listAll` pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Paging {
    /// As documented: `start` is the offset of the page.
    Documented,
    /// `start` is ignored: every page is the first one.
    IgnoreStart,
}

/// Where the DNS writes take the keys from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteAuth {
    /// From the JSON body only, as the writes' request schemas require (the default).
    Body,
    /// From the body, or from the headers when the body has none, as the description's
    /// "Authentication" section reads in general.
    BodyOrHeaders,
}

/// A domain of the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Domain {
    /// The domain, without a trailing dot.
    pub name: String,
    /// Opted in to API access.
    pub api_access: bool,
    /// Served by name servers the provider does not operate.
    pub not_local: bool,
}

/// One record as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The record's identifier.
    pub id: u64,
    /// The domain, without a trailing dot.
    pub domain: String,
    /// The owner name relative to the domain, empty for the apex.
    pub name: String,
    /// The record type.
    pub rtype: String,
    /// The value as sent.
    pub content: String,
    /// TTL in seconds.
    pub ttl: u32,
    /// The priority; `None` where it does not apply.
    pub prio: Option<u32>,
    /// The notes.
    pub notes: Option<String>,
}

#[derive(Debug)]
struct Inner {
    /// The seed the mock was started with, for [`Control::reset`].
    seed: Seed,
    changes: Changes,
    domains: Vec<Domain>,
    records: Vec<Record>,
    /// The provider's default NS records: published, but not in `/dns/retrieve`.
    default_ns: Vec<Record>,
    next_id: u64,
    paging: Paging,
    write_auth: WriteAuth,
}

impl Inner {
    /// The state of a mock started with `seed`.
    fn new(seed: Seed, changes: Changes) -> Inner {
        Inner {
            domains: seed
                .domains
                .iter()
                .map(|name| Domain {
                    name: name.to_lowercase(),
                    api_access: true,
                    not_local: false,
                })
                .collect(),
            seed,
            changes,
            records: Vec::new(),
            default_ns: Vec::new(),
            next_id: 100_000,
            paging: Paging::Documented,
            write_auth: WriteAuth::Body,
        }
    }

    fn domain(&self, name: &str) -> Option<&Domain> {
        self.domains.iter().find(|d| d.name == name)
    }

    /// What a DNS server for the mock's domains would answer (module documentation).
    fn published(&self) -> Published {
        let mut out = Published::new();
        for domain in &self.domains {
            out.zone(&domain.name);
        }
        for record in self.records.iter().chain(&self.default_ns) {
            if self.domain(&record.domain).is_none() {
                continue;
            }
            let prio = record.prio.unwrap_or(0);
            let value = match record.rtype.as_str() {
                "TXT" => quoted(&record.content),
                "CNAME" | "ALIAS" | "NS" => host(&record.content),
                "MX" => format!("{prio} {}", host(&record.content)),
                "SRV" => match record.content.split_whitespace().collect::<Vec<_>>()[..] {
                    [weight, port, target] => format!("{prio} {weight} {port} {}", host(target)),
                    _ => record.content.clone(),
                },
                _ => record.content.clone(),
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

/// A host name with its trailing dot.
fn host(content: &str) -> String {
    format!("{}.", content.trim().trim_end_matches('.').to_lowercase())
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

/// The absolute name, with a trailing dot, of `name` (relative, empty for the apex) in
/// `domain`.
fn absolute(name: &str, domain: &str) -> String {
    if name.is_empty() {
        format!("{domain}.")
    } else {
        format!("{name}.{domain}.")
    }
}

/// The fully qualified name without a trailing dot, as `/dns/retrieve` states it.
fn fqdn(name: &str, domain: &str) -> String {
    if name.is_empty() {
        domain.to_owned()
    } else {
        format!("{name}.{domain}")
    }
}

/// The relative name of a name a test gives: empty for `@` and for the domain itself, the part
/// left of the domain for a name that ends with it (with or without a trailing dot), any other
/// name as it is.
fn given(name: &str, domain: &str) -> String {
    let lower = name.trim().to_lowercase();
    let bare = lower.strip_suffix('.').unwrap_or(&lower);
    if bare == "@" || bare == domain || bare.is_empty() {
        String::new()
    } else if let Some(prefix) = bare.strip_suffix(&format!(".{domain}")) {
        prefix.to_owned()
    } else {
        bare.to_owned()
    }
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running Porkbun mock. Dereferences to its [`MockServer`] for the request log and the fault
/// queue; [`PorkbunMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct PorkbunMock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of a [`PorkbunMock`]. Cheap to clone, so that a fault hook
/// ([`Fault::run`](crate::Fault::run)) can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
    changes: Changes,
    log: RequestLog,
    faults: Faults,
}

impl Deref for PorkbunMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl PorkbunMock {
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
            .route("/api/json/v3/ping", get(ping).post(ping))
            .route("/api/json/v3/domain/listAll", get(list_all).post(list_all))
            .route(
                "/api/json/v3/dns/retrieve/{domain}",
                get(retrieve).post(retrieve),
            )
            .route("/api/json/v3/dns/create/{domain}", post(create))
            .route("/api/json/v3/dns/edit/{domain}/{id}", post(edit))
            .route("/api/json/v3/dns/delete/{domain}/{id}", post(delete))
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

impl ChangeSource for PorkbunMock {
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

    /// Returns the mock to the seed it was started with: its keys and domains, all opted in to
    /// API access, no records, identifiers counted from the start again, documented paging,
    /// [`WriteAuth::Body`], an
    /// empty request log and no pending faults. Reports the removal of every rrset that was
    /// published.
    pub fn reset(&self) {
        self.faults.clear();
        self.change(|inner| {
            let seed = inner.seed.clone();
            *inner = Inner::new(seed, inner.changes.clone());
        });
        self.log.clear();
    }

    /// Every record the API lists, in creation order.
    pub fn records(&self) -> Vec<Record> {
        lock(&self.state).records.clone()
    }

    /// The `content` of the TXT records at `name` (absolute or relative to the first domain), in
    /// creation order.
    pub fn txt_values(&self, name: &str) -> Vec<String> {
        self.records_at(name, "TXT")
            .into_iter()
            .map(|r| r.content)
            .collect()
    }

    /// The records of type `rtype` at `name` (absolute or relative to the first domain), in
    /// creation order.
    pub fn records_at(&self, name: &str, rtype: &str) -> Vec<Record> {
        let inner = lock(&self.state);
        let domain = inner
            .domains
            .first()
            .map_or_else(String::new, |d| d.name.clone());
        let wanted = given(name, &domain);
        inner
            .records
            .iter()
            .filter(|r| r.domain == domain && r.rtype == rtype && r.name == wanted)
            .cloned()
            .collect()
    }

    /// Adds a record directly, as another writer would. `name` is absolute, relative to the
    /// domain or `@`. Returns the record's identifier.
    pub fn insert_record(
        &self,
        domain: &str,
        name: &str,
        rtype: &str,
        content: &str,
        ttl: u32,
    ) -> u64 {
        let prio = matches!(rtype, "MX" | "SRV").then_some(0);
        self.insert_record_with(domain, name, rtype, content, ttl, prio, None)
    }

    /// [`Control::insert_record`] with the priority and the notes.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_record_with(
        &self,
        domain: &str,
        name: &str,
        rtype: &str,
        content: &str,
        ttl: u32,
        prio: Option<u32>,
        notes: Option<&str>,
    ) -> u64 {
        let domain = domain.to_lowercase();
        self.change(|inner| {
            inner.next_id += 1;
            let id = inner.next_id;
            inner.records.push(Record {
                id,
                name: given(name, &domain),
                domain,
                rtype: rtype.to_owned(),
                content: content.to_owned(),
                ttl,
                prio,
                notes: notes.map(str::to_owned),
            });
            id
        })
    }

    /// Seeds the provider's default NS records at the apex of `domain`: published, but not in
    /// the API's listing and not editable through it. The host names are those of the spec's
    /// example of a `warnings` text, moved under `.test` (`maceio.ns.porkbun.test` and three more).
    pub fn insert_zone_defaults(&self, domain: &str) {
        let domain = domain.to_lowercase();
        self.change(|inner| {
            for ns in [
                "maceio.ns.porkbun.test",
                "curitiba.ns.porkbun.test",
                "salvador.ns.porkbun.test",
                "fortaleza.ns.porkbun.test",
            ] {
                inner.next_id += 1;
                let id = inner.next_id;
                inner.default_ns.push(Record {
                    id,
                    domain: domain.clone(),
                    name: String::new(),
                    rtype: "NS".to_owned(),
                    content: ns.to_owned(),
                    ttl: 86_400,
                    prio: None,
                    notes: None,
                });
            }
        });
    }

    /// Deletes the record `id` directly, as another writer would.
    pub fn delete_record(&self, id: u64) {
        self.change(|inner| inner.records.retain(|r| r.id != id));
    }

    /// Adds a domain, opted in to API access.
    pub fn insert_domain(&self, domain: &str) {
        self.change(|inner| {
            inner.domains.push(Domain {
                name: domain.to_lowercase(),
                api_access: true,
                not_local: false,
            });
        });
    }

    /// Opts `domain` in to or out of API access.
    pub fn set_api_access(&self, domain: &str, on: bool) {
        let mut inner = lock(&self.state);
        for d in inner.domains.iter_mut().filter(|d| d.name == domain) {
            d.api_access = on;
        }
    }

    /// Marks `domain` as served by name servers the provider does not operate, or not.
    pub fn set_not_local(&self, domain: &str, not_local: bool) {
        let mut inner = lock(&self.state);
        for d in inner.domains.iter_mut().filter(|d| d.name == domain) {
            d.not_local = not_local;
        }
    }

    /// Gives every record of `domain` a new identifier, as a domain deleted and created again
    /// with the same records would have.
    pub fn recreate_domain(&self, domain: &str) {
        let mut inner = lock(&self.state);
        let mut next = inner.next_id;
        for record in inner.records.iter_mut().filter(|r| r.domain == domain) {
            next += 1;
            record.id = next;
        }
        inner.next_id = next;
    }

    /// How `/domain/listAll` pages.
    pub fn set_paging(&self, paging: Paging) {
        lock(&self.state).paging = paging;
    }

    /// Where the DNS writes take the keys from.
    pub fn set_write_auth(&self, write_auth: WriteAuth) {
        lock(&self.state).write_auth = write_auth;
    }
}

// ---- Answers -----------------------------------------------------------------------------------

/// A refusal in the documented shape: HTTP 400 with `status`, `code` and `message`, and the
/// members of `extra`.
fn refusal(code: &str, message: &str, extra: Value) -> Response {
    let mut body = json!({"status": "ERROR", "code": code, "message": message});
    if let (Some(body), Value::Object(extra)) = (body.as_object_mut(), extra) {
        body.extend(extra);
    }
    (StatusCode::BAD_REQUEST, axum::Json(body)).into_response()
}

fn invalid_input(message: &str) -> Response {
    refusal("INVALID_INPUT", message, Value::Null)
}

fn success(mut body: Value) -> Response {
    if let Some(object) = body.as_object_mut() {
        object.insert("status".into(), json!("SUCCESS"));
    }
    axum::Json(body).into_response()
}

/// The JSON object of a request body. A `GET` has none; a `POST` must have one.
fn body_object(method: &Method, body: &Bytes) -> Result<Map<String, Value>, Response> {
    if *method == Method::GET && body.is_empty() {
        return Ok(Map::new());
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(object)) => Ok(object),
        _ => Err(refusal(
            "INVALID_OR_EMPTY_JSON",
            "The request body is missing or not valid JSON.",
            Value::Null,
        )),
    }
}

/// Refuses a member of `body` that `allowed` does not list.
fn known_members(body: &Map<String, Value>, allowed: &[&str]) -> Result<(), Response> {
    match body.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(_) => Err(invalid_input(
            "The request body has a member this call does not take.",
        )),
        None => Ok(()),
    }
}

/// Which keys the request carries: those of the body, else those of the headers. `Ok(false)`
/// when it carries none.
fn keys(state: &Shared, headers: &HeaderMap, body: &Map<String, Value>) -> Result<bool, Response> {
    let in_body = body.contains_key("apikey") || body.contains_key("secretapikey");
    let (key, secret) = if in_body {
        (
            body.get("apikey")
                .and_then(Value::as_str)
                .map(str::to_owned),
            body.get("secretapikey")
                .and_then(Value::as_str)
                .map(str::to_owned),
        )
    } else {
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        (header("x-api-key"), header("x-secret-api-key"))
    };
    if key.is_none() && secret.is_none() {
        return Ok(false);
    }
    let inner = lock(state);
    if key.as_deref() == Some(inner.seed.api_key.as_str())
        && secret.as_deref() == Some(inner.seed.secret_api_key.as_str())
    {
        Ok(true)
    } else {
        Err(refusal(
            "INVALID_API_KEYS_001",
            "Invalid API key. (001)",
            Value::Null,
        ))
    }
}

/// `Ok` when the request carries the keys of the seed.
fn authorize(
    state: &Shared,
    headers: &HeaderMap,
    body: &Map<String, Value>,
) -> Result<(), Response> {
    if keys(state, headers, body)? {
        Ok(())
    } else {
        Err(refusal(
            "API_KEY_REQUIRED",
            "No API key was provided.",
            Value::Null,
        ))
    }
}

/// `Ok` when a DNS write carries the keys of the seed where [`WriteAuth`] takes them from.
fn authorize_write(
    state: &Shared,
    headers: &HeaderMap,
    body: &Map<String, Value>,
) -> Result<(), Response> {
    let body_only = lock(state).write_auth == WriteAuth::Body;
    if body_only && !body.contains_key("apikey") && !body.contains_key("secretapikey") {
        return Err(refusal(
            "API_KEY_REQUIRED",
            "No API key was provided.",
            Value::Null,
        ));
    }
    authorize(state, headers, body)
}

/// The domain of a `/dns/*` path, when it is in the account and opted in to API access.
fn dns_domain(inner: &Inner, domain: &str) -> Result<Domain, Response> {
    let account = json!({"account": inner.seed.account});
    match inner.domain(&domain.to_lowercase()) {
        None => Err(refusal(
            "INVALID_DOMAIN",
            "Domain is invalid or not in the account.",
            account,
        )),
        Some(d) if !d.api_access => Err(refusal(
            "API_ACCESS_DISABLED",
            "The domain is not opted in to API access.",
            account,
        )),
        Some(d) => Ok(d.clone()),
    }
}

/// A non-negative integer member: a JSON number or a string of digits. `Ok(None)` when absent or
/// `null`.
fn integer(body: &Map<String, Value>, key: &str) -> Result<Option<u64>, Response> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| invalid_input("A number is out of range.")),
        Some(Value::String(s)) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => s
            .parse()
            .map(Some)
            .map_err(|_| invalid_input("A number is out of range.")),
        Some(_) => Err(invalid_input("A number has the wrong type.")),
    }
}

/// An optional string member.
fn string<'a>(body: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, Response> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(invalid_input("A text member has the wrong type.")),
    }
}

/// A TTL member: the account minimum when absent or 0; below it is refused.
fn ttl_member(body: &Map<String, Value>) -> Result<Option<u32>, Response> {
    match integer(body, "ttl")? {
        None | Some(0) => Ok(None),
        Some(ttl) if ttl < u64::from(MIN_TTL) => Err(invalid_input(
            "The TTL is below the minimum of the account.",
        )),
        Some(ttl) => u32::try_from(ttl)
            .map(Some)
            .map_err(|_| invalid_input("The TTL is out of range.")),
    }
}

/// The checks of the documentation and of the module documentation on a record as it would be
/// stored.
fn validate(record: &Record) -> Result<(), Response> {
    if !TYPES.contains(&record.rtype.as_str()) {
        return Err(refusal(
            "INVALID_TYPE",
            "The DNS record type is not supported.",
            Value::Null,
        ));
    }
    if record.content.is_empty() {
        return Err(refusal(
            "MISSING_PARAMETER",
            "content is required.",
            Value::Null,
        ));
    }
    match record.rtype.as_str() {
        "A" if record.content.parse::<std::net::Ipv4Addr>().is_err() => {
            Err(invalid_input("The content is not an IPv4 address."))
        }
        "AAAA" if record.content.parse::<std::net::Ipv6Addr>().is_err() => {
            Err(invalid_input("The content is not an IPv6 address."))
        }
        _ => Ok(()),
    }
}

/// The relative name of a request's `name`: blank for the apex; a name that includes the domain
/// is refused ("Do not include the domain name itself").
fn request_name(name: &str, domain: &str) -> Result<String, Response> {
    let name = name.trim().to_lowercase();
    if name == domain || name.ends_with(&format!(".{domain}")) || name.ends_with('.') {
        return Err(invalid_input(
            "The name must not include the domain name itself.",
        ));
    }
    Ok(name)
}

fn record_json(record: &Record) -> Value {
    json!({
        "id": record.id.to_string(),
        "name": fqdn(&record.name, &record.domain),
        "type": record.rtype,
        "content": record.content,
        "ttl": record.ttl.to_string(),
        "prio": record.prio.map(|p| p.to_string()),
        "notes": record.notes,
    })
}

/// The `warnings` of a write to `domain`, if it has any.
fn with_warnings(mut body: Value, domain: &Domain) -> Value {
    if domain.not_local
        && let Some(object) = body.as_object_mut()
    {
        object.insert(
            "warnings".into(),
            json!([format!(
                "{} is delegated to nameservers we do not operate, so this change was saved \
                 to your Porkbun DNS zone but does NOT affect what resolves.",
                domain.name
            )]),
        );
    }
    body
}

// ---- Handlers ----------------------------------------------------------------------------------

async fn ping(
    State(state): State<Shared>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let body = match body_object(&method, &body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(response) = known_members(&body, &["apikey", "secretapikey"]) {
        return response;
    }
    match keys(&state, &headers, &body) {
        Err(response) => response,
        Ok(false) => success(json!({"yourIp": "127.0.0.1"})),
        Ok(true) => {
            let account = lock(&state).seed.account.clone();
            success(json!({
                "yourIp": "127.0.0.1",
                "credentialsValid": true,
                "account": account,
                "scopes": ["full"],
            }))
        }
    }
}

/// The members of `ListAllRequest`.
const LIST_ALL_MEMBERS: &[&str] = &[
    "apikey",
    "secretapikey",
    "start",
    "includeLabels",
    "domain",
    "nameContains",
    "expiringWithinDays",
    "addedAfter",
    "addedBefore",
    "createdAfter",
    "createdBefore",
    "expiresAfter",
    "expiresBefore",
    "tlds",
    "autoRenew",
    "apiAccess",
    "sortName",
    "sortDirection",
];

async fn list_all(
    State(state): State<Shared>,
    method: Method,
    headers: HeaderMap,
    Query(query): Query<Vec<(String, String)>>,
    body: Bytes,
) -> Response {
    let mut body = match body_object(&method, &body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(response) = known_members(&body, LIST_ALL_MEMBERS) {
        return response;
    }
    if let Err(response) = authorize(&state, &headers, &body) {
        return response;
    }
    // A `GET` gives the parameters in the query.
    for (key, value) in query {
        if !LIST_ALL_MEMBERS.contains(&key.as_str()) {
            return invalid_input("The query has a parameter this call does not take.");
        }
        body.insert(key, Value::String(value));
    }
    let start = match integer(&body, "start") {
        Ok(start) => usize::try_from(start.unwrap_or(0)).unwrap_or(usize::MAX),
        Err(response) => return response,
    };
    let exact = match string(&body, "domain") {
        Ok(exact) => exact.map(|d| d.trim_end_matches('.').to_lowercase()),
        Err(response) => return response,
    };
    let access = match string(&body, "apiAccess") {
        Ok(None) => None,
        Ok(Some("yes")) => Some(true),
        Ok(Some("no")) => Some(false),
        Ok(Some(_)) | Err(_) => return invalid_input("apiAccess must be yes or no."),
    };
    let inner = lock(&state);
    let start = if inner.paging == Paging::IgnoreStart {
        0
    } else {
        start
    };
    let domains: Vec<Value> = inner
        .domains
        .iter()
        .filter(|d| exact.as_ref().is_none_or(|e| *e == d.name))
        .filter(|d| access.is_none_or(|a| a == d.api_access))
        .skip(start)
        .take(PAGE_SIZE)
        .map(|d| {
            let tld = d.name.rsplit('.').next().unwrap_or_default();
            json!({
                "domain": d.name, "status": "ACTIVE", "tld": tld,
                "createDate": "2021-01-15 10:00:00", "expireDate": "2027-01-15 10:00:00",
                "addedDate": "2021-01-15 10:00:00", "securityLock": 1, "whoisPrivacy": 1,
                "autoRenew": 0, "apiAccess": u8::from(d.api_access),
                "notLocal": u8::from(d.not_local),
            })
        })
        .collect();
    success(json!({"count": domains.len(), "domains": domains}))
}

async fn retrieve(
    State(state): State<Shared>,
    method: Method,
    headers: HeaderMap,
    Path(domain): Path<String>,
    body: Bytes,
) -> Response {
    let body = match body_object(&method, &body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(response) = known_members(&body, &["apikey", "secretapikey"]) {
        return response;
    }
    if let Err(response) = authorize(&state, &headers, &body) {
        return response;
    }
    let inner = lock(&state);
    let domain = match dns_domain(&inner, &domain) {
        Ok(domain) => domain,
        Err(response) => return response,
    };
    let records: Vec<Value> = inner
        .records
        .iter()
        .filter(|r| r.domain == domain.name)
        .map(record_json)
        .collect();
    success(json!({"cloudflare": "disabled", "records": records}))
}

/// The members of `CreateDnsRequest`.
const CREATE_MEMBERS: &[&str] = &[
    "apikey",
    "secretapikey",
    "name",
    "type",
    "content",
    "ttl",
    "prio",
    "notes",
    "dryRun",
];

async fn create(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(domain): Path<String>,
    body: Bytes,
) -> Response {
    let body = match body_object(&Method::POST, &body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(response) = known_members(&body, CREATE_MEMBERS) {
        return response;
    }
    if let Err(response) = authorize_write(&state, &headers, &body) {
        return response;
    }
    let mut inner = lock(&state);
    let domain = match dns_domain(&inner, &domain) {
        Ok(domain) => domain,
        Err(response) => return response,
    };
    let fields = (|| {
        let rtype = string(&body, "type")?
            .ok_or_else(|| refusal("MISSING_PARAMETER", "type is required.", Value::Null))?;
        let content = string(&body, "content")?
            .ok_or_else(|| refusal("MISSING_PARAMETER", "content is required.", Value::Null))?;
        let name = request_name(string(&body, "name")?.unwrap_or_default(), &domain.name)?;
        let ttl = ttl_member(&body)?.unwrap_or(MIN_TTL);
        let prio = integer(&body, "prio")?
            .map(|p| u32::try_from(p).map_err(|_| invalid_input("prio is out of range.")))
            .transpose()?;
        let notes = string(&body, "notes")?.map(str::to_owned);
        let dry_run = body.get("dryRun").and_then(Value::as_bool) == Some(true);
        Ok::<_, Response>((
            rtype.to_owned(),
            content.to_owned(),
            name,
            ttl,
            prio,
            notes,
            dry_run,
        ))
    })();
    let (rtype, content, name, ttl, prio, notes, dry_run) = match fields {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let record = Record {
        id: inner.next_id + 1,
        domain: domain.name.clone(),
        name,
        prio: prio.or_else(|| matches!(rtype.as_str(), "MX" | "SRV").then_some(0)),
        rtype,
        content,
        ttl,
        notes,
    };
    if let Err(response) = validate(&record) {
        return response;
    }
    let at_name: Vec<&Record> = inner
        .records
        .iter()
        .filter(|r| r.domain == record.domain && r.name == record.name)
        .collect();
    if let Some(existing) = at_name
        .iter()
        .find(|r| r.rtype == record.rtype && r.content == record.content)
    {
        return refusal(
            "DUPLICATE_RECORD",
            "A record with this name, type and content already exists.",
            json!({"existingId": existing.id.to_string()}),
        );
    }
    // A CNAME is exclusive of every other type at its name (`RECORD_CONFLICT`).
    let blocking: Vec<Value> = at_name
        .iter()
        .filter(|r| record.rtype == "CNAME" || r.rtype == "CNAME")
        .map(|r| {
            json!({"id": r.id.to_string(), "name": fqdn(&r.name, &r.domain), "type": r.rtype,
                   "content": r.content})
        })
        .collect();
    if !blocking.is_empty() {
        return refusal(
            "RECORD_CONFLICT",
            "A CNAME record cannot share its name with other records.",
            json!({"conflictingRecords": blocking}),
        );
    }
    let count = inner
        .records
        .iter()
        .filter(|r| r.domain == record.domain)
        .count();
    if count >= ZONE_RECORD_LIMIT {
        return refusal(
            "ZONE_RECORD_LIMIT",
            "The zone is at the maximum number of DNS records.",
            json!({"count": count, "limit": ZONE_RECORD_LIMIT}),
        );
    }
    if dry_run {
        return success(json!({"wouldSucceed": true}));
    }
    inner.next_id += 1;
    let id = record.id;
    let before = inner.published();
    inner.records.push(record);
    inner.report(&before, Origin::Api);
    success(with_warnings(json!({"id": id}), &domain))
}

async fn edit(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((domain, id)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let body = match body_object(&Method::POST, &body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(response) = known_members(&body, CREATE_MEMBERS) {
        return response;
    }
    if let Err(response) = authorize_write(&state, &headers, &body) {
        return response;
    }
    let mut inner = lock(&state);
    let domain = match dns_domain(&inner, &domain) {
        Ok(domain) => domain,
        Err(response) => return response,
    };
    let Some(index) = id.parse::<u64>().ok().and_then(|id| {
        inner
            .records
            .iter()
            .position(|r| r.domain == domain.name && r.id == id)
    }) else {
        return refusal(
            "INVALID_RECORD_ID",
            "The DNS record ID was not found.",
            Value::Null,
        );
    };
    let Some(current) = inner.records.get(index).cloned() else {
        return refusal(
            "INVALID_RECORD_ID",
            "The DNS record ID was not found.",
            Value::Null,
        );
    };
    let updated = (|| {
        let mut record = current.clone();
        if let Some(name) = string(&body, "name")? {
            record.name = request_name(name, &domain.name)?;
        }
        if let Some(rtype) = string(&body, "type")? {
            rtype.clone_into(&mut record.rtype);
        }
        if let Some(content) = string(&body, "content")? {
            content.clone_into(&mut record.content);
        }
        if body.contains_key("ttl") {
            record.ttl = ttl_member(&body)?.unwrap_or(MIN_TTL);
        }
        if let Some(prio) = integer(&body, "prio")? {
            record.prio =
                Some(u32::try_from(prio).map_err(|_| invalid_input("prio is out of range."))?);
        }
        match string(&body, "notes")? {
            Some("") => record.notes = None,
            Some(notes) => record.notes = Some(notes.to_owned()),
            None => {}
        }
        validate(&record)?;
        Ok::<_, Response>(record)
    })();
    let updated = match updated {
        Ok(updated) => updated,
        Err(response) => return response,
    };
    if body.get("dryRun").and_then(Value::as_bool) == Some(true) {
        return success(json!({"wouldSucceed": true}));
    }
    let before = inner.published();
    if let Some(slot) = inner.records.get_mut(index) {
        *slot = updated;
    }
    inner.report(&before, Origin::Api);
    success(with_warnings(json!({}), &domain))
}

async fn delete(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((domain, id)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let body = match body_object(&Method::POST, &body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(response) = known_members(&body, &["apikey", "secretapikey", "dryRun"]) {
        return response;
    }
    if let Err(response) = authorize_write(&state, &headers, &body) {
        return response;
    }
    let mut inner = lock(&state);
    let domain = match dns_domain(&inner, &domain) {
        Ok(domain) => domain,
        Err(response) => return response,
    };
    let Some(index) = id.parse::<u64>().ok().and_then(|id| {
        inner
            .records
            .iter()
            .position(|r| r.domain == domain.name && r.id == id)
    }) else {
        return refusal(
            "INVALID_RECORD_ID",
            "The DNS record ID was not found.",
            Value::Null,
        );
    };
    if body.get("dryRun").and_then(Value::as_bool) == Some(true) {
        return success(json!({"wouldSucceed": true}));
    }
    let before = inner.published();
    inner.records.remove(index);
    inner.report(&before, Origin::Api);
    success(with_warnings(json!({}), &domain))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::body::Bytes;
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, HeaderValue, StatusCode};

    use super::{Inner, Record, Seed, WriteAuth, create, given, lock, quoted};
    use crate::changes::Changes;

    /// A write that carries the keys only as headers is refused by default and taken under
    /// `WriteAuth::BodyOrHeaders`; one with the keys in the body is taken either way.
    #[tokio::test]
    async fn porkbun_writes_take_the_keys_from_the_body() {
        let seed = Seed::standard();
        let state = Arc::new(Mutex::new(Inner::new(seed.clone(), Changes::new())));
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_str(&seed.api_key).unwrap());
        headers.insert(
            "x-secret-api-key",
            HeaderValue::from_str(&seed.secret_api_key).unwrap(),
        );
        let bare = Bytes::from(r#"{"type":"TXT","content":"a"}"#);
        let answer = |response: axum::response::Response| async move {
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            (status, String::from_utf8(body.to_vec()).unwrap())
        };
        let refused = create(
            State(state.clone()),
            headers.clone(),
            Path("example.org".to_owned()),
            bare.clone(),
        )
        .await;
        let (status, body) = answer(refused).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("API_KEY_REQUIRED"), "{body}");
        let keyed = Bytes::from(
            serde_json::json!({
                "apikey": seed.api_key, "secretapikey": seed.secret_api_key,
                "type": "TXT", "content": "b"
            })
            .to_string(),
        );
        let taken = create(
            State(state.clone()),
            HeaderMap::new(),
            Path("example.org".to_owned()),
            keyed,
        )
        .await;
        assert_eq!(answer(taken).await.0, StatusCode::OK);
        lock(&state).write_auth = WriteAuth::BodyOrHeaders;
        let taken = create(State(state), headers, Path("example.org".to_owned()), bare).await;
        assert_eq!(answer(taken).await.0, StatusCode::OK);
    }

    fn record(name: &str, rtype: &str, content: &str, prio: Option<u32>) -> Record {
        Record {
            id: 1,
            domain: "example.org".into(),
            name: name.into(),
            rtype: rtype.into(),
            content: content.into(),
            ttl: 600,
            prio,
            notes: None,
        }
    }

    #[test]
    fn porkbun_published_values_are_zone_file_text() {
        let mut inner = Inner::new(Seed::standard(), Changes::new());
        inner.records = vec![
            record("", "MX", "mail.example.org", Some(10)),
            record("_sip._tcp", "SRV", "5 5060 sip.example.org", Some(1)),
            record("www", "CNAME", "Target.example.net.", None),
            record("www", "TXT", "say \"hi\"", None),
            record("", "CAA", "0 issue \"ca.example.net\"", None),
        ];
        let published = format!("{:?}", inner.published());
        for text in [
            "10 mail.example.org.",
            "1 5 5060 sip.example.org.",
            "target.example.net.",
            "say \\\\\\\"hi",
            "0 issue \\\"ca.example.net\\\"",
        ] {
            assert!(published.contains(text), "{text} in {published}");
        }
        assert_eq!(quoted("a"), "\"a\"");
    }

    #[test]
    fn porkbun_names_given_by_tests_are_relative() {
        assert_eq!(given("example.org", "example.org"), "");
        assert_eq!(given("@", "example.org"), "");
        assert_eq!(given("www.example.org.", "example.org"), "www");
        assert_eq!(given("WWW", "example.org"), "www");
    }
}
