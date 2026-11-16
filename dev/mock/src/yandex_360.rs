//! Mock of the Yandex 360 API (`DomainDNSService` and the domain listing).
//!
//! Shapes follow the provider's documentation, the same sources the client cites:
//!
//! - Create: <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Create>:
//!   `POST /directory/v1/org/{orgId}/domains/{domain}/dns` with `type` (one of `A`, `AAAA`,
//!   `CNAME`, `MX`, `TXT`, `SRV`, `NS`, `CAA`), `name` and `ttl` required, and the fields of the
//!   types: `address` (A, AAAA), `target` (CNAME, SRV), `exchange` and `preference` (MX), `text`
//!   (TXT), `port`, `priority`, `weight` (SRV), `flag`, `tag` and `value` (CAA, the value
//!   "enclosed in double quotes"); `200` with the record and its `recordId`; `400`, `401`, `403`,
//!   `404`, `500` with the body `{code, message, details}`.
//! - List: <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_List>:
//!   `GET` on the same path with `page` (default 1) and `perPage` (default 50); the answer holds
//!   `records`, `page`, `pages`, `perPage`, `total`; a record has `recordId`, `type`, `name`,
//!   `ttl` and the type's fields.
//! - Edit: <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Edit.md>:
//!   `POST …/dns/{recordId}` with `type`, `name` and `ttl` required and the fields above except
//!   the CAA fields, which the request does not have; `200` with the record.
//! - Delete: <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Delete>:
//!   `DELETE …/dns/{recordId}`, `200` with `{}`.
//! - The apex: the help page of the console's DNS editor,
//!   <https://yandex.ru/support/yandex-360/business/admin/ru/domains/dns/a.md>, writes the main
//!   domain as `@`.
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
//! - the `name` of a created or edited record is read as relative to the domain, as lego sends
//!   it, and `@` as the apex (the help page above, which describes the console, not the API); an
//!   empty name and a name with a trailing dot are refused with `400`; a record at the apex is
//!   stated as `@` ([`NameForm::Relative`]) or as the domain's full name ([`NameForm::Full`]),
//!   and the full form is the one the listing page's field description names; the full name
//!   with a trailing dot ([`NameForm::Absolute`]) is a third form no source shows, kept so that
//!   the absolute reading can be tested apart from the ambiguous dotless one;
//! - a name stored relative may repeat the domain (`www.example.org` inside `example.org`, the
//!   owner `www.example.org.example.org`): a create stores its name as sent, and
//!   [`Control::insert_relative`] stores one directly;
//! - a `ttl` that is not a positive integer is refused with `400`; no range is enforced, as
//!   none is documented;
//! - the fields a create or an edit requires per type, and their checks, all refused with `400`:
//!   A `address` an IPv4 address, AAAA `address` an IPv6 address, CNAME a non-empty `target`, MX
//!   a non-empty `exchange` and `preference` 0 to 65535, TXT a non-empty `text`, SRV a non-empty
//!   `target` and `priority`, `weight`, `port` 0 to 65535 each, CAA `flag` 0 to 255, a non-empty
//!   `tag` and a `value` that starts and ends with `"`; a field of another type than the
//!   record's; NS (no page names the field of its value); in an edit, a CAA type or a CAA field;
//! - host names (`target`, `exchange`) are stored and answered exactly as sent, with or without
//!   a trailing dot;
//! - an edit replaces the record's type, name, TTL and fields with those of the body, and keeps
//!   its identifier; an unknown identifier is `404`;
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
//!
//! The mock is a [`ChangeSource`]: it reports every change of its published records through
//! [`Yandex360Mock::changes`], the records of one name and type grouped into one rrset, and a
//! [`link`](crate::link::link) serves them over DNS. Only delegated domains are published: the
//! provider's name servers answer for a domain delegated to them, and a domain that is not is
//! left out with its records. The published form of a record: the owner name made absolute (`@`
//! is the domain; a stored name is relative, also one that repeats the domain); A and AAAA the
//! `address`; CNAME the `target`, MX `<preference> <exchange>`, SRV
//! `<priority> <weight> <port> <target>`, each host name read as absolute with or without the
//! trailing dot (as the client reads it) and published with the dot; TXT the `text`, as it is
//! when it is quoted and as one quoted value (in 255-octet character-strings) otherwise, the
//! rule by which the client reads it; CAA `<flag> <tag> <value>`. Left out: NS records, whose
//! value field no page names, and a record that lacks a field of its type (possible only
//! through the control handle). [`Control::reset`] returns the mock to its seed.

#![allow(clippy::result_large_err)]

use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Map, Value, json};

use crate::changes::{ChangeSource, Changes, Origin, Published};
use crate::{Faults, MockServer, RequestLog};

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
    /// The full name, with a trailing dot.
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
    /// The `text` field; empty when the record has none.
    pub text: String,
    /// Every other field of the type (`address`, `target`, `exchange`, `preference`, `port`,
    /// `priority`, `weight`, `flag`, `tag`, `value`), as sent.
    pub fields: Map<String, Value>,
    /// TTL in seconds.
    pub ttl: u32,
}

impl Record {
    /// A string field other than `text`.
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).and_then(Value::as_str)
    }

    /// A number field.
    pub fn number(&self, key: &str) -> Option<u64> {
        self.fields.get(key).and_then(Value::as_u64)
    }
}

/// The fields of each type, as the create page names them.
const TYPE_FIELDS: &[(&str, &[&str])] = &[
    ("A", &["address"]),
    ("AAAA", &["address"]),
    ("CNAME", &["target"]),
    ("MX", &["exchange", "preference"]),
    ("TXT", &["text"]),
    ("SRV", &["target", "priority", "weight", "port"]),
    ("CAA", &["flag", "tag", "value"]),
];

/// Every type field of the create page.
const ALL_FIELDS: &[&str] = &[
    "address",
    "target",
    "exchange",
    "preference",
    "text",
    "port",
    "priority",
    "weight",
    "flag",
    "tag",
    "value",
];

/// The CAA fields, which an edit does not have.
const CAA_FIELDS: &[&str] = &["flag", "tag", "value"];

#[derive(Debug)]
struct Inner {
    /// The seed the mock was started with, for [`Control::reset`].
    seed: Seed,
    changes: Changes,
    org_id: String,
    token: String,
    domains: Vec<(String, bool)>,
    records: Vec<Record>,
    next_id: u64,
    /// Caps `perPage`, to force small pages.
    page_cap: Option<usize>,
    name_form: NameForm,
}

impl Inner {
    /// The state of a mock started with `seed`.
    fn new(seed: Seed, changes: Changes) -> Inner {
        Inner {
            org_id: seed.org_id.clone(),
            token: seed.token.clone(),
            domains: seed.domains.clone(),
            seed,
            changes,
            records: Vec::new(),
            next_id: 1000,
            page_cap: None,
            name_form: NameForm::Relative,
        }
    }

    /// What a DNS server for the mock's delegated domains would answer (module documentation).
    fn published(&self) -> Published {
        let mut out = Published::new();
        let delegated = |domain: &str| self.domains.iter().any(|(d, on)| d == domain && *on);
        for (domain, _) in self.domains.iter().filter(|(_, on)| *on) {
            out.zone(domain);
        }
        for record in &self.records {
            if !delegated(&record.domain) {
                continue;
            }
            let Some(value) = published_value(record) else {
                continue;
            };
            let owner = if record.name == "@" {
                record.domain.clone()
            } else {
                format!("{}.{}", record.name, record.domain)
            };
            out.record(
                &record.domain,
                &owner,
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

/// The value of `record` in zone-file text form (module documentation); `None` for a record the
/// mock does not publish.
fn published_value(record: &Record) -> Option<String> {
    let host = |key: &str| {
        let name = record.field(key)?;
        Some(if name.ends_with('.') {
            name.to_owned()
        } else {
            format!("{name}.")
        })
    };
    let number = |key: &str| record.number(key);
    Some(match record.rtype.as_str() {
        "A" | "AAAA" => record.field("address")?.to_owned(),
        "CNAME" => host("target")?,
        "MX" => format!("{} {}", number("preference")?, host("exchange")?),
        "SRV" => format!(
            "{} {} {} {}",
            number("priority")?,
            number("weight")?,
            number("port")?,
            host("target")?
        ),
        "CAA" => format!(
            "{} {} {}",
            number("flag")?,
            record.field("tag")?,
            record.field("value")?
        ),
        "TXT"
            if record.text.len() >= 2
                && record.text.starts_with('"')
                && record.text.ends_with('"') =>
        {
            record.text.clone()
        }
        "TXT" => character_strings(&record.text),
        _ => return None,
    })
}

/// `text` as quoted character-strings of at most 255 octets each (RFC 1035 section 5.1): `"`
/// and `\` escaped with a backslash, any octet outside printable ASCII as `\DDD`.
fn character_strings(text: &str) -> String {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return "\"\"".to_owned();
    }
    let mut out = Vec::new();
    for chunk in bytes.chunks(255) {
        let mut string = String::from("\"");
        for &byte in chunk {
            match byte {
                b'"' | b'\\' => {
                    string.push('\\');
                    string.push(char::from(byte));
                }
                0x20..=0x7e => string.push(char::from(byte)),
                _ => string.push_str(&format!("\\{byte:03}")),
            }
        }
        string.push('"');
        out.push(string);
    }
    out.join(" ")
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
    changes: Changes,
    log: RequestLog,
    faults: Faults,
}

impl Deref for Yandex360Mock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl Yandex360Mock {
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
            .route("/directory/v1/org/{org}/domains", get(domains_list))
            .route(
                "/directory/v1/org/{org}/domains/{domain}/dns",
                get(records_list).post(record_create),
            )
            .route(
                "/directory/v1/org/{org}/domains/{domain}/dns/{id}",
                post(record_edit).delete(record_delete),
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
        self.server.url("")
    }

    /// The state control.
    pub fn control(&self) -> &Control {
        &self.control
    }
}

impl ChangeSource for Yandex360Mock {
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

    /// Returns the mock to the seed it was started with: its organization, token and domains, no
    /// records, record identifiers from 1001 again, no page cap, relative names in listings, an
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

    /// The records of `rtype` at `name` (absolute or relative to the first domain), in creation
    /// order.
    pub fn records_at(&self, name: &str, rtype: &str) -> Vec<Record> {
        let inner = lock(&self.state);
        let domain = inner.domains.first().map_or("", |d| d.0.as_str());
        let wanted = relative(name, domain);
        inner
            .records
            .iter()
            .filter(|r| r.rtype == rtype && r.domain == domain && r.name == wanted)
            .cloned()
            .collect()
    }

    /// Adds a record with a `text` field and no other, as another writer would, without any
    /// check. `name` is absolute or relative to the domain. Returns the record's identifier.
    pub fn insert_record(
        &self,
        domain: &str,
        name: &str,
        rtype: &str,
        text: &str,
        ttl: u32,
    ) -> u64 {
        self.insert(domain, name, rtype, text.to_owned(), Map::new(), ttl)
    }

    /// Adds a record with the given fields (a JSON object; `text` among them or not), as another
    /// writer would, without any check. Returns the record's identifier.
    pub fn insert_fields(
        &self,
        domain: &str,
        name: &str,
        rtype: &str,
        fields: Value,
        ttl: u32,
    ) -> u64 {
        let mut fields = match fields {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        let text = match fields.remove("text") {
            Some(Value::String(text)) => text,
            _ => String::new(),
        };
        self.insert(domain, name, rtype, text, fields, ttl)
    }

    /// Adds a record with the given fields at `name` taken as relative to `domain` exactly as
    /// given (`@` for the apex), as another writer would, without any check: a name that repeats
    /// the domain stays below it. Returns the record's identifier.
    pub fn insert_relative(
        &self,
        domain: &str,
        name: &str,
        rtype: &str,
        fields: Value,
        ttl: u32,
    ) -> u64 {
        let mut fields = match fields {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        let text = match fields.remove("text") {
            Some(Value::String(text)) => text,
            _ => String::new(),
        };
        self.insert_stored(domain, name.to_lowercase(), rtype, text, fields, ttl)
    }

    fn insert(
        &self,
        domain: &str,
        name: &str,
        rtype: &str,
        text: String,
        fields: Map<String, Value>,
        ttl: u32,
    ) -> u64 {
        self.insert_stored(domain, relative(name, domain), rtype, text, fields, ttl)
    }

    /// Adds a record under the stored (relative) name `name`.
    fn insert_stored(
        &self,
        domain: &str,
        name: String,
        rtype: &str,
        text: String,
        fields: Map<String, Value>,
        ttl: u32,
    ) -> u64 {
        self.change(|inner| {
            inner.next_id += 1;
            let id = inner.next_id;
            inner.records.push(Record {
                id,
                domain: domain.to_owned(),
                name,
                rtype: rtype.to_owned(),
                text,
                fields,
                ttl,
            });
            id
        })
    }

    /// Deletes the record `id` directly, as another writer would.
    pub fn delete_record(&self, id: u64) {
        self.change(|inner| inner.records.retain(|r| r.id != id));
    }

    /// Adds a domain, delegated or not.
    pub fn insert_domain(&self, domain: &str, delegated: bool) {
        self.change(|inner| inner.domains.push((domain.to_owned(), delegated)));
    }

    /// Deletes `domain` with its records and creates it again with the same records under new
    /// identifiers.
    pub fn recreate_domain(&self, domain: &str) {
        self.change(|inner| {
            let mut next = inner.next_id;
            for record in inner.records.iter_mut().filter(|r| r.domain == domain) {
                next += 1;
                record.id = next;
            }
            inner.next_id = next;
        });
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
        (NameForm::Absolute, "@") => format!("{}.", record.domain),
        (NameForm::Absolute, name) => format!("{name}.{}.", record.domain),
    };
    let mut body = json!({
        "recordId": record.id, "type": record.rtype, "name": name, "ttl": record.ttl
    });
    if let Some(object) = body.as_object_mut() {
        if !record.text.is_empty() {
            object.insert("text".to_owned(), Value::String(record.text.clone()));
        }
        for (key, value) in &record.fields {
            object.insert(key.clone(), value.clone());
        }
    }
    body
}

/// What a create or an edit body describes, after the checks.
struct Written {
    name: String,
    rtype: String,
    text: String,
    fields: Map<String, Value>,
    ttl: u32,
}

fn is_u16(value: &Value) -> bool {
    value.as_u64().is_some_and(|n| n <= u64::from(u16::MAX))
}

fn non_empty(value: &Value) -> bool {
    value.as_str().is_some_and(|s| !s.is_empty())
}

/// The checks of one type field (see the inventions at the top of the file).
fn field_ok(rtype: &str, key: &str, value: &Value) -> bool {
    match (rtype, key) {
        ("A", "address") => value
            .as_str()
            .is_some_and(|s| s.parse::<std::net::Ipv4Addr>().is_ok()),
        ("AAAA", "address") => value
            .as_str()
            .is_some_and(|s| s.parse::<std::net::Ipv6Addr>().is_ok()),
        (_, "preference" | "priority" | "weight" | "port") => is_u16(value),
        ("CAA", "flag") => value.as_u64().is_some_and(|n| n <= 255),
        ("CAA", "value") => value
            .as_str()
            .is_some_and(|s| s.len() >= 2 && s.starts_with('"') && s.ends_with('"')),
        _ => non_empty(value),
    }
}

/// Checks a create (`edit` false) or an edit body; `Err` is the answer to give.
fn check_body(body: &[u8], edit: bool) -> Result<Written, Response> {
    let Ok(body) = serde_json::from_slice::<Value>(body) else {
        return Err(bad_request("the body is not JSON"));
    };
    let Some(object) = body.as_object() else {
        return Err(bad_request("the body is not an object"));
    };
    let Some(rtype) = object.get("type").and_then(Value::as_str) else {
        return Err(bad_request("type is required"));
    };
    if rtype == "NS" {
        return Err(bad_request("the mock does not know the fields of NS"));
    }
    let Some(&(_, own)) = TYPE_FIELDS.iter().find(|(t, _)| *t == rtype) else {
        return Err(bad_request("type is not a known record type"));
    };
    if edit && rtype == "CAA" {
        return Err(bad_request("an edit has no CAA fields"));
    }
    let Some(name) = object.get("name").and_then(Value::as_str) else {
        return Err(bad_request("name is required"));
    };
    if name.is_empty() || name.ends_with('.') {
        return Err(bad_request("the name is empty or absolute"));
    }
    let Some(ttl) = object
        .get("ttl")
        .and_then(Value::as_u64)
        .filter(|&t| t >= 1 && t <= u64::from(u32::MAX))
    else {
        return Err(bad_request(
            "ttl is required and must be a positive integer",
        ));
    };
    let mut fields = Map::new();
    for &key in ALL_FIELDS {
        let Some(value) = object.get(key) else {
            continue;
        };
        if !own.contains(&key) || (edit && CAA_FIELDS.contains(&key)) {
            return Err(bad_request("a field of another record type"));
        }
        if !field_ok(rtype, key, value) {
            return Err(bad_request("a field is not valid"));
        }
        fields.insert(key.to_owned(), value.clone());
    }
    if own.iter().any(|key| !fields.contains_key(*key)) {
        return Err(bad_request("a field of the type is missing"));
    }
    let text = match fields.remove("text") {
        Some(Value::String(text)) => text,
        _ => String::new(),
    };
    Ok(Written {
        // Relative to the domain, as lego sends it, or `@`: stored as given.
        name: name.to_lowercase(),
        rtype: rtype.to_owned(),
        text,
        fields,
        // `ttl` was checked to fit.
        ttl: u32::try_from(ttl).unwrap_or(u32::MAX),
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
    let written = match check_body(&body, false) {
        Ok(written) => written,
        Err(response) => return response,
    };
    inner.next_id += 1;
    let record = Record {
        id: inner.next_id,
        domain: domain.clone(),
        name: written.name,
        rtype: written.rtype,
        text: written.text,
        fields: written.fields,
        ttl: written.ttl,
    };
    let created = record_json(&record, inner.name_form);
    let before = inner.published();
    inner.records.push(record);
    inner.report(&before, Origin::Api);
    axum::Json(created).into_response()
}

async fn record_edit(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((org, domain, id)): Path<(String, String, String)>,
    body: axum::body::Bytes,
) -> Response {
    let mut inner = lock(&state);
    if let Err(response) = domain_of(&inner, &headers, &org, &domain) {
        return response;
    }
    let Ok(id) = id.parse::<u64>() else {
        return bad_request("recordId is not a number");
    };
    let written = match check_body(&body, true) {
        Ok(written) => written,
        Err(response) => return response,
    };
    let form = inner.name_form;
    let before = inner.published();
    let Some(record) = inner
        .records
        .iter_mut()
        .find(|r| r.domain == domain && r.id == id)
    else {
        return not_found();
    };
    record.name = written.name;
    record.rtype = written.rtype;
    record.text = written.text;
    record.fields = written.fields;
    record.ttl = written.ttl;
    let answer = record_json(record, form);
    inner.report(&before, Origin::Api);
    axum::Json(answer).into_response()
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
    let published = inner.published();
    let before = inner.records.len();
    inner
        .records
        .retain(|r| !(r.domain == domain && r.id == id));
    if inner.records.len() == before {
        return not_found();
    }
    inner.report(&published, Origin::Api);
    axum::Json(json!({})).into_response()
}
