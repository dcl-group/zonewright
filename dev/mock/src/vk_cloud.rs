//! Mock of the VK Cloud public DNS API (v2) and of the Keystone identity service in front of it.
//!
//! Shapes follow the sources the client cites:
//!
//! - The provider's OpenAPI description of the public DNS API, linked from
//!   <https://cloud.vk.ru/docs/ru/tools-for-using-services/api/api-spec/network-api/api-dns>
//!   (`assets/public-dns-api.json`, "the OpenAPI" below): `GET /v2/dns/` answers `200` with an
//!   array of zones (`zone` without the trailing dot, `tenant`, `status`, the identifier) or `404`
//!   ("records not found"); for each type `{type}` of `a`, `aaaa`, `cname`, `mx`, `ns`, `srv`
//!   and `txt`, `GET /v2/dns/{zone}/{type}/` answers `200` with an array of
//!   `{uuid, name, dns, ttl, <the type's fields>}` or `404`; `POST /v2/dns/{zone}/{type}/` takes
//!   the type's `…_Create` fields and answers `201` with the new record, `400` for a validation
//!   error, `409` for a duplicate; `DELETE /v2/dns/{zone}/{type}/{record}` answers `204`, or
//!   `404` when the record is not found; `PUT /v2/dns/{zone}/{type}/{record}` takes the type's
//!   `…_Update` fields (`name` for A, AAAA and SRV, `content` for CNAME, MX, NS and TXT) and
//!   answers `200` with the changed record, `400` for a validation error, `404` when the record
//!   is not found; a request without a valid token answers `401`. The
//!   fields per type: A `name`, `ipv4`, `ttl`; AAAA `name`, `ipv6`, `ttl`; CNAME, NS and TXT
//!   `name`, `content`, `ttl`; MX `name`, `content`, `priority`, `ttl`; SRV `name`, `priority`,
//!   `weight`, `port`, `host` and an optional `ttl` (the OpenAPI's `required` lists). `ttl` is
//!   60 to 2147483648; TXT content is at most 255 characters; the content of CNAME, MX and NS
//!   "must consist of two or more subdomains", labels of at most 63 characters, and "cannot
//!   start or end with a hyphen or a dot" (`content-cname`, `content-mx`, `content-ns`); the
//!   SRV host "must consist of two or more subdomains" (the console documentation,
//!   <https://cloud.vk.ru/docs/en/networks/dns/publicdns>).
//! - lego `providers/dns/vkcloud` (`internal/types.go`): the zone identifier is listed as
//!   `uuid`. The OpenAPI names it `DnsUuid`; [`Seed::zone_id_key`] picks either.
//! - Keystone (the OpenStack Identity v3 API, as the provider's token documentation uses it):
//!   `POST /identity/v3/auth/tokens` answers `201` with the token in `X-Subject-Token` and
//!   `token.expires_at` in the body; wrong credentials answer `401`.
//!
//! Answers this mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading. A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - whether an empty listing is `404` or `200 []` is not stated (the OpenAPI documents `404`
//!   "records not found" next to `200`); [`Seed::empty_is_404`] picks one, `404` by default;
//! - a TXT listing or a create in a zone that does not exist answers `404` (documented for the
//!   listing as "records not found" only, not documented for the create);
//!   [`Seed::unknown_zone_lists_empty`] makes the listing answer `200 []` instead;
//! - a create of a name and value that exists (same type, same fields) is the "duplication" of
//!   the documented `409`;
//! - a create with a field the type's `…_Create` schema does not have is refused with `400`
//!   (the OpenAPI does not forbid extra fields; the mock refuses them so that a client sending
//!   another type's field is noticed);
//! - an SRV create without `ttl` stores 3600 (the OpenAPI makes it optional and names no
//!   default);
//! - `priority`, `weight` and `port` above 65535 are refused with `400` (the OpenAPI names no
//!   range); an `ipv4` or `ipv6` that does not parse as an address is refused with `400`;
//! - zones of another project are not listed, and requests into them answer `404`;
//! - a record name ending in a dot is refused with `400` (names are relative to the zone);
//! - an update changes exactly the fields its body names and keeps the record's identifier and
//!   TTL; an update body without any of the type's `…_Update` fields, or with a field the schema
//!   does not have, is refused with `400` (the OpenAPI requires no field and does not forbid
//!   extra ones); its values are checked as a create's are;
//! - error bodies are `{"error": {"code", "message"}}`; error texts are invented.
//!
//! One documented rule is deliberately not enforced: the OpenAPI describes record names and the
//! content of CNAME, MX, NS and TXT as "only digits, Latin letters, hyphen and dot", which would
//! refuse every ACME challenge name (`_acme-challenge`), every wildcard and SRV name and many
//! challenge values; lego's provider exists to write exactly those, so the description is taken
//! as a copy of the zone-name rule.
//!
//! A test holds a [`VkCloudMock`]. It dereferences to the [`MockServer`], so the request log
//! and the fault queue of the shared harness work as usual:
//!
//! ```text
//! let mock = VkCloudMock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("POST", "/public-dns/v2/dns/*/txt/").status(500));
//! // ... drive the client against mock.dns_url() and mock.identity_url() ...
//! assert_eq!(mock.control().txt_values("example.org", "_acme-challenge"), ["v1"]);
//! ```
//!
//! The mock is a [`ChangeSource`]: it reports every change of its published records through
//! [`VkCloudMock::changes`], the records of one name and type grouped into one rrset, and a
//! [`link`](crate::link::link) serves them over DNS. Every zone is published, whichever project
//! owns it. A record's name is read relative to its zone (`@` or an empty name is the apex; a
//! name ending in a dot is taken as absolute). The published form of a value: A and AAAA as
//! stored; CNAME and NS as `<content>.`; MX as `<priority> <content>.`; SRV as
//! `<priority> <weight> <port> <host>.`; TXT content that starts with a double quote as it is
//! (presentation form), any other content quoted as one character-string. The TTL of the set is
//! the smallest TTL of its records. A record of a type the mock does not know (written through
//! [`Control::insert_record`]) is published under the type's name in upper case with its
//! `content` field. Tokens and zone identifiers change nothing published. [`Control::reset`]
//! returns the mock to its seed.

// Handlers return finished HTTP answers as their error values and hand them straight to axum;
// boxing them would only add noise.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::changes::{ChangeSource, Changes, Origin, Published};
use crate::{Faults, MockServer, RequestLog};

/// Path of the DNS API below the server's base URL.
pub const DNS_PATH: &str = "/public-dns/v2/dns";

/// Path of the identity service below the server's base URL.
pub const IDENTITY_PATH: &str = "/identity/v3";

/// Longest TXT content the API accepts (the OpenAPI, `content-txt`).
const MAX_CONTENT: usize = 255;

/// TTL range the API accepts (the OpenAPI, `ttl`).
const TTL_MIN: u64 = 60;
const TTL_MAX: u64 = 2_147_483_648;

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// Users that can obtain a token.
    pub users: Vec<User>,
    /// Zones, in listing order.
    pub zones: Vec<SeedZone>,
    /// Answer an empty listing with `404` instead of `200 []`.
    pub empty_is_404: bool,
    /// Answer a TXT listing under a zone identifier that does not exist with `200 []` instead
    /// of `404`.
    pub unknown_zone_lists_empty: bool,
    /// The key of the zone identifier in the zone listing: `uuid` (lego) or `DnsUuid` (the
    /// OpenAPI).
    pub zone_id_key: &'static str,
    /// Lifetime of an issued token, as stated in `token.expires_at`.
    pub token_ttl_s: u64,
}

/// A user of the identity service.
#[derive(Clone, Debug)]
pub struct User {
    /// The user's name (an e-mail address at the provider).
    pub username: String,
    /// The user's Keystone domain.
    pub user_domain: String,
    /// The user's password.
    pub password: String,
    /// The project a token is scoped to.
    pub project_id: String,
}

/// A zone of the seed.
#[derive(Clone, Debug)]
pub struct SeedZone {
    /// The zone name, without the trailing dot.
    pub name: String,
    /// The project (tenant) that owns it.
    pub project_id: String,
}

impl Seed {
    /// User `dns@example.test` in domain `users` with password `test-only-password`, scoped to
    /// project `b5b7ffd4ef0547e5b222f44555df0000`, and the zone `example.org` in that project.
    /// Empty listings answer `404`; zones carry their identifier as `uuid`.
    pub fn standard() -> Self {
        Self {
            users: vec![User {
                username: "dns@example.test".into(),
                user_domain: "users".into(),
                password: "test-only-password".into(),
                project_id: PROJECT.into(),
            }],
            zones: vec![SeedZone {
                name: "example.org".into(),
                project_id: PROJECT.into(),
            }],
            empty_is_404: true,
            unknown_zone_lists_empty: false,
            zone_id_key: "uuid",
            token_ttl_s: 24 * 60 * 60,
        }
    }
}

/// The project of the standard seed.
pub const PROJECT: &str = "b5b7ffd4ef0547e5b222f44555df0000";

/// The path segments of the record types the API documents.
pub const KINDS: [&str; 7] = ["a", "aaaa", "cname", "mx", "ns", "srv", "txt"];

/// A record of any type as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The record's identifier.
    pub uuid: String,
    /// The zone's identifier.
    pub zone_id: String,
    /// The type's path segment (`a`, `mx`, ...).
    pub kind: String,
    /// The name relative to the zone, `@` for the apex, as written.
    pub name: String,
    /// The type's value fields as written (`ipv4`, `content`, `priority`, ...).
    pub fields: Map<String, Value>,
    /// TTL in seconds.
    pub ttl: u64,
}

impl Record {
    /// A value field as text: strings as they are, numbers in decimal.
    pub fn field(&self, key: &str) -> Option<String> {
        match self.fields.get(key)? {
            Value::String(s) => Some(s.clone()),
            other => Some(other.to_string()),
        }
    }

    /// The record's value in zone-file form (module documentation).
    fn published_value(&self) -> String {
        let host = |name: String| format!("{}.", name.trim_end_matches('.'));
        let text = |key: &str| self.field(key).unwrap_or_default();
        match self.kind.as_str() {
            "a" => text("ipv4"),
            "aaaa" => text("ipv6"),
            "cname" | "ns" => host(text("content")),
            "mx" => format!("{} {}", text("priority"), host(text("content"))),
            "srv" => format!(
                "{} {} {} {}",
                text("priority"),
                text("weight"),
                text("port"),
                host(text("host"))
            ),
            "txt" => {
                let content = text("content");
                if content.starts_with('"') {
                    content
                } else {
                    quote(&content)
                }
            }
            _ => text("content"),
        }
    }

    fn to_txt(&self) -> TxtRecord {
        TxtRecord {
            uuid: self.uuid.clone(),
            zone_id: self.zone_id.clone(),
            name: self.name.clone(),
            content: self.field("content").unwrap_or_default(),
            ttl: self.ttl,
        }
    }
}

/// A TXT record as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TxtRecord {
    /// The record's identifier.
    pub uuid: String,
    /// The zone's identifier.
    #[serde(skip)]
    pub zone_id: String,
    /// The name relative to the zone, `@` for the apex, as written.
    pub name: String,
    /// The content as written.
    pub content: String,
    /// TTL in seconds.
    pub ttl: u64,
}

/// A zone as the mock holds it.
#[derive(Clone, Debug)]
pub struct Zone {
    /// The zone's identifier.
    pub id: String,
    /// The zone name, lowercase, without the trailing dot.
    pub name: String,
    /// The project that owns it.
    pub project_id: String,
}

#[derive(Debug)]
struct IssuedToken {
    project_id: String,
    revoked: bool,
}

#[derive(Debug)]
struct Inner {
    /// The seed the mock was started with, for [`Control::reset`]; `seed` below can be changed
    /// by [`Control::set_token_ttl`].
    initial: Seed,
    changes: Changes,
    seed: Seed,
    zones: Vec<Zone>,
    records: Vec<Record>,
    tokens: HashMap<String, IssuedToken>,
    issued: Vec<String>,
    next_id: u64,
}

impl Inner {
    /// The state of a mock started with `seed`.
    fn new(seed: Seed, changes: Changes) -> Inner {
        let mut inner = Inner {
            initial: seed.clone(),
            changes,
            seed: seed.clone(),
            zones: Vec::new(),
            records: Vec::new(),
            tokens: HashMap::new(),
            issued: Vec::new(),
            next_id: 0,
        };
        for zone in &seed.zones {
            let id = inner.new_id();
            inner.zones.push(Zone {
                id,
                name: bare(&zone.name),
                project_id: zone.project_id.clone(),
            });
        }
        inner
    }

    /// What a DNS server for the mock's zones would answer (module documentation).
    fn published(&self) -> Published {
        let mut out = Published::new();
        for zone in &self.zones {
            out.zone(&zone.name);
        }
        for record in &self.records {
            let Some(zone) = self.zones.iter().find(|z| z.id == record.zone_id) else {
                continue;
            };
            let relative = record.name.trim();
            let name = if relative.is_empty() || relative == "@" {
                zone.name.clone()
            } else if relative.ends_with('.') {
                relative.to_owned()
            } else {
                format!("{relative}.{}", zone.name)
            };
            let ttl = u32::try_from(record.ttl).unwrap_or(u32::MAX);
            out.record(
                &zone.name,
                &name,
                &record.kind,
                Some(ttl),
                record.published_value(),
            );
        }
        out
    }

    /// Reports every published rrset that differs from `before`. Called with the state locked,
    /// after a change.
    fn report(&self, before: &Published, origin: Origin) {
        self.changes.emit_diff(before, &self.published(), origin);
    }

    /// A new identifier in the UUID form the provider uses.
    fn new_id(&mut self) -> String {
        self.next_id += 1;
        format!("00000000-0000-4000-8000-{:012x}", self.next_id)
    }
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running VK Cloud mock. Dereferences to its [`MockServer`] for the request log and the
/// fault queue; [`VkCloudMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct VkCloudMock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of a [`VkCloudMock`]. Cheap to clone, so that a fault hook
/// ([`Fault::run`](crate::Fault::run)) can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
    changes: Changes,
    log: RequestLog,
    faults: Faults,
}

impl Deref for VkCloudMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl VkCloudMock {
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
            .route("/identity/v3/auth/tokens", post(keystone))
            .route("/public-dns/v2/dns/", get(zones_list))
            .route(
                "/public-dns/v2/dns/{zone}/{kind}/",
                get(record_list).post(record_create),
            )
            .route(
                "/public-dns/v2/dns/{zone}/{kind}/{record}",
                get(record_get).put(record_update).delete(record_delete),
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

    /// The DNS API endpoint, for the client's `dns_url`.
    pub fn dns_url(&self) -> String {
        self.server.url(DNS_PATH)
    }

    /// The identity endpoint, for the client's `identity_url`.
    pub fn identity_url(&self) -> String {
        self.server.url(IDENTITY_PATH)
    }

    /// The state control.
    pub fn control(&self) -> &Control {
        &self.control
    }
}

impl ChangeSource for VkCloudMock {
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

    /// Returns the mock to the seed it was started with: its users, its zones under their first
    /// identifiers, no records, no tokens issued, the token lifetime of the seed, an empty
    /// request log and no pending faults. Reports the removal of every rrset that was published.
    pub fn reset(&self) {
        self.faults.clear();
        self.change(|inner| {
            let seed = inner.initial.clone();
            *inner = Inner::new(seed, inner.changes.clone());
        });
        self.log.clear();
    }

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
        let name = bare(name);
        lock(&self.state)
            .zones
            .iter()
            .find(|z| z.name == name)
            .map(|z| z.id.clone())
            .unwrap_or_else(|| panic!("no zone {name}"))
    }

    /// Adds a zone of `project_id` and returns its identifier.
    pub fn insert_zone(&self, name: &str, project_id: &str) -> String {
        self.change(|inner| {
            let id = inner.new_id();
            inner.zones.push(Zone {
                id: id.clone(),
                name: bare(name),
                project_id: project_id.to_owned(),
            });
            id
        })
    }

    /// Deletes zone `name` and creates it again under a new identifier, with the same records
    /// (under new record identifiers). Returns the new zone identifier.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn recreate_zone(&self, name: &str) -> String {
        let old_id = self.zone_id(name);
        self.change(|inner| {
            let new_id = inner.new_id();
            for zone in inner.zones.iter_mut().filter(|z| z.id == old_id) {
                zone.id = new_id.clone();
            }
            let moved: Vec<usize> = (0..inner.records.len())
                .filter(|&i| inner.records[i].zone_id == old_id)
                .collect();
            for i in moved {
                let uuid = inner.new_id();
                let record = &mut inner.records[i];
                record.zone_id = new_id.clone();
                record.uuid = uuid;
            }
            new_id
        })
    }

    /// Every TXT record, in creation order.
    pub fn records(&self) -> Vec<TxtRecord> {
        lock(&self.state)
            .records
            .iter()
            .filter(|r| r.kind == "txt")
            .map(Record::to_txt)
            .collect()
    }

    /// Every record of every type, in creation order.
    pub fn all_records(&self) -> Vec<Record> {
        lock(&self.state).records.clone()
    }

    /// The records of type `kind` (`a`, `mx`, ...) of zone `zone` whose stored name is `name`,
    /// in creation order.
    pub fn records_of(&self, zone: &str, kind: &str, name: &str) -> Vec<Record> {
        let zone_id = self.zone_id(zone);
        lock(&self.state)
            .records
            .iter()
            .filter(|r| r.zone_id == zone_id && r.kind == kind && r.name == name)
            .cloned()
            .collect()
    }

    /// The TXT records of zone `zone` whose stored name is `name`.
    pub fn records_at(&self, zone: &str, name: &str) -> Vec<TxtRecord> {
        self.records_of(zone, "txt", name)
            .iter()
            .map(Record::to_txt)
            .collect()
    }

    /// The contents of the TXT records of zone `zone` whose stored name is `name`, in creation
    /// order.
    pub fn txt_values(&self, zone: &str, name: &str) -> Vec<String> {
        self.records_at(zone, name)
            .into_iter()
            .map(|r| r.content)
            .collect()
    }

    /// Creates a TXT record directly, as another writer would: `name` is stored as given.
    /// Returns the record's identifier.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn insert_txt(&self, zone: &str, name: &str, content: &str, ttl: u64) -> String {
        self.insert_record(zone, "txt", name, json!({ "content": content }), ttl)
    }

    /// Creates a record of type `kind` directly, as another writer would, without validation:
    /// `name` and the value fields of the object `fields` are stored as given. Returns the
    /// record's identifier.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn insert_record(
        &self,
        zone: &str,
        kind: &str,
        name: &str,
        fields: Value,
        ttl: u64,
    ) -> String {
        let zone_id = self.zone_id(zone);
        self.change(|inner| {
            let uuid = inner.new_id();
            inner.records.push(Record {
                uuid: uuid.clone(),
                zone_id,
                kind: kind.to_owned(),
                name: name.to_owned(),
                fields: fields.as_object().cloned().unwrap_or_default(),
                ttl,
            });
            uuid
        })
    }

    /// Deletes the record with identifier `uuid`, as another writer would.
    pub fn delete_record(&self, uuid: &str) {
        self.change(|inner| inner.records.retain(|r| r.uuid != uuid));
    }

    /// Deletes the TXT records of zone `zone` whose stored name is `name`, as another writer
    /// would.
    pub fn delete_txt_at(&self, zone: &str, name: &str) {
        let zone_id = self.zone_id(zone);
        self.change(|inner| {
            inner
                .records
                .retain(|r| !(r.zone_id == zone_id && r.kind == "txt" && r.name == name));
        });
    }

    /// Revokes every token issued so far: requests with them answer `401`.
    pub fn revoke_tokens(&self) {
        for token in lock(&self.state).tokens.values_mut() {
            token.revoked = true;
        }
    }

    /// Every token issued so far, in order.
    pub fn issued_tokens(&self) -> Vec<String> {
        lock(&self.state).issued.clone()
    }

    /// Number of tokens issued so far.
    pub fn tokens_issued(&self) -> usize {
        lock(&self.state).issued.len()
    }

    /// Lifetime stated for tokens issued from now on. The mock does not enforce it; revoke
    /// tokens to make the API refuse them.
    pub fn set_token_ttl(&self, seconds: u64) {
        lock(&self.state).seed.token_ttl_s = seconds;
    }
}

/// `name` lowercase without a trailing dot.
fn bare(name: &str) -> String {
    name.trim().trim_end_matches('.').to_lowercase()
}

/// `text` as one quoted character-string, `"` and `\` escaped.
fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        if matches!(c, '"' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// An error answer in the invented shape.
fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        axum::Json(json!({"error": {"code": status.as_u16(), "message": message}})),
    )
        .into_response()
}

/// `seconds` since the Unix epoch as an RFC 3339 timestamp in UTC.
fn rfc3339(seconds: u64) -> String {
    let days = seconds / 86_400;
    let rest = seconds % 86_400;
    // Civil date from days since 1970-01-01 (H. Hinnant, "chrono-Compatible Low-Level Date
    // Algorithms").
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000000Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

async fn keystone(State(state): State<Shared>, body: Bytes) -> Response {
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "malformed request body");
    };
    let auth = &request["auth"];
    let user = &auth["identity"]["password"]["user"];
    let project = &auth["scope"]["project"];
    let mut inner = lock(&state);
    let found = inner
        .seed
        .users
        .iter()
        .find(|u| {
            auth["identity"]["methods"] == json!(["password"])
                && user["name"].as_str() == Some(u.username.as_str())
                && user["domain"]["name"].as_str() == Some(u.user_domain.as_str())
                && user["password"].as_str() == Some(u.password.as_str())
                && project["id"].as_str() == Some(u.project_id.as_str())
        })
        .cloned();
    let Some(user) = found else {
        return error(
            StatusCode::UNAUTHORIZED,
            "The request you have made requires authentication.",
        );
    };
    let n = inner.issued.len() + 1;
    let token = format!("gAAAA-vk-mock-token-{n:04}-zz");
    inner.tokens.insert(
        token.clone(),
        IssuedToken {
            project_id: user.project_id.clone(),
            revoked: false,
        },
    );
    inner.issued.push(token.clone());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let expires_at = rfc3339(now + inner.seed.token_ttl_s);
    drop(inner);
    let mut response = (
        StatusCode::CREATED,
        axum::Json(json!({"token": {
            "expires_at": expires_at,
            "methods": ["password"],
            "project": {"id": user.project_id}
        }})),
    )
        .into_response();
    if let Ok(value) = token.parse() {
        response.headers_mut().insert("x-subject-token", value);
    }
    response
}

/// The project of the request's `X-Auth-Token`, or the `401` answer.
fn authorize(state: &Shared, headers: &HeaderMap) -> Result<String, Response> {
    let refused = || error(StatusCode::UNAUTHORIZED, "authorization error");
    let token = headers
        .get("x-auth-token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(refused)?;
    match lock(state).tokens.get(token) {
        Some(t) if !t.revoked => Ok(t.project_id.clone()),
        _ => Err(refused()),
    }
}

/// The zone `zone_id` of `project`, or `404`.
fn own_zone(state: &Shared, zone_id: &str, project: &str) -> Result<Zone, Response> {
    lock(state)
        .zones
        .iter()
        .find(|z| z.id == zone_id && z.project_id == project)
        .cloned()
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "records not found"))
}

/// A listing: `404` when empty and the seed says so, else `200` with the array.
fn listing(state: &Shared, items: Vec<Value>) -> Response {
    if items.is_empty() && lock(state).seed.empty_is_404 {
        return error(StatusCode::NOT_FOUND, "records not found");
    }
    axum::Json(Value::Array(items)).into_response()
}

fn record_json(record: &Record) -> Value {
    let mut value = json!({
        "uuid": record.uuid,
        "name": record.name,
        "dns": format!("/v2/dns/{}", record.zone_id),
        "ttl": record.ttl,
    });
    if let Some(object) = value.as_object_mut() {
        for (key, field) in &record.fields {
            object.insert(key.clone(), field.clone());
        }
    }
    value
}

async fn zones_list(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    let inner = lock(&state);
    let key = inner.seed.zone_id_key;
    let zones: Vec<Value> = inner
        .zones
        .iter()
        .filter(|z| z.project_id == project)
        .map(|z| {
            let mut value = json!({
                "tenant": z.project_id,
                "zone": z.name,
                "soa_primary_dns": "ns1.example.test",
                "soa_admin_email": "admin@example.test.",
                "soa_serial": 1,
                "soa_refresh": 86400,
                "soa_retry": 7200,
                "soa_expire": 3_600_000,
                "soa_ttl": 86400,
                "status": "active",
            });
            value[key] = json!(z.id);
            value
        })
        .collect();
    drop(inner);
    listing(&state, zones)
}

/// The type of a path segment, or the `404` answer.
fn kind_of(kind: &str) -> Result<&'static str, Response> {
    KINDS
        .into_iter()
        .find(|k| *k == kind)
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "not found"))
}

async fn record_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((zone_id, kind)): Path<(String, String)>,
) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    let kind = match kind_of(&kind) {
        Ok(kind) => kind,
        Err(response) => return response,
    };
    if let Err(response) = own_zone(&state, &zone_id, &project) {
        if lock(&state).seed.unknown_zone_lists_empty {
            return axum::Json(Value::Array(Vec::new())).into_response();
        }
        return response;
    }
    let records: Vec<Value> = lock(&state)
        .records
        .iter()
        .filter(|r| r.zone_id == zone_id && r.kind == kind)
        .map(record_json)
        .collect();
    listing(&state, records)
}

async fn record_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((zone_id, kind, record_id)): Path<(String, String, String)>,
) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    let kind = match kind_of(&kind) {
        Ok(kind) => kind,
        Err(response) => return response,
    };
    if let Err(response) = own_zone(&state, &zone_id, &project) {
        return response;
    }
    let found = lock(&state)
        .records
        .iter()
        .find(|r| r.zone_id == zone_id && r.kind == kind && r.uuid == record_id)
        .map(record_json);
    match found {
        Some(record) => axum::Json(record).into_response(),
        None => error(StatusCode::NOT_FOUND, "record not found"),
    }
}

/// The value fields of a type's `…_Create` schema (`name` and `ttl` apart).
fn value_fields(kind: &str) -> &'static [&'static str] {
    match kind {
        "a" => &["ipv4"],
        "aaaa" => &["ipv6"],
        "mx" => &["content", "priority"],
        "srv" => &["priority", "weight", "port", "host"],
        _ => &["content"],
    }
}

/// A host name of CNAME, MX or NS content, or an SRV host: at least two labels of 1 to 63
/// characters, at most 255 characters, not starting or ending with a hyphen or a dot.
fn valid_fqdn(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 255
        && !text.starts_with(['-', '.'])
        && !text.ends_with(['-', '.'])
        && text.contains('.')
        && text.split('.').all(|l| (1..=63).contains(&l.len()))
}

/// The validation of a create's value fields (the module documentation lists the rules).
fn check_fields(
    kind: &str,
    request: &Map<String, Value>,
) -> Result<Map<String, Value>, &'static str> {
    let mut fields = Map::new();
    for key in request.keys() {
        if !matches!(key.as_str(), "name" | "ttl") && !value_fields(kind).contains(&key.as_str()) {
            return Err("unknown field");
        }
    }
    for key in value_fields(kind) {
        let value = request.get(*key).ok_or("a required field is missing")?;
        let valid = match *key {
            "ipv4" => value
                .as_str()
                .is_some_and(|s| s.parse::<Ipv4Addr>().is_ok()),
            "ipv6" => value
                .as_str()
                .is_some_and(|s| s.parse::<Ipv6Addr>().is_ok()),
            "priority" | "weight" | "port" => value.as_u64().is_some_and(|n| n <= 65_535),
            "host" => value.as_str().is_some_and(valid_fqdn),
            _ if kind == "txt" => value
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.chars().count() <= MAX_CONTENT),
            _ => value.as_str().is_some_and(valid_fqdn),
        };
        if !valid {
            return Err("invalid field value");
        }
        fields.insert((*key).to_owned(), value.clone());
    }
    Ok(fields)
}

async fn record_create(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((zone_id, kind)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    let kind = match kind_of(&kind) {
        Ok(kind) => kind,
        Err(response) => return response,
    };
    if let Err(response) = own_zone(&state, &zone_id, &project) {
        return response;
    }
    let Ok(Value::Object(request)) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "malformed request body");
    };
    let Some(name) = request.get("name").and_then(Value::as_str) else {
        return error(StatusCode::BAD_REQUEST, "name is required");
    };
    if name.is_empty() || name.ends_with('.') {
        return error(StatusCode::BAD_REQUEST, "invalid record name");
    }
    let ttl = match (request.get("ttl"), kind) {
        (None, "srv") => 3600,
        (None, _) => return error(StatusCode::BAD_REQUEST, "ttl is required"),
        (Some(ttl), _) => match ttl.as_u64() {
            Some(ttl) if (TTL_MIN..=TTL_MAX).contains(&ttl) => ttl,
            _ => return error(StatusCode::BAD_REQUEST, "invalid ttl"),
        },
    };
    let fields = match check_fields(kind, &request) {
        Ok(fields) => fields,
        Err(message) => return error(StatusCode::BAD_REQUEST, message),
    };
    let mut inner = lock(&state);
    if inner
        .records
        .iter()
        .any(|r| r.zone_id == zone_id && r.kind == kind && r.name == name && r.fields == fields)
    {
        return error(StatusCode::CONFLICT, "duplicate record");
    }
    let record = Record {
        uuid: inner.new_id(),
        zone_id,
        kind: kind.to_owned(),
        name: name.to_owned(),
        fields,
        ttl,
    };
    let before = inner.published();
    inner.records.push(record.clone());
    inner.report(&before, Origin::Api);
    (StatusCode::CREATED, axum::Json(record_json(&record))).into_response()
}

/// The fields of a type's `…_Update` schema.
fn update_fields(kind: &str) -> &'static [&'static str] {
    match kind {
        "a" | "aaaa" | "srv" => &["name"],
        _ => &["content"],
    }
}

async fn record_update(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((zone_id, kind, record_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    let kind = match kind_of(&kind) {
        Ok(kind) => kind,
        Err(response) => return response,
    };
    if let Err(response) = own_zone(&state, &zone_id, &project) {
        return response;
    }
    let Ok(Value::Object(request)) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "malformed request body");
    };
    let allowed = update_fields(kind);
    if request.is_empty() || request.keys().any(|k| !allowed.contains(&k.as_str())) {
        return error(StatusCode::BAD_REQUEST, "invalid update fields");
    }
    let mut changes = Map::new();
    for (key, value) in &request {
        let valid = match (key.as_str(), kind) {
            ("name", _) => value
                .as_str()
                .is_some_and(|s| !s.is_empty() && !s.ends_with('.')),
            (_, "txt") => value
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.chars().count() <= MAX_CONTENT),
            _ => value.as_str().is_some_and(valid_fqdn),
        };
        if !valid {
            return error(StatusCode::BAD_REQUEST, "invalid field value");
        }
        changes.insert(key.clone(), value.clone());
    }
    let mut inner = lock(&state);
    let before = inner.published();
    let Some(record) = inner
        .records
        .iter_mut()
        .find(|r| r.zone_id == zone_id && r.kind == kind && r.uuid == record_id)
    else {
        return error(StatusCode::NOT_FOUND, "record not found");
    };
    for (key, value) in changes {
        match (key.as_str(), value) {
            ("name", Value::String(name)) => record.name = name,
            (_, value) => {
                record.fields.insert(key, value);
            }
        }
    }
    let answer = record_json(record);
    inner.report(&before, Origin::Api);
    axum::Json(answer).into_response()
}

async fn record_delete(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((zone_id, kind, record_id)): Path<(String, String, String)>,
) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    let kind = match kind_of(&kind) {
        Ok(kind) => kind,
        Err(response) => return response,
    };
    if let Err(response) = own_zone(&state, &zone_id, &project) {
        return response;
    }
    let mut inner = lock(&state);
    let published = inner.published();
    let before = inner.records.len();
    inner
        .records
        .retain(|r| !(r.zone_id == zone_id && r.kind == kind && r.uuid == record_id));
    if inner.records.len() == before {
        return error(StatusCode::NOT_FOUND, "record not found");
    }
    inner.report(&published, Origin::Api);
    StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
mod tests {
    use super::rfc3339;

    #[test]
    fn timestamps_are_rfc3339() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000000Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00.000000Z");
    }
}
