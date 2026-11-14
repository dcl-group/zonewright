//! Mock of the VK Cloud public DNS API (v2) and of the Keystone identity service in front of it.
//!
//! Shapes follow the sources the client cites:
//!
//! - The provider's OpenAPI description of the public DNS API, linked from
//!   <https://cloud.vk.ru/docs/ru/tools-for-using-services/api/api-spec/network-api/api-dns>
//!   (`assets/public-dns-api.json`, "the OpenAPI" below): `GET /v2/dns/` answers `200` with an
//!   array of zones (`zone` without the trailing dot, `tenant`, `status`, the identifier) or `404`
//!   ("records not found"); `GET /v2/dns/{zone}/txt/` answers `200` with an array of
//!   `{uuid, name, dns, content, ttl}` or `404`; `POST /v2/dns/{zone}/txt/` takes `name`,
//!   `content` (at most 255 characters) and `ttl` (60 to 2147483648), all three required, and
//!   answers `201` with the new record, `400` for a validation error, `409` for a duplicate;
//!   `DELETE /v2/dns/{zone}/txt/{record}` answers `204`, or `404` when the record is not found;
//!   a request without a valid token answers `401`.
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
//! - a create of a name and content that exists is the "duplication" of the documented `409`;
//! - zones of another project are not listed, and requests into them answer `404`;
//! - a record name ending in a dot is refused with `400` (names are relative to the zone);
//! - error bodies are `{"error": {"code", "message"}}`; error texts are invented.
//!
//! One documented rule is deliberately not enforced: the OpenAPI describes record names and TXT
//! content as "only digits, Latin letters, hyphen and dot", which would refuse every ACME
//! challenge name (`_acme-challenge`) and many challenge values; lego's provider exists to write
//! exactly those, so the description is taken as a copy of the zone-name rule.
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

// Handlers return finished HTTP answers as their error values and hand them straight to axum;
// boxing them would only add noise.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
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
use serde_json::{Value, json};

use crate::MockServer;

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
            zone_id_key: "uuid",
            token_ttl_s: 24 * 60 * 60,
        }
    }
}

/// The project of the standard seed.
pub const PROJECT: &str = "b5b7ffd4ef0547e5b222f44555df0000";

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
    seed: Seed,
    zones: Vec<Zone>,
    records: Vec<TxtRecord>,
    tokens: HashMap<String, IssuedToken>,
    issued: Vec<String>,
    next_id: u64,
}

impl Inner {
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
}

impl Deref for VkCloudMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl VkCloudMock {
    /// Starts the mock with `seed`.
    pub async fn start(seed: Seed) -> Self {
        let mut inner = Inner {
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
        let state = Arc::new(Mutex::new(inner));
        let router = Router::new()
            .route("/identity/v3/auth/tokens", post(keystone))
            .route("/public-dns/v2/dns/", get(zones_list))
            .route(
                "/public-dns/v2/dns/{zone}/txt/",
                get(txt_list).post(txt_create),
            )
            .route(
                "/public-dns/v2/dns/{zone}/txt/{record}",
                get(txt_get).delete(txt_delete),
            )
            .with_state(state.clone());
        Self {
            server: MockServer::start(router).await,
            control: Control { state },
        }
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
        let mut inner = lock(&self.state);
        let id = inner.new_id();
        inner.zones.push(Zone {
            id: id.clone(),
            name: bare(name),
            project_id: project_id.to_owned(),
        });
        id
    }

    /// Deletes zone `name` and creates it again under a new identifier, with the same records
    /// (under new record identifiers). Returns the new zone identifier.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn recreate_zone(&self, name: &str) -> String {
        let old_id = self.zone_id(name);
        let mut inner = lock(&self.state);
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
    }

    /// Every TXT record, in creation order.
    pub fn records(&self) -> Vec<TxtRecord> {
        lock(&self.state).records.clone()
    }

    /// The TXT records of zone `zone` whose stored name is `name`.
    pub fn records_at(&self, zone: &str, name: &str) -> Vec<TxtRecord> {
        let zone_id = self.zone_id(zone);
        lock(&self.state)
            .records
            .iter()
            .filter(|r| r.zone_id == zone_id && r.name == name)
            .cloned()
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
        let zone_id = self.zone_id(zone);
        let mut inner = lock(&self.state);
        let uuid = inner.new_id();
        inner.records.push(TxtRecord {
            uuid: uuid.clone(),
            zone_id,
            name: name.to_owned(),
            content: content.to_owned(),
            ttl,
        });
        uuid
    }

    /// Deletes the TXT records of zone `zone` whose stored name is `name`, as another writer
    /// would.
    pub fn delete_txt_at(&self, zone: &str, name: &str) {
        let zone_id = self.zone_id(zone);
        lock(&self.state)
            .records
            .retain(|r| !(r.zone_id == zone_id && r.name == name));
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

fn record_json(record: &TxtRecord) -> Value {
    json!({
        "uuid": record.uuid,
        "name": record.name,
        "dns": format!("/v2/dns/{}", record.zone_id),
        "content": record.content,
        "ttl": record.ttl,
    })
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

async fn txt_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(zone_id): Path<String>,
) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    if let Err(response) = own_zone(&state, &zone_id, &project) {
        return response;
    }
    let records: Vec<Value> = lock(&state)
        .records
        .iter()
        .filter(|r| r.zone_id == zone_id)
        .map(record_json)
        .collect();
    listing(&state, records)
}

async fn txt_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((zone_id, record_id)): Path<(String, String)>,
) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    if let Err(response) = own_zone(&state, &zone_id, &project) {
        return response;
    }
    let found = lock(&state)
        .records
        .iter()
        .find(|r| r.zone_id == zone_id && r.uuid == record_id)
        .map(record_json);
    match found {
        Some(record) => axum::Json(record).into_response(),
        None => error(StatusCode::NOT_FOUND, "record not found"),
    }
}

async fn txt_create(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(zone_id): Path<String>,
    body: Bytes,
) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    if let Err(response) = own_zone(&state, &zone_id, &project) {
        return response;
    }
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "malformed request body");
    };
    let (Some(name), Some(content), Some(ttl)) = (
        request["name"].as_str(),
        request["content"].as_str(),
        request["ttl"].as_u64(),
    ) else {
        return error(
            StatusCode::BAD_REQUEST,
            "name, content and ttl are required",
        );
    };
    if name.is_empty() || name.ends_with('.') {
        return error(StatusCode::BAD_REQUEST, "invalid record name");
    }
    if content.is_empty() || content.chars().count() > MAX_CONTENT {
        return error(StatusCode::BAD_REQUEST, "invalid content");
    }
    if !(TTL_MIN..=TTL_MAX).contains(&ttl) {
        return error(StatusCode::BAD_REQUEST, "invalid ttl");
    }
    let mut inner = lock(&state);
    if inner
        .records
        .iter()
        .any(|r| r.zone_id == zone_id && r.name == name && r.content == content)
    {
        return error(StatusCode::CONFLICT, "duplicate record");
    }
    let record = TxtRecord {
        uuid: inner.new_id(),
        zone_id,
        name: name.to_owned(),
        content: content.to_owned(),
        ttl,
    };
    inner.records.push(record.clone());
    (StatusCode::CREATED, axum::Json(record_json(&record))).into_response()
}

async fn txt_delete(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((zone_id, record_id)): Path<(String, String)>,
) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    if let Err(response) = own_zone(&state, &zone_id, &project) {
        return response;
    }
    let mut inner = lock(&state);
    let before = inner.records.len();
    inner
        .records
        .retain(|r| !(r.zone_id == zone_id && r.uuid == record_id));
    if inner.records.len() == before {
        return error(StatusCode::NOT_FOUND, "record not found");
    }
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
