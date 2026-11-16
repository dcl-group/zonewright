//! Mock of the Selectel DNS v2 API and of the Keystone identity service in front of it.
//!
//! Shapes follow the provider's documentation, the same sources the client cites:
//!
//! - DNS v2: <https://docs.selectel.ru/api/docs/cloud-services/dns_api/dns_api_actual/> and the
//!   OpenAPI document behind it, <https://docs.selectel.ru/api/dns-actual.json>: zones and
//!   rrsets in `{count, next_offset, result}` pages with `limit` (minimum 1, default 1000) and
//!   `offset`; create answers `200` with the new rrset; `PATCH` (`ttl` and `records` required,
//!   `comment` at most 255 characters, `X-Managed-By` header) and `DELETE` (`X-Managed-By`
//!   header, no request body) answer `204`; a
//!   missing zone or rrset is `404`; validation errors are `422`; error bodies are
//!   `{"error", "description"}`; `ttl` 60 to 604800; `records` 1 to 100; the types of
//!   `AllowedRecordTypes`.
//! - Keystone: <https://docs.selectel.ru/en/api/authorization/> and the OpenStack Identity v3
//!   API: `POST /identity/v3/auth/tokens` answers `201` with the token in `X-Subject-Token`
//!   and `token.expires_at` and `token.project` in the body; wrong credentials answer `401`.
//!
//! Answers this mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading. A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - a create of a name and type that exists answers `409` (the documented codes of the create
//!   are 200, 400, 401, 404, 422, 500; `409` is documented for zone calls only);
//! - the zone `filter` and the rrset `name` filter match substrings, so a listing returns
//!   "noisy" neighbors the client must skip;
//! - a zone of another project is either hidden from `GET /zones` or listed
//!   ([`Seed::list_foreign_zones`]); requests into it answer `403` on every path (documented
//!   for `PATCH` and `DELETE` only);
//! - a TXT record whose content is not quoted is refused with `422`; content that does not have
//!   the form of its type (below) is refused with `422` as well (the documented validation
//!   status; the per-type check itself is the mock's reading of the sources), except in an
//!   update for a record whose content the rrset already holds: the provider's own data written
//!   back unchanged are accepted as they are;
//! - the content of DNAME, HTTPS and SVCB records is not checked beyond being non-empty: no source
//!   gives its form;
//! - a create of an SOA rrset, and an update or delete of the SOA rrset or of the NS rrset at the
//!   apex, is refused with `422` (the documentation says these "cannot be edited or deleted",
//!   not with which status);
//! - an update replaces the comment with the one it carries (none when absent) and the
//!   managing resource with its `X-Managed-By` header (none when absent);
//! - a delete removes an rrset whether or not it is managed, with or without an `X-Managed-By`
//!   header, and whatever UUID the header names (the documentation does not say whether the
//!   header must match, or what it changes);
//! - an `X-Managed-By` header that is not a UUID (`PATCH` and `DELETE`; the documented schema
//!   is a UUID or null) and a `DELETE` with a request body (the documented call has none) are
//!   refused with `422`, the documented validation status;
//! - the next offset of the last page is `0`.
//!
//! Content per type, as the provider's Terraform documentation for `selectel_domains_rrset_v2`
//! describes it (`docs/resources/domains_rrset_v2.md` in
//! `github.com/selectel/terraform-provider-selectel`): A an IPv4 address; AAAA an IPv6 address;
//! TXT text wrapped in quotes; CNAME, ALIAS and NS a name "with a dot at the end"; MX
//! `<priority> <host>`; SRV `<priority> <weight> <port> <target>`; SSHFP
//! `<algorithm> <fingerprint_type> <fingerprint>` with algorithm 1 to 4, type 1 or 2 and a hex
//! fingerprint; CAA `<flag> <tag> <value>` with flag 0 to 128, tag one of `issue`, `issuewild`,
//! `iodef`, `auth`, `path`, `policy`, and the value wrapped in quotes. The mock accepts nothing
//! looser; a name's labels are checked only for being non-empty.
//!
//! Error texts are invented.
//!
//! A test holds a [`SelectelV2Mock`]. It dereferences to the [`MockServer`], so the request log
//! and the fault queue of the shared harness work as usual:
//!
//! ```text
//! let mock = SelectelV2Mock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("POST", "/domains/v2/zones/*/rrset").status(500));
//! // ... drive the client against mock.base_url() and mock.auth_url() ...
//! assert_eq!(mock.control().txt_values("_acme-challenge.example.org"), ["v1"]);
//! // Requests the API received, and tokens the identity service issued:
//! assert_eq!(mock.log().count(Some("POST"), "/domains/v2/zones/*/rrset"), 2);
//! assert_eq!(mock.control().tokens_issued(), 1);
//! ```
//!
//! The mock is a [`ChangeSource`]: it reports every change of its published records (records
//! that are not disabled, in every zone of every project) through [`SelectelV2Mock::changes`],
//! and a [`link`](crate::link::link) serves them over DNS. The `disabled` flag of a zone does not
//! change what is published. [`Control::reset`] returns the mock to its seed.

// Handlers return finished HTTP answers as their error values and hand them straight to axum;
// boxing them would only add noise.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::changes::{ChangeSource, Changes, Origin, Published};
use crate::{Faults, MockServer, RequestLog};

/// Path of the DNS API below the server's base URL.
pub const API_PATH: &str = "/domains/v2";

/// Path of the identity service below the server's base URL.
pub const IDENTITY_PATH: &str = "/identity/v3";

/// Record types the DNS API accepts (the OpenAPI, `AllowedRecordTypes`).
const TYPES: [&str; 14] = [
    "A", "AAAA", "ALIAS", "CAA", "CNAME", "DNAME", "HTTPS", "MX", "NS", "SOA", "SRV", "SVCB",
    "SSHFP", "TXT",
];

/// Default page size and largest rrset the API accepts.
const DEFAULT_LIMIT: usize = 1000;
const MAX_RECORDS: usize = 100;

/// Longest comment of an rrset.
const MAX_COMMENT: usize = 255;

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// Service users that can obtain a token.
    pub users: Vec<User>,
    /// Zones, in listing order.
    pub zones: Vec<SeedZone>,
    /// List zones of other projects in `GET /zones` (requests into them answer `403`). The live
    /// API's behavior is not established, so the client is tested against both.
    pub list_foreign_zones: bool,
    /// Lifetime of an issued token, as stated in `token.expires_at`.
    pub token_ttl_s: u64,
}

/// A service user.
#[derive(Clone, Debug)]
pub struct User {
    /// The account number, which is also the user's Keystone domain.
    pub account_id: String,
    /// The user's name.
    pub username: String,
    /// The user's password.
    pub password: String,
    /// The project a token is scoped to.
    pub project_id: String,
    /// The project's name, for scope by name.
    pub project_name: String,
}

/// A zone of the seed.
#[derive(Clone, Debug)]
pub struct SeedZone {
    /// The zone name, with or without the trailing dot.
    pub name: String,
    /// The project that owns it.
    pub project_id: String,
}

impl Seed {
    /// Account `123456`, user `zw-test-user` with password `test-only-password` in project
    /// `project-a` (named `dns-project`), and the zone `example.org.` in that project. Tokens
    /// state a lifetime of 24 hours, as the provider's do.
    pub fn standard() -> Self {
        Self {
            users: vec![User {
                account_id: "123456".into(),
                username: "zw-test-user".into(),
                password: "test-only-password".into(),
                project_id: "project-a".into(),
                project_name: "dns-project".into(),
            }],
            zones: vec![SeedZone {
                name: "example.org.".into(),
                project_id: "project-a".into(),
            }],
            list_foreign_zones: false,
            token_ttl_s: 24 * 60 * 60,
        }
    }
}

/// One record of an rrset, as the API carries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The record's value in the API's text form; TXT content is quoted.
    pub content: String,
    /// A disabled record is kept but not published.
    #[serde(default)]
    pub disabled: bool,
}

/// An rrset as the API returns it.
#[derive(Clone, Debug, Serialize)]
pub struct Rrset {
    /// The rrset's identifier.
    pub id: String,
    /// The zone's identifier.
    pub zone_id: String,
    /// The owner name, absolute, with the trailing dot.
    pub name: String,
    /// The record type.
    #[serde(rename = "type")]
    pub rtype: String,
    /// TTL in seconds.
    pub ttl: u32,
    /// Free text; `null` when unset.
    pub comment: Option<String>,
    /// Free text; `null` when unset.
    pub managed_by: Option<String>,
    /// The records.
    pub records: Vec<Record>,
}

/// A zone as the mock holds it.
#[derive(Clone, Debug)]
pub struct Zone {
    /// The zone's identifier.
    pub id: String,
    /// The zone name, lowercase, with the trailing dot.
    pub name: String,
    /// The project that owns it.
    pub project_id: String,
    /// A disabled zone is listed with `"disabled": true`.
    pub disabled: bool,
}

#[derive(Debug)]
struct IssuedToken {
    project_id: String,
    revoked: bool,
}

#[derive(Debug)]
struct Inner {
    /// The seed the mock was started with, for [`Control::reset`].
    original: Seed,
    /// The seed in force; [`Control::set_token_ttl`] changes it.
    seed: Seed,
    zones: Vec<Zone>,
    rrsets: Vec<Rrset>,
    tokens: HashMap<String, IssuedToken>,
    issued: Vec<String>,
    next_id: u64,
    changes: Changes,
}

impl Inner {
    /// The state of a mock started with `seed`.
    fn new(seed: Seed, changes: Changes) -> Inner {
        let mut inner = Inner {
            original: seed.clone(),
            seed: seed.clone(),
            zones: Vec::new(),
            rrsets: Vec::new(),
            tokens: HashMap::new(),
            issued: Vec::new(),
            next_id: 0,
            changes,
        };
        for zone in &seed.zones {
            let id = inner.new_id();
            inner.zones.push(Zone {
                id,
                name: fqdn(&zone.name),
                project_id: zone.project_id.clone(),
                disabled: false,
            });
        }
        inner
    }

    /// What a DNS server for the mock's zones would answer: the records that are not disabled.
    fn published(&self) -> Published {
        let mut out = Published::new();
        for zone in &self.zones {
            out.zone(&zone.name);
        }
        for rrset in &self.rrsets {
            let Some(zone) = self.zone(&rrset.zone_id) else {
                continue;
            };
            let values = rrset
                .records
                .iter()
                .filter(|r| !r.disabled)
                .map(|r| r.content.clone())
                .collect();
            out.rrset(
                &zone.name,
                &rrset.name,
                &rrset.rtype,
                Some(rrset.ttl),
                values,
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

    fn zone(&self, id: &str) -> Option<&Zone> {
        self.zones.iter().find(|z| z.id == id)
    }
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running Selectel v2 mock. Dereferences to its [`MockServer`] for the request log and the
/// fault queue; [`SelectelV2Mock::control`] reads and changes the state.
#[derive(Debug)]
pub struct SelectelV2Mock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of a [`SelectelV2Mock`]. Cheap to clone, so that a fault hook
/// ([`Fault::run`](crate::Fault::run)) can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
    changes: Changes,
    log: RequestLog,
    faults: Faults,
}

impl Deref for SelectelV2Mock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl SelectelV2Mock {
    /// Starts the mock with `seed` on `127.0.0.1` with an ephemeral port.
    pub async fn start(seed: Seed) -> Self {
        Self::start_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), seed).await
    }

    /// Starts the mock with `seed` on `addr` ([`MockServer::start_on`]).
    pub async fn start_on(addr: SocketAddr, seed: Seed) -> Self {
        let changes = Changes::new();
        let state = Arc::new(Mutex::new(Inner::new(seed, changes.clone())));
        let router = Router::new()
            .route("/identity/v3/auth/tokens", post(keystone))
            .route("/domains/v2/zones", get(zones_list))
            .route("/domains/v2/zones/{zone}", get(zone_get))
            .route(
                "/domains/v2/zones/{zone}/rrset",
                get(rrset_list).post(rrset_create),
            )
            .route(
                "/domains/v2/zones/{zone}/rrset/{rrset}",
                get(rrset_get).patch(rrset_update).delete(rrset_delete),
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

    /// The DNS API endpoint, for the client's `base_url`.
    pub fn base_url(&self) -> String {
        self.server.url(API_PATH)
    }

    /// The identity endpoint, for the client's `auth_url`.
    pub fn auth_url(&self) -> String {
        self.server.url(IDENTITY_PATH)
    }

    /// The state control.
    pub fn control(&self) -> &Control {
        &self.control
    }
}

impl ChangeSource for SelectelV2Mock {
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

    /// Returns the mock to the seed it was started with: its zones under their first
    /// identifiers, no rrsets, no issued tokens, the token lifetime of the seed, an empty request
    /// log and no pending faults. Reports the removal of every rrset that was published.
    pub fn reset(&self) {
        self.faults.clear();
        self.change(|inner| {
            let seed = inner.original.clone();
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
        let name = fqdn(name);
        lock(&self.state)
            .zones
            .iter()
            .find(|z| z.name == name)
            .map(|z| z.id.clone())
            .unwrap_or_else(|| panic!("no zone {name}"))
    }

    /// Adds a zone of `project_id`.
    pub fn insert_zone(&self, name: &str, project_id: &str) -> String {
        let mut inner = lock(&self.state);
        let id = inner.new_id();
        inner.zones.push(Zone {
            id: id.clone(),
            name: fqdn(name),
            project_id: project_id.to_owned(),
            disabled: false,
        });
        id
    }

    /// Marks zone `name` disabled or enabled.
    pub fn set_zone_disabled(&self, name: &str, disabled: bool) {
        let name = fqdn(name);
        for zone in lock(&self.state)
            .zones
            .iter_mut()
            .filter(|z| z.name == name)
        {
            zone.disabled = disabled;
        }
    }

    /// Deletes zone `name` and creates it again under a new identifier, with the same rrsets
    /// (under new rrset identifiers). Returns the new zone identifier.
    pub fn recreate_zone(&self, name: &str) -> String {
        let name = fqdn(name);
        let mut inner = lock(&self.state);
        let new_id = inner.new_id();
        let old_id = inner
            .zones
            .iter()
            .find(|z| z.name == name)
            .map(|z| z.id.clone())
            .unwrap_or_else(|| panic!("no zone {name}"));
        for zone in inner.zones.iter_mut().filter(|z| z.id == old_id) {
            zone.id = new_id.clone();
        }
        let moved: Vec<usize> = (0..inner.rrsets.len())
            .filter(|&i| inner.rrsets[i].zone_id == old_id)
            .collect();
        for i in moved {
            let rrset_id = inner.new_id();
            let rrset = &mut inner.rrsets[i];
            rrset.zone_id = new_id.clone();
            rrset.id = rrset_id;
        }
        new_id
    }

    /// Every rrset.
    pub fn rrsets(&self) -> Vec<Rrset> {
        lock(&self.state).rrsets.clone()
    }

    /// The rrset of `name` and `rtype`, if any.
    pub fn rrset(&self, name: &str, rtype: &str) -> Option<Rrset> {
        let name = fqdn(name);
        lock(&self.state)
            .rrsets
            .iter()
            .find(|r| r.name == name && r.rtype == rtype)
            .cloned()
    }

    /// Creates an rrset in zone `zone` directly, as another writer would: `contents` are the
    /// API's text, each record enabled. Returns the rrset's identifier.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn insert_rrset(
        &self,
        zone: &str,
        name: &str,
        rtype: &str,
        ttl: u32,
        contents: &[&str],
    ) -> String {
        let zone_id = self.zone_id(zone);
        self.change(|inner| {
            let id = inner.new_id();
            inner.rrsets.push(Rrset {
                id: id.clone(),
                zone_id,
                name: fqdn(name),
                rtype: rtype.to_owned(),
                ttl,
                comment: None,
                managed_by: None,
                records: contents
                    .iter()
                    .map(|content| Record {
                        content: (*content).to_owned(),
                        disabled: false,
                    })
                    .collect(),
            });
            id
        })
    }

    /// Sets the comment of the rrset of `name` and `rtype`.
    pub fn set_comment(&self, name: &str, rtype: &str, comment: Option<&str>) {
        let name = fqdn(name);
        for rrset in lock(&self.state)
            .rrsets
            .iter_mut()
            .filter(|r| r.name == name && r.rtype == rtype)
        {
            rrset.comment = comment.map(str::to_owned);
        }
    }

    /// Sets the managing resource of the rrset of `name` and `rtype`.
    pub fn set_managed_by(&self, name: &str, rtype: &str, managed_by: Option<&str>) {
        let name = fqdn(name);
        for rrset in lock(&self.state)
            .rrsets
            .iter_mut()
            .filter(|r| r.name == name && r.rtype == rtype)
        {
            rrset.managed_by = managed_by.map(str::to_owned);
        }
    }

    /// Deletes the rrset of `name` and `rtype` directly, as another writer would.
    pub fn delete_rrset(&self, name: &str, rtype: &str) {
        let name = fqdn(name);
        self.change(|inner| {
            inner
                .rrsets
                .retain(|r| !(r.name == name && r.rtype == rtype));
        });
    }

    /// Disables or enables the TXT records of `name` whose unquoted content is `value`.
    pub fn set_txt_disabled(&self, name: &str, value: &str, disabled: bool) {
        let name = fqdn(name);
        self.change(|inner| {
            for rrset in inner
                .rrsets
                .iter_mut()
                .filter(|r| r.name == name && r.rtype == "TXT")
            {
                for record in rrset
                    .records
                    .iter_mut()
                    .filter(|r| unquoted(&r.content) == value)
                {
                    record.disabled = disabled;
                }
            }
        });
    }

    /// Disables or enables the records of `name` and `rtype` whose content is `content`.
    pub fn set_disabled(&self, name: &str, rtype: &str, content: &str, disabled: bool) {
        let name = fqdn(name);
        self.change(|inner| {
            for rrset in inner
                .rrsets
                .iter_mut()
                .filter(|r| r.name == name && r.rtype == rtype)
            {
                for record in rrset.records.iter_mut().filter(|r| r.content == content) {
                    record.disabled = disabled;
                }
            }
        });
    }

    /// The contents of the records of `name` and `rtype`, in rrset order, each with its
    /// `disabled` flag; empty when there is no such rrset.
    pub fn contents(&self, name: &str, rtype: &str) -> Vec<(String, bool)> {
        self.rrset(name, rtype)
            .map(|r| {
                r.records
                    .into_iter()
                    .map(|record| (record.content, record.disabled))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The TXT contents of `name` with the outer quotes removed, in rrset order, disabled
    /// records included.
    pub fn txt_values(&self, name: &str) -> Vec<String> {
        self.txt_records(name)
            .into_iter()
            .map(|r| unquoted(&r.content).to_owned())
            .collect()
    }

    /// The unquoted TXT contents of the disabled records of `name`.
    pub fn txt_disabled(&self, name: &str) -> Vec<String> {
        self.txt_records(name)
            .into_iter()
            .filter(|r| r.disabled)
            .map(|r| unquoted(&r.content).to_owned())
            .collect()
    }

    fn txt_records(&self, name: &str) -> Vec<Record> {
        self.rrset(name, "TXT")
            .map(|r| r.records)
            .unwrap_or_default()
    }

    /// Revokes every token issued so far: requests with them answer `401`.
    pub fn revoke_tokens(&self) {
        for token in lock(&self.state).tokens.values_mut() {
            token.revoked = true;
        }
    }

    /// Lifetime stated for tokens issued from now on. The mock does not enforce it; revoke
    /// tokens to make the API refuse them.
    pub fn set_token_ttl(&self, seconds: u64) {
        lock(&self.state).seed.token_ttl_s = seconds;
    }

    /// Every token issued so far, in order.
    pub fn issued_tokens(&self) -> Vec<String> {
        lock(&self.state).issued.clone()
    }

    /// Number of tokens issued so far.
    pub fn tokens_issued(&self) -> usize {
        lock(&self.state).issued.len()
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

/// The content without its outer quotes.
fn unquoted(content: &str) -> &str {
    content.trim_matches('"')
}

/// An error answer in the documented shape.
fn error(status: StatusCode, error: &str, description: Option<&str>) -> Response {
    let mut body = json!({ "error": error });
    if let Some(description) = description {
        body["description"] = json!(description);
    }
    (status, axum::Json(body)).into_response()
}

fn validation(description: &str) -> Response {
    error(
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation error",
        Some(description),
    )
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
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": {
                "code": 401,
                "message": "The request you have made requires authentication.",
                "title": "Unauthorized"
            }})),
        )
            .into_response()
    };
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "malformed request body", None);
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
                && user["domain"]["name"].as_str() == Some(u.account_id.as_str())
                && user["password"].as_str() == Some(u.password.as_str())
                && (project["id"].as_str() == Some(u.project_id.as_str())
                    || (project["name"].as_str() == Some(u.project_name.as_str())
                        && project["domain"]["name"].as_str() == Some(u.account_id.as_str())))
        })
        .cloned();
    let Some(user) = found else {
        return unauthorized();
    };
    let n = inner.issued.len() + 1;
    let token = format!("gAAAA-mock-token-{n:04}-zz");
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
            "project": {"id": user.project_id, "name": user.project_name}
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
    let refused = || error(StatusCode::UNAUTHORIZED, "authorization required", None);
    let token = headers
        .get("x-auth-token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(refused)?;
    match lock(state).tokens.get(token) {
        Some(t) if !t.revoked => Ok(t.project_id.clone()),
        _ => Err(refused()),
    }
}

/// The zone `zone_id` as `project` may use it: `404` when there is none, `403` when it belongs
/// to another project.
fn own_zone(state: &Shared, zone_id: &str, project: &str) -> Result<Zone, Response> {
    match lock(state).zone(zone_id) {
        None => Err(error(StatusCode::NOT_FOUND, "zone not found", None)),
        Some(zone) if zone.project_id != project => Err(error(
            StatusCode::FORBIDDEN,
            "forbidden",
            Some("the zone belongs to another project"),
        )),
        Some(zone) => Ok(zone.clone()),
    }
}

fn query<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// One page of `items` by `limit` and `offset`: `next_offset` is the offset of the next page,
/// `0` on the last page.
fn paginate<T: Serialize>(items: Vec<T>, pairs: &[(String, String)]) -> Response {
    let limit = match query(pairs, "limit").map(str::parse::<usize>) {
        None => DEFAULT_LIMIT,
        Some(Ok(limit)) if limit >= 1 => limit,
        Some(_) => return validation("limit must be at least 1"),
    };
    let offset = match query(pairs, "offset").map(str::parse::<usize>) {
        None => 0,
        Some(Ok(offset)) => offset,
        Some(Err(_)) => return validation("offset must be a non-negative integer"),
    };
    let count = items.len();
    let page: Vec<T> = items.into_iter().skip(offset).take(limit).collect();
    let next = if offset.saturating_add(limit) < count {
        offset + limit
    } else {
        0
    };
    axum::Json(json!({ "count": count, "next_offset": next, "result": page })).into_response()
}

fn zone_json(zone: &Zone) -> Value {
    json!({
        "id": zone.id,
        "name": zone.name,
        "project_id": zone.project_id,
        "comment": null,
        "disabled": zone.disabled,
        "protected": false,
        "created_at": "2026-01-10T12:00:00Z",
        "updated_at": "2026-01-10T12:00:00Z",
        "delegation_checked_at": "2026-11-09T08:00:00Z",
        "last_delegated_at": "2026-01-11T00:00:00Z",
        "last_check_status": true
    })
}

async fn zones_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    let filter = query(&pairs, "filter").unwrap_or("").to_lowercase();
    let inner = lock(&state);
    let zones: Vec<Value> = inner
        .zones
        .iter()
        .filter(|z| z.project_id == project || inner.seed.list_foreign_zones)
        .filter(|z| z.name.contains(&filter))
        .map(zone_json)
        .collect();
    drop(inner);
    paginate(zones, &pairs)
}

async fn zone_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(zone_id): Path<String>,
) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    match own_zone(&state, &zone_id, &project) {
        Ok(zone) => axum::Json(zone_json(&zone)).into_response(),
        Err(response) => response,
    }
}

async fn rrset_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(zone_id): Path<String>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    if let Err(response) = own_zone(&state, &zone_id, &project) {
        return response;
    }
    let name = query(&pairs, "name").unwrap_or("").to_lowercase();
    // `rrset_types` may repeat, and one value may list several types separated by commas.
    let types: Vec<&str> = pairs
        .iter()
        .filter(|(k, _)| k == "rrset_types")
        .flat_map(|(_, v)| v.split(','))
        .collect();
    let items: Vec<Rrset> = lock(&state)
        .rrsets
        .iter()
        .filter(|r| r.zone_id == zone_id && r.name.contains(&name))
        .filter(|r| types.is_empty() || types.contains(&r.rtype.as_str()))
        .cloned()
        .collect();
    paginate(items, &pairs)
}

async fn rrset_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((zone_id, rrset_id)): Path<(String, String)>,
) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    if let Err(response) = own_zone(&state, &zone_id, &project) {
        return response;
    }
    let found = lock(&state)
        .rrsets
        .iter()
        .find(|r| r.id == rrset_id && r.zone_id == zone_id)
        .cloned();
    match found {
        Some(rrset) => axum::Json(rrset).into_response(),
        None => error(StatusCode::NOT_FOUND, "rrset not found", None),
    }
}

fn validate_ttl(ttl: Option<u64>) -> Result<u32, Response> {
    match ttl {
        Some(ttl) if (60..=604_800).contains(&ttl) => {
            u32::try_from(ttl).map_err(|_| validation("ttl must be between 60 and 604800"))
        }
        _ => Err(validation("ttl must be between 60 and 604800")),
    }
}

/// The records of a create or update. `held` are the contents the rrset holds now (none for a
/// create): a record with one of them is the provider's own data written back unchanged and is
/// not checked against the content rules (invented, see the module documentation).
fn validate_records(
    rtype: &str,
    records: &Value,
    held: &[String],
) -> Result<Vec<Record>, Response> {
    let records: Vec<Record> =
        serde_json::from_value(records.clone()).map_err(|_| validation("records are invalid"))?;
    if records.is_empty() || records.len() > MAX_RECORDS {
        return Err(validation("records must hold 1 to 100 items"));
    }
    let checked = || records.iter().filter(|r| !held.contains(&r.content));
    let quoted = |c: &str| c.len() >= 2 && c.starts_with('"') && c.ends_with('"');
    if rtype == "TXT" && checked().any(|r| !quoted(&r.content)) {
        return Err(validation("TXT content must be quoted"));
    }
    if checked().any(|r| !content_valid(rtype, &r.content)) {
        return Err(validation("content does not match the record type"));
    }
    Ok(records)
}

/// The content has the form the provider's documentation gives for `rtype` (module
/// documentation).
fn content_valid(rtype: &str, content: &str) -> bool {
    let fields: Vec<&str> = content.split(' ').collect();
    let number = |text: &str, max: u32| text.parse::<u32>().is_ok_and(|n| n <= max);
    let absolute = |text: &str| {
        text == "."
            || (text.len() > 1
                && text.ends_with('.')
                && text
                    .trim_end_matches('.')
                    .split('.')
                    .all(|label| !label.is_empty()))
    };
    let quoted = |text: &str| text.len() >= 2 && text.starts_with('"') && text.ends_with('"');
    match (rtype, fields.as_slice()) {
        ("A", [address]) => address.parse::<std::net::Ipv4Addr>().is_ok(),
        ("AAAA", [address]) => address.parse::<std::net::Ipv6Addr>().is_ok(),
        ("TXT", _) => quoted(content),
        ("CNAME" | "ALIAS" | "NS", [target]) => absolute(target),
        ("MX", [priority, host]) => number(priority, 65_535) && absolute(host),
        ("SRV", [priority, weight, port, target]) => {
            number(priority, 65_535)
                && number(weight, 65_535)
                && number(port, 65_535)
                && absolute(target)
        }
        ("SSHFP", [algorithm, fp_type, fingerprint]) => {
            matches!(*algorithm, "1" | "2" | "3" | "4")
                && matches!(*fp_type, "1" | "2")
                && !fingerprint.is_empty()
                && fingerprint.len() % 2 == 0
                && fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
        }
        ("CAA", [flag, tag, value @ ..]) => {
            number(flag, 128)
                && matches!(
                    *tag,
                    "issue" | "issuewild" | "iodef" | "auth" | "path" | "policy"
                )
                && quoted(&value.join(" "))
        }
        ("DNAME" | "HTTPS" | "SVCB" | "SOA", _) => !content.trim().is_empty(),
        _ => false,
    }
}

/// The rrset is one the documentation says cannot be edited or deleted: SOA, and NS at the apex.
fn protected(zone: &Zone, name: &str, rtype: &str) -> bool {
    rtype == "SOA" || (rtype == "NS" && name == zone.name)
}

fn validate_comment(comment: Option<&Value>) -> Result<Option<String>, Response> {
    match comment {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.chars().count() <= MAX_COMMENT => Ok(Some(text.clone())),
        Some(_) => Err(validation(
            "comment must be a string of at most 255 characters",
        )),
    }
}

async fn rrset_create(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(zone_id): Path<String>,
    body: Bytes,
) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    let zone = match own_zone(&state, &zone_id, &project) {
        Ok(zone) => zone,
        Err(response) => return response,
    };
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "malformed request body", None);
    };
    let Some(name) = request["name"].as_str() else {
        return validation("name is required");
    };
    if !name.ends_with('.') {
        return validation("name must be absolute");
    }
    let name = name.to_lowercase();
    if name != zone.name && !name.ends_with(&format!(".{}", zone.name)) {
        return validation("name is outside the zone");
    }
    let rtype = request["type"].as_str().unwrap_or("");
    if !TYPES.contains(&rtype) {
        return validation("unsupported type");
    }
    if protected(&zone, &name, rtype) {
        return validation("this record set cannot be created");
    }
    let ttl = match validate_ttl(request["ttl"].as_u64()) {
        Ok(ttl) => ttl,
        Err(response) => return response,
    };
    let records = match validate_records(rtype, &request["records"], &[]) {
        Ok(records) => records,
        Err(response) => return response,
    };
    let comment = match validate_comment(request.get("comment")) {
        Ok(comment) => comment,
        Err(response) => return response,
    };
    let mut inner = lock(&state);
    if inner
        .rrsets
        .iter()
        .any(|r| r.zone_id == zone_id && r.name == name && r.rtype == rtype)
    {
        return error(StatusCode::CONFLICT, "rrset already exists", None);
    }
    let rrset = Rrset {
        id: inner.new_id(),
        zone_id,
        name,
        rtype: rtype.to_owned(),
        ttl,
        comment,
        managed_by: None,
        records,
    };
    let before = inner.published();
    inner.rrsets.push(rrset.clone());
    inner.report(&before, Origin::Api);
    axum::Json(rrset).into_response()
}

async fn rrset_update(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((zone_id, rrset_id)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    let zone = match own_zone(&state, &zone_id, &project) {
        Ok(zone) => zone,
        Err(response) => return response,
    };
    let Ok(Value::Object(request)) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "malformed request body", None);
    };
    // The update form has `ttl`, `records` and `comment` only (`RRSetUpdateForm`).
    if request
        .keys()
        .any(|k| !matches!(k.as_str(), "ttl" | "records" | "comment"))
    {
        return validation("unexpected field");
    }
    let managed_by = match managed_by(&headers) {
        Ok(managed_by) => managed_by,
        Err(response) => return response,
    };
    let Some((name, rtype, held)) = lock(&state)
        .rrsets
        .iter()
        .find(|r| r.id == rrset_id && r.zone_id == zone_id)
        .map(|r| {
            let held: Vec<String> = r.records.iter().map(|rec| rec.content.clone()).collect();
            (r.name.clone(), r.rtype.clone(), held)
        })
    else {
        return error(StatusCode::NOT_FOUND, "rrset not found", None);
    };
    if protected(&zone, &name, &rtype) {
        return validation("this record set cannot be edited");
    }
    let ttl = match validate_ttl(request.get("ttl").and_then(Value::as_u64)) {
        Ok(ttl) => ttl,
        Err(response) => return response,
    };
    let Some(records) = request.get("records") else {
        return validation("records are required");
    };
    let records = match validate_records(&rtype, records, &held) {
        Ok(records) => records,
        Err(response) => return response,
    };
    let comment = match validate_comment(request.get("comment")) {
        Ok(comment) => comment,
        Err(response) => return response,
    };
    let mut inner = lock(&state);
    let before = inner.published();
    if let Some(rrset) = inner.rrsets.iter_mut().find(|r| r.id == rrset_id) {
        rrset.ttl = ttl;
        rrset.records = records;
        rrset.comment = comment;
        rrset.managed_by = managed_by;
    }
    inner.report(&before, Origin::Api);
    StatusCode::NO_CONTENT.into_response()
}

/// The `X-Managed-By` header of `PATCH` and `DELETE`: absent, or a UUID.
// Source: the OpenAPI, header parameter `X-Managed-By` (not required; `anyOf` a string of
// format `uuid` or null).
fn managed_by(headers: &HeaderMap) -> Result<Option<String>, Response> {
    let Some(value) = headers.get("x-managed-by") else {
        return Ok(None);
    };
    match value.to_str() {
        Ok(text) if is_uuid(text) => Ok(Some(text.to_owned())),
        _ => Err(validation("X-Managed-By is not a UUID")),
    }
}

/// `text` is a UUID in its hyphenated hexadecimal form.
fn is_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12])
        && groups
            .iter()
            .all(|g| g.bytes().all(|b| b.is_ascii_hexdigit()))
}

async fn rrset_delete(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((zone_id, rrset_id)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let project = match authorize(&state, &headers) {
        Ok(project) => project,
        Err(response) => return response,
    };
    let zone = match own_zone(&state, &zone_id, &project) {
        Ok(zone) => zone,
        Err(response) => return response,
    };
    if !body.is_empty() {
        return validation("the delete takes no request body");
    }
    if let Err(response) = managed_by(&headers) {
        return response;
    }
    let mut inner = lock(&state);
    if inner
        .rrsets
        .iter()
        .any(|r| r.id == rrset_id && r.zone_id == zone_id && protected(&zone, &r.name, &r.rtype))
    {
        return validation("this record set cannot be deleted");
    }
    let published = inner.published();
    let before = inner.rrsets.len();
    inner
        .rrsets
        .retain(|r| !(r.id == rrset_id && r.zone_id == zone_id));
    if inner.rrsets.len() == before {
        return error(StatusCode::NOT_FOUND, "rrset not found", None);
    }
    inner.report(&published, Origin::Api);
    StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
mod tests {
    use super::{content_valid, is_uuid, rfc3339};

    #[test]
    fn content_is_checked_per_type() {
        for (rtype, content) in [
            ("A", "192.0.2.1"),
            ("AAAA", "2001:db8::1"),
            ("TXT", "\"hello, world!\""),
            ("CNAME", "origin.example."),
            ("ALIAS", "origin.example."),
            ("NS", "a.ns.example."),
            ("MX", "10 mail.example.org."),
            ("SRV", "10 20 30 example.org."),
            ("SRV", "0 0 0 ."),
            ("SSHFP", "1 1 7491973e5f8b39d5327cd4e08bc81b05f7710b49"),
            ("CAA", "128 issue \"ca.example.net\""),
            ("CAA", "0 iodef \"mailto:a b@example.org\""),
        ] {
            assert!(content_valid(rtype, content), "{rtype} {content}");
        }
        for (rtype, content) in [
            ("A", "192.0.2"),
            ("A", "192.0.2.1 "),
            ("AAAA", "192.0.2.1"),
            ("TXT", "unquoted"),
            ("CNAME", "origin.example"),
            ("MX", "mail.example.org."),
            ("MX", "70000 mail.example.org."),
            ("SRV", "10 20 example.org."),
            ("SSHFP", "5 1 abcd"),
            ("SSHFP", "1 3 abcd"),
            ("SSHFP", "1 1 abc"),
            ("CAA", "129 issue \"ca\""),
            ("CAA", "0 other \"ca\""),
            ("CAA", "0 issue ca"),
            ("TLSA", "3 1 1 abcd"),
            ("DNAME", ""),
        ] {
            assert!(!content_valid(rtype, content), "{rtype} {content}");
        }
    }

    #[test]
    fn timestamps_are_rfc3339() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000000Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00.000000Z");
        assert_eq!(rfc3339(4_102_444_799), "2099-12-31T23:59:59.000000Z");
    }

    #[test]
    fn managed_by_is_a_uuid() {
        assert!(is_uuid("00000000-0000-4000-8000-0000000000aa"));
        assert!(is_uuid("0A1B2C3D-4E5F-6789-ABCD-EF0123456789"));
        for text in [
            "",
            "terraform",
            "00000000000040008000000000000000",
            "00000000-0000-4000-8000-0000000000a",
            "00000000-0000-4000-8000-0000000000aaa",
            "0000000g-0000-4000-8000-0000000000aa",
            "00000000-0000-4000-8000-0000000000aa-",
        ] {
            assert!(!is_uuid(text), "{text}");
        }
    }
}
