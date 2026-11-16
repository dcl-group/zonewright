//! Mock of the DNSimple API v2 (identity, zones and zone records).
//!
//! Shapes follow the provider's documentation, the same sources the client cites, read on
//! 2026-11-16:
//!
//! - Overview: <https://developer.dnsimple.com/v2/>: the version in the path (`/v2`),
//!   `Authorization: Bearer <token>`, every resource below `/:account`, the envelope `data`, the
//!   `pagination` object (`current_page`, `per_page`, `total_entries`, `total_pages`) with `page`
//!   (default 1) and `per_page` (default 30, maximum 100), error bodies with a `message` (`401`
//!   `{"message": "Authentication failed"}`, `404` `{"message": "Not Found"}`, `400`
//!   `{"message": "Validation failed", "errors": {...}}`).
//! - Identity: <https://developer.dnsimple.com/v2/identity/>: `GET /v2/whoami` answers
//!   `{"data": {"user": null, "account": {...}}}` for an account token and
//!   `{"data": {"user": {...}, "account": null}}` for a user token.
//! - Zones: <https://developer.dnsimple.com/v2/zones/> and the OpenAPI description
//!   <https://developer.dnsimple.com/v2/openapi.json> (`Zone`): `GET /v2/:account/zones` and
//!   `GET /v2/:account/zones/:zone` by the zone's name, `404` for a missing zone; the members
//!   `id`, `account_id`, `name`, `reverse`, `secondary`, `last_transferred_at`, `active`,
//!   `created_at`, `updated_at`.
//! - Records: <https://developer.dnsimple.com/v2/zones/records/> and OpenAPI `ZoneRecord`: list
//!   with the filters `name` (equal), `name_like` (containing) and `type` (equal); create with
//!   `name` (relative, `""` for the apex), `type` and `content` required and `ttl`, `priority`,
//!   `regions`, `integrated_zones` optional, answered `201`; update by PATCH with `name`,
//!   `content`, `ttl`, `priority`, `regions`, `integrated_zones` ("zero or any of them"),
//!   answered `200`; delete answered `204`; `404` for a missing record; the record members `id`,
//!   `zone_id` (the zone's name in the examples), `parent_id` (always `null`), `name`,
//!   `content`, `ttl` (OpenAPI default 3600), `priority` (`null` unless given), `type`, `regions`
//!   (`["global"]` unless given), `system_record`, `created_at`, `updated_at`. The record types of
//!   OpenAPI `ZoneRecordType`; the regions of `ZoneRecordRegion`.
//! - System records: OpenAPI `ZoneRecord.system_record` ("not modifiable") and the documented
//!   listing, whose SOA record and four apex NS records are system records
//!   ([`Control::insert_zone_defaults`] seeds that listing's records, with the host names moved
//!   under `.test`: `ns1.dnsimple-edge.test` to `ns4.dnsimple-edge.test`, `admin.dnsimple.test`).
//! - TXT: <https://support.dnsimple.com/articles/txt-record-format/>: content of at most 1000
//!   characters; an unquoted value is published wrapped in quotes, a quoted one as it is.
//!
//! Answers this mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading. A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - a path whose account is not the token's (for a user token: not one of the accounts it
//!   reaches) is `404` (the Overview: "doesn't exist or the authenticated account doesn't have
//!   permissions to access the resource");
//! - a `per_page` outside 1 to 100 or a `page` below 1 is `400`; `per_page` is further capped at
//!   [`Seed::page_size`] (100 unless set) or [`Control::set_page_cap`]; `total_pages` is 0 for
//!   an empty listing; [`Control::set_paging`] answers a listing in two readings the
//!   documentation does not exclude ([`Paging`]);
//! - `400` for a create or an update with a member the documented input does not have (an
//!   update with `type` included), without a required member, with a type outside the
//!   documented list, of an SOA record, with a `name` that ends with a dot or is `@`, a `ttl`
//!   that is not a non-negative integer, a `priority` outside 0 to 65535, a region outside the
//!   documented list, an A or AAAA `content` that is not an address, an SRV `content` that is
//!   not `<weight> <port> <target>`, a CAA `content` that is not `<flags> <tag> <value>`, or a
//!   TXT `content` over 1000 characters; and for an update or a delete of a system record;
//! - creating a record equal to an existing one is accepted (no source says otherwise);
//! - `priority` defaults to 0 for MX and SRV (OpenAPI: "default": 0) and stays `null` for the
//!   other types;
//! - the answers state TXT `content` exactly as written unless [`Control::set_txt_quoted`] makes
//!   them wrap unquoted content in quotes, the form the TXT article describes for publishing;
//!   which form the API answers is not documented;
//! - the `X-RateLimit-*` headers are sent only on the two refusals below, not on every answer;
//! - the hourly quota is not counted: [`Control::exhaust_quota`] makes every authenticated
//!   request get the documented quota answer until [`Control::restore_quota`], and
//!   [`Control::block_failed_auth`] makes every request get the documented block answer until
//!   [`Control::restore_quota`].
//!
//! The two documented refusals (Overview, "Rate limiting"): the exceeded quota is `429` with
//! `{"message": "quota exceeded"}`, `X-RateLimit-Limit`, `X-RateLimit-Remaining: 0` and
//! `X-RateLimit-Reset` ("The time at which the current rate limit window in Unix time
//! format"), without `Retry-After`; the block after too many failed authentications is `429` with
//! a message that starts "Too many failed authentication attempts" and names the end of the block
//! in ISO 8601, `Retry-After` in seconds, `X-RateLimit-Remaining: 0`, `X-RateLimit-Reset` and no
//! `X-RateLimit-Limit`, also for a valid token.
//!
//! Error texts are invented.
//!
//! A test holds a [`DnsimpleMock`]. It dereferences to the [`MockServer`], so the request log
//! and the fault queue of the shared harness work as usual:
//!
//! ```text
//! let mock = DnsimpleMock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("POST", "/v2/*/zones/*/records").status(500));
//! // ... drive the client against mock.base_url() ...
//! assert_eq!(mock.control().txt_values("_acme-challenge.example.org"), ["v1"]);
//! ```
//!
//! The mock is a [`ChangeSource`]: it reports every change of its published records through
//! [`DnsimpleMock::changes`], the records of one name and type grouped into one rrset (the TTL
//! of the set the smallest of its records), and a [`link`](crate::link::link) serves them over
//! DNS. Published are the records of the account's zones that are published in every region
//! (`regions` empty or `global`), each at its absolute name. The form of a value: A and AAAA
//! `content`; CNAME and NS `content` with a trailing dot added; MX as `<priority> <content>.`;
//! SRV as `<priority> <content>.`; CAA `content`; TXT `content` when it starts with a quote,
//! otherwise quoted character-strings of at most 255 bytes. Left out: SOA records (a DNS server
//! for the zone has its own), records limited to some regions, and records of a zone that is
//! not on the account. [`Control::reset`] returns the mock to its seed.

#![allow(clippy::result_large_err)]

use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Map, Value, json};

use crate::changes::{ChangeSource, Changes, Origin, Published};
use crate::{Faults, MockServer, RequestLog};

/// Path of the API below the server's base URL.
pub const API_PATH: &str = "/v2";

/// Largest `per_page` the API accepts (Overview, "Pagination").
const MAX_PER_PAGE: usize = 100;

/// Default `per_page` (Overview, "Pagination").
const DEFAULT_PER_PAGE: usize = 30;

/// Default TTL of a record created without one (OpenAPI `TTL`, "default": 3600).
const DEFAULT_TTL: u32 = 3600;

/// The record types of OpenAPI `ZoneRecordType`.
const TYPES: &[&str] = &[
    "A", "AAAA", "ALIAS", "CAA", "CNAME", "DNSKEY", "DS", "HINFO", "MX", "NAPTR", "NS", "POOL",
    "PTR", "SOA", "SPF", "SRV", "SSHFP", "TXT", "URL",
];

/// The regions of OpenAPI `ZoneRecordRegion`.
const REGIONS: &[&str] = &[
    "global", "SV1", "ORD", "IAD", "AMS", "TKO", "SYD", "CDG", "FRA",
];

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The account the tokens belong to.
    pub account_id: u64,
    /// The account token the API accepts.
    pub token: String,
    /// User tokens the API accepts: they reach the account, and `whoami` answers no account.
    pub user_tokens: Vec<String>,
    /// The zones of the account, without a trailing dot.
    pub zones: Vec<String>,
    /// The largest page of a listing.
    pub page_size: usize,
}

impl Seed {
    /// Account 1010 with the account token `test-only-token`, no user token, the zone
    /// `example.org`, pages of at most 100.
    pub fn standard() -> Self {
        Self {
            account_id: 1010,
            token: "test-only-token".into(),
            user_tokens: Vec::new(),
            zones: vec!["example.org".into()],
            page_size: MAX_PER_PAGE,
        }
    }
}

/// How a listing pages: the documented reading and two readings the documentation does not
/// exclude, for tests of a client's end rule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Paging {
    /// `page` is honored and the `pagination` object describes the whole listing.
    #[default]
    Standard,
    /// `page` is ignored: every request answers the first page's items, with `current_page`
    /// stated as the page asked for.
    IgnorePage,
    /// `total_pages` is stated as 1 whatever the number of pages.
    OnePage,
}

/// One zone as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Zone {
    /// The zone's identifier.
    pub id: u64,
    /// The name, without a trailing dot.
    pub name: String,
    /// DNS services are active.
    pub active: bool,
    /// A secondary zone.
    pub secondary: bool,
}

/// The members of a record beyond its name, type, content and TTL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extra {
    /// The priority; `None` is answered as `null`.
    pub priority: Option<u64>,
    /// The regions.
    pub regions: Vec<String>,
    /// A system record.
    pub system: bool,
}

impl Default for Extra {
    fn default() -> Extra {
        Extra {
            priority: None,
            regions: vec!["global".to_owned()],
            system: false,
        }
    }
}

/// One record as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The record's identifier.
    pub id: u64,
    /// The zone, without a trailing dot.
    pub zone: String,
    /// The owner name relative to the zone, `""` for the apex.
    pub name: String,
    /// The record type.
    pub rtype: String,
    /// The value, without the priority.
    pub content: String,
    /// TTL in seconds.
    pub ttl: u32,
    /// The priority, the regions and the system flag.
    pub extra: Extra,
}

#[derive(Debug)]
struct Inner {
    /// The seed the mock was started with, for [`Control::reset`].
    seed: Seed,
    changes: Changes,
    zones: Vec<Zone>,
    records: Vec<Record>,
    next_id: u64,
    page_cap: usize,
    paging: Paging,
    txt_quoted: bool,
    /// The quota is exhausted until this Unix time.
    quota_reset: Option<u64>,
    /// Requests are blocked: `Retry-After` seconds and the Unix time the block ends.
    auth_block: Option<(u64, u64)>,
}

impl Inner {
    /// The state of a mock started with `seed`.
    fn new(seed: Seed, changes: Changes) -> Inner {
        let zones = seed
            .zones
            .iter()
            .enumerate()
            .map(|(i, name)| Zone {
                id: u64::try_from(i).unwrap_or(0) + 1,
                name: name.clone(),
                active: true,
                secondary: false,
            })
            .collect();
        Inner {
            page_cap: seed.page_size.max(1),
            seed,
            changes,
            zones,
            records: Vec::new(),
            next_id: 1000,
            paging: Paging::Standard,
            txt_quoted: false,
            quota_reset: None,
            auth_block: None,
        }
    }

    fn has_zone(&self, zone: &str) -> bool {
        self.zones.iter().any(|z| z.name == zone)
    }

    /// What a DNS server for the mock's zones would answer (module documentation).
    fn published(&self) -> Published {
        let mut out = Published::new();
        for zone in &self.zones {
            out.zone(&zone.name);
        }
        for record in &self.records {
            if !self.has_zone(&record.zone) || !global(&record.extra.regions) {
                continue;
            }
            let host = |text: &str| format!("{}.", text.trim().trim_end_matches('.'));
            let priority = record.extra.priority.unwrap_or(0);
            let value = match record.rtype.as_str() {
                "TXT" if record.content.starts_with('"') => record.content.clone(),
                "TXT" => quoted(&record.content),
                "CNAME" | "NS" => host(&record.content),
                "MX" => format!("{priority} {}", host(&record.content)),
                "SRV" => {
                    let mut fields: Vec<&str> = record.content.split_whitespace().collect();
                    let target = fields.pop().map(host).unwrap_or_default();
                    format!("{priority} {} {target}", fields.join(" "))
                }
                // A DNS server for the zone answers its own SOA.
                "SOA" => continue,
                _ => record.content.clone(),
            };
            out.record(
                &record.zone,
                &absolute(&record.name, &record.zone),
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

/// The record is published in every region.
fn global(regions: &[String]) -> bool {
    regions.is_empty() || regions.iter().all(|r| r == "global")
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

/// A running DNSimple mock. Dereferences to its [`MockServer`] for the request log and the
/// fault queue; [`DnsimpleMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct DnsimpleMock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of a [`DnsimpleMock`]. Cheap to clone, so that a fault hook
/// ([`Fault::run`](crate::Fault::run)) can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
    changes: Changes,
    log: RequestLog,
    faults: Faults,
}

impl Deref for DnsimpleMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl DnsimpleMock {
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
            .route("/v2/whoami", get(whoami))
            .route("/v2/{account}/zones", get(zones_list))
            .route("/v2/{account}/zones/{zone}", get(zone_get))
            .route(
                "/v2/{account}/zones/{zone}/records",
                get(records_list).post(record_create),
            )
            .route(
                "/v2/{account}/zones/{zone}/records/{id}",
                get(record_get).patch(record_update).delete(record_delete),
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

impl ChangeSource for DnsimpleMock {
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

    /// Returns the mock to the seed it was started with: its tokens and zones, no records,
    /// identifiers counted from the start again, the documented paging and answer forms, an
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

    /// The records of type `rtype` at `name` (absolute or relative to the first zone), in
    /// creation order.
    pub fn records_at(&self, name: &str, rtype: &str) -> Vec<Record> {
        let inner = lock(&self.state);
        let first = inner.zones.first().map_or("", |z| z.name.as_str());
        let wanted = given(name, first);
        inner
            .records
            .iter()
            .filter(|r| r.rtype == rtype && absolute(&r.name, &r.zone) == wanted)
            .cloned()
            .collect()
    }

    /// The contents of the TXT records at `name` (absolute or relative to the first zone), in
    /// creation order.
    pub fn txt_values(&self, name: &str) -> Vec<String> {
        self.records_at(name, "TXT")
            .into_iter()
            .map(|r| r.content)
            .collect()
    }

    /// Adds a record directly, as another writer would. `name` is absolute or relative to the
    /// zone. Returns the record's identifier.
    pub fn insert_record(
        &self,
        zone: &str,
        name: &str,
        rtype: &str,
        content: &str,
        ttl: u32,
    ) -> u64 {
        self.insert_record_with(zone, name, rtype, content, ttl, Extra::default())
    }

    /// [`Control::insert_record`] with the members beyond the content.
    pub fn insert_record_with(
        &self,
        zone: &str,
        name: &str,
        rtype: &str,
        content: &str,
        ttl: u32,
        extra: Extra,
    ) -> u64 {
        self.change(|inner| {
            inner.next_id += 1;
            let id = inner.next_id;
            inner.records.push(Record {
                id,
                zone: zone.to_owned(),
                name: relative(&given(name, zone), zone),
                rtype: rtype.to_owned(),
                content: content.to_owned(),
                ttl,
                extra,
            });
            id
        })
    }

    /// Seeds the system records of the documented listing: an SOA record and four NS records at
    /// the apex, each a system record.
    pub fn insert_zone_defaults(&self, zone: &str) {
        let system = Extra {
            system: true,
            ..Extra::default()
        };
        self.insert_record_with(
            zone,
            "",
            "SOA",
            "ns1.dnsimple-edge.test admin.dnsimple.test 1458642070 86400 7200 604800 300",
            3600,
            system.clone(),
        );
        for ns in [
            "ns1.dnsimple-edge.test",
            "ns2.dnsimple-edge.test",
            "ns3.dnsimple-edge.test",
            "ns4.dnsimple-edge.test",
        ] {
            self.insert_record_with(zone, "", "NS", ns, 3600, system.clone());
        }
    }

    /// Deletes the record `id` directly, as another writer would.
    pub fn delete_record(&self, id: u64) {
        self.change(|inner| inner.records.retain(|r| r.id != id));
    }

    /// Adds a zone.
    pub fn insert_zone(&self, zone: &str) {
        self.change(|inner| {
            inner.next_id += 1;
            let id = inner.next_id;
            inner.zones.push(Zone {
                id,
                name: zone.to_owned(),
                active: true,
                secondary: false,
            });
        });
    }

    /// Deletes `zone` with its records, as another writer would.
    pub fn remove_zone(&self, zone: &str) {
        self.change(|inner| {
            inner.zones.retain(|z| z.name != zone);
            inner.records.retain(|r| r.zone != zone);
        });
    }

    /// Sets the `active` and `secondary` flags of `zone`.
    pub fn set_zone_flags(&self, zone: &str, active: bool, secondary: bool) {
        let mut inner = lock(&self.state);
        for z in inner.zones.iter_mut().filter(|z| z.name == zone) {
            z.active = active;
            z.secondary = secondary;
        }
    }

    /// Deletes `zone` with its records and creates it again with the same records under new
    /// identifiers.
    pub fn recreate_zone(&self, zone: &str) {
        let mut inner = lock(&self.state);
        let mut next = inner.next_id;
        for record in inner.records.iter_mut().filter(|r| r.zone == zone) {
            next += 1;
            record.id = next;
        }
        inner.next_id = next;
    }

    /// Caps `per_page` at `cap`, so that listings come in small pages.
    pub fn set_page_cap(&self, cap: usize) {
        lock(&self.state).page_cap = cap.max(1);
    }

    /// How listings page from now on ([`Paging`]).
    pub fn set_paging(&self, paging: Paging) {
        lock(&self.state).paging = paging;
    }

    /// Answers every authenticated request with the documented quota answer, its window ending
    /// at `reset_unix` (module documentation).
    pub fn exhaust_quota(&self, reset_unix: u64) {
        lock(&self.state).quota_reset = Some(reset_unix);
    }

    /// Answers every request, also with a valid token, with the documented block after too many
    /// failed authentications: `Retry-After: retry_after` and `X-RateLimit-Reset: reset_unix`.
    pub fn block_failed_auth(&self, retry_after: u64, reset_unix: u64) {
        lock(&self.state).auth_block = Some((retry_after, reset_unix));
    }

    /// Ends [`Control::exhaust_quota`] and [`Control::block_failed_auth`].
    pub fn restore_quota(&self) {
        let mut inner = lock(&self.state);
        inner.quota_reset = None;
        inner.auth_block = None;
    }

    /// Answers the `content` of a TXT record that does not start with a quote wrapped in
    /// quotes, as the TXT article describes publishing (module documentation).
    pub fn set_txt_quoted(&self, quoted: bool) {
        lock(&self.state).txt_quoted = quoted;
    }
}

/// The absolute name, lowercase, with a trailing dot, of `name` relative to `zone`.
fn absolute(name: &str, zone: &str) -> String {
    let name = name.trim().to_lowercase();
    let zone = zone.to_lowercase();
    if name.is_empty() {
        format!("{zone}.")
    } else {
        format!("{name}.{zone}.")
    }
}

/// The absolute name of a name a test gives: `""`, a name that is the zone or ends with it
/// (with or without a trailing dot) is taken as absolute, any other as relative.
fn given(name: &str, zone: &str) -> String {
    let lower = name.trim().to_lowercase();
    let bare = lower.strip_suffix('.').unwrap_or(&lower);
    let zone = zone.to_lowercase();
    if bare.is_empty() {
        format!("{zone}.")
    } else if bare == zone || bare.ends_with(&format!(".{zone}")) {
        format!("{bare}.")
    } else {
        format!("{bare}.{zone}.")
    }
}

/// `name`, absolute, relative to `zone` as the mock stores it: `""` for the zone itself.
fn relative(name: &str, zone: &str) -> String {
    let name = name.trim().to_lowercase();
    let name = name.strip_suffix('.').unwrap_or(&name);
    let zone = zone.to_lowercase();
    if name == zone {
        String::new()
    } else {
        name.strip_suffix(&format!(".{zone}"))
            .unwrap_or(name)
            .to_owned()
    }
}

/// An error answer in the documented shape.
fn error(status: StatusCode, message: &str) -> Response {
    (status, axum::Json(json!({ "message": message }))).into_response()
}

/// `400 Validation failed` with the problem under `field`.
fn invalid(field: &str, problem: &str) -> Response {
    let mut errors = Map::new();
    errors.insert(field.to_owned(), json!([problem]));
    (
        StatusCode::BAD_REQUEST,
        axum::Json(json!({ "message": "Validation failed", "errors": errors })),
    )
        .into_response()
}

fn not_found() -> Response {
    error(StatusCode::NOT_FOUND, "Not Found")
}

/// Who the request is: `Ok(true)` for the account token, `Ok(false)` for a user token.
fn authorize(state: &Shared, headers: &HeaderMap) -> Result<bool, Response> {
    let inner = lock(state);
    if let Some((retry_after, reset)) = inner.auth_block {
        let message = format!(
            "Too many failed authentication attempts. Try again after {}.",
            iso8601(reset)
        );
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            [
                ("retry-after", retry_after.to_string()),
                ("x-ratelimit-remaining", "0".to_owned()),
                ("x-ratelimit-reset", reset.to_string()),
            ],
            axum::Json(json!({ "message": message })),
        )
            .into_response());
    }
    let given = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let account_token = match given {
        Some(token) if token == inner.seed.token => true,
        Some(token) if inner.seed.user_tokens.iter().any(|t| t == token) => false,
        _ => return Err(error(StatusCode::UNAUTHORIZED, "Authentication failed")),
    };
    if let Some(reset) = inner.quota_reset {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            [
                ("x-ratelimit-limit", "2400".to_owned()),
                ("x-ratelimit-remaining", "0".to_owned()),
                ("x-ratelimit-reset", reset.to_string()),
            ],
            axum::Json(json!({ "message": "quota exceeded" })),
        )
            .into_response());
    }
    Ok(account_token)
}

/// A Unix time as an ISO 8601 UTC timestamp, `2026-09-30T14:00:00Z`.
fn iso8601(unix: u64) -> String {
    let days = unix / 86_400;
    let secs = unix % 86_400;
    // Days since 1970-01-01 to a civil date (H. Hinnant, "chrono-Compatible Low-Level Date
    // Algorithms", `civil_from_days`).
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// [`authorize`] and the account of the path: `404` unless it is the account the token
/// reaches.
fn authorize_account(state: &Shared, headers: &HeaderMap, account: &str) -> Result<(), Response> {
    authorize(state, headers)?;
    let ours = lock(state).seed.account_id;
    if account.parse::<u64>().ok() == Some(ours) {
        Ok(())
    } else {
        Err(not_found())
    }
}

fn query<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// One page of `items` by `per_page` and `page`, with the `pagination` object.
fn paginate(state: &Shared, items: Vec<Value>, pairs: &[(String, String)]) -> Response {
    let per_page = match query(pairs, "per_page").map(str::parse::<usize>) {
        None => DEFAULT_PER_PAGE,
        Some(Ok(n)) if (1..=MAX_PER_PAGE).contains(&n) => n,
        Some(_) => return invalid("per_page", "must be between 1 and 100"),
    };
    let page = match query(pairs, "page").map(str::parse::<usize>) {
        None => 1,
        Some(Ok(n)) if n >= 1 => n,
        Some(_) => return invalid("page", "must be at least 1"),
    };
    let (cap, paging) = {
        let inner = lock(state);
        (inner.page_cap, inner.paging)
    };
    let per_page = per_page.min(cap);
    let total = items.len();
    let total_pages = total.div_ceil(per_page);
    let served = match paging {
        Paging::IgnorePage => 1,
        _ => page,
    };
    let shown: Vec<Value> = items
        .into_iter()
        .skip((served - 1).saturating_mul(per_page))
        .take(per_page)
        .collect();
    let stated_pages = match paging {
        Paging::OnePage => 1,
        _ => total_pages,
    };
    axum::Json(json!({
        "data": shown,
        "pagination": {
            "current_page": page, "per_page": per_page, "total_entries": total,
            "total_pages": stated_pages
        }
    }))
    .into_response()
}

async fn whoami(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let account_token = match authorize(&state, &headers) {
        Ok(account_token) => account_token,
        Err(response) => return response,
    };
    let id = lock(&state).seed.account_id;
    let stamp = "2016-01-07T17:45:13Z";
    if account_token {
        axum::Json(json!({"data": {"user": null, "account": {
            "id": id, "email": "example-account@example.com", "name": "Example Account",
            "plan_identifier": "teams-v1-monthly", "created_at": stamp, "updated_at": stamp
        }}}))
        .into_response()
    } else {
        axum::Json(json!({"data": {"user": {
            "id": 1, "email": "example-user@example.com", "created_at": stamp,
            "updated_at": stamp
        }, "account": null}}))
        .into_response()
    }
}

fn zone_json(zone: &Zone, account: u64) -> Value {
    let stamp = "2015-04-23T07:40:03Z";
    json!({
        "id": zone.id, "account_id": account, "name": zone.name, "reverse": false,
        "secondary": zone.secondary, "last_transferred_at": null, "active": zone.active,
        "created_at": stamp, "updated_at": stamp
    })
}

async fn zones_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(account): Path<String>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    if let Err(response) = authorize_account(&state, &headers, &account) {
        return response;
    }
    let items: Vec<Value> = {
        let inner = lock(&state);
        inner
            .zones
            .iter()
            .map(|z| zone_json(z, inner.seed.account_id))
            .collect()
    };
    paginate(&state, items, &pairs)
}

async fn zone_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((account, zone)): Path<(String, String)>,
) -> Response {
    if let Err(response) = authorize_account(&state, &headers, &account) {
        return response;
    }
    let inner = lock(&state);
    let Some(found) = inner.zones.iter().find(|z| z.name == zone) else {
        return not_found();
    };
    let mut body = zone_json(found, inner.seed.account_id);
    let count = inner.records.iter().filter(|r| r.zone == zone).count();
    body["records_count"] = json!(count);
    body["records_limit"] = json!(1000);
    body["records_overage"] = json!(0);
    axum::Json(json!({ "data": body })).into_response()
}

fn record_json(record: &Record, inner: &Inner) -> Value {
    let content = if inner.txt_quoted && record.rtype == "TXT" && !record.content.starts_with('"') {
        quoted(&record.content)
    } else {
        record.content.clone()
    };
    let stamp = "2016-01-07T17:45:13Z";
    json!({
        "id": record.id, "zone_id": record.zone, "parent_id": null, "name": record.name,
        "content": content, "ttl": record.ttl, "priority": record.extra.priority,
        "type": record.rtype, "regions": record.extra.regions,
        "system_record": record.extra.system, "created_at": stamp, "updated_at": stamp
    })
}

async fn records_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((account, zone)): Path<(String, String)>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    if let Err(response) = authorize_account(&state, &headers, &account) {
        return response;
    }
    let items: Vec<Value> = {
        let inner = lock(&state);
        if !inner.has_zone(&zone) {
            return not_found();
        }
        inner
            .records
            .iter()
            .filter(|r| r.zone == zone)
            .filter(|r| query(&pairs, "type").is_none_or(|t| t == r.rtype))
            .filter(|r| query(&pairs, "name").is_none_or(|n| n == r.name))
            .filter(|r| query(&pairs, "name_like").is_none_or(|n| r.name.contains(n)))
            .map(|r| record_json(r, &inner))
            .collect()
    };
    paginate(&state, items, &pairs)
}

async fn record_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((account, zone, id)): Path<(String, String, String)>,
) -> Response {
    if let Err(response) = authorize_account(&state, &headers, &account) {
        return response;
    }
    let inner = lock(&state);
    let found = id
        .parse::<u64>()
        .ok()
        .and_then(|id| inner.records.iter().find(|r| r.zone == zone && r.id == id));
    match found {
        Some(record) => axum::Json(json!({ "data": record_json(record, &inner) })).into_response(),
        None => not_found(),
    }
}

/// The members of a request body, refusing any the documented input does not have.
fn members(body: &[u8], allowed: &[&str]) -> Result<Map<String, Value>, Response> {
    let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(body) else {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "the body is not a JSON object",
        ));
    };
    if let Some(unknown) = map.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(invalid(unknown, "is not a known attribute"));
    }
    Ok(map)
}

/// A `name` member: relative, without a trailing dot and not `@`.
fn name_member(value: &Value) -> Result<String, Response> {
    match value.as_str() {
        Some(name) if !name.ends_with('.') && name != "@" && !name.contains(' ') => {
            Ok(name.to_lowercase())
        }
        _ => Err(invalid("name", "is not a valid record name")),
    }
}

fn ttl_member(value: &Value) -> Result<u32, Response> {
    value
        .as_u64()
        .and_then(|t| u32::try_from(t).ok())
        .ok_or_else(|| invalid("ttl", "is not a number"))
}

fn priority_member(value: &Value) -> Result<Option<u64>, Response> {
    match value {
        Value::Null => Ok(None),
        other => match other.as_u64().filter(|&p| p <= 65_535) {
            Some(p) => Ok(Some(p)),
            None => Err(invalid("priority", "is not a valid priority")),
        },
    }
}

fn regions_member(value: &Value) -> Result<Vec<String>, Response> {
    let list = value
        .as_array()
        .ok_or_else(|| invalid("regions", "is not a list"))?;
    list.iter()
        .map(|r| match r.as_str() {
            Some(code) if REGIONS.contains(&code) => Ok(code.to_owned()),
            _ => Err(invalid("regions", "holds an unknown region")),
        })
        .collect()
}

/// The per-type rules (module documentation) for a record as it would be stored.
fn validate(record: &Record) -> Result<(), Response> {
    let content = record.content.as_str();
    if content.is_empty() {
        return Err(invalid("content", "can't be blank"));
    }
    let number = |text: &str, max: u64| text.parse::<u64>().is_ok_and(|n| n <= max);
    let fine = match record.rtype.as_str() {
        "A" => content.parse::<Ipv4Addr>().is_ok(),
        "AAAA" => content.parse::<std::net::Ipv6Addr>().is_ok(),
        "SRV" => matches!(
            content.split_whitespace().collect::<Vec<_>>().as_slice(),
            [weight, port, _target] if number(weight, 65_535) && number(port, 65_535)
        ),
        "CAA" => matches!(
            content.splitn(3, ' ').collect::<Vec<_>>().as_slice(),
            [flags, tag, value] if number(flags, 255) && !tag.is_empty() && !value.is_empty()
        ),
        "TXT" => content.chars().count() <= 1000,
        _ => true,
    };
    if fine {
        Ok(())
    } else {
        Err(invalid("content", "is not valid for the record type"))
    }
}

async fn record_create(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((account, zone)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Response {
    if let Err(response) = authorize_account(&state, &headers, &account) {
        return response;
    }
    let mut inner = lock(&state);
    if !inner.has_zone(&zone) {
        return not_found();
    }
    let allowed = [
        "name",
        "type",
        "content",
        "ttl",
        "priority",
        "regions",
        "integrated_zones",
    ];
    let map = match members(&body, &allowed) {
        Ok(map) => map,
        Err(response) => return response,
    };
    let name = match map.get("name").map(name_member) {
        Some(Ok(name)) => name,
        Some(Err(response)) => return response,
        None => return invalid("name", "can't be blank"),
    };
    let Some(rtype) = map.get("type").and_then(Value::as_str) else {
        return invalid("record_type", "can't be blank");
    };
    if !TYPES.contains(&rtype) || rtype == "SOA" {
        return invalid("record_type", "unsupported");
    }
    let Some(content) = map.get("content").and_then(Value::as_str) else {
        return invalid("content", "can't be blank");
    };
    let ttl = match map.get("ttl").map(ttl_member) {
        None => DEFAULT_TTL,
        Some(Ok(ttl)) => ttl,
        Some(Err(response)) => return response,
    };
    let priority = match map.get("priority").map(priority_member) {
        None => None,
        Some(Ok(priority)) => priority,
        Some(Err(response)) => return response,
    };
    let priority = priority.or(matches!(rtype, "MX" | "SRV").then_some(0));
    let regions = match map.get("regions").map(regions_member) {
        None => vec!["global".to_owned()],
        Some(Ok(regions)) => regions,
        Some(Err(response)) => return response,
    };
    let record = Record {
        id: inner.next_id + 1,
        zone: zone.clone(),
        name,
        rtype: rtype.to_owned(),
        content: content.to_owned(),
        ttl,
        extra: Extra {
            priority,
            regions,
            system: false,
        },
    };
    if let Err(response) = validate(&record) {
        return response;
    }
    inner.next_id += 1;
    let created = record_json(&record, &inner);
    let before = inner.published();
    inner.records.push(record);
    inner.report(&before, Origin::Api);
    (StatusCode::CREATED, axum::Json(json!({ "data": created }))).into_response()
}

async fn record_update(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((account, zone, id)): Path<(String, String, String)>,
    body: axum::body::Bytes,
) -> Response {
    if let Err(response) = authorize_account(&state, &headers, &account) {
        return response;
    }
    let mut inner = lock(&state);
    let Some(index) = id.parse::<u64>().ok().and_then(|id| {
        inner
            .records
            .iter()
            .position(|r| r.zone == zone && r.id == id)
    }) else {
        return not_found();
    };
    let Some(current) = inner.records.get(index).cloned() else {
        return not_found();
    };
    if current.extra.system {
        return error(StatusCode::BAD_REQUEST, "System records cannot be modified");
    }
    let allowed = [
        "name",
        "content",
        "ttl",
        "priority",
        "regions",
        "integrated_zones",
    ];
    let map = match members(&body, &allowed) {
        Ok(map) => map,
        Err(response) => return response,
    };
    let mut updated = current;
    if let Some(value) = map.get("name") {
        match name_member(value) {
            Ok(name) => updated.name = name,
            Err(response) => return response,
        }
    }
    if let Some(value) = map.get("content") {
        match value.as_str() {
            Some(content) => updated.content = content.to_owned(),
            None => return invalid("content", "is not a string"),
        }
    }
    if let Some(value) = map.get("ttl") {
        match ttl_member(value) {
            Ok(ttl) => updated.ttl = ttl,
            Err(response) => return response,
        }
    }
    if let Some(value) = map.get("priority") {
        match priority_member(value) {
            Ok(priority) => updated.extra.priority = priority,
            Err(response) => return response,
        }
    }
    if let Some(value) = map.get("regions") {
        match regions_member(value) {
            Ok(regions) => updated.extra.regions = regions,
            Err(response) => return response,
        }
    }
    if let Err(response) = validate(&updated) {
        return response;
    }
    let answer = record_json(&updated, &inner);
    let before = inner.published();
    if let Some(slot) = inner.records.get_mut(index) {
        *slot = updated;
    }
    inner.report(&before, Origin::Api);
    axum::Json(json!({ "data": answer })).into_response()
}

async fn record_delete(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((account, zone, id)): Path<(String, String, String)>,
) -> Response {
    if let Err(response) = authorize_account(&state, &headers, &account) {
        return response;
    }
    let Ok(id) = id.parse::<u64>() else {
        return not_found();
    };
    let mut inner = lock(&state);
    let Some(record) = inner.records.iter().find(|r| r.zone == zone && r.id == id) else {
        return not_found();
    };
    if record.extra.system {
        return error(StatusCode::BAD_REQUEST, "System records cannot be deleted");
    }
    let published = inner.published();
    inner.records.retain(|r| !(r.zone == zone && r.id == id));
    inner.report(&published, Origin::Api);
    StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
mod tests {
    use super::{absolute, given, quoted, relative};

    #[test]
    fn names_are_relative_to_the_zone() {
        assert_eq!(absolute("", "example.org"), "example.org.");
        assert_eq!(absolute("www", "example.org"), "www.example.org.");
        assert_eq!(given("www.example.org.", "example.org"), "www.example.org.");
        assert_eq!(given("www", "example.org"), "www.example.org.");
        assert_eq!(relative("example.org.", "example.org"), "");
        assert_eq!(relative("a.b.example.org.", "example.org"), "a.b");
    }

    #[test]
    fn unix_times_print_as_iso8601() {
        assert_eq!(super::iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::iso8601(1_790_776_800), "2026-09-30T14:00:00Z");
        assert_eq!(super::iso8601(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn txt_is_quoted_in_chunks() {
        assert_eq!(quoted("v1"), "\"v1\"");
        assert_eq!(quoted("a\"b"), "\"a\\\"b\"");
        let long = "x".repeat(300);
        assert_eq!(
            quoted(&long),
            format!("\"{}\" \"{}\"", "x".repeat(255), "x".repeat(45))
        );
    }
}
