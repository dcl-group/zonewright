//! Mock of the Hetzner Cloud API's DNS part (zones, RRSets, RRSet actions, actions).
//!
//! Shapes follow the provider's documentation, the same sources the client cites. The
//! reference is <https://docs.hetzner.cloud/reference/cloud> with its published OpenAPI
//! description <https://docs.hetzner.cloud/cloud.spec.json>:
//!
//! - Zones: `GET /v1/zones` (`name` and `mode` filters, `page`, `per_page` 1 to 50, default 25;
//!   an invalid value of either parameter is replaced by its default; the answer's
//!   `meta.pagination` has `page`, `per_page`, `previous_page`, `next_page`, `last_page` and
//!   `total_entries`, each of the last four possibly `null`) and `GET /v1/zones/{id_or_name}`.
//! - Zone RRSets: `GET /v1/zones/{id_or_name}/rrsets/{rr_name}/{rr_type}`. `rr_name` is lower
//!   case, has no trailing dot and does not end with the zone name, `@` is the apex; `rr_type` is
//!   one of an enumeration; `ttl` is an integer from 60 to 2147483647 or `null` ("If not set, the
//!   Zone's Default TTL is used"); the records have a `value` and a `comment`. `422`
//!   `incorrect_zone_mode` for a zone that is not in primary mode.
//! - Zone RRSets, record level: `GET /v1/zones/{id_or_name}/rrsets` (`page`, `per_page` 1 to 50,
//!   default 25; the answer's `rrsets` and `meta.pagination` as for zones),
//!   `POST /v1/zones/{id_or_name}/rrsets` (`name`, `type`, `records` required, `ttl` and `labels`
//!   optional, no other property; `201` with `rrset` and `action`) and
//!   `DELETE /v1/zones/{id_or_name}/rrsets/{rr_name}/{rr_type}` (`201` with an action). An rrset
//!   carries `labels` and `protection.change` ("Prevent the Resource from being changed").
//! - Zone RRSet Actions: `add_records` (`records`, 1 to 50 distinct, required; `ttl`, optional: "If
//!   set, and the RRSet being updated already has a TTL, the values must be the same"; no other
//!   property; the rrset is created when it does not exist, else the records are appended),
//!   `remove_records` (`records`; the rrset is deleted when no record is left), `set_records`
//!   (`records`, 1 to 50 distinct, required, each `value` and optional `comment`: "Overwrites the
//!   resource records (RRs) of an existing RRSet") and `change_ttl` (`ttl` required, 60 to
//!   2147483647 or `null`), all answered `201` with an action. A write to a protected rrset is
//!   refused with `423` `protected` (Errors table: "The Action you are trying to start is
//!   protected for this resource").
//! - Record values, per type, as the DNS record type pages show them
//!   (<https://docs.hetzner.com/networking/dns/record-types/overview/>): A and AAAA an address;
//!   CNAME, NS and PTR a name; MX `priority name` (reference, tag Zone RRSets: `10
//!   smtp.example.com.`); SRV `priority weight port name`; TLSA `usage selector matching hex`;
//!   TXT quoted. A name ending in a dot is absolute, one without is relative to the zone
//!   (<https://docs.hetzner.com/networking/dns/faq/records/>); the mock stores the text as
//!   written.
//! - Actions: `GET /v1/actions/{id}`; `status` is `running`, `success` or `error`; `error` is
//!   `null` or `{code, message}`.
//! - Errors: `{"error": {"code", "message", "details"}}` with the codes and statuses of the
//!   Errors table (`401` `unauthorized`, `404` `not_found`, `409` `uniqueness_error`, `422`
//!   `invalid_input`, `423` `locked`, `429` `rate_limit_exceeded`, ...).
//! - <https://docs.hetzner.com/networking/dns/record-types/txt-record/>: "The value has to be
//!   quoted."
//!
//! Answers this mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading. A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - a missing zone and a missing rrset are both answered `404` `not_found` (the reference lists
//!   no status for them; hcloud-go reads the code `not_found` as absence), and a listing or read
//!   of a zone under an identifier the mock does not know is a `404` too;
//! - a value that is not "quoted" is refused with `422` `invalid_input`: it has to start and end
//!   with a double quote (the documentation shows how a value looks, not how the API validates
//!   it); a `rr_type` outside the enumeration is refused with `422` `invalid_input`;
//! - `add_records` with a value that the rrset holds already is refused with `409`
//!   `uniqueness_error`, and `remove_records` with a value the rrset does not hold is refused
//!   with `422` `invalid_input`; `remove_records` on a missing rrset is `404` `not_found`;
//! - the action in the answer to a write is `running`; it finishes after the number of looks set
//!   by [`Control::set_action_looks`] (default 1: the first `GET /v1/actions/{id}` answers
//!   `success` or `error`), and the change takes effect when it finishes, not before;
//! - `add_records` with a `ttl` on an rrset that has none gives the rrset that TTL (the
//!   reference says only that a `ttl` must equal the TTL an rrset already has);
//! - a record's `comment` is kept and answered as it was written (empty when none was given);
//! - the `ratelimit-*` headers are not sent;
//! - `POST /v1/zones/{id}/rrsets` for a name and type that exist is refused with `409`
//!   `uniqueness_error`; for type `SOA` it is refused with `422` `invalid_input`; `set_records`,
//!   `change_ttl` and `DELETE` of a missing rrset are `404` `not_found`;
//! - the value checks of the types whose form no page gives (CAA, DS, HINFO, HTTPS, RP, SOA,
//!   SVCB) only require a non-empty value; a TXT value must start and end with a double quote;
//! - the rrset listing returns the rrsets in creation order, without a `sort` parameter;
//! - a new rrset created without `ttl` keeps `null`; `set_records` keeps the rrset's TTL, labels
//!   and protection; `change_ttl` keeps its records.
//!
//! Error texts are invented.
//!
//! A test holds a [`HetznerMock`]. It dereferences to the [`MockServer`], so the request log and
//! the fault queue of the shared harness work as usual:
//!
//! ```text
//! let mock = HetznerMock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("POST", "/v1/zones/*/rrsets/*/TXT/actions/add_records").status(502));
//! // ... drive the client against mock.base_url() ...
//! assert_eq!(mock.control().txt_values("_acme-challenge"), ["\"v1\""]);
//! ```

// Reason: the error side of a handler's result is the response it answers with.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde_json::{Value, json};

use crate::MockServer;

/// Path of the API below the server's base URL.
pub const API_PATH: &str = "/v1";

/// Largest `per_page` the API accepts.
const MAX_PER_PAGE: usize = 50;

/// Default `per_page`.
const DEFAULT_PER_PAGE: usize = 25;

/// Largest number of records in one action request.
const MAX_RECORDS: usize = 50;

/// The record types of the documented enumeration.
const TYPES: [&str; 16] = [
    "A", "AAAA", "CAA", "CNAME", "DS", "HINFO", "HTTPS", "MX", "NS", "PTR", "RP", "SOA", "SRV",
    "SVCB", "TLSA", "TXT",
];

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The API token the API accepts.
    pub token: String,
    /// The zones: name without a trailing dot and mode, `primary` or `secondary`. Identifiers
    /// are assigned from 1001.
    pub zones: Vec<(String, String)>,
}

impl Seed {
    /// Token `test-only-token`, the primary zone `example.org` and the secondary zone
    /// `mirror.example.net`.
    pub fn standard() -> Self {
        Self {
            token: "test-only-token".into(),
            zones: vec![
                ("example.org".into(), "primary".into()),
                ("mirror.example.net".into(), "secondary".into()),
            ],
        }
    }
}

/// One record of an rrset as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRecord {
    /// The value as written, with its quotes.
    pub value: String,
    /// The comment.
    pub comment: String,
}

/// One rrset as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rrset {
    /// The identifier of its zone.
    pub zone_id: u64,
    /// The owner name relative to the zone, `@` for the apex.
    pub name: String,
    /// The record type.
    pub rtype: String,
    /// The TTL; `None` when the zone's default applies.
    pub ttl: Option<u32>,
    /// The records, in the order they were added.
    pub records: Vec<StoredRecord>,
    /// The labels, as key and value.
    pub labels: Vec<(String, String)>,
    /// Change protection.
    pub protected: bool,
}

impl Rrset {
    /// The values of the records.
    pub fn values(&self) -> Vec<String> {
        self.records.iter().map(|r| r.value.clone()).collect()
    }
}

#[derive(Clone, Debug)]
struct Zone {
    id: u64,
    name: String,
    mode: String,
}

/// What an action does when it finishes.
#[derive(Clone, Debug)]
enum Change {
    Add {
        zone_id: u64,
        name: String,
        rtype: String,
        ttl: Option<u32>,
        records: Vec<StoredRecord>,
    },
    Remove {
        zone_id: u64,
        name: String,
        rtype: String,
        values: Vec<String>,
    },
    Create(Rrset),
    Set {
        zone_id: u64,
        name: String,
        rtype: String,
        records: Vec<StoredRecord>,
    },
    Ttl {
        zone_id: u64,
        name: String,
        rtype: String,
        ttl: Option<u32>,
    },
    Delete {
        zone_id: u64,
        name: String,
        rtype: String,
    },
}

#[derive(Clone, Debug)]
struct ActionState {
    command: &'static str,
    zone_id: u64,
    looks_left: u32,
    change: Change,
    error: Option<(String, String)>,
    finished: bool,
}

#[derive(Debug)]
struct Inner {
    token: String,
    zones: Vec<Zone>,
    rrsets: Vec<Rrset>,
    actions: HashMap<u64, ActionState>,
    next_zone: u64,
    next_action: u64,
    page_cap: Option<usize>,
    null_total: bool,
    action_looks: u32,
    fail_next_action: Option<(String, String)>,
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running Hetzner mock. Dereferences to its [`MockServer`] for the request log and the fault
/// queue; [`HetznerMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct HetznerMock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of a [`HetznerMock`]. Cheap to clone, so that a fault hook
/// ([`Fault::run`](crate::Fault::run)) can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
}

impl Deref for HetznerMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl HetznerMock {
    /// Starts the mock with `seed`.
    pub async fn start(seed: Seed) -> Self {
        let mut next_zone = 1000;
        let zones = seed
            .zones
            .into_iter()
            .map(|(name, mode)| {
                next_zone += 1;
                Zone {
                    id: next_zone,
                    name,
                    mode,
                }
            })
            .collect();
        let state = Arc::new(Mutex::new(Inner {
            token: seed.token,
            zones,
            rrsets: Vec::new(),
            actions: HashMap::new(),
            next_zone,
            next_action: 5000,
            page_cap: None,
            null_total: false,
            action_looks: 1,
            fail_next_action: None,
        }));
        let router = Router::new()
            .route("/v1/zones", get(zones_list))
            .route("/v1/zones/{zone}", get(zone_get))
            .route(
                "/v1/zones/{zone}/rrsets",
                get(rrsets_list).post(rrset_create),
            )
            .route(
                "/v1/zones/{zone}/rrsets/{name}/{rtype}",
                get(rrset_get).merge(delete(rrset_delete)),
            )
            .route(
                "/v1/zones/{zone}/rrsets/{name}/{rtype}/actions/add_records",
                post(add_records),
            )
            .route(
                "/v1/zones/{zone}/rrsets/{name}/{rtype}/actions/set_records",
                post(set_records),
            )
            .route(
                "/v1/zones/{zone}/rrsets/{name}/{rtype}/actions/change_ttl",
                post(change_ttl),
            )
            .route(
                "/v1/zones/{zone}/rrsets/{name}/{rtype}/actions/remove_records",
                post(remove_records),
            )
            .route("/v1/actions/{id}", get(action_get))
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
    /// Every rrset, in creation order.
    pub fn rrsets(&self) -> Vec<Rrset> {
        lock(&self.state).rrsets.clone()
    }

    /// The rrset of `name` and `rtype` in the first zone; `name` is relative or absolute.
    pub fn rrset(&self, name: &str, rtype: &str) -> Option<Rrset> {
        let inner = lock(&self.state);
        let zone = inner.zones.first()?;
        let wanted = relative(name, &zone.name);
        inner
            .rrsets
            .iter()
            .find(|r| r.zone_id == zone.id && r.name == wanted && r.rtype == rtype)
            .cloned()
    }

    /// The values of the TXT rrset at `name` in the first zone, as stored (with their quotes);
    /// empty when there is none.
    pub fn txt_values(&self, name: &str) -> Vec<String> {
        self.rrset(name, "TXT")
            .map(|r| r.values())
            .unwrap_or_default()
    }

    /// Creates an rrset directly, as another writer would, in the zone `zone` (replacing one
    /// of the same name and type). `values` are stored as given.
    pub fn insert_rrset(
        &self,
        zone: &str,
        name: &str,
        rtype: &str,
        ttl: Option<u32>,
        values: &[&str],
    ) {
        let mut inner = lock(&self.state);
        let Some(zone_id) = inner.zones.iter().find(|z| z.name == zone).map(|z| z.id) else {
            return;
        };
        let name = relative(name, zone);
        inner
            .rrsets
            .retain(|r| !(r.zone_id == zone_id && r.name == name && r.rtype == rtype));
        inner.rrsets.push(Rrset {
            zone_id,
            name,
            rtype: rtype.to_owned(),
            ttl,
            records: values
                .iter()
                .map(|v| StoredRecord {
                    value: (*v).to_owned(),
                    comment: String::new(),
                })
                .collect(),
            labels: Vec::new(),
            protected: false,
        });
    }

    /// Changes the rrset of `name` and `rtype` in the zone `zone` directly, as another writer
    /// would.
    pub fn update_rrset(
        &self,
        zone: &str,
        name: &str,
        rtype: &str,
        change: impl FnOnce(&mut Rrset),
    ) {
        let mut inner = lock(&self.state);
        let Some(zone_id) = inner.zones.iter().find(|z| z.name == zone).map(|z| z.id) else {
            return;
        };
        let name = relative(name, zone);
        if let Some(set) = inner
            .rrsets
            .iter_mut()
            .find(|r| r.zone_id == zone_id && r.name == name && r.rtype == rtype)
        {
            change(set);
        }
    }

    /// Appends a record to an existing rrset directly, as another writer would, with a
    /// `comment`.
    pub fn add_value(&self, zone: &str, name: &str, rtype: &str, value: &str, comment: &str) {
        let mut inner = lock(&self.state);
        let Some(zone_id) = inner.zones.iter().find(|z| z.name == zone).map(|z| z.id) else {
            return;
        };
        let name = relative(name, zone);
        if let Some(set) = inner
            .rrsets
            .iter_mut()
            .find(|r| r.zone_id == zone_id && r.name == name && r.rtype == rtype)
        {
            set.records.push(StoredRecord {
                value: value.to_owned(),
                comment: comment.to_owned(),
            });
        }
    }

    /// Deletes the rrset directly, as another writer would.
    pub fn delete_rrset(&self, zone: &str, name: &str, rtype: &str) {
        let mut inner = lock(&self.state);
        let Some(zone_id) = inner.zones.iter().find(|z| z.name == zone).map(|z| z.id) else {
            return;
        };
        let name = relative(name, zone);
        inner
            .rrsets
            .retain(|r| !(r.zone_id == zone_id && r.name == name && r.rtype == rtype));
    }

    /// Adds a zone in `mode`, `primary` or `secondary`. Returns its identifier.
    pub fn add_zone(&self, name: &str, mode: &str) -> u64 {
        let mut inner = lock(&self.state);
        inner.next_zone += 1;
        let id = inner.next_zone;
        inner.zones.push(Zone {
            id,
            name: name.to_owned(),
            mode: mode.to_owned(),
        });
        id
    }

    /// The identifier of the zone `name`.
    pub fn zone_id(&self, name: &str) -> Option<u64> {
        lock(&self.state)
            .zones
            .iter()
            .find(|z| z.name == name)
            .map(|z| z.id)
    }

    /// Deletes the zone with its rrsets and creates it again under a new identifier; the rrsets
    /// come back only when `keep_records` is true. Returns the new identifier.
    pub fn recreate_zone(&self, name: &str, keep_records: bool) -> u64 {
        let mut inner = lock(&self.state);
        inner.next_zone += 1;
        let new = inner.next_zone;
        let Some(zone) = inner.zones.iter_mut().find(|z| z.name == name) else {
            return 0;
        };
        let old = zone.id;
        zone.id = new;
        if keep_records {
            for set in inner.rrsets.iter_mut().filter(|r| r.zone_id == old) {
                set.zone_id = new;
            }
        } else {
            inner.rrsets.retain(|r| r.zone_id != old);
        }
        new
    }

    /// Deletes the zone with its rrsets.
    pub fn delete_zone(&self, name: &str) {
        let mut inner = lock(&self.state);
        if let Some(id) = inner.zones.iter().find(|z| z.name == name).map(|z| z.id) {
            inner.zones.retain(|z| z.id != id);
            inner.rrsets.retain(|r| r.zone_id != id);
        }
    }

    /// Caps `per_page` at `cap`, so that the zone listing comes in small pages.
    pub fn set_page_cap(&self, cap: usize) {
        lock(&self.state).page_cap = Some(cap.max(1));
    }

    /// Makes the zone listing state `total_entries: null` (documented as possible).
    pub fn set_null_total(&self, null: bool) {
        lock(&self.state).null_total = null;
    }

    /// The number of `GET /v1/actions/{id}` looks an action needs to finish: the last one
    /// answers `success` or `error`, the ones before `running`. Applies to actions created from
    /// now on. At least 1.
    pub fn set_action_looks(&self, looks: u32) {
        lock(&self.state).action_looks = looks.max(1);
    }

    /// The next action finishes with the status `error`, the given code and message, and its
    /// change is not applied.
    pub fn fail_next_action(&self, code: &str, message: &str) {
        lock(&self.state).fail_next_action = Some((code.to_owned(), message.to_owned()));
    }
}

/// `name` relative to `zone`: `@` for the zone itself, a trailing dot and the zone's suffix
/// removed, lower case.
fn relative(name: &str, zone: &str) -> String {
    let name = name.trim().to_lowercase();
    let name = name.strip_suffix('.').unwrap_or(&name);
    let zone = zone.to_lowercase();
    if name == "@" || name == zone {
        "@".to_owned()
    } else {
        name.strip_suffix(&format!(".{zone}"))
            .unwrap_or(name)
            .to_owned()
    }
}

/// An error answer in the documented shape.
fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        axum::Json(json!({"error": {"code": code, "message": message, "details": null}})),
    )
        .into_response()
}

fn invalid(message: &str) -> Response {
    error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_input", message)
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
            "unable to authenticate",
        ))
    }
}

fn query<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn zone_json(zone: &Zone, inner: &Inner) -> Value {
    let count: usize = inner
        .rrsets
        .iter()
        .filter(|r| r.zone_id == zone.id)
        .map(|r| r.records.len())
        .sum();
    json!({
        "id": zone.id, "name": zone.name, "created": "2026-01-01T00:00:00Z", "mode": zone.mode,
        "ttl": 3600, "status": "ok", "record_count": count, "labels": {},
        "protection": {"delete": false}, "primary_nameservers": []
    })
}

async fn zones_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let inner = lock(&state);
    // An invalid value is replaced by the default.
    let per_page = match query(&pairs, "per_page").map(str::parse::<usize>) {
        Some(Ok(n)) if (1..=MAX_PER_PAGE).contains(&n) => n,
        _ => DEFAULT_PER_PAGE,
    };
    let per_page = inner.page_cap.map_or(per_page, |cap| per_page.min(cap));
    let page = match query(&pairs, "page").map(str::parse::<usize>) {
        Some(Ok(n)) if n >= 1 => n,
        _ => 1,
    };
    let mut zones: Vec<&Zone> = inner
        .zones
        .iter()
        .filter(|z| query(&pairs, "name").is_none_or(|n| n == z.name))
        .filter(|z| query(&pairs, "mode").is_none_or(|m| m == z.mode))
        .collect();
    zones.sort_by_key(|z| z.id);
    let total = zones.len();
    let last = total.div_ceil(per_page).max(1);
    let shown: Vec<Value> = zones
        .into_iter()
        .skip((page - 1) * per_page)
        .take(per_page)
        .map(|z| zone_json(z, &inner))
        .collect();
    let next = (page < last).then_some(page + 1);
    let previous = (page > 1).then_some(page - 1);
    axum::Json(json!({
        "zones": shown,
        "meta": {"pagination": {
            "page": page, "per_page": per_page, "previous_page": previous, "next_page": next,
            "last_page": next.map(|_| last),
            "total_entries": if inner.null_total { Value::Null } else { json!(total) },
        }}
    }))
    .into_response()
}

/// The zone named by an identifier or a name.
fn find_zone(inner: &Inner, key: &str) -> Option<Zone> {
    inner
        .zones
        .iter()
        .find(|z| z.id.to_string() == key || z.name == key)
        .cloned()
}

async fn zone_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let inner = lock(&state);
    match find_zone(&inner, &key) {
        Some(zone) => axum::Json(json!({"zone": zone_json(&zone, &inner)})).into_response(),
        None => not_found("zone not found"),
    }
}

/// The zone of a request on its rrsets: `404` when unknown, `422` when not primary.
fn rrset_zone(inner: &Inner, key: &str) -> Result<Zone, Response> {
    let zone = find_zone(inner, key).ok_or_else(|| not_found("zone not found"))?;
    if zone.mode != "primary" {
        return Err(error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "incorrect_zone_mode",
            "this operation is not supported for this zone's mode",
        ));
    }
    Ok(zone)
}

async fn rrset_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((key, name, rtype)): Path<(String, String, String)>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let inner = lock(&state);
    let zone = match rrset_zone(&inner, &key) {
        Ok(zone) => zone,
        Err(response) => return response,
    };
    if !TYPES.contains(&rtype.as_str()) {
        return invalid("unknown rrset type");
    }
    match inner
        .rrsets
        .iter()
        .find(|r| r.zone_id == zone.id && r.name == name && r.rtype == rtype)
    {
        Some(set) => axum::Json(json!({"rrset": rrset_json(set)})).into_response(),
        None => not_found("rrset not found"),
    }
}

/// An rrset in the documented shape.
fn rrset_json(set: &Rrset) -> Value {
    let labels: serde_json::Map<String, Value> = set
        .labels
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();
    json!({
        "id": format!("{}/{}", set.name, set.rtype), "name": set.name, "type": set.rtype,
        "ttl": set.ttl, "labels": labels, "protection": {"change": set.protected},
        "zone": set.zone_id,
        "records": set.records.iter()
            .map(|r| json!({"value": r.value, "comment": r.comment}))
            .collect::<Vec<_>>(),
    })
}

fn find_mut<'a>(
    inner: &'a mut Inner,
    zone_id: u64,
    name: &str,
    rtype: &str,
) -> Option<&'a mut Rrset> {
    inner
        .rrsets
        .iter_mut()
        .find(|r| r.zone_id == zone_id && r.name == name && r.rtype == rtype)
}

fn find<'a>(inner: &'a Inner, zone_id: u64, name: &str, rtype: &str) -> Option<&'a Rrset> {
    inner
        .rrsets
        .iter()
        .find(|r| r.zone_id == zone_id && r.name == name && r.rtype == rtype)
}

fn protected() -> Response {
    error(
        StatusCode::LOCKED,
        "protected",
        "the action is protected for this resource",
    )
}

/// A name inside a value: absolute with a trailing dot, or relative to the zone; `.` is the
/// root. Label lengths are not checked: the documentation states no rule for them.
fn value_name(text: &str) -> bool {
    let body = text.strip_suffix('.').unwrap_or(text);
    text == "."
        || (!body.is_empty()
            && body.split('.').all(|label| {
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'*')
            }))
}

/// A record value as the record type pages show it (see the module documentation).
fn value_valid(rtype: &str, value: &str) -> bool {
    let fields: Vec<&str> = value.split(' ').collect();
    let number = |text: &str, max: u32| text.parse::<u32>().is_ok_and(|n| n <= max);
    let quoted = |text: &str| text.len() >= 2 && text.starts_with('"') && text.ends_with('"');
    match (rtype, fields.as_slice()) {
        ("A", [address]) => address.parse::<std::net::Ipv4Addr>().is_ok(),
        ("AAAA", [address]) => address.parse::<std::net::Ipv6Addr>().is_ok(),
        ("TXT", _) => quoted(value),
        ("CNAME" | "NS" | "PTR", [target]) => value_name(target),
        ("MX", [priority, host]) => number(priority, 65_535) && value_name(host),
        ("SRV", [priority, weight, port, target]) => {
            number(priority, 65_535)
                && number(weight, 65_535)
                && number(port, 65_535)
                && value_name(target)
        }
        ("TLSA", [usage, selector, matching, data]) => {
            number(usage, 255)
                && number(selector, 255)
                && number(matching, 255)
                && !data.is_empty()
                && data.len() % 2 == 0
                && data.bytes().all(|b| b.is_ascii_hexdigit())
        }
        ("CAA" | "DS" | "HINFO" | "HTTPS" | "RP" | "SOA" | "SVCB", _) => !value.trim().is_empty(),
        _ => false,
    }
}

/// Every record value is valid for `rtype`.
fn check_values(rtype: &str, records: &[StoredRecord]) -> Result<(), Response> {
    if records.iter().all(|r| value_valid(rtype, &r.value)) {
        Ok(())
    } else {
        Err(invalid("a record value is not valid for the rrset type"))
    }
}

/// A TTL: an integer from 60 to 2147483647, or `null` where `nullable`.
// Source: the documented range.
fn parse_ttl(value: Option<&Value>, nullable: bool) -> Result<Option<u32>, Response> {
    match value {
        None => Ok(None),
        Some(Value::Null) if nullable => Ok(None),
        Some(value) => match value
            .as_u64()
            .filter(|&t| (60..=2_147_483_647).contains(&t))
        {
            Some(ttl) => Ok(Some(ttl as u32)),
            None => Err(invalid("ttl must be an integer from 60 to 2147483647")),
        },
    }
}

/// The JSON object of a request body, with only `allowed` keys.
fn body_object(body: &[u8], allowed: &[&str]) -> Result<Value, Response> {
    let Ok(body) = serde_json::from_slice::<Value>(body) else {
        return Err(error(StatusCode::BAD_REQUEST, "json_error", "invalid JSON"));
    };
    let Some(object) = body.as_object() else {
        return Err(invalid("the body must be an object"));
    };
    if object.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(invalid("unknown property"));
    }
    Ok(body)
}

async fn rrsets_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let inner = lock(&state);
    let zone = match rrset_zone(&inner, &key) {
        Ok(zone) => zone,
        Err(response) => return response,
    };
    // An invalid value is replaced by the default.
    let per_page = match query(&pairs, "per_page").map(str::parse::<usize>) {
        Some(Ok(n)) if (1..=MAX_PER_PAGE).contains(&n) => n,
        _ => DEFAULT_PER_PAGE,
    };
    let per_page = inner.page_cap.map_or(per_page, |cap| per_page.min(cap));
    let page = match query(&pairs, "page").map(str::parse::<usize>) {
        Some(Ok(n)) if n >= 1 => n,
        _ => 1,
    };
    let sets: Vec<&Rrset> = inner
        .rrsets
        .iter()
        .filter(|r| r.zone_id == zone.id)
        .filter(|r| query(&pairs, "name").is_none_or(|n| n == r.name))
        .filter(|r| {
            let types: Vec<&str> = pairs
                .iter()
                .filter(|(k, _)| k == "type")
                .map(|(_, v)| v.as_str())
                .collect();
            types.is_empty() || types.contains(&r.rtype.as_str())
        })
        .collect();
    let total = sets.len();
    let last = total.div_ceil(per_page).max(1);
    let shown: Vec<Value> = sets
        .into_iter()
        .skip((page - 1) * per_page)
        .take(per_page)
        .map(rrset_json)
        .collect();
    let next = (page < last).then_some(page + 1);
    let previous = (page > 1).then_some(page - 1);
    axum::Json(json!({
        "rrsets": shown,
        "meta": {"pagination": {
            "page": page, "per_page": per_page, "previous_page": previous, "next_page": next,
            "last_page": next.map(|_| last),
            "total_entries": if inner.null_total { Value::Null } else { json!(total) },
        }}
    }))
    .into_response()
}

async fn rrset_create(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(key): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    let zone = match rrset_zone(&inner, &key) {
        Ok(zone) => zone,
        Err(response) => return response,
    };
    let body = match body_object(&body, &["name", "type", "ttl", "records", "labels"]) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (Some(name), Some(rtype)) = (
        body.get("name").and_then(Value::as_str),
        body.get("type").and_then(Value::as_str),
    ) else {
        return invalid("name and type are required");
    };
    let (name, rtype) = (name.to_owned(), rtype.to_owned());
    if let Err(response) = check_target(&zone, &name, &rtype) {
        return response;
    }
    if rtype == "SOA" {
        return invalid("SOA records are managed by the API");
    }
    // `records` must not be empty and its values distinct; the create states no maximum.
    let Some(list) = body.get("records").and_then(Value::as_array) else {
        return invalid("records is required");
    };
    if list.is_empty() {
        return invalid("records must not be empty");
    }
    let records = match parse_record_list(list) {
        Ok(records) => records,
        Err(response) => return response,
    };
    if let Err(response) = check_values(&rtype, &records) {
        return response;
    }
    let ttl = match parse_ttl(body.get("ttl"), true) {
        Ok(ttl) => ttl,
        Err(response) => return response,
    };
    let labels = match body.get("labels") {
        None => Vec::new(),
        Some(Value::Object(map)) => {
            let mut out = Vec::new();
            for (k, v) in map {
                let Some(v) = v.as_str() else {
                    return invalid("a label value must be a string");
                };
                out.push((k.clone(), v.to_owned()));
            }
            out
        }
        Some(_) => return invalid("labels must be an object"),
    };
    if find(&inner, zone.id, &name, &rtype).is_some() {
        return error(
            StatusCode::CONFLICT,
            "uniqueness_error",
            "an rrset with this name and type exists already",
        );
    }
    let rrset = Rrset {
        zone_id: zone.id,
        name,
        rtype,
        ttl,
        records,
        labels,
        protected: false,
    };
    let view = rrset_json(&rrset);
    let created = start_action(&mut inner, "create_rrset", zone.id, Change::Create(rrset));
    let Some(action) = action_view(&inner) else {
        return created;
    };
    (
        StatusCode::CREATED,
        axum::Json(json!({"rrset": view, "action": action})),
    )
        .into_response()
}

/// The view of the action created last, as `running`.
fn action_view(inner: &Inner) -> Option<Value> {
    let id = inner.next_action;
    inner
        .actions
        .get(&id)
        .map(|action| action_json(id, action, "running"))
}

async fn rrset_delete(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((key, name, rtype)): Path<(String, String, String)>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    let zone = match rrset_zone(&inner, &key) {
        Ok(zone) => zone,
        Err(response) => return response,
    };
    if let Err(response) = check_target(&zone, &name, &rtype) {
        return response;
    }
    let Some(set) = find(&inner, zone.id, &name, &rtype) else {
        return not_found("rrset not found");
    };
    if set.protected {
        return protected();
    }
    let change = Change::Delete {
        zone_id: zone.id,
        name,
        rtype,
    };
    start_action(&mut inner, "delete_rrset", zone.id, change)
}

async fn set_records(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((key, name, rtype)): Path<(String, String, String)>,
    body: axum::body::Bytes,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    let zone = match rrset_zone(&inner, &key) {
        Ok(zone) => zone,
        Err(response) => return response,
    };
    let body = match body_object(&body, &["records"]) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(response) = check_target(&zone, &name, &rtype) {
        return response;
    }
    let records = match parse_records(&body) {
        Ok(records) => records,
        Err(response) => return response,
    };
    if let Err(response) = check_values(&rtype, &records) {
        return response;
    }
    let Some(set) = find(&inner, zone.id, &name, &rtype) else {
        return not_found("rrset not found");
    };
    if set.protected {
        return protected();
    }
    let change = Change::Set {
        zone_id: zone.id,
        name,
        rtype,
        records,
    };
    start_action(&mut inner, "set_rrset_records", zone.id, change)
}

async fn change_ttl(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((key, name, rtype)): Path<(String, String, String)>,
    body: axum::body::Bytes,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    let zone = match rrset_zone(&inner, &key) {
        Ok(zone) => zone,
        Err(response) => return response,
    };
    let body = match body_object(&body, &["ttl"]) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(response) = check_target(&zone, &name, &rtype) {
        return response;
    }
    if body.get("ttl").is_none() {
        return invalid("ttl is required");
    }
    let ttl = match parse_ttl(body.get("ttl"), true) {
        Ok(ttl) => ttl,
        Err(response) => return response,
    };
    let Some(set) = find(&inner, zone.id, &name, &rtype) else {
        return not_found("rrset not found");
    };
    if set.protected {
        return protected();
    }
    let change = Change::Ttl {
        zone_id: zone.id,
        name,
        rtype,
        ttl,
    };
    start_action(&mut inner, "change_rrset_ttl", zone.id, change)
}

/// The records of an action body: 1 to 50 objects with a string `value` and an optional string
/// `comment`, no other key, distinct values.
fn parse_records(body: &Value) -> Result<Vec<StoredRecord>, Response> {
    let Some(list) = body.get("records").and_then(Value::as_array) else {
        return Err(invalid("records is required"));
    };
    if list.is_empty() || list.len() > MAX_RECORDS {
        return Err(invalid("records must hold 1 to 50 entries"));
    }
    parse_record_list(list)
}

/// Record objects with a string `value` and an optional string `comment`, no other key,
/// distinct values.
fn parse_record_list(list: &[Value]) -> Result<Vec<StoredRecord>, Response> {
    let mut out: Vec<StoredRecord> = Vec::new();
    for item in list {
        let Some(object) = item.as_object() else {
            return Err(invalid("a record must be an object"));
        };
        if object.keys().any(|k| k != "value" && k != "comment") {
            return Err(invalid("a record has an unknown property"));
        }
        let Some(value) = object.get("value").and_then(Value::as_str) else {
            return Err(invalid("a record needs a string value"));
        };
        let comment = match object.get("comment") {
            None => "",
            Some(Value::String(comment)) => comment,
            Some(_) => return Err(invalid("a comment must be a string")),
        };
        if out.iter().any(|r| r.value == value) {
            return Err(invalid("records must be distinct"));
        }
        out.push(StoredRecord {
            value: value.to_owned(),
            comment: comment.to_owned(),
        });
    }
    Ok(out)
}

/// The checks both actions share: a name as documented, a type of the enumeration.
fn check_target(zone: &Zone, name: &str, rtype: &str) -> Result<(), Response> {
    if name.is_empty()
        || name != name.to_lowercase()
        || name.ends_with('.')
        || name == zone.name
        || name.ends_with(&format!(".{}", zone.name))
    {
        return Err(invalid("invalid rrset name"));
    }
    if !TYPES.contains(&rtype) {
        return Err(invalid("unknown rrset type"));
    }
    Ok(())
}

fn start_action(
    inner: &mut Inner,
    command: &'static str,
    zone_id: u64,
    change: Change,
) -> Response {
    inner.next_action += 1;
    let id = inner.next_action;
    let error = inner.fail_next_action.take();
    inner.actions.insert(
        id,
        ActionState {
            command,
            zone_id,
            looks_left: inner.action_looks,
            change,
            error,
            finished: false,
        },
    );
    (
        StatusCode::CREATED,
        axum::Json(json!({"action": action_json(id, &inner.actions[&id], "running")})),
    )
        .into_response()
}

fn action_json(id: u64, action: &ActionState, status: &str) -> Value {
    let error = match (status, &action.error) {
        ("error", Some((code, message))) => json!({"code": code, "message": message}),
        _ => Value::Null,
    };
    json!({
        "id": id, "command": action.command, "status": status,
        "progress": if status == "running" { 50 } else { 100 },
        "started": "2026-01-01T00:00:00Z",
        "finished": if status == "running" { Value::Null } else { json!("2026-01-01T00:00:01Z") },
        "resources": [{"id": action.zone_id, "type": "zone"}],
        "error": error,
    })
}

async fn add_records(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((key, name, rtype)): Path<(String, String, String)>,
    body: axum::body::Bytes,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    let zone = match rrset_zone(&inner, &key) {
        Ok(zone) => zone,
        Err(response) => return response,
    };
    let Ok(body) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "json_error", "invalid JSON");
    };
    let Some(object) = body.as_object() else {
        return invalid("the body must be an object");
    };
    if object.keys().any(|k| k != "records" && k != "ttl") {
        return invalid("unknown property");
    }
    if let Err(response) = check_target(&zone, &name, &rtype) {
        return response;
    }
    let records = match parse_records(&body) {
        Ok(records) => records,
        Err(response) => return response,
    };
    let ttl = match body.get("ttl") {
        None | Some(Value::Null) => None,
        // Source: the documented range.
        Some(value) => match value
            .as_u64()
            .filter(|&t| (60..=2_147_483_647).contains(&t))
        {
            Some(ttl) => Some(ttl as u32),
            None => return invalid("ttl must be an integer from 60 to 2147483647"),
        },
    };
    if rtype == "TXT"
        && records
            .iter()
            .any(|r| !(r.value.len() >= 2 && r.value.starts_with('"') && r.value.ends_with('"')))
    {
        return invalid("a TXT value has to be quoted");
    }
    let existing = inner
        .rrsets
        .iter()
        .find(|r| r.zone_id == zone.id && r.name == name && r.rtype == rtype);
    if let Some(set) = existing {
        if set.protected {
            return protected();
        }
        if let (Some(asked), Some(have)) = (ttl, set.ttl)
            && asked != have
        {
            return invalid("the ttl differs from the ttl of the rrset");
        }
        if records
            .iter()
            .any(|r| set.records.iter().any(|have| have.value == r.value))
        {
            return error(
                StatusCode::CONFLICT,
                "uniqueness_error",
                "a record with this value exists already",
            );
        }
    }
    let change = Change::Add {
        zone_id: zone.id,
        name,
        rtype,
        ttl,
        records,
    };
    start_action(&mut inner, "add_rrset_records", zone.id, change)
}

async fn remove_records(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((key, name, rtype)): Path<(String, String, String)>,
    body: axum::body::Bytes,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    let zone = match rrset_zone(&inner, &key) {
        Ok(zone) => zone,
        Err(response) => return response,
    };
    let Ok(body) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "json_error", "invalid JSON");
    };
    let Some(object) = body.as_object() else {
        return invalid("the body must be an object");
    };
    if object.keys().any(|k| k != "records") {
        return invalid("unknown property");
    }
    if let Err(response) = check_target(&zone, &name, &rtype) {
        return response;
    }
    let records = match parse_records(&body) {
        Ok(records) => records,
        Err(response) => return response,
    };
    let Some(set) = inner
        .rrsets
        .iter()
        .find(|r| r.zone_id == zone.id && r.name == name && r.rtype == rtype)
    else {
        return not_found("rrset not found");
    };
    if set.protected {
        return protected();
    }
    // The value identifies the record: an exact comparison of the text.
    if records
        .iter()
        .any(|r| !set.records.iter().any(|have| have.value == r.value))
    {
        return invalid("a record to remove is not in the rrset");
    }
    let change = Change::Remove {
        zone_id: zone.id,
        name,
        rtype,
        values: records.into_iter().map(|r| r.value).collect(),
    };
    start_action(&mut inner, "remove_rrset_records", zone.id, change)
}

/// Applies the change of a finished action.
fn apply(inner: &mut Inner, change: Change) {
    match change {
        Change::Add {
            zone_id,
            name,
            rtype,
            ttl,
            records,
        } => {
            if let Some(set) = inner
                .rrsets
                .iter_mut()
                .find(|r| r.zone_id == zone_id && r.name == name && r.rtype == rtype)
            {
                set.records.extend(records);
                if set.ttl.is_none() {
                    set.ttl = ttl;
                }
            } else {
                inner.rrsets.push(Rrset {
                    zone_id,
                    name,
                    rtype,
                    ttl,
                    records,
                    labels: Vec::new(),
                    protected: false,
                });
            }
        }
        Change::Create(rrset) => {
            inner.rrsets.retain(|r| {
                !(r.zone_id == rrset.zone_id && r.name == rrset.name && r.rtype == rrset.rtype)
            });
            inner.rrsets.push(rrset);
        }
        Change::Set {
            zone_id,
            name,
            rtype,
            records,
        } => {
            if let Some(set) = find_mut(inner, zone_id, &name, &rtype) {
                set.records = records;
            }
        }
        Change::Ttl {
            zone_id,
            name,
            rtype,
            ttl,
        } => {
            if let Some(set) = find_mut(inner, zone_id, &name, &rtype) {
                set.ttl = ttl;
            }
        }
        Change::Delete {
            zone_id,
            name,
            rtype,
        } => {
            inner
                .rrsets
                .retain(|r| !(r.zone_id == zone_id && r.name == name && r.rtype == rtype));
        }
        Change::Remove {
            zone_id,
            name,
            rtype,
            values,
        } => {
            for set in inner
                .rrsets
                .iter_mut()
                .filter(|r| r.zone_id == zone_id && r.name == name && r.rtype == rtype)
            {
                set.records.retain(|r| !values.contains(&r.value));
            }
            inner.rrsets.retain(|r| !r.records.is_empty());
        }
    }
}

async fn action_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    let Some(id) = id
        .parse::<u64>()
        .ok()
        .filter(|id| inner.actions.contains_key(id))
    else {
        return not_found("action not found");
    };
    let Some(action) = inner.actions.get_mut(&id) else {
        return not_found("action not found");
    };
    if !action.finished {
        action.looks_left = action.looks_left.saturating_sub(1);
        if action.looks_left > 0 {
            let view = action_json(id, action, "running");
            return axum::Json(json!({"action": view})).into_response();
        }
        action.finished = true;
        if action.error.is_none() {
            let change = action.change.clone();
            apply(&mut inner, change);
        }
    }
    let Some(action) = inner.actions.get(&id) else {
        return not_found("action not found");
    };
    let status = if action.error.is_some() {
        "error"
    } else {
        "success"
    };
    axum::Json(json!({"action": action_json(id, action, status)})).into_response()
}
