//! Mock of Azure DNS: the Azure Resource Manager REST API for public DNS zones
//! (`Microsoft.Network/dnsZones`, API version `2018-05-01`) and the token endpoint of the
//! Microsoft identity platform (client credentials grant with a client secret).
//!
//! Sources, read 2026-11-16: the Azure DNS REST reference for `2018-05-01`
//! (<https://learn.microsoft.com/en-us/rest/api/dns/>: Record Sets Create Or Update, Get, Delete,
//! List By DNS Zone; Zones Get, List By Resource Group), the Azure DNS overview of zones and
//! records (<https://learn.microsoft.com/en-us/azure/dns/dns-zones-records>), the Azure DNS FAQ,
//! the Azure DNS limits (<https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits>),
//! Resource Manager throttling
//! (<https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling>),
//! the client credentials flow
//! (<https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow>),
//! the Go SDK `armdns` v1.2.0 and lego `providers/dns/azuredns/`.
//!
//! What the documentation says and the mock does:
//!
//! - one server for both hosts: the token endpoint `POST /{tenant}/oauth2/v2.0/token` (the
//!   client's `login_url` is [`AzureDnsMock::login_url`]) and Resource Manager below `/`
//!   ([`AzureDnsMock::management_url`]); every Resource Manager call needs
//!   `Authorization: Bearer <token>` with a token the endpoint issued, and
//!   `api-version=2018-05-01`;
//! - the token request is a form with `client_id`, `client_secret`, `scope` and
//!   `grant_type=client_credentials`; the answer is `{"token_type": "Bearer", "expires_in": …,
//!   "access_token": …}`; a scope the seed does not accept is `400` with `invalid_scope`;
//! - zones of one subscription and resource group: `GET …/dnsZones` (a page of `value` with
//!   `nextLink`) and `GET …/dnsZones/{zone}`; a new zone gets an SOA and an NS record set at `@`
//!   (TTL 3600) with the seed's name servers;
//! - record sets addressed by zone, type and relative name (`@` at the apex): `GET`, `PUT` (`201`
//!   created, `200` updated, the whole record set replaced), `DELETE` (`200` deleted, `204` not
//!   found), `GET …/recordsets` (a page of `value` with `nextLink`, at most
//!   [`Seed::page_size`] items, 100 unless set); each record set has an `etag` that changes with
//!   every write; `If-Match: <etag>` or `*` and `If-None-Match: *` make a `PUT` conditional,
//!   `If-Match` a `DELETE`;
//! - the per-type properties and objects of the reference (`ARecords`, `caaRecords`,
//!   `CNAMERecord`, …), `TTL`, `metadata` and `targetResource` (an alias, for A, AAAA and CNAME
//!   only); `fqdn` and `provisioningState` in answers;
//! - refused (the documentation says what is not allowed, not with which status; see below): a
//!   type outside the API version's enumeration, a TTL outside 1 to 2147483647, a create of an
//!   SOA record set, a change of the SOA host, a delete of the SOA record set, a CNAME at the
//!   apex, a CNAME next to another record set at its name and the reverse, an apex NS record set
//!   without the zone's name servers, more than 20 records in a record set (400 in a TXT record
//!   set), a TXT string longer than 255 characters, TXT strings longer than 4096 characters in
//!   all in one record set, a CAA tag other than `issue`, `issuewild` and `iodef`;
//! - Resource Manager throttling: `429` with `Retry-After` ([`Control::set_throttled`]), and
//!   `429` with the code `RetryableErrorDueToAnotherOperation` while another operation holds the
//!   resource ([`Control::set_locked`]).
//!
//! What the mock invents because the documentation is silent, chosen so that a client cannot
//! rely on a lenient reading:
//!
//! - every status of a refusal other than the token endpoint's `400 invalid_scope` and the
//!   throttling `429`: the refusals listed above are `400` with the code `BadRequest`, except a
//!   CNAME next to another record set (and the reverse), which is `409` with `Conflict`;
//! - every error body is a `CloudError` (`{"error": {"code", "message"}}`) with invented codes
//!   and texts; the token endpoint's errors are `{"error", "error_description", "error_codes"}`
//!   with invented `AADSTS` numbers;
//! - a failed `If-Match` or `If-None-Match` is `412` with the code `PreconditionFailed` unless
//!   [`Control::set_failed_condition`] sets another status and code; the etag of a condition is
//!   compared byte for byte with the stored one, quotes and a `W/` prefix included; an `etag`
//!   member in a `PUT` body is ignored;
//! - a `DELETE` with `If-Match` of a record set that does not exist is `204`, as without it;
//! - a `GET` of a missing record set or zone is `404`; so is any call naming another
//!   subscription or resource group, or a zone the group does not hold;
//! - a request without a token the endpoint issued is `401` with `InvalidAuthenticationToken`;
//!   [`Control::expire_tokens`] makes every issued token invalid; a wrong client ID or secret is
//!   `401` with `invalid_client`, another tenant `400` with `invalid_request`; only the scopes of
//!   [`Seed::scopes`] are accepted (the standard seed: the double-slash form the documentation
//!   prescribes for Resource Manager, and no other);
//! - a missing or other `api-version` is `400`;
//! - a `PUT` without `TTL` is `400`; so is a body member other than `etag` and `properties`, a
//!   property the reference does not list as writable (`fqdn` and `provisioningState`
//!   included), the record property of another type (also an empty one), records next to a
//!   `targetResource`, and a record object with a member its definition does not have; an empty
//!   record list is accepted;
//! - the lock answer ([`Control::set_locked`]) carries `Retry-After`;
//! - a record set name is stored lowercase; a wildcard name arrives percent-encoded in a path
//!   (`%2A`) and is decoded before the record set is looked up, as a web framework decodes a
//!   path segment;
//! - the etags are GUID-shaped counters ([`Control::set_etag`] sets any other); tokens are
//!   `azure-mock-token-<n>`; `$skipToken` is the offset of the next page, and `nextLink` an
//!   absolute URL on the host the request named ([`Control::set_link_base`] names another);
//!   [`Control::set_paging`] makes the listings page in ways the documentation does not exclude
//!   ([`Paging`]), for tests of a client's end rule;
//! - the zone's name servers and the SOA contact are names under `example` domains (the seed's
//!   [`Seed::name_servers`]), not the provider's;
//! - the published form of a TXT record is its strings quoted, `"` and `\` escaped, joined with
//!   a space; names in records are published with a trailing dot added.
//!
//! Not modeled: zone creation and deletion through the API, `PATCH`, `$top` and
//! `$recordsetnamesuffix`, listing by type, private zones, record set limits per zone,
//! `metadata` validation, DNSSEC and the preview API versions, the rate limits themselves beyond
//! the throttled answer, and every other way to authenticate.
//!
//! The mock is a [`ChangeSource`]: it reports every change of its published records (every
//! record set of every zone, except aliases, whose answer comes from the target resource the
//! mock does not hold, and the SOA record set, which the server that serves the zone answers
//! with its own) through [`AzureDnsMock::changes`], and a
//! [`link`](crate::link::link) serves them over DNS. [`Control::reset`] returns the mock to its
//! seed.

// Handlers return finished HTTP answers as their error values and hand them straight to axum;
// boxing them would only add noise.
#![allow(clippy::result_large_err)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Map, Value, json};

use crate::MockServer;
use crate::changes::{ChangeSource, Changes, Origin, Published};

/// The API version the mock serves.
pub const API_VERSION: &str = "2018-05-01";

/// The largest TTL.
const TTL_MAX: u64 = 2_147_483_647;

/// The most records of a record set, and of a TXT record set.
const MAX_RECORDS: usize = 20;
const MAX_TXT_RECORDS: usize = 400;

/// The longest TXT string, and all TXT strings of a record set together.
const STRING_MAX: usize = 255;
const TXT_TOTAL_MAX: usize = 4096;

/// The record properties, one per type.
const RECORD_KEYS: &[&str] = &[
    "ARecords",
    "AAAARecords",
    "caaRecords",
    "CNAMERecord",
    "MXRecords",
    "NSRecords",
    "PTRRecords",
    "SOARecord",
    "SRVRecords",
    "TXTRecords",
];

/// The property holding the records of `rtype`, and whether it is one object.
fn record_key(rtype: &str) -> Option<(&'static str, bool)> {
    Some(match rtype {
        "A" => ("ARecords", false),
        "AAAA" => ("AAAARecords", false),
        "CAA" => ("caaRecords", false),
        "CNAME" => ("CNAMERecord", true),
        "MX" => ("MXRecords", false),
        "NS" => ("NSRecords", false),
        "PTR" => ("PTRRecords", false),
        "SOA" => ("SOARecord", true),
        "SRV" => ("SRVRecords", false),
        "TXT" => ("TXTRecords", false),
        _ => return None,
    })
}

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The tenant of the service principal.
    pub tenant_id: String,
    /// The application (client) ID.
    pub client_id: String,
    /// The client secret the token endpoint accepts.
    pub client_secret: String,
    /// The scopes the token endpoint accepts.
    pub scopes: Vec<String>,
    /// The subscription that holds the resource group.
    pub subscription_id: String,
    /// The resource group that holds the zones.
    pub resource_group: String,
    /// Zones, without the trailing dot.
    pub zones: Vec<String>,
    /// The largest page of a listing.
    pub page_size: usize,
    /// `expires_in` of an issued token, in seconds.
    pub token_lifetime: u64,
    /// The name servers of a new zone (its apex NS record set and SOA host).
    pub name_servers: Vec<String>,
}

impl Seed {
    /// The tenant `test-tenant.example`, the client `zw-test-client` with the secret
    /// `test-only-secret`, the scope `https://management.azure.com//.default`, the subscription
    /// `00000000-0000-0000-0000-000000000001` with the resource group `zw-test-rg` holding
    /// `example.org`, pages of 100, tokens of 3599 seconds, and the name servers
    /// `ns1.dns-one.example` to `ns4.dns-four.example` (synthetic names in the reserved
    /// `example` domain, shaped like the four name servers the provider assigns).
    pub fn standard() -> Self {
        Self {
            tenant_id: "test-tenant.example".into(),
            client_id: "zw-test-client".into(),
            client_secret: "test-only-secret".into(),
            scopes: vec!["https://management.azure.com//.default".into()],
            subscription_id: "00000000-0000-0000-0000-000000000001".into(),
            resource_group: "zw-test-rg".into(),
            zones: vec!["example.org".into()],
            page_size: 100,
            token_lifetime: 3599,
            name_servers: vec![
                "ns1.dns-one.example".into(),
                "ns2.dns-two.example".into(),
                "ns3.dns-three.example".into(),
                "ns4.dns-four.example".into(),
            ],
        }
    }
}

/// A record set as the mock holds it, in the API's own form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordSet {
    /// The zone, without the trailing dot.
    pub zone: String,
    /// The name relative to the zone, lowercase; `@` at the apex.
    pub name: String,
    /// The record type.
    pub rtype: String,
    /// The etag; it changes with every write.
    pub etag: String,
    /// The writable properties: `TTL`, `metadata`, `targetResource` and the record property of
    /// the type.
    pub properties: Map<String, Value>,
}

impl RecordSet {
    /// The owner name, fully qualified, without the trailing dot.
    pub fn fqdn(&self) -> String {
        owner(&self.zone, &self.name)
    }

    /// `TTL`, if it is a number.
    pub fn ttl(&self) -> Option<u64> {
        self.properties.get("TTL").and_then(Value::as_u64)
    }

    /// The record objects of the type: the list, or the one object of CNAME and SOA.
    pub fn records(&self) -> Vec<Value> {
        let Some((key, _)) = record_key(&self.rtype) else {
            return Vec::new();
        };
        match self.properties.get(key) {
            Some(Value::Array(items)) => items.clone(),
            Some(object @ Value::Object(_)) => vec![object.clone()],
            _ => Vec::new(),
        }
    }

    /// An alias: `targetResource` with an `id`.
    pub fn is_alias(&self) -> bool {
        self.properties
            .get("targetResource")
            .and_then(|t| t.get("id"))
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty())
    }
}

/// How a listing pages: the documented reading and readings a client must not loop on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Paging {
    /// As documented: `$skipToken` is honored, and `nextLink` leads to the following page.
    #[default]
    Documented,
    /// `$skipToken` is ignored: every request answers the first page, with a `nextLink`.
    IgnoreToken,
    /// The `nextLink` of every page after the first carries the `$skipToken` of the request
    /// itself: the second page is served, and the token does not advance from there.
    RepeatToken,
    /// The `nextLink` carries no `$skipToken`.
    NoTokenInLink,
    /// After the last item, one more page: empty, without a `nextLink`.
    EmptyLastPage,
    /// Between two pages of items, an empty page whose `nextLink` leads to the next page of
    /// items: the end is only where no `nextLink` is.
    EmptyPageBetween,
}

#[derive(Debug)]
struct Inner {
    original: Seed,
    seed: Seed,
    zones: Vec<String>,
    sets: Vec<RecordSet>,
    tokens: Vec<String>,
    issued: u64,
    etags: u64,
    paging: Paging,
    throttled: Option<u32>,
    locked: Option<u32>,
    failed_condition: (u16, String),
    link_base: Option<String>,
    changes: Changes,
}

impl Inner {
    fn new(seed: Seed, changes: Changes) -> Inner {
        let mut inner = Inner {
            original: seed.clone(),
            seed: seed.clone(),
            zones: Vec::new(),
            sets: Vec::new(),
            tokens: Vec::new(),
            issued: 0,
            etags: 0,
            paging: Paging::Documented,
            throttled: None,
            locked: None,
            failed_condition: (412, "PreconditionFailed".into()),
            link_base: None,
            changes,
        };
        for zone in &seed.zones {
            inner.add_zone(zone);
        }
        inner
    }

    fn etag(&mut self) -> String {
        self.etags += 1;
        format!("00000000-0000-0000-0000-{:012x}", self.etags)
    }

    fn add_zone(&mut self, name: &str) {
        let zone = plain(name);
        if self.zones.contains(&zone) {
            return;
        }
        self.zones.push(zone.clone());
        let host = self
            .seed
            .name_servers
            .first()
            .cloned()
            .unwrap_or_else(|| "ns1.dns-one.example".into());
        let soa = json!({
            "TTL": 3600,
            "SOARecord": {
                "host": host,
                "email": "hostmaster.dns-one.example",
                "serialNumber": 1,
                "refreshTime": 3600,
                "retryTime": 300,
                "expireTime": 2_419_200,
                "minimumTTL": 300,
            },
        });
        let ns: Vec<Value> = self
            .seed
            .name_servers
            .iter()
            .map(|ns| json!({ "nsdname": ns }))
            .collect();
        let ns = json!({ "TTL": 172_800, "NSRecords": ns });
        for (rtype, properties) in [("SOA", soa), ("NS", ns)] {
            let etag = self.etag();
            if let Value::Object(properties) = properties {
                self.sets.push(RecordSet {
                    zone: zone.clone(),
                    name: "@".into(),
                    rtype: rtype.into(),
                    etag,
                    properties,
                });
            }
        }
    }

    /// What a DNS server for the mock's zones would answer: every record set of every zone,
    /// except aliases and the SOA record set.
    fn published(&self) -> Published {
        let mut out = Published::new();
        for zone in &self.zones {
            out.zone(zone);
        }
        for set in &self.sets {
            if set.is_alias() || set.rtype == "SOA" {
                continue;
            }
            let values: Vec<String> = set
                .records()
                .iter()
                .filter_map(|r| presentation(&set.rtype, r))
                .collect();
            let ttl = set.ttl().and_then(|t| u32::try_from(t).ok());
            out.rrset(
                &set.zone,
                &format!("{}.", set.fqdn()),
                &set.rtype,
                ttl,
                values,
            );
        }
        out
    }

    fn report(&self, before: &Published, origin: Origin) {
        self.changes.emit_diff(before, &self.published(), origin);
    }

    fn find(&self, zone: &str, name: &str, rtype: &str) -> Option<usize> {
        self.sets
            .iter()
            .position(|s| s.zone == zone && s.name == name && s.rtype == rtype)
    }

    fn find_fqdn(&self, fqdn: &str, rtype: &str) -> Option<usize> {
        let fqdn = plain(fqdn);
        self.sets
            .iter()
            .position(|s| s.fqdn() == fqdn && s.rtype == rtype)
    }

    fn zone_of(&self, fqdn: &str) -> Option<String> {
        let fqdn = plain(fqdn);
        self.zones
            .iter()
            .filter(|z| relative(&fqdn, z).is_some())
            .max_by_key(|z| z.len())
            .cloned()
    }
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Reads and changes the state of a mock. Cheap to clone, so that a fault hook
/// ([`Fault::run`](crate::Fault::run)) can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
    changes: Changes,
    server: Arc<ServerParts>,
}

/// The request log and the fault queue of the server, for [`Control::reset`].
#[derive(Debug)]
struct ServerParts {
    log: crate::RequestLog,
    faults: crate::Faults,
}

/// A running Azure DNS mock. Dereferences to its [`MockServer`] for the request log and the
/// fault queue; [`AzureDnsMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct AzureDnsMock {
    server: MockServer,
    control: Control,
}

impl Deref for AzureDnsMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl AzureDnsMock {
    /// Starts the mock with `seed` on `127.0.0.1` with an ephemeral port.
    pub async fn start(seed: Seed) -> Self {
        Self::start_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), seed).await
    }

    /// Starts the mock with `seed` on `addr` ([`MockServer::start_on`]). On an address other than
    /// loopback, for an isolated test network only.
    pub async fn start_on(addr: SocketAddr, seed: Seed) -> Self {
        let changes = Changes::new();
        let state = Arc::new(Mutex::new(Inner::new(seed, changes.clone())));
        let zones = "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/dnsZones";
        let router = Router::new()
            .route("/{tenant}/oauth2/v2.0/token", post(token))
            .route(zones, get(zones_list))
            .route(&format!("{zones}/{{zone}}"), get(zone_get))
            .route(&format!("{zones}/{{zone}}/recordsets"), get(sets_list))
            .route(
                &format!("{zones}/{{zone}}/{{rtype}}/{{name}}"),
                get(set_get).put(set_put).delete(set_delete),
            )
            .with_state(state.clone());
        let server = MockServer::start_on(addr, router).await;
        let control = Control {
            state,
            changes,
            server: Arc::new(ServerParts {
                log: server.log().clone(),
                faults: server.faults().clone(),
            }),
        };
        Self { server, control }
    }

    /// The identity platform host, for the client's `login_url`.
    pub fn login_url(&self) -> String {
        self.server.url("")
    }

    /// The Resource Manager endpoint, for the client's `management_url`.
    pub fn management_url(&self) -> String {
        self.server.url("")
    }

    /// The state control.
    pub fn control(&self) -> &Control {
        &self.control
    }
}

impl ChangeSource for AzureDnsMock {
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

    /// Returns the mock to the seed it was started with: its zones with their SOA and NS record
    /// sets, no other record set, no issued token, documented paging, no throttling, an empty
    /// request log and no pending faults. Reports the removal of every record set that was
    /// published.
    pub fn reset(&self) {
        self.server.faults.clear();
        self.change(|inner| {
            let seed = inner.original.clone();
            *inner = Inner::new(seed, inner.changes.clone());
        });
        self.server.log.clear();
    }

    /// Every zone.
    pub fn zones(&self) -> Vec<String> {
        lock(&self.state).zones.clone()
    }

    /// Adds a zone with its SOA and NS record sets.
    pub fn insert_zone(&self, name: &str) {
        self.change(|inner| inner.add_zone(name));
    }

    /// Removes zone `name` and its record sets.
    pub fn remove_zone(&self, name: &str) {
        let name = plain(name);
        self.change(|inner| {
            inner.zones.retain(|z| *z != name);
            inner.sets.retain(|s| s.zone != name);
        });
    }

    /// How listings page from now on ([`Paging`]).
    pub fn set_paging(&self, paging: Paging) {
        lock(&self.state).paging = paging;
    }

    /// The largest page of a listing from now on.
    pub fn set_page_size(&self, size: usize) {
        lock(&self.state).seed.page_size = size;
    }

    /// With `Some(seconds)`, every Resource Manager request is answered `429 Too Many Requests`
    /// with `Retry-After: <seconds>` until this is called with `None`.
    pub fn set_throttled(&self, retry_after: Option<u32>) {
        lock(&self.state).throttled = retry_after;
    }

    /// With `Some(seconds)`, every `PUT` and `DELETE` of a record set is answered `429` with the
    /// code `RetryableErrorDueToAnotherOperation` and `Retry-After: <seconds>` until this is
    /// called with `None`.
    pub fn set_locked(&self, retry_after: Option<u32>) {
        lock(&self.state).locked = retry_after;
    }

    /// The status and code of the answer to a failed `If-Match` or `If-None-Match` from now on;
    /// `412` with `PreconditionFailed` unless set. The documentation gives neither.
    ///
    /// # Panics
    ///
    /// If `status` is not a valid status code.
    pub fn set_failed_condition(&self, status: u16, code: &str) {
        assert!(
            StatusCode::from_u16(status).is_ok(),
            "invalid status code {status}"
        );
        lock(&self.state).failed_condition = (status, code.to_owned());
    }

    /// With `Some(origin)` (such as `http://127.0.0.1:8080`), every `nextLink` names that origin
    /// instead of the host the request named, until this is called with `None`.
    pub fn set_link_base(&self, origin: Option<&str>) {
        lock(&self.state).link_base = origin.map(|o| o.trim_end_matches('/').to_owned());
    }

    /// Sets the etag of the record set of `name` and `rtype` to `etag` exactly, as a service
    /// spelling its etags otherwise would; reports nothing, since nothing published changes.
    ///
    /// # Panics
    ///
    /// If there is no such record set.
    pub fn set_etag(&self, name: &str, rtype: &str, etag: &str) {
        let mut inner = lock(&self.state);
        let at = inner
            .find_fqdn(name, rtype)
            .unwrap_or_else(|| panic!("no record set {name} {rtype}"));
        inner.sets[at].etag = etag.to_owned();
    }

    /// Makes every issued token invalid: the next request with one is `401`.
    pub fn expire_tokens(&self) {
        lock(&self.state).tokens.clear();
    }

    /// The number of tokens the endpoint has issued.
    pub fn tokens_issued(&self) -> u64 {
        lock(&self.state).issued
    }

    /// Every record set.
    pub fn rrsets(&self) -> Vec<RecordSet> {
        lock(&self.state).sets.clone()
    }

    /// The record set of owner `name` (fully qualified, with or without the trailing dot) and
    /// `rtype`, if any.
    pub fn rrset(&self, name: &str, rtype: &str) -> Option<RecordSet> {
        let inner = lock(&self.state);
        inner
            .find_fqdn(name, rtype)
            .map(|at| inner.sets[at].clone())
    }

    /// The strings of every TXT record at `name`, in order; empty when there is no TXT record
    /// set.
    pub fn txt(&self, name: &str) -> Vec<Vec<String>> {
        self.rrset(name, "TXT")
            .map(|set| {
                set.records()
                    .iter()
                    .map(|r| {
                        r.get("value")
                            .and_then(Value::as_array)
                            .map(|v| {
                                v.iter()
                                    .map(|s| s.as_str().unwrap_or_default().to_owned())
                                    .collect()
                            })
                            .unwrap_or_default()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Creates the record set of `name` and `rtype` directly, as another writer would, with
    /// `records` (the value of the type's record property: a list, or one object for CNAME and
    /// SOA) stored as given (unchecked), or replaces the records and the TTL of the one there.
    /// The etag changes.
    ///
    /// # Panics
    ///
    /// If no zone holds `name`, or `rtype` is not a type of the API version.
    pub fn insert_rrset(&self, name: &str, rtype: &str, ttl: u64, records: Value) {
        let (key, _) = record_key(rtype).unwrap_or_else(|| panic!("no type {rtype}"));
        self.upsert(name, rtype, |properties| {
            properties.insert("TTL".into(), Value::from(ttl));
            properties.insert(key.into(), records);
        });
    }

    /// Creates an alias record set at `name` of `rtype` pointing at the Azure resource
    /// `target_id`, as another writer would.
    ///
    /// # Panics
    ///
    /// If no zone holds `name`.
    pub fn insert_alias(&self, name: &str, rtype: &str, ttl: u64, target_id: &str) {
        self.upsert(name, rtype, |properties| {
            properties.insert("TTL".into(), Value::from(ttl));
            properties.insert("targetResource".into(), json!({ "id": target_id }));
        });
    }

    fn upsert(&self, name: &str, rtype: &str, f: impl FnOnce(&mut Map<String, Value>)) {
        self.change(|inner| {
            let zone = inner
                .zone_of(name)
                .unwrap_or_else(|| panic!("no zone holds {name}"));
            let fqdn = plain(name);
            let rel = match relative(&fqdn, &zone) {
                Some("") | None => "@".to_owned(),
                Some(rel) => rel.to_owned(),
            };
            let etag = inner.etag();
            match inner.find(&zone, &rel, rtype) {
                Some(at) => {
                    f(&mut inner.sets[at].properties);
                    inner.sets[at].etag = etag;
                }
                None => {
                    let mut properties = Map::new();
                    f(&mut properties);
                    inner.sets.push(RecordSet {
                        zone,
                        name: rel,
                        rtype: rtype.to_owned(),
                        etag,
                        properties,
                    });
                }
            }
        });
    }

    /// Changes the record set of `name` and `rtype` with `f`, as another writer would; the etag
    /// changes.
    ///
    /// # Panics
    ///
    /// If there is no such record set.
    pub fn edit_rrset(&self, name: &str, rtype: &str, f: impl FnOnce(&mut RecordSet)) {
        self.change(|inner| {
            let at = inner
                .find_fqdn(name, rtype)
                .unwrap_or_else(|| panic!("no record set {name} {rtype}"));
            let etag = inner.etag();
            f(&mut inner.sets[at]);
            inner.sets[at].etag = etag;
        });
    }

    /// Deletes the record set of `name` and `rtype` directly, as another writer would.
    pub fn delete_rrset(&self, name: &str, rtype: &str) {
        self.change(|inner| {
            if let Some(at) = inner.find_fqdn(name, rtype) {
                inner.sets.remove(at);
            }
        });
    }
}

/// `name` lowercase without a trailing dot.
fn plain(name: &str) -> String {
    let name = name.trim().to_lowercase();
    name.strip_suffix('.').map(str::to_owned).unwrap_or(name)
}

/// The owner of `name` (relative, `@` the apex) in `zone`, without the trailing dot.
fn owner(zone: &str, name: &str) -> String {
    if name == "@" || name.is_empty() {
        zone.to_owned()
    } else {
        format!("{name}.{zone}")
    }
}

/// `name` relative to `zone`; `""` for the zone itself, `None` outside it.
fn relative<'a>(name: &'a str, zone: &str) -> Option<&'a str> {
    if name == zone {
        return Some("");
    }
    name.strip_suffix(zone)?.strip_suffix('.')
}

/// A `CloudError` answer.
fn cloud_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        axum::Json(json!({ "error": { "code": code, "message": message } })),
    )
        .into_response()
}

fn bad_request(message: &str) -> Response {
    cloud_error(StatusCode::BAD_REQUEST, "BadRequest", message)
}

/// An identity platform error answer.
fn identity_error(status: StatusCode, error: &str, number: u32, text: &str) -> Response {
    (
        status,
        axum::Json(json!({
            "error": error,
            "error_description": format!("AADSTS{number}: {text}"),
            "error_codes": [number],
            "timestamp": "2026-01-01 00:00:00Z",
            "trace_id": "00000000-0000-0000-0000-000000000000",
            "correlation_id": "00000000-0000-0000-0000-000000000000",
        })),
    )
        .into_response()
}

async fn token(
    State(state): State<Shared>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"));
    if !form_type {
        return identity_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            900_144,
            "The request body must be form-encoded.",
        );
    }
    let Ok(pairs) = serde_urlencoded_pairs(&body) else {
        return identity_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            900_144,
            "The request body could not be read.",
        );
    };
    let field = |key: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    if let Some((key, _)) = pairs.iter().find(|(k, _)| {
        !matches!(
            k.as_str(),
            "client_id" | "client_secret" | "scope" | "grant_type"
        )
    }) {
        return identity_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            900_144,
            &format!("The request has an unknown parameter '{key}'."),
        );
    }
    let mut inner = lock(&state);
    if tenant != inner.seed.tenant_id {
        return identity_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            90_002,
            "Tenant not found.",
        );
    }
    if field("grant_type") != Some("client_credentials") {
        return identity_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            70_003,
            "The grant type is not supported.",
        );
    }
    if field("client_id") != Some(inner.seed.client_id.as_str())
        || field("client_secret") != Some(inner.seed.client_secret.as_str())
    {
        return identity_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            7_000_215,
            "Invalid client secret provided.",
        );
    }
    let scope_ok = field("scope").is_some_and(|scope| inner.seed.scopes.iter().any(|s| s == scope));
    if !scope_ok {
        return identity_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            70_011,
            "The provided value for the input parameter 'scope' is not valid.",
        );
    }
    inner.issued += 1;
    let token = format!("azure-mock-token-{}", inner.issued);
    inner.tokens.push(token.clone());
    let lifetime = inner.seed.token_lifetime;
    axum::Json(json!({
        "token_type": "Bearer",
        "expires_in": lifetime,
        "ext_expires_in": lifetime,
        "access_token": token,
    }))
    .into_response()
}

/// The pairs of a form body.
fn serde_urlencoded_pairs(body: &[u8]) -> Result<Vec<(String, String)>, ()> {
    let text = std::str::from_utf8(body).map_err(drop)?;
    let mut out = Vec::new();
    for pair in text.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        out.push((form_decode(key)?, form_decode(value)?));
    }
    Ok(out)
}

/// Decodes one form component: `+` is a space, `%XX` a byte.
fn form_decode(text: &str) -> Result<String, ()> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = bytes.get(at + 1..at + 3).ok_or(())?;
                let hex = std::str::from_utf8(hex).map_err(drop)?;
                out.push(u8::from_str_radix(hex, 16).map_err(drop)?);
                at += 2;
            }
            b => out.push(b),
        }
        at += 1;
    }
    String::from_utf8(out).map_err(drop)
}

/// Checks the throttle, the token, the API version, the subscription and the resource group.
fn admit(
    inner: &Inner,
    headers: &HeaderMap,
    pairs: &[(String, String)],
    sub: &str,
    rg: &str,
) -> Result<(), Response> {
    if let Some(wait) = inner.throttled {
        let mut response = cloud_error(
            StatusCode::TOO_MANY_REQUESTS,
            "SubscriptionRequestsThrottled",
            &format!(
                "The request for subscription '{sub}' could not be processed due to an \
                 excessive volume of traffic. Please try again later."
            ),
        );
        response
            .headers_mut()
            .insert("retry-after", HeaderValue::from(wait));
        return Err(response);
    }
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if !token.is_some_and(|t| inner.tokens.iter().any(|known| known == t)) {
        return Err(cloud_error(
            StatusCode::UNAUTHORIZED,
            "InvalidAuthenticationToken",
            "The access token is invalid.",
        ));
    }
    match query(pairs, "api-version") {
        Some(API_VERSION) => {}
        Some(_) => {
            return Err(bad_request("The api-version is not supported."));
        }
        None => {
            return Err(cloud_error(
                StatusCode::BAD_REQUEST,
                "MissingApiVersionParameter",
                "The api-version query parameter is required.",
            ));
        }
    }
    if sub != inner.seed.subscription_id || rg != inner.seed.resource_group {
        return Err(cloud_error(
            StatusCode::NOT_FOUND,
            "ResourceGroupNotFound",
            "Resource group could not be found.",
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

fn zone_missing() -> Response {
    cloud_error(
        StatusCode::NOT_FOUND,
        "ParentResourceNotFound",
        "The DNS zone could not be found.",
    )
}

/// The path of the resource group's zones.
fn zones_path(inner: &Inner) -> String {
    format!(
        "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones",
        inner.seed.subscription_id, inner.seed.resource_group
    )
}

/// One page of `all` by the request's `$skipToken`, with `nextLink` (module documentation).
fn listing(
    inner: &Inner,
    headers: &HeaderMap,
    path: &str,
    pairs: &[(String, String)],
    all: Vec<Value>,
) -> Response {
    let size = inner.seed.page_size.max(1);
    let token = query(pairs, "$skipToken");
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1");
    let origin = inner
        .link_base
        .clone()
        .unwrap_or_else(|| format!("http://{host}"));
    let base = format!("{origin}{path}?api-version={API_VERSION}");
    // An empty page between two pages of items (`Paging::EmptyPageBetween`).
    if let Some(at) = token.and_then(|t| t.strip_prefix('e')) {
        let Ok(at) = at.parse::<usize>() else {
            return bad_request("The skip token is not valid.");
        };
        return axum::Json(json!({
            "value": [],
            "nextLink": format!("{base}&$skipToken={at}"),
        }))
        .into_response();
    }
    let offset = match (inner.paging, token) {
        (Paging::IgnoreToken, _) | (_, None) => 0,
        (_, Some(token)) => match token.parse::<usize>() {
            Ok(offset) => offset,
            Err(_) => return bad_request("The skip token is not valid."),
        },
    };
    let total = all.len();
    let items: Vec<Value> = all.into_iter().skip(offset).take(size).collect();
    let after = offset.saturating_add(size);
    let next = if after < total {
        Some(match (inner.paging, token) {
            (Paging::RepeatToken, Some(t)) => format!("{base}&$skipToken={t}"),
            (Paging::NoTokenInLink, _) => base.clone(),
            (Paging::EmptyPageBetween, _) => format!("{base}&$skipToken=e{after}"),
            _ => format!("{base}&$skipToken={after}"),
        })
    } else if inner.paging == Paging::EmptyLastPage && offset < total {
        Some(format!("{base}&$skipToken={after}"))
    } else {
        None
    };
    let mut body = json!({ "value": items });
    if let Some(next) = next {
        body["nextLink"] = Value::from(next);
    }
    axum::Json(body).into_response()
}

fn zone_json(inner: &Inner, zone: &str) -> Value {
    let count = inner.sets.iter().filter(|s| s.zone == zone).count();
    json!({
        "id": format!("{}/{zone}", zones_path(inner)),
        "etag": "00000000-0000-0000-0000-000000000000",
        "location": "global",
        "name": zone,
        "type": "Microsoft.Network/dnsZones",
        "properties": {
            "maxNumberOfRecordSets": 10_000,
            "maxNumberOfRecordsPerRecordSet": MAX_RECORDS,
            "numberOfRecordSets": count,
            "nameServers": inner.seed.name_servers,
            "zoneType": "Public",
        },
        "tags": {},
    })
}

fn set_json(inner: &Inner, set: &RecordSet) -> Value {
    let mut properties = set.properties.clone();
    let fqdn = if set.name == "@" {
        set.zone.clone()
    } else {
        format!("{}.{}", set.name, set.zone)
    };
    properties.insert("fqdn".into(), Value::from(fqdn));
    properties.insert("provisioningState".into(), Value::from("Succeeded"));
    json!({
        "id": format!("{}/{}/{}/{}", zones_path(inner), set.zone, set.rtype, set.name),
        "etag": set.etag,
        "name": set.name,
        "type": format!("Microsoft.Network/dnsZones/{}", set.rtype),
        "properties": properties,
    })
}

async fn zones_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((sub, rg)): Path<(String, String)>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let inner = lock(&state);
    if let Err(response) = admit(&inner, &headers, &pairs, &sub, &rg) {
        return response;
    }
    let all: Vec<Value> = inner.zones.iter().map(|z| zone_json(&inner, z)).collect();
    let path = zones_path(&inner);
    listing(&inner, &headers, &path, &pairs, all)
}

async fn zone_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((sub, rg, zone)): Path<(String, String, String)>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let inner = lock(&state);
    if let Err(response) = admit(&inner, &headers, &pairs, &sub, &rg) {
        return response;
    }
    let zone = plain(&zone);
    if inner.zones.contains(&zone) {
        axum::Json(zone_json(&inner, &zone)).into_response()
    } else {
        cloud_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFound",
            "The DNS zone could not be found.",
        )
    }
}

async fn sets_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((sub, rg, zone)): Path<(String, String, String)>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let inner = lock(&state);
    if let Err(response) = admit(&inner, &headers, &pairs, &sub, &rg) {
        return response;
    }
    let zone = plain(&zone);
    if !inner.zones.contains(&zone) {
        return zone_missing();
    }
    let all: Vec<Value> = inner
        .sets
        .iter()
        .filter(|s| s.zone == zone)
        .map(|s| set_json(&inner, s))
        .collect();
    let path = format!("{}/{zone}/recordsets", zones_path(&inner));
    listing(&inner, &headers, &path, &pairs, all)
}

/// The name of a path: lowercase; `@` is the apex.
fn path_name(name: &str) -> String {
    name.to_lowercase()
}

async fn set_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((sub, rg, zone, rtype, name)): Path<(String, String, String, String, String)>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let inner = lock(&state);
    if let Err(response) = admit(&inner, &headers, &pairs, &sub, &rg) {
        return response;
    }
    let zone = plain(&zone);
    if !inner.zones.contains(&zone) {
        return zone_missing();
    }
    match inner.find(&zone, &path_name(&name), &rtype) {
        Some(at) => axum::Json(set_json(&inner, &inner.sets[at])).into_response(),
        None => cloud_error(
            StatusCode::NOT_FOUND,
            "NotFound",
            "The record set could not be found.",
        ),
    }
}

/// `429` while the resource is locked by another operation.
fn locked(inner: &Inner) -> Result<(), Response> {
    match inner.locked {
        None => Ok(()),
        Some(wait) => {
            let mut response = cloud_error(
                StatusCode::TOO_MANY_REQUESTS,
                "RetryableErrorDueToAnotherOperation",
                "Another operation is in progress on the resource. Please retry.",
            );
            response
                .headers_mut()
                .insert("retry-after", HeaderValue::from(wait));
            Err(response)
        }
    }
}

/// The conditional headers against the record set as it is (`current`: its etag, `None` when
/// there is none).
fn precondition(inner: &Inner, headers: &HeaderMap, current: Option<&str>) -> Result<(), Response> {
    let failed = || {
        let (status, code) = &inner.failed_condition;
        cloud_error(
            StatusCode::from_u16(*status).unwrap_or(StatusCode::PRECONDITION_FAILED),
            code,
            "The condition specified using HTTP conditional header(s) is not met.",
        )
    };
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if let Some(value) = header("if-match") {
        match current {
            Some(_) if value == "*" => {}
            Some(etag) if value == etag => {}
            _ => return Err(failed()),
        }
    }
    if header("if-none-match") == Some("*") && current.is_some() {
        return Err(failed());
    }
    Ok(())
}

async fn set_put(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((sub, rg, zone, rtype, name)): Path<(String, String, String, String, String)>,
    Query(pairs): Query<Vec<(String, String)>>,
    body: Bytes,
) -> Response {
    let mut inner = lock(&state);
    if let Err(response) = admit(&inner, &headers, &pairs, &sub, &rg) {
        return response;
    }
    if let Err(response) = locked(&inner) {
        return response;
    }
    let zone = plain(&zone);
    if !inner.zones.contains(&zone) {
        return zone_missing();
    }
    let name = path_name(&name);
    let Some((key, single)) = record_key(&rtype) else {
        return bad_request("The record type is not supported.");
    };
    let at = inner.find(&zone, &name, &rtype);
    if let Err(response) = precondition(&inner, &headers, at.map(|at| inner.sets[at].etag.as_str()))
    {
        return response;
    }
    let properties = match parse_body(&body, &rtype, key, single) {
        Ok(properties) => properties,
        Err(response) => return response,
    };
    let records = match properties.get(key) {
        Some(Value::Array(items)) => items.clone(),
        Some(object @ Value::Object(_)) => vec![object.clone()],
        _ => Vec::new(),
    };
    if let Err(response) = rules(&inner, &zone, &name, &rtype, &records, at) {
        return response;
    }
    let before = inner.published();
    let etag = inner.etag();
    let (status, at) = match at {
        Some(at) => {
            inner.sets[at].properties = properties;
            inner.sets[at].etag = etag;
            (StatusCode::OK, at)
        }
        None => {
            inner.sets.push(RecordSet {
                zone,
                name,
                rtype,
                etag,
                properties,
            });
            (StatusCode::CREATED, inner.sets.len() - 1)
        }
    };
    let answer = set_json(&inner, &inner.sets[at]);
    inner.report(&before, Origin::Api);
    (status, axum::Json(answer)).into_response()
}

/// Parses and checks a `PUT` body: its properties, with only the documented writable ones.
fn parse_body(
    bytes: &[u8],
    rtype: &str,
    key: &str,
    single: bool,
) -> Result<Map<String, Value>, Response> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| bad_request("The request body is not JSON."))?;
    let Value::Object(object) = value else {
        return Err(bad_request("The request body must be a record set object."));
    };
    if let Some(member) = object
        .keys()
        .find(|k| !matches!(k.as_str(), "etag" | "properties"))
    {
        return Err(bad_request(&format!(
            "The member '{member}' cannot be written."
        )));
    }
    let Some(Value::Object(properties)) = object.get("properties") else {
        return Err(bad_request("The record set has no properties."));
    };
    for (name, value) in properties {
        let writable = matches!(name.as_str(), "metadata" | "TTL" | "targetResource")
            || RECORD_KEYS.contains(&name.as_str());
        if !writable {
            return Err(bad_request(&format!(
                "The property '{name}' cannot be written."
            )));
        }
        if RECORD_KEYS.contains(&name.as_str()) && name != key {
            return Err(bad_request(&format!(
                "The property '{name}' does not belong to a record set of type {rtype}."
            )));
        }
        if name == "metadata" && !(value.is_object() || value.is_null()) {
            return Err(bad_request("The metadata must be an object."));
        }
    }
    let ttl = properties.get("TTL").and_then(Value::as_u64);
    if !ttl.is_some_and(|t| (1..=TTL_MAX).contains(&t)) {
        return Err(bad_request(
            "The TTL must be an integer between 1 and 2147483647.",
        ));
    }
    let alias = properties
        .get("targetResource")
        .and_then(|t| t.get("id"))
        .and_then(Value::as_str)
        .is_some_and(|id| !id.is_empty());
    let records = properties.get(key);
    if alias {
        if !matches!(rtype, "A" | "AAAA" | "CNAME") {
            return Err(bad_request(
                "An alias is supported for A, AAAA and CNAME record sets only.",
            ));
        }
        if records.is_some_and(|r| !r.is_null()) {
            return Err(bad_request("An alias record set cannot hold records."));
        }
    }
    let items: Vec<&Value> = match (records, single) {
        (None | Some(Value::Null), _) => Vec::new(),
        (Some(object @ Value::Object(_)), true) => vec![object],
        (Some(Value::Array(items)), false) => items.iter().collect(),
        _ => {
            return Err(bad_request(&format!(
                "The property '{key}' has the wrong form."
            )));
        }
    };
    let limit = if rtype == "TXT" {
        MAX_TXT_RECORDS
    } else {
        MAX_RECORDS
    };
    if items.len() > limit {
        return Err(bad_request("The record set holds too many records."));
    }
    let mut txt_total = 0;
    for item in items {
        txt_total += record_check(rtype, item)?;
    }
    if txt_total > TXT_TOTAL_MAX {
        return Err(bad_request(
            "The TXT record set is longer than 4096 characters.",
        ));
    }
    Ok(properties.clone())
}

/// Checks one record object of `rtype`; the length of its TXT strings.
fn record_check(rtype: &str, item: &Value) -> Result<usize, Response> {
    let Value::Object(object) = item else {
        return Err(bad_request("A record must be an object."));
    };
    let members: &[&str] = match rtype {
        "A" => &["ipv4Address"],
        "AAAA" => &["ipv6Address"],
        "CAA" => &["flags", "tag", "value"],
        "CNAME" => &["cname"],
        "MX" => &["preference", "exchange"],
        "NS" => &["nsdname"],
        "PTR" => &["ptrdname"],
        "SOA" => &[
            "host",
            "email",
            "serialNumber",
            "refreshTime",
            "retryTime",
            "expireTime",
            "minimumTTL",
        ],
        "SRV" => &["priority", "weight", "port", "target"],
        "TXT" => &["value"],
        _ => &[],
    };
    if let Some(member) = object.keys().find(|k| !members.contains(&k.as_str())) {
        return Err(bad_request(&format!(
            "The record member '{member}' is not known."
        )));
    }
    let text = |key: &str| object.get(key).and_then(Value::as_str);
    let int = |key: &str, max: u64| {
        object
            .get(key)
            .and_then(Value::as_u64)
            .filter(|n| *n <= max)
    };
    let name = |key: &str| text(key).is_some_and(|n| !n.is_empty() && !n.contains(' '));
    let bad = |what: &str| Err(bad_request(&format!("The {what} is not valid.")));
    match rtype {
        "A" if text("ipv4Address")
            .and_then(|a| a.parse::<Ipv4Addr>().ok())
            .is_none() =>
        {
            bad("IPv4 address")
        }
        "AAAA"
            if text("ipv6Address")
                .and_then(|a| a.parse::<Ipv6Addr>().ok())
                .is_none() =>
        {
            bad("IPv6 address")
        }
        "CNAME" if !name("cname") => bad("canonical name"),
        "NS" if !name("nsdname") => bad("name server name"),
        "PTR" if !name("ptrdname") => bad("PTR target"),
        "MX" if int("preference", 65_535).is_none() || !name("exchange") => bad("MX record"),
        "SRV"
            if int("priority", 65_535).is_none()
                || int("weight", 65_535).is_none()
                || int("port", 65_535).is_none()
                || !name("target") =>
        {
            bad("SRV record")
        }
        "CAA"
            if int("flags", 255).is_none()
                || !matches!(text("tag"), Some("issue" | "issuewild" | "iodef"))
                || text("value").is_none() =>
        {
            bad("CAA record")
        }
        "TXT" => {
            let Some(strings) = object.get("value").and_then(Value::as_array) else {
                return bad("TXT record");
            };
            let mut total = 0;
            for string in strings {
                let Some(string) = string.as_str() else {
                    return bad("TXT record");
                };
                if string.chars().count() > STRING_MAX {
                    return Err(bad_request("A TXT string is longer than 255 characters."));
                }
                total += string.chars().count();
            }
            Ok(total)
        }
        _ => Ok(0),
    }
}

/// The rules that span record sets (module documentation).
fn rules(
    inner: &Inner,
    zone: &str,
    name: &str,
    rtype: &str,
    records: &[Value],
    at: Option<usize>,
) -> Result<(), Response> {
    match rtype {
        "SOA" => {
            let Some(at) = at else {
                return Err(bad_request("Record sets of type SOA cannot be created."));
            };
            let host = |set: &[Value]| set.first().and_then(|r| r.get("host")).cloned();
            if host(records) != host(&inner.sets[at].records()) {
                return Err(bad_request("The SOA host cannot be changed."));
            }
        }
        "CNAME" if name == "@" => {
            return Err(bad_request(
                "A CNAME record set cannot be at the zone apex.",
            ));
        }
        "NS" if name == "@" => {
            let held: Vec<&str> = records
                .iter()
                .filter_map(|r| r.get("nsdname").and_then(Value::as_str))
                .map(|n| n.trim_end_matches('.'))
                .collect();
            if !inner
                .seed
                .name_servers
                .iter()
                .all(|ns| held.contains(&ns.as_str()))
            {
                return Err(bad_request(
                    "The Azure DNS name servers cannot be removed from the apex NS record set.",
                ));
            }
        }
        _ => {}
    }
    let others = inner.sets.iter().any(|s| {
        s.zone == zone
            && s.name == name
            && s.rtype != rtype
            && (rtype == "CNAME" || s.rtype == "CNAME")
    });
    if others {
        return Err(cloud_error(
            StatusCode::CONFLICT,
            "Conflict",
            "A CNAME record set cannot coexist with another record set of the same name.",
        ));
    }
    Ok(())
}

async fn set_delete(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((sub, rg, zone, rtype, name)): Path<(String, String, String, String, String)>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let mut inner = lock(&state);
    if let Err(response) = admit(&inner, &headers, &pairs, &sub, &rg) {
        return response;
    }
    if let Err(response) = locked(&inner) {
        return response;
    }
    let zone = plain(&zone);
    if !inner.zones.contains(&zone) {
        return zone_missing();
    }
    let name = path_name(&name);
    if rtype == "SOA" || (rtype == "NS" && name == "@") {
        return bad_request("The record set at the zone apex cannot be deleted.");
    }
    let Some(at) = inner.find(&zone, &name, &rtype) else {
        return StatusCode::NO_CONTENT.into_response();
    };
    if let Err(response) = precondition(&inner, &headers, Some(inner.sets[at].etag.as_str())) {
        return response;
    }
    let before = inner.published();
    inner.sets.remove(at);
    inner.report(&before, Origin::Api);
    StatusCode::OK.into_response()
}

// ---- Published form ----------------------------------------------------------------------------

/// A name inside a record, with the trailing dot.
fn dotted(name: &str) -> String {
    if name.ends_with('.') {
        name.to_lowercase()
    } else {
        format!("{}.", name.to_lowercase())
    }
}

/// A character-string in quotes, `"` and `\` escaped, bytes outside printable ASCII as `\DDD`.
fn quote(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for &byte in bytes {
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
}

/// The zone-file text of one record object of `rtype`, or `None` for an object outside the
/// documented form.
fn presentation(rtype: &str, r: &Value) -> Option<String> {
    let text = |key: &str| r.get(key).and_then(Value::as_str);
    let int = |key: &str| r.get(key).and_then(Value::as_u64);
    Some(match rtype {
        "A" => text("ipv4Address")?.to_owned(),
        "AAAA" => text("ipv6Address")?.parse::<Ipv6Addr>().ok()?.to_string(),
        "CNAME" => dotted(text("cname")?),
        "NS" => dotted(text("nsdname")?),
        "PTR" => dotted(text("ptrdname")?),
        "MX" => format!("{} {}", int("preference")?, dotted(text("exchange")?)),
        "SRV" => format!(
            "{} {} {} {}",
            int("priority")?,
            int("weight")?,
            int("port")?,
            dotted(text("target")?)
        ),
        "CAA" => format!(
            "{} {} {}",
            int("flags")?,
            text("tag")?,
            quote(text("value")?.as_bytes())
        ),
        "TXT" => {
            let strings = r.get("value")?.as_array()?;
            let parts: Vec<String> = strings
                .iter()
                .map(|s| s.as_str().map(|s| quote(s.as_bytes())))
                .collect::<Option<_>>()?;
            if parts.is_empty() {
                return None;
            }
            parts.join(" ")
        }
        "SOA" => format!(
            "{} {} {} {} {} {} {}",
            dotted(text("host")?),
            dotted(text("email")?),
            int("serialNumber")?,
            int("refreshTime")?,
            int("retryTime")?,
            int("expireTime")?,
            int("minimumTTL")?
        ),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{form_decode, presentation, record_check};

    #[test]
    fn records_are_checked() {
        for (rtype, item) in [
            ("A", json!({"ipv4Address": "127.0.0.1"})),
            (
                "MX",
                json!({"preference": 0, "exchange": "mail.contoso.com"}),
            ),
            (
                "CAA",
                json!({"flags": 0, "tag": "issue", "value": "ca.contoso.com"}),
            ),
            ("TXT", json!({"value": ["string1", "string2"]})),
        ] {
            assert!(record_check(rtype, &item).is_ok(), "{rtype} {item}");
        }
        for (rtype, item) in [
            ("A", json!({"ipv4Address": "127.0.0"})),
            ("A", json!({"ipv4Address": "127.0.0.1", "extra": 1})),
            ("CAA", json!({"flags": 0, "tag": "other", "value": "x"})),
            ("TXT", json!({"value": ["x".repeat(256)]})),
            ("MX", json!({"preference": 70000, "exchange": "m"})),
        ] {
            assert!(record_check(rtype, &item).is_err(), "{rtype} {item}");
        }
    }

    #[test]
    fn records_are_published_in_zone_file_form() {
        assert_eq!(
            presentation("TXT", &json!({"value": ["a\"b", "c"]})).as_deref(),
            Some("\"a\\\"b\" \"c\"")
        );
        assert_eq!(
            presentation(
                "MX",
                &json!({"preference": 10, "exchange": "Mail.example.org"})
            )
            .as_deref(),
            Some("10 mail.example.org.")
        );
        assert_eq!(form_decode("a+b%2Bc").unwrap(), "a b+c");
    }
}
