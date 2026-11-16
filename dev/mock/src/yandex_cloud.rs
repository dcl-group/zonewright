//! Mock of the Yandex Cloud DNS API, the IAM token service and the Operation API.
//!
//! Shapes follow the provider's documentation, the same sources the client cites:
//!
//! - IAM: <https://yandex.cloud/en/docs/iam/operations/iam-token/create-for-sa> and
//!   <https://yandex.cloud/en/docs/iam/api-ref/IamToken/create>: `POST /iam/v1/tokens` with
//!   `{"jwt"}` (at most 8000 characters); the JWT's header has `typ` `JWT`, `alg` `PS256` (the
//!   only algorithm) and `kid`, its claims `iss`, `aud` (the token URL), `iat` and `exp` with
//!   `exp - iat <= 3600`; the answer is `200` with `iamToken` and `expiresAt` (RFC 3339). The
//!   mock verifies the RSASSA-PSS SHA-256 signature with `aws-lc-rs` and the public half of a key
//!   pair generated at run time ([`test_key`]); it shares no code with the client.
//! - DNS: `DnsZone.list` (`folderId` required, at most 50 characters; `pageSize` at most 1000;
//!   `pageToken`; `{dnsZones, nextPageToken}`), `DnsZone.get`, `DnsZone.getRecordSet` (`name`
//!   and `type` required, `type` at most 10 characters), `DnsZone.listRecordSets` (`pageSize` at
//!   most 1000, `pageToken`; `{recordSets, nextPageToken}`), `DnsZone.updateRecordSets` (at most 1000
//!   deletions and 1000 additions; "Returns error when: Deleted record is not found; Found record
//!   with matched type and name but different TTL, value, or description; Attempted to add record
//!   with existing name and type"; deletions first; `200` with an `Operation`). A `RecordSet` has
//!   `name` (1 to 254 characters), `type` (1 to 20), `ttl` (an int64 as a string, 0 to
//!   2147483647), `data` (1 to 100 elements of 1 to 1024 characters) and `description`.
//! - Operation: `GET /operations/{id}` with `id`, `done`, and `error` or `response`.
//! - Errors (<https://yandex.cloud/en/docs/api-design-guide/concepts/errors>): bodies are
//!   `{code, message, details}`, and gRPC codes map to statuses (`NOT_FOUND` 404,
//!   `ALREADY_EXISTS` 409, `INVALID_ARGUMENT` and `FAILED_PRECONDITION` 400, `PERMISSION_DENIED`
//!   403, `UNAUTHENTICATED` 401).
//! - Proto3 JSON (<https://protobuf.dev/programming-guides/json/>): an int64 is a string on
//!   output and a string or a number on input; empty lists and empty tokens are omitted.
//! - Record data (<https://yandex.cloud/en/docs/dns/concepts/resource-record>): the types A,
//!   AAAA, ANAME, CAA, CNAME, HTTPS, MX, NS, PTR, SOA, SRV, SVCB and TXT, each in the form the
//!   page describes; "Only ASCII characters are supported"; "Uppercase letters in domain names in
//!   values aren't supported without quotation marks"; a `;` outside double quotes starts a
//!   comment; a TXT character-string is at most 255 characters; CAA tags `issue`, `issuewild`,
//!   `iodef`, `contactemail`, `contactphone` with the value in double quotes; SVCB and HTTPS
//!   parameters `mandatory`, `alpn`, `no-default-alpn`, `port`, `ipv4hint`, `ipv6hint`,
//!   `echconfig`, written unquoted as on the page; a CNAME "can't coexist with other records
//!   under the same name". Data written by a client are checked against these forms; data put in
//!   with [`Control::insert_rrset`] are not, so that a test can seed what the API might return,
//!   and neither is an element of an addition that the deletion of the same set in the same
//!   request carries (invented: the provider's own data written back unchanged).
//!
//! Answers this mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading. A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - which status, or which operation error, a failed condition of `updateRecordSets` produces:
//!   by default the call is refused synchronously with the status of the error mapping (`404`
//!   `NOT_FOUND` for a deletion that matches no set, `400` `FAILED_PRECONDITION` for a set that
//!   differs, `409` `ALREADY_EXISTS` for an addition that exists); with
//!   [`StrictFailure::Operation`] the call is accepted and its operation finishes with the
//!   error;
//! - a deletion matches when name, type, TTL and description are equal and the data are the same
//!   values in any order;
//! - `getRecordSet` and `updateRecordSets` accept a name relative to the zone (`@` for the apex)
//!   or absolute with the trailing dot, and the mock returns names absolute;
//! - a missing zone or record set is `404` with code 5 (the error mapping states the status, not
//!   that these calls use it); a refused JWT is `401` with code 16; a folder other than the
//!   configured one is `403` with code 7;
//! - an operation reports `done: false` in the answer to `updateRecordSets` and `done: true` on
//!   the first poll (configurable with [`Control::set_operation_polls`]);
//! - zone and operation identifiers are lowercase letters and digits;
//! - data that break the rules of the record types page, a type the page does not list, and a
//!   CNAME next to other data are refused with `400` and code 3 (`INVALID_ARGUMENT`);
//! - `listRecordSets` returns the record sets in the order they were created, names absolute
//!   (or, with [`Control::set_listing_names`], relative to the zone, `@` for the apex), and
//!   refuses a `filter` (the client lists whole zones; a mock that ignored the filter would hide
//!   a client that relied on it); its page token is an offset, and any other token is `400`.
//!
//! Error texts are invented.
//!
//! The mock is a [`ChangeSource`]: it reports every change of its published records through
//! [`YandexCloudMock::changes`], and a [`link`](crate::link::link) serves them over DNS. An
//! `updateRecordSets` is published when the mock applies it, which is when it is accepted (see
//! above): polling its operation changes nothing, and a call refused or set to fail publishes
//! nothing. Only public zones are published; a private zone is answered only inside the cloud
//! networks it is bound to, so it and its record sets are left out. Left out as well: ANAME
//! sets, which the provider answers with the addresses of their target, which the mock does not
//! resolve, and a set whose owner name is outside its zone (possible only through
//! [`Control::insert_rrset`]). The published form of a set: its absolute owner name; the TTL as
//! a number; a name inside a CNAME, NS, PTR, MX, SRV, SVCB or HTTPS value made absolute, `@` as
//! the zone and a name without the trailing dot read as absolute and given the dot (the record
//! types page writes such names, for ANAME and MX, without the dot and means them absolute); a
//! TXT value as quoted character-strings, an unquoted value split at its spaces into several
//! strings (the page's master-file rule) and every string of more than 255 octets split into
//! 255-octet chunks ("Chunks longer than 255 characters are split automatically"); any other
//! value as stored. [`Control::reset`] returns the mock to its seed.

// Handlers return finished HTTP answers as their error values and hand them straight to axum;
// boxing them would only add noise.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::{self, KeyPair as _, UnparsedPublicKey};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};

use crate::changes::{ChangeSource, Changes, Origin, Published};
use crate::{Faults, MockServer, RequestLog};

/// Path of the DNS API below the server's base URL.
pub const DNS_PATH: &str = "/dns/v1";

/// Path of the IAM token endpoint below the server's base URL.
pub const IAM_PATH: &str = "/iam/v1/tokens";

/// Path of the Operation API below the server's base URL.
pub const OPERATION_PATH: &str = "/operations";

/// Largest page of the zone listing.
const MAX_PAGE_SIZE: usize = 1000;

/// Longest folder ID.
const MAX_FOLDER_ID: usize = 50;

/// Largest number of deletions, and of additions, in one `updateRecordSets`.
const MAX_CHANGES: usize = 1000;

/// Longest JWT the token endpoint accepts.
const MAX_JWT: usize = 8000;

/// A synthetic RSA key pair, generated at run time and never stored.
pub struct TestKey {
    /// The private key as PKCS#8 PEM, after the warning line the provider's CLI writes.
    pub private_pem: String,
    /// The public key as RSAPublicKey DER.
    pub public_der: Vec<u8>,
}

impl std::fmt::Debug for TestKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestKey").finish_non_exhaustive()
    }
}

fn generate_key() -> TestKey {
    let pair = KeyPair::generate(KeySize::Rsa2048).expect("RSA key generation");
    let pkcs8: Pkcs8V1Der<'static> = pair.as_der().expect("PKCS#8 encoding");
    TestKey {
        private_pem: pem(
            "PRIVATE KEY",
            pkcs8.as_ref(),
            "PLEASE DO NOT REMOVE THIS LINE! Synthetic test key, not a credential.\n",
        ),
        public_der: pair.public_key().as_ref().to_vec(),
    }
}

/// A PEM document with `label` around `der`, after `preamble`.
pub fn pem(label: &str, der: &[u8], preamble: &str) -> String {
    let body = STANDARD.encode(der);
    let mut out = format!("{preamble}-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The key pair of the standard seed, generated once per test process.
pub fn test_key() -> &'static TestKey {
    static KEY: OnceLock<TestKey> = OnceLock::new();
    KEY.get_or_init(generate_key)
}

/// A second key pair that no seed registers, for signatures the mock must refuse.
pub fn other_test_key() -> &'static TestKey {
    static KEY: OnceLock<TestKey> = OnceLock::new();
    KEY.get_or_init(generate_key)
}

/// An EC P-256 private key in PKCS#8 PEM, generated at run time: a key the client must refuse.
pub fn ec_private_key_pem() -> String {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("EC key generation");
    pem("PRIVATE KEY", pkcs8.as_ref(), "")
}

/// How a failed condition of `updateRecordSets` is reported (not documented; see the module).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrictFailure {
    /// The call is refused with the status of the error mapping.
    Http,
    /// The call is accepted; its operation finishes with the error.
    Operation,
}

/// How `listRecordSets` spells owner names (not documented; see the module).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListingNames {
    /// Absolute, with the trailing dot.
    Absolute,
    /// Relative to the zone, `@` for the apex.
    Relative,
}

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The authorized key's ID: the `kid` the mock accepts.
    pub key_id: String,
    /// The service account: the `iss` the mock accepts.
    pub service_account_id: String,
    /// The public key that verifies the JWT, as RSAPublicKey DER.
    pub public_key: Vec<u8>,
    /// The folder the service account may list.
    pub folder_id: String,
    /// Zones, in listing order.
    pub zones: Vec<SeedZone>,
    /// Lifetime stated for issued tokens.
    pub token_ttl_s: u64,
}

/// A zone of the seed.
#[derive(Clone, Debug)]
pub struct SeedZone {
    /// The DNS suffix, with or without the trailing dot.
    pub zone: String,
    /// Publicly visible (else private).
    pub public: bool,
}

impl Seed {
    /// Key `ajetestkey0000000001` of service account `ajetestsa00000000001` with the key pair of
    /// [`test_key`], folder `b1gtestfolder000001` holding the private zone `example.org.` and
    /// the public zone `example.org.`, in that order. Tokens state a lifetime of 12 hours.
    pub fn standard() -> Self {
        Self {
            key_id: "ajetestkey0000000001".into(),
            service_account_id: "ajetestsa00000000001".into(),
            public_key: test_key().public_der.clone(),
            folder_id: "b1gtestfolder000001".into(),
            zones: vec![
                SeedZone {
                    zone: "example.org.".into(),
                    public: false,
                },
                SeedZone {
                    zone: "example.org.".into(),
                    public: true,
                },
            ],
            token_ttl_s: 12 * 60 * 60,
        }
    }

    /// The authorized key file of this seed with `private_pem` as its key, in the shape the
    /// provider's CLI writes, extra keys included.
    pub fn authorized_key(&self, private_pem: &str) -> Value {
        json!({
            "id": self.key_id,
            "service_account_id": self.service_account_id,
            "created_at": "2026-01-10T12:00:00Z",
            "key_algorithm": "RSA_2048",
            "public_key": "-----BEGIN PUBLIC KEY-----\nnot used\n-----END PUBLIC KEY-----\n",
            "private_key": private_pem,
        })
    }
}

/// A zone as the mock holds it.
#[derive(Clone, Debug)]
pub struct Zone {
    /// The zone's identifier.
    pub id: String,
    /// The DNS suffix, lowercase, with the trailing dot.
    pub zone: String,
    /// Publicly visible.
    pub public: bool,
}

/// A record set as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordSet {
    /// The zone's identifier.
    pub zone_id: String,
    /// The owner name, absolute, lowercase.
    pub name: String,
    /// The record type.
    pub rtype: String,
    /// TTL in seconds, as the API carries it.
    pub ttl: String,
    /// The data.
    pub data: Vec<String>,
    /// The description, if any.
    pub description: Option<String>,
}

impl RecordSet {
    fn to_json(&self) -> Value {
        let mut set = json!({
            "name": self.name,
            "type": self.rtype,
            "ttl": self.ttl,
            "data": self.data,
        });
        if let Some(description) = &self.description {
            set["description"] = json!(description);
        }
        set
    }

    fn matches(&self, other: &RecordSet) -> bool {
        let mut a = self.data.clone();
        let mut b = other.data.clone();
        a.sort();
        b.sort();
        self.ttl == other.ttl && self.description == other.description && a == b
    }
}

#[derive(Debug)]
struct Op {
    polls_left: u32,
    error: Option<(i64, String)>,
}

#[derive(Debug)]
struct Inner {
    /// The seed the mock was started with, for [`Control::reset`].
    original: Seed,
    /// The seed in force; [`Control::set_token_ttl`] changes it.
    seed: Seed,
    changes: Changes,
    iam_url: String,
    zones: Vec<Zone>,
    rrsets: Vec<RecordSet>,
    tokens: HashMap<String, bool>,
    issued: Vec<String>,
    operations: HashMap<String, Op>,
    operation_polls: u32,
    fail_next_operation: Option<String>,
    strict_failure: StrictFailure,
    page_size: Option<usize>,
    record_page_size: Option<usize>,
    listing_names: ListingNames,
    next_id: u64,
}

impl Inner {
    /// The state of a mock started with `seed`; `iam_url` is the `aud` the token endpoint
    /// requires.
    fn new(seed: Seed, changes: Changes, iam_url: String) -> Inner {
        let mut inner = Inner {
            original: seed.clone(),
            seed: seed.clone(),
            changes,
            iam_url,
            zones: Vec::new(),
            rrsets: Vec::new(),
            tokens: HashMap::new(),
            issued: Vec::new(),
            operations: HashMap::new(),
            operation_polls: 1,
            fail_next_operation: None,
            strict_failure: StrictFailure::Http,
            page_size: None,
            record_page_size: None,
            listing_names: ListingNames::Absolute,
            next_id: 0,
        };
        for zone in &seed.zones {
            let id = inner.new_id("dnszone");
            inner.zones.push(Zone {
                id,
                zone: fqdn(&zone.zone),
                public: zone.public,
            });
        }
        inner
    }

    /// What a DNS server for the mock's public zones would answer (module documentation).
    fn published(&self) -> Published {
        let mut out = Published::new();
        for zone in self.zones.iter().filter(|z| z.public) {
            out.zone(&zone.zone);
        }
        for set in &self.rrsets {
            let Some(zone) = self.zones.iter().find(|z| z.id == set.zone_id && z.public) else {
                continue;
            };
            let inside = set.name == zone.zone || set.name.ends_with(&format!(".{}", zone.zone));
            if !inside || set.rtype == "ANAME" {
                continue;
            }
            let values = set
                .data
                .iter()
                .map(|d| published_value(&set.rtype, d, &zone.zone))
                .collect();
            out.rrset(
                &zone.zone,
                &set.name,
                &set.rtype,
                set.ttl.parse::<u32>().ok(),
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

    fn new_id(&mut self, prefix: &str) -> String {
        self.next_id += 1;
        format!("{prefix}{:012}", self.next_id)
    }
}

/// A data element in zone-file text form (module documentation).
fn published_value(rtype: &str, data: &str, zone: &str) -> String {
    let host = |name: &str| {
        if name == "@" {
            zone.to_owned()
        } else if name.ends_with('.') {
            name.to_owned()
        } else {
            format!("{name}.")
        }
    };
    let fields: Vec<&str> = data.split(' ').collect();
    match (rtype, fields.as_slice()) {
        ("CNAME" | "NS" | "PTR", [target]) => host(target),
        ("MX", [preference, exchange]) => format!("{preference} {}", host(exchange)),
        ("SRV", [priority, weight, port, target]) => {
            format!("{priority} {weight} {port} {}", host(target))
        }
        ("SVCB" | "HTTPS", [priority, target, params @ ..]) => {
            let mut out = format!("{priority} {}", host(target));
            for param in params {
                out.push(' ');
                out.push_str(param);
            }
            out
        }
        ("TXT", _) => txt_value(data),
        _ => data.to_owned(),
    }
}

/// A TXT data element as quoted character-strings of at most 255 octets each: quoted strings
/// as they are (split when longer), unquoted text split at its spaces.
fn txt_value(data: &str) -> String {
    let strings: Vec<&str> = if data.starts_with('"') {
        // The API's quoted form (see `check_txt`): strings in double quotes separated by spaces.
        data.split('"')
            .enumerate()
            .filter(|(i, _)| i % 2 == 1)
            .map(|(_, s)| s)
            .collect()
    } else {
        data.split(' ').filter(|s| !s.is_empty()).collect()
    };
    let mut out = Vec::new();
    for string in strings {
        let bytes = string.as_bytes();
        if bytes.is_empty() {
            out.push("\"\"".to_owned());
        }
        for chunk in bytes.chunks(255) {
            let mut text = String::from("\"");
            for &byte in chunk {
                match byte {
                    b'"' | b'\\' => {
                        text.push('\\');
                        text.push(char::from(byte));
                    }
                    0x20..=0x7e => text.push(char::from(byte)),
                    _ => text.push_str(&format!("\\{byte:03}")),
                }
            }
            text.push('"');
            out.push(text);
        }
    }
    out.join(" ")
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running Yandex Cloud mock. Dereferences to its [`MockServer`] for the request log and the
/// fault queue; [`YandexCloudMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct YandexCloudMock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of a [`YandexCloudMock`]. Cheap to clone, so that a fault hook
/// can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
    changes: Changes,
    log: RequestLog,
    faults: Faults,
}

impl Deref for YandexCloudMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl YandexCloudMock {
    /// Starts the mock with `seed` on `127.0.0.1` with an ephemeral port.
    pub async fn start(seed: Seed) -> Self {
        Self::start_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), seed).await
    }

    /// Starts the mock with `seed` on `addr` ([`MockServer::start_on`]). On an address other than
    /// loopback, for an isolated test network only.
    pub async fn start_on(addr: SocketAddr, seed: Seed) -> Self {
        let changes = Changes::new();
        let state = Arc::new(Mutex::new(Inner::new(seed, changes.clone(), String::new())));
        let router = Router::new()
            .route(IAM_PATH, post(iam_token))
            .route("/dns/v1/zones", get(zones_list))
            .route("/dns/v1/zones/{zone}", get(zone_get).post(zone_post))
            .route("/operations/{id}", get(operation_get))
            .with_state(state.clone());
        let server = MockServer::start_on(addr, router).await;
        lock(&state).iam_url = server.url(IAM_PATH);
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

    /// The token endpoint, for the client's `iam_url`; also the `aud` the mock requires.
    pub fn iam_url(&self) -> String {
        self.server.url(IAM_PATH)
    }

    /// The Operation API endpoint, for the client's `operation_url`.
    pub fn operation_url(&self) -> String {
        self.server.url(OPERATION_PATH)
    }

    /// The state control.
    pub fn control(&self) -> &Control {
        &self.control
    }
}

impl ChangeSource for YandexCloudMock {
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
    /// identifiers, no record sets, no issued tokens, the token lifetime of the seed, no pending
    /// operations, one poll per operation, no pending operation failure, failed conditions
    /// refused over HTTP, no page sizes, absolute listing names, an empty request log and no
    /// pending faults. Reports the removal of every rrset that was published.
    pub fn reset(&self) {
        self.faults.clear();
        self.change(|inner| {
            let seed = inner.original.clone();
            let iam_url = inner.iam_url.clone();
            *inner = Inner::new(seed, inner.changes.clone(), iam_url);
        });
        self.log.clear();
    }

    /// Every zone.
    pub fn zones(&self) -> Vec<Zone> {
        lock(&self.state).zones.clone()
    }

    /// The identifier of the public zone `zone`.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn zone_id(&self, zone: &str) -> String {
        let zone = fqdn(zone);
        lock(&self.state)
            .zones
            .iter()
            .find(|z| z.zone == zone && z.public)
            .map(|z| z.id.clone())
            .unwrap_or_else(|| panic!("no public zone {zone}"))
    }

    /// Adds a zone to the folder; returns its identifier.
    pub fn insert_zone(&self, zone: &str, public: bool) -> String {
        self.change(|inner| {
            let id = inner.new_id("dnszone");
            inner.zones.push(Zone {
                id: id.clone(),
                zone: fqdn(zone),
                public,
            });
            id
        })
    }

    /// Deletes the public zone `zone` and creates it again under a new identifier, with the
    /// same record sets. Returns the new identifier.
    pub fn recreate_zone(&self, zone: &str) -> String {
        let old = self.zone_id(zone);
        self.change(|inner| {
            let new = inner.new_id("dnszone");
            for z in inner.zones.iter_mut().filter(|z| z.id == old) {
                z.id = new.clone();
            }
            for r in inner.rrsets.iter_mut().filter(|r| r.zone_id == old) {
                r.zone_id = new.clone();
            }
            new
        })
    }

    /// Every record set.
    pub fn rrsets(&self) -> Vec<RecordSet> {
        lock(&self.state).rrsets.clone()
    }

    /// The record set of `name` and `rtype` in the public zone `zone`, if any.
    pub fn rrset(&self, zone: &str, name: &str, rtype: &str) -> Option<RecordSet> {
        let zone_id = self.zone_id(zone);
        let name = fqdn(name);
        lock(&self.state)
            .rrsets
            .iter()
            .find(|r| r.zone_id == zone_id && r.name == name && r.rtype == rtype)
            .cloned()
    }

    /// The TXT data of `name` in the public zone `zone`, in order.
    pub fn txt(&self, zone: &str, name: &str) -> Vec<String> {
        self.rrset(zone, name, "TXT")
            .map(|r| r.data)
            .unwrap_or_default()
    }

    /// Creates a record set directly, as another writer would, replacing one of the same name
    /// and type.
    pub fn insert_rrset(&self, zone: &str, name: &str, rtype: &str, ttl: &str, data: &[&str]) {
        let zone_id = self.zone_id(zone);
        let name = fqdn(name);
        self.change(|inner| {
            inner
                .rrsets
                .retain(|r| !(r.zone_id == zone_id && r.name == name && r.rtype == rtype));
            inner.rrsets.push(RecordSet {
                zone_id,
                name,
                rtype: rtype.to_owned(),
                ttl: ttl.to_owned(),
                data: data.iter().map(|d| (*d).to_owned()).collect(),
                description: None,
            });
        });
    }

    /// Appends `value` to the TXT data of `name`, creating the set with TTL 300 if needed: a
    /// change by another writer.
    pub fn append_txt(&self, zone: &str, name: &str, value: &str) {
        match self.rrset(zone, name, "TXT") {
            Some(mut set) => {
                set.data.push(value.to_owned());
                let data: Vec<&str> = set.data.iter().map(String::as_str).collect();
                let description = set.description.clone();
                self.insert_rrset(zone, name, "TXT", &set.ttl, &data);
                self.set_description(zone, name, "TXT", description.as_deref());
            }
            None => self.insert_rrset(zone, name, "TXT", "300", &[value]),
        }
    }

    /// Sets the description of a record set.
    pub fn set_description(&self, zone: &str, name: &str, rtype: &str, description: Option<&str>) {
        let zone_id = self.zone_id(zone);
        let name = fqdn(name);
        self.change(|inner| {
            for r in inner
                .rrsets
                .iter_mut()
                .filter(|r| r.zone_id == zone_id && r.name == name && r.rtype == rtype)
            {
                r.description = description.map(str::to_owned);
            }
        });
    }

    /// Deletes a record set directly, as another writer would.
    pub fn delete_rrset(&self, zone: &str, name: &str, rtype: &str) {
        let zone_id = self.zone_id(zone);
        let name = fqdn(name);
        self.change(|inner| {
            inner
                .rrsets
                .retain(|r| !(r.zone_id == zone_id && r.name == name && r.rtype == rtype));
        });
    }

    /// Revokes every token issued so far: requests with them answer `401`.
    pub fn revoke_tokens(&self) {
        for revoked in lock(&self.state).tokens.values_mut() {
            *revoked = true;
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

    /// Lifetime stated for tokens issued from now on.
    pub fn set_token_ttl(&self, seconds: u64) {
        lock(&self.state).seed.token_ttl_s = seconds;
    }

    /// Number of polls an operation of `updateRecordSets` reports `done: false` for before it
    /// is done; `0` answers the call with a finished operation.
    pub fn set_operation_polls(&self, polls: u32) {
        lock(&self.state).operation_polls = polls;
    }

    /// The next accepted `updateRecordSets` is not applied; its operation finishes with an
    /// error carrying `message`.
    pub fn fail_next_operation(&self, message: &str) {
        lock(&self.state).fail_next_operation = Some(message.to_owned());
    }

    /// How a failed condition of `updateRecordSets` is reported.
    pub fn set_strict_failure(&self, mode: StrictFailure) {
        lock(&self.state).strict_failure = mode;
    }

    /// Page size of the zone listing, whatever the client asks for.
    pub fn set_page_size(&self, size: usize) {
        lock(&self.state).page_size = Some(size);
    }

    /// Page size of the record set listing, whatever the client asks for.
    pub fn set_record_page_size(&self, size: usize) {
        lock(&self.state).record_page_size = Some(size);
    }

    /// How the record set listing spells owner names.
    pub fn set_listing_names(&self, names: ListingNames) {
        lock(&self.state).listing_names = names;
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

/// An error answer in the documented shape.
fn error(status: StatusCode, code: i64, message: &str) -> Response {
    (
        status,
        axum::Json(json!({"code": code, "message": message, "details": []})),
    )
        .into_response()
}

fn invalid(message: &str) -> Response {
    error(StatusCode::BAD_REQUEST, 3, message)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// `seconds` since the Unix epoch as an RFC 3339 timestamp in UTC.
fn rfc3339(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (H. Hinnant, "chrono-Compatible Low-Level Date
    // Algorithms").
    let z = days + 719_468;
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

fn b64_json(part: &str) -> Option<Value> {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).ok()?).ok()
}

/// Checks a JWT as the documentation describes it, signature included.
fn jwt_valid(inner: &Inner, jwt: &str) -> bool {
    let parts: Vec<&str> = jwt.split('.').collect();
    let [header, claims, sig] = parts.as_slice() else {
        return false;
    };
    let (Some(h), Some(c), Ok(sig)) = (
        b64_json(header),
        b64_json(claims),
        URL_SAFE_NO_PAD.decode(sig),
    ) else {
        return false;
    };
    let seed = &inner.seed;
    let header_ok = h["typ"] == "JWT" && h["alg"] == "PS256" && h["kid"] == seed.key_id.as_str();
    let (iat, exp) = (c["iat"].as_i64(), c["exp"].as_i64());
    let now = now();
    let times_ok = matches!((iat, exp), (Some(iat), Some(exp))
        if iat <= now + 60 && exp > now && exp > iat && exp - iat <= 3600);
    let claims_ok = c["iss"] == seed.service_account_id.as_str()
        && c["aud"] == inner.iam_url.as_str()
        && times_ok;
    let message = format!("{header}.{claims}");
    let signature_ok =
        UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, &seed.public_key)
            .verify(message.as_bytes(), &sig)
            .is_ok();
    header_ok && claims_ok && signature_ok
}

async fn iam_token(State(state): State<Shared>, body: Bytes) -> Response {
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return invalid("malformed request body");
    };
    let Some(jwt) = request["jwt"].as_str() else {
        return invalid("jwt is required");
    };
    if jwt.len() > MAX_JWT {
        return invalid("jwt is too long");
    }
    let mut inner = lock(&state);
    if !jwt_valid(&inner, jwt) {
        return error(StatusCode::UNAUTHORIZED, 16, "the JWT is not valid");
    }
    let token = format!("t1.mock-iam-token-{:04}.zz", inner.issued.len() + 1);
    inner.tokens.insert(token.clone(), false);
    inner.issued.push(token.clone());
    let ttl = i64::try_from(inner.seed.token_ttl_s).unwrap_or(i64::MAX);
    let expires_at = rfc3339(now().saturating_add(ttl));
    axum::Json(json!({"iamToken": token, "expiresAt": expires_at})).into_response()
}

/// The `401` answer unless the request carries a live token.
fn authorize(state: &Shared, headers: &HeaderMap) -> Result<(), Response> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    match lock(state).tokens.get(token) {
        Some(false) => Ok(()),
        _ => Err(error(StatusCode::UNAUTHORIZED, 16, "unauthenticated")),
    }
}

fn zone_json(folder: &str, zone: &Zone) -> Value {
    let mut out = json!({
        "id": zone.id,
        "folderId": folder,
        "createdAt": "2026-01-10T12:00:00Z",
        "name": format!("zone-{}", zone.id),
        "zone": zone.zone,
    });
    if zone.public {
        out["publicVisibility"] = json!({});
    } else {
        out["privateVisibility"] = json!({"networkIds": ["enpnetwork0001"]});
    }
    out
}

async fn zones_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let inner = lock(&state);
    let Some(folder) = q.get("folderId") else {
        return invalid("folderId is required");
    };
    if folder.len() > MAX_FOLDER_ID {
        return invalid("folderId is too long");
    }
    if *folder != inner.seed.folder_id {
        return error(StatusCode::FORBIDDEN, 7, "permission denied");
    }
    let asked = match q.get("pageSize").map(|s| s.parse::<usize>()) {
        None => MAX_PAGE_SIZE,
        Some(Ok(size)) if (1..=MAX_PAGE_SIZE).contains(&size) => size,
        Some(_) => return invalid("pageSize must be 1 to 1000"),
    };
    let size = inner.page_size.unwrap_or(asked);
    let offset = match q.get("pageToken").map(|s| s.parse::<usize>()) {
        None => 0,
        Some(Ok(offset)) => offset,
        Some(Err(_)) => return invalid("invalid page token"),
    };
    let all: Vec<Value> = inner.zones.iter().map(|z| zone_json(folder, z)).collect();
    let page: Vec<Value> = all.iter().skip(offset).take(size).cloned().collect();
    // Proto3 JSON omits an empty list and an empty token.
    let mut out = json!({});
    if !page.is_empty() {
        out["dnsZones"] = json!(page);
    }
    if offset + size < all.len() {
        out["nextPageToken"] = json!((offset + size).to_string());
    }
    axum::Json(out).into_response()
}

/// Splits `{zone}` into the zone identifier and the custom method after `:`.
fn split_method(segment: &str) -> (&str, &str) {
    segment.split_once(':').unwrap_or((segment, ""))
}

async fn zone_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(segment): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let (zone_id, method) = split_method(&segment);
    let inner = lock(&state);
    let Some(zone) = inner.zones.iter().find(|z| z.id == zone_id).cloned() else {
        return error(StatusCode::NOT_FOUND, 5, "DnsZone not found");
    };
    match method {
        "" => axum::Json(zone_json(&inner.seed.folder_id, &zone)).into_response(),
        "getRecordSet" => {
            let (Some(name), Some(rtype)) = (q.get("name"), q.get("type")) else {
                return invalid("name and type are required");
            };
            if rtype.is_empty() || rtype.len() > 10 || name.is_empty() || name.len() > 255 {
                return invalid("invalid name or type");
            }
            let Some(name) = absolute(name, &zone.zone) else {
                return invalid("the name is outside the zone");
            };
            match inner
                .rrsets
                .iter()
                .find(|r| r.zone_id == zone.id && r.name == name && r.rtype == *rtype)
            {
                Some(set) => axum::Json(set.to_json()).into_response(),
                None => error(StatusCode::NOT_FOUND, 5, "RecordSet not found"),
            }
        }
        "listRecordSets" => list_record_sets(&inner, &zone, &q),
        _ => error(StatusCode::NOT_FOUND, 5, "no such method"),
    }
}

fn list_record_sets(inner: &Inner, zone: &Zone, q: &HashMap<String, String>) -> Response {
    if q.contains_key("filter") {
        return invalid("this mock does not implement filter");
    }
    let asked = match q.get("pageSize").map(|s| s.parse::<usize>()) {
        None => MAX_PAGE_SIZE,
        Some(Ok(size)) if (1..=MAX_PAGE_SIZE).contains(&size) => size,
        Some(_) => return invalid("pageSize must be 1 to 1000"),
    };
    let size = inner.record_page_size.unwrap_or(asked);
    let offset = match q.get("pageToken").map(|s| s.parse::<usize>()) {
        None => 0,
        Some(Ok(offset)) => offset,
        Some(Err(_)) => return invalid("invalid page token"),
    };
    let all: Vec<Value> = inner
        .rrsets
        .iter()
        .filter(|r| r.zone_id == zone.id)
        .map(|r| {
            let mut set = r.to_json();
            if inner.listing_names == ListingNames::Relative {
                let relative = if r.name == zone.zone {
                    "@".to_owned()
                } else {
                    r.name
                        .strip_suffix(&format!(".{}", zone.zone))
                        .unwrap_or(&r.name)
                        .to_owned()
                };
                set["name"] = json!(relative);
            }
            set
        })
        .collect();
    let page: Vec<Value> = all.iter().skip(offset).take(size).cloned().collect();
    let mut out = json!({});
    if !page.is_empty() {
        out["recordSets"] = json!(page);
    }
    if offset + size < all.len() {
        out["nextPageToken"] = json!((offset + size).to_string());
    }
    axum::Json(out).into_response()
}

/// `name` relative to `zone` (`@` for the apex) or absolute, as an absolute lowercase name;
/// `None` when it is outside the zone.
fn absolute(name: &str, zone: &str) -> Option<String> {
    let name = name.trim().to_lowercase();
    let full = if name == "@" {
        zone.to_owned()
    } else if name.ends_with('.') {
        name
    } else {
        format!("{name}.{zone}")
    };
    (full == zone || full.ends_with(&format!(".{zone}"))).then_some(full)
}

/// A record set of a request, validated against the documented limits.
fn parse_set(value: &Value, zone: &Zone) -> Result<RecordSet, Response> {
    let name = value["name"].as_str().unwrap_or("");
    if name.is_empty() || name.chars().count() > 254 {
        return Err(invalid("name must be 1 to 254 characters"));
    }
    let name = absolute(name, &zone.zone).ok_or_else(|| invalid("the name is outside the zone"))?;
    let rtype = value["type"].as_str().unwrap_or("");
    if rtype.is_empty() || rtype.len() > 20 {
        return Err(invalid("type must be 1 to 20 characters"));
    }
    // Proto3 JSON: an int64 is a string or a number on input; omitted is zero.
    let ttl = match &value["ttl"] {
        Value::Null => Some(0),
        Value::String(text) => text.parse::<i64>().ok(),
        Value::Number(number) => number.as_i64(),
        _ => None,
    };
    let ttl = match ttl {
        Some(ttl) if (0..=2_147_483_647).contains(&ttl) => ttl.to_string(),
        _ => return Err(invalid("ttl must be 0 to 2147483647")),
    };
    let Some(data) = value["data"].as_array() else {
        return Err(invalid("data is required"));
    };
    if data.is_empty() || data.len() > 100 {
        return Err(invalid("data must hold 1 to 100 elements"));
    }
    let mut out = Vec::with_capacity(data.len());
    for element in data {
        match element.as_str() {
            Some(text) if !text.is_empty() && text.chars().count() <= 1024 => {
                out.push(text.to_owned());
            }
            _ => return Err(invalid("each data element must be 1 to 1024 characters")),
        }
    }
    let description = match &value["description"] {
        Value::Null => None,
        Value::String(text) if text.is_empty() => None,
        Value::String(text) => Some(text.clone()),
        _ => return Err(invalid("description must be a string")),
    };
    Ok(RecordSet {
        zone_id: zone.id.clone(),
        name,
        rtype: rtype.to_owned(),
        ttl,
        data: out,
        description,
    })
}

async fn zone_post(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(segment): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let (zone_id, method) = split_method(&segment);
    if method != "updateRecordSets" {
        return error(StatusCode::NOT_FOUND, 5, "no such method");
    }
    let mut inner = lock(&state);
    let Some(zone) = inner.zones.iter().find(|z| z.id == zone_id).cloned() else {
        return error(StatusCode::NOT_FOUND, 5, "DnsZone not found");
    };
    let Ok(Value::Object(request)) = serde_json::from_slice::<Value>(&body) else {
        return invalid("malformed request body");
    };
    if request
        .keys()
        .any(|k| !matches!(k.as_str(), "deletions" | "additions"))
    {
        return invalid("unknown field");
    }
    let list = |key: &str| -> Result<Vec<RecordSet>, Response> {
        match request.get(key) {
            None => Ok(Vec::new()),
            Some(Value::Array(items)) if items.len() <= MAX_CHANGES => {
                items.iter().map(|v| parse_set(v, &zone)).collect()
            }
            Some(_) => Err(invalid("deletions and additions are lists of at most 1000")),
        }
    };
    let (deletions, additions) = match (list("deletions"), list("additions")) {
        (Ok(d), Ok(a)) => (d, a),
        (Err(response), _) | (_, Err(response)) => return response,
    };
    // Data of an addition are checked against the documented forms, except an element that the
    // deletion of the same set in this request carries: it is the provider's own data, written
    // back.
    for addition in &additions {
        let kept: Vec<&String> = deletions
            .iter()
            .filter(|d| d.name == addition.name && d.rtype == addition.rtype)
            .flat_map(|d| d.data.iter())
            .collect();
        for text in addition.data.iter().filter(|t| !kept.contains(t)) {
            if let Err(message) = check_data(&addition.rtype, text) {
                return invalid(&message);
            }
        }
    }
    let mut next = inner.rrsets.clone();
    let mut failure: Option<(StatusCode, i64, &str)> = None;
    for deletion in &deletions {
        let position = next.iter().position(|r| {
            r.zone_id == deletion.zone_id && r.name == deletion.name && r.rtype == deletion.rtype
        });
        match position {
            None => {
                failure = Some((StatusCode::NOT_FOUND, 5, "deleted record set not found"));
                break;
            }
            Some(p) if !next[p].matches(deletion) => {
                failure = Some((
                    StatusCode::BAD_REQUEST,
                    9,
                    "found record set with matched type and name but different TTL, value or description",
                ));
                break;
            }
            Some(p) => {
                next.remove(p);
            }
        }
    }
    if failure.is_none() {
        for addition in &additions {
            if next.iter().any(|r| {
                r.zone_id == addition.zone_id
                    && r.name == addition.name
                    && r.rtype == addition.rtype
            }) {
                failure = Some((StatusCode::CONFLICT, 6, "record set already exists"));
                break;
            }
            let cname_clash = next.iter().any(|r| {
                r.zone_id == addition.zone_id
                    && r.name == addition.name
                    && (r.rtype == "CNAME") != (addition.rtype == "CNAME")
            });
            if cname_clash {
                return invalid("a CNAME cannot coexist with other records under the same name");
            }
            next.push(addition.clone());
        }
    }
    let mut error_of_operation = inner.fail_next_operation.take().map(|m| (9, m));
    if let Some((status, code, message)) = failure {
        if inner.strict_failure == StrictFailure::Http {
            return error(status, code, message);
        }
        error_of_operation = Some((code, message.to_owned()));
    }
    if error_of_operation.is_none() {
        let before = inner.published();
        inner.rrsets = next;
        inner.report(&before, Origin::Api);
    }
    let id = inner.new_id("dnsop");
    let polls = inner.operation_polls;
    let done = polls == 0;
    let mut out = json!({
        "id": id,
        "description": "Update record sets",
        "createdAt": "2026-01-10T12:00:00Z",
        "createdBy": inner.seed.service_account_id,
        "modifiedAt": "2026-01-10T12:00:00Z",
        "done": done,
    });
    if done {
        set_result(&mut out, error_of_operation.as_ref());
    }
    inner.operations.insert(
        id,
        Op {
            polls_left: polls,
            error: error_of_operation,
        },
    );
    axum::Json(out).into_response()
}

/// Checks one data element of type `rtype` against the record types page (see the module).
fn check_data(rtype: &str, text: &str) -> Result<(), String> {
    let fail = |what: &str| Err(format!("{rtype} data: {what}"));
    if !text.is_ascii() {
        return fail("only ASCII characters are supported");
    }
    let fields: Vec<&str> = text.split(' ').collect();
    if rtype != "TXT" && rtype != "CAA" && fields.iter().any(|f| f.is_empty()) {
        return fail("fields are separated by one space");
    }
    let host = |name: &str| {
        !name.is_empty()
            && name != "."
            && name.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'.' | b'-' | b'_' | b'*')
            })
            && !name.contains("..")
    };
    let target = |name: &str| name == "." || host(name);
    let number = |field: &str| field.parse::<u16>().is_ok();
    let ok = match (rtype, fields.as_slice()) {
        ("A", [address]) => address.parse::<std::net::Ipv4Addr>().is_ok(),
        ("AAAA", [address]) => address.parse::<std::net::Ipv6Addr>().is_ok(),
        ("CNAME" | "ANAME" | "NS" | "PTR", [name]) => host(name),
        ("MX", [preference, exchange]) => number(preference) && target(exchange),
        ("SRV", [priority, weight, port, name]) => {
            number(priority) && number(weight) && number(port) && target(name)
        }
        ("SOA", [mname, rname, rest @ ..]) => {
            host(mname)
                && host(rname)
                && rest.len() == 5
                && rest.iter().all(|f| f.parse::<u32>().is_ok())
        }
        ("CAA", [flag, tag, value @ ..]) => {
            let value = value.join(" ");
            flag.parse::<u8>().is_ok()
                && [
                    "issue",
                    "issuewild",
                    "iodef",
                    "contactemail",
                    "contactphone",
                ]
                .contains(tag)
                && value.len() >= 2
                && value.starts_with('"')
                && value.ends_with('"')
                && !value[1..value.len() - 1].contains('"')
        }
        ("SVCB" | "HTTPS", [priority, name, params @ ..]) => {
            number(priority)
                && target(name)
                && params.iter().all(|param| {
                    let (key, value) = param.split_once('=').unwrap_or((param, ""));
                    !value.contains('"')
                        && match key {
                            "no-default-alpn" => value.is_empty(),
                            "mandatory" | "alpn" | "port" | "ipv4hint" | "ipv6hint"
                            | "echconfig" => !value.is_empty(),
                            _ => false,
                        }
                })
        }
        ("TXT", _) => return check_txt(text).map_err(|what| format!("TXT data: {what}")),
        ("A" | "AAAA" | "CNAME" | "ANAME" | "NS" | "PTR" | "MX" | "SRV" | "SOA" | "CAA", _)
        | ("SVCB" | "HTTPS", _) => false,
        _ => return fail("the record type is not supported"),
    };
    if ok {
        Ok(())
    } else {
        fail("not in the documented form")
    }
}

/// TXT: one unquoted string without spaces, quotes or `;`, or quoted strings of at most 255
/// characters separated by spaces.
fn check_txt(text: &str) -> Result<(), &'static str> {
    if !text.starts_with('"') {
        return if text.contains([' ', '"', ';']) {
            Err("spaces, quotes and ';' need double quotes")
        } else {
            Ok(())
        };
    }
    let mut rest = text;
    while !rest.is_empty() {
        let Some(inner) = rest.strip_prefix('"') else {
            return Err("text outside double quotes");
        };
        let Some(end) = inner.find('"') else {
            return Err("an unterminated quote");
        };
        if end > 255 {
            return Err("a character-string is longer than 255 characters");
        }
        rest = &inner[end + 1..];
        if let Some(next) = rest.strip_prefix(' ') {
            rest = next;
            if rest.is_empty() {
                return Err("a trailing space");
            }
        } else if !rest.is_empty() {
            return Err("strings are separated by spaces");
        }
    }
    Ok(())
}

fn set_result(out: &mut Value, error: Option<&(i64, String)>) {
    match error {
        Some((code, message)) => {
            out["error"] = json!({"code": code, "message": message, "details": []});
        }
        None => out["response"] = json!({}),
    }
}

async fn operation_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let mut inner = lock(&state);
    let Some(op) = inner.operations.get_mut(&id) else {
        return error(StatusCode::NOT_FOUND, 5, "operation not found");
    };
    op.polls_left = op.polls_left.saturating_sub(1);
    let done = op.polls_left == 0;
    let mut out = json!({"id": id, "done": done});
    if done {
        set_result(&mut out, op.error.as_ref());
    }
    axum::Json(out).into_response()
}

#[cfg(test)]
mod tests {
    use super::{absolute, check_data, rfc3339};

    #[test]
    fn data_follow_the_record_types_page() {
        for (rtype, text) in [
            ("A", "192.0.2.1"),
            ("AAAA", "2001:db8::1"),
            ("CNAME", "host.example.com."),
            ("ANAME", "example.com.website.yandexcloud.test"),
            ("MX", "10 mx-primary.example.com."),
            ("SRV", "10 70 8080 host.example.com."),
            ("SRV", "0 0 0 ."),
            ("CAA", "0 issue \";\""),
            ("CAA", "0 iodef \"mailto:security@example.com\""),
            (
                "SVCB",
                "1 . alpn=h3,h3-29,h2 ipv4hint=10.0.0.1 ipv6hint=::1",
            ),
            ("HTTPS", "0 svc4.example.net."),
            ("TXT", "\"v=spf1 ip4=192.0.2.0 -all\""),
            ("TXT", "\"a\" \"b\""),
            ("TXT", "plain"),
            (
                "SOA",
                "ns1.yandexcloud.test. mx.cloud.yandex.test. 1 10800 900 604800 86400",
            ),
        ] {
            assert_eq!(check_data(rtype, text), Ok(()), "{rtype} {text}");
        }
        for (rtype, text) in [
            ("A", "192.0.2.256"),
            ("CNAME", "Host.example.com."),
            ("MX", "10  mx.example.com."),
            ("CAA", "0 issuemail \"ca.example.net\""),
            ("CAA", "0 issue ca.example.net"),
            ("SVCB", "1 . alpn=\"h2\""),
            ("SVCB", "1 . key65000=x"),
            ("TXT", "two words"),
            ("TXT", "\"a\"b"),
            ("TLSA", "3 1 1 0a1b"),
            ("A", "café"),
        ] {
            assert!(check_data(rtype, text).is_err(), "{rtype} {text}");
        }
        let long = format!("\"{}\"", "x".repeat(256));
        assert!(check_data("TXT", &long).is_err());
    }

    #[test]
    fn timestamps_are_rfc3339() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000000Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00.000000Z");
    }

    #[test]
    fn names_are_made_absolute() {
        let zone = "example.org.";
        assert_eq!(absolute("@", zone).as_deref(), Some("example.org."));
        assert_eq!(absolute("_a", zone).as_deref(), Some("_a.example.org."));
        assert_eq!(
            absolute("_A.Example.org.", zone).as_deref(),
            Some("_a.example.org.")
        );
        assert_eq!(absolute("x.example.net.", zone), None);
    }
}
