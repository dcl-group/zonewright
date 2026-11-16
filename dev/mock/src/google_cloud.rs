//! Mock of the Google Cloud DNS API (v1) and of the OAuth 2.0 token endpoint it is used with.
//!
//! Shapes follow the provider's documentation, the same sources the client cites:
//!
//! - Token endpoint (<https://developers.google.com/identity/protocols/oauth2/service-account>):
//!   `POST` with the form members `grant_type` (`urn:ietf:params:oauth:grant-type:jwt-bearer`)
//!   and `assertion`, a JWT whose header has `alg` `RS256` (the only supported value) and `typ`
//!   `JWT`, and an optional `kid`, and whose claims are `iss` (the service account's e-mail),
//!   `scope` (space-delimited), `aud` (the token endpoint), `iat` and `exp` (at most one hour
//!   after `iat`). The answer is `200` with `access_token`, `token_type` and `expires_in`; an
//!   error is `{"error", "error_description"}` with `400` (RFC 6749 section 5.2), `invalid_grant`
//!   for a bad signature, a wrong issuer or audience, or times out of range, and `invalid_scope`
//!   for a scope list that is not space-delimited. The mock verifies the RSASSA-PKCS1-v1_5
//!   SHA-256 signature with `aws-lc-rs` and the public half of a key pair generated at run time
//!   ([`test_key`]); it shares no code with the client. A `kid` that names another key is not
//!   refused: "if the key ID is wrong, all keys of the service account are tried".
//! - Cloud DNS (<https://www.googleapis.com/discovery/v1/apis/dns/v1/rest>, revision 20261111):
//!   `managedZones.list` (`dnsName`, `maxResults`, `pageToken`; `{managedZones, nextPageToken}`),
//!   `managedZones.get` (by name or ID), `resourceRecordSets.list` (`name`, `type` only with
//!   `name`, `maxResults`, `pageToken`; `{rrsets, nextPageToken}`), `changes.create` and
//!   `changes.get`. A `ResourceRecordSet` has `kind`, `name`, `type`, `ttl`, `rrdatas`,
//!   `signatureRrdatas` and `routingPolicy`; a `Change` has `kind`, `id`, `startTime`, `status`
//!   (`pending` or `done`), `isServing`, `additions` and `deletions`, applied atomically;
//!   deletions "Must match existing data exactly". Members outside these schemas are refused.
//! - Errors (<https://google.aip.dev/193>, <https://docs.cloud.google.com/dns/docs/error-messages>):
//!   `{"error": {"code", "message", "status", "errors": [{"domain", "reason", "message"}]}}` with
//!   the reasons `alreadyExists`, `notFound`, `preconditionFailed`, `invalidValue`,
//!   `invalidRecordCount`, `cnameResourceRecordSetConflict`, `recordTypeDisallowedAtZoneApex`,
//!   `wildcardNotAllowed`.
//! - Limits (<https://docs.cloud.google.com/dns/quotas>, records pages): 1000 additions and 1000
//!   deletions per change; 100000 bytes of rrdata per change; a TXT rrdata of at most 1000
//!   characters with character-strings of at most 255; NS and SOA at the zone apex are created
//!   with the zone and cannot be deleted; a CNAME has no other data at its name, holds one
//!   record, and is not at the apex; NS is never a wildcard; MX, CNAME, NS and SRV targets end
//!   with a dot.
//!
//! Answers this mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading. A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - an rrdata of an addition that the deletion of the same rrset in the same change carries is
//!   not checked against the forms above: it is the provider's own data written back (data put
//!   in with [`Control::insert_rrset`] is never checked, so that a test can seed what the API
//!   might return);
//! - the statuses of the reasons: `alreadyExists` 409, `notFound` 404, `preconditionFailed` 412
//!   by default ([`Control::set_precondition_status`] sets another), the other refusals of a
//!   change 400; a missing managed zone 404; a missing or revoked token 401 (`authError`); a
//!   project other than the seed's 403 (`forbidden`);
//! - a deletion matches when name, type, TTL, `rrdatas` (in the same order), `signatureRrdatas`
//!   and `routingPolicy` are equal; `kind` is not compared; a deletion of an rrset that does not
//!   exist is `preconditionFailed` as well;
//! - an addition without `ttl`, a name without the trailing dot or outside the zone, and the
//!   `name` query parameter without the trailing dot are refused (`invalidValue`); the removal of
//!   the apex NS or SOA without an addition of the same name and type is `invalidValue`;
//! - a change is applied when it is accepted and answered `pending`; it is `done` on the first
//!   `changes.get` ([`Control::set_change_polls`] changes the number of looks, 0 answers `done`
//!   at once);
//! - an empty listing has no `rrsets` (or `managedZones`) member; listings are in the order the
//!   rrsets and zones were created; a page token is an offset, any other token is
//!   `invalidValue`; `filter` is refused (the client does not use it, and a mock that ignored
//!   it would hide a client that relied on it);
//! - managed zone IDs are decimal numbers, change IDs too; the IDs of the zones of the seed start
//!   at `1000000000000000001`;
//! - data of the types the supported record types page lists without a form this mock checks
//!   (ALIAS, DNSKEY, DS, HTTPS, IPSECKEY, NAPTR, PTR, SPF, SSHFP, SVCB) are accepted as given; a
//!   type the page does not list is `invalidValue`.
//!
//! Error texts are invented.
//!
//! The mock is a [`ChangeSource`]: it reports every change of its published records through
//! [`GoogleCloudMock::changes`], and a [`link`](crate::link::link) serves them over DNS. A change
//! is published when the mock applies it, which is when it is accepted: polling it changes
//! nothing, and a change refused publishes nothing. Only public managed zones are published;
//! rrsets with a routing policy are left out (they are answered dynamically, which the mock does
//! not model), the SOA rrset (the server that serves the zone answers with its own, as in the
//! Route 53 mock), and an rrset whose owner name is outside its zone (possible only through
//! [`Control::insert_rrset`]). The published form of an rrset: its owner name; the TTL; a name
//! inside a CNAME, NS, PTR, MX or SRV value without the trailing dot given one; a TXT rrdata as
//! quoted character-strings of at most 255 octets (an unquoted rrdata quoted, a longer string
//! split); any other value as stored. [`Control::reset`] returns the mock to its seed.

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
use serde_json::{Map, Value, json};

use crate::changes::{ChangeSource, Changes, Origin, Published};
use crate::{Faults, MockServer, RequestLog};

/// Path of the Cloud DNS API below the server's base URL.
pub const DNS_PATH: &str = "/dns/v1";

/// Path of the token endpoint below the server's base URL.
pub const TOKEN_PATH: &str = "/token";

/// The grant type of the token request.
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Scopes that allow `changes.create`.
const WRITE_SCOPES: [&str; 2] = [
    "https://www.googleapis.com/auth/ndev.clouddns.readwrite",
    "https://www.googleapis.com/auth/cloud-platform",
];

/// Largest number of additions, and of deletions, in one change.
const MAX_CHANGES: usize = 1000;

/// Largest total size of the rrdatas of one change, in bytes.
const MAX_CHANGE_BYTES: usize = 100_000;

/// Longest TXT rrdata, in characters.
const MAX_TXT: usize = 1000;

/// Members of a `ResourceRecordSet`.
const RRSET_MEMBERS: [&str; 7] = [
    "kind",
    "name",
    "type",
    "ttl",
    "rrdatas",
    "signatureRrdatas",
    "routingPolicy",
];

/// Members of a `Change`.
const CHANGE_MEMBERS: [&str; 7] = [
    "kind",
    "id",
    "startTime",
    "status",
    "isServing",
    "additions",
    "deletions",
];

/// Types of the supported record types page.
const LISTED_TYPES: [&str; 20] = [
    "A", "AAAA", "ALIAS", "CAA", "CNAME", "DNSKEY", "DS", "HTTPS", "IPSECKEY", "MX", "NAPTR", "NS",
    "PTR", "SOA", "SPF", "SRV", "SSHFP", "SVCB", "TLSA", "TXT",
];

/// A synthetic RSA key pair, generated at run time and never stored.
pub struct TestKey {
    /// The private key as PKCS#8 PEM.
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
        private_pem: pem("PRIVATE KEY", pkcs8.as_ref()),
        public_der: pair.public_key().as_ref().to_vec(),
    }
}

/// A PEM document with `label` around `der`, with the line breaks a key file holds.
pub fn pem(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
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

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The service account's e-mail: the `iss` the token endpoint accepts.
    pub client_email: String,
    /// The key's ID, written to the key file.
    pub private_key_id: String,
    /// The public key that verifies the JWT, as RSAPublicKey DER.
    pub public_key: Vec<u8>,
    /// The project the service account may use.
    pub project_id: String,
    /// Managed zones, in listing order.
    pub zones: Vec<SeedZone>,
    /// `expires_in` of issued tokens, in seconds.
    pub token_ttl_s: u64,
}

/// A managed zone of the seed.
#[derive(Clone, Debug)]
pub struct SeedZone {
    /// The managed zone's name.
    pub name: String,
    /// The DNS name, with or without the trailing dot.
    pub dns_name: String,
    /// Public (else private).
    pub public: bool,
}

impl Seed {
    /// Service account `zw-test@zw-test-project.iam.gserviceaccount.com` with key
    /// `0123456789abcdef0123456789abcdef01234567` of [`test_key`], project `zw-test-project`
    /// holding the private managed zone `example-org-private` and the public managed zone
    /// `example-org`, both for `example.org.`, in that order. Tokens state a lifetime of one
    /// hour.
    pub fn standard() -> Self {
        Self {
            client_email: "zw-test@zw-test-project.iam.gserviceaccount.com".into(),
            private_key_id: "0123456789abcdef0123456789abcdef01234567".into(),
            public_key: test_key().public_der.clone(),
            project_id: "zw-test-project".into(),
            zones: vec![
                SeedZone {
                    name: "example-org-private".into(),
                    dns_name: "example.org.".into(),
                    public: false,
                },
                SeedZone {
                    name: "example-org".into(),
                    dns_name: "example.org.".into(),
                    public: true,
                },
            ],
            token_ttl_s: 3600,
        }
    }

    /// The service account key file of this seed with `private_pem` as its key, in the shape
    /// the provider's console writes, every member included.
    pub fn key_file(&self, private_pem: &str) -> Value {
        json!({
            "type": "service_account",
            "project_id": self.project_id,
            "private_key_id": self.private_key_id,
            "private_key": private_pem,
            "client_email": self.client_email,
            "client_id": "100000000000000000001",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/zw-test",
            "universe_domain": "googleapis.com",
        })
    }
}

/// A managed zone as the mock holds it.
#[derive(Clone, Debug)]
pub struct Zone {
    /// The zone's ID.
    pub id: String,
    /// The zone's name.
    pub name: String,
    /// The DNS name, lowercase, with the trailing dot.
    pub dns_name: String,
    /// Public.
    pub public: bool,
}

/// An rrset as the mock holds it.
#[derive(Clone, Debug, PartialEq)]
pub struct Rrset {
    /// The managed zone's ID.
    pub zone_id: String,
    /// The owner name, as written (lowercase, with the trailing dot when written by a client).
    pub name: String,
    /// The record type.
    pub rtype: String,
    /// TTL in seconds.
    pub ttl: Option<i64>,
    /// The data.
    pub rrdatas: Vec<String>,
    /// DNSSEC signatures, if any.
    pub signature_rrdatas: Vec<String>,
    /// A routing policy, if any.
    pub routing_policy: Option<Value>,
}

impl Rrset {
    fn to_json(&self) -> Value {
        let mut set = json!({
            "kind": "dns#resourceRecordSet",
            "name": self.name,
            "type": self.rtype,
        });
        if let Some(ttl) = self.ttl {
            set["ttl"] = json!(ttl);
        }
        if !self.rrdatas.is_empty() {
            set["rrdatas"] = json!(self.rrdatas);
        }
        if !self.signature_rrdatas.is_empty() {
            set["signatureRrdatas"] = json!(self.signature_rrdatas);
        }
        if let Some(policy) = &self.routing_policy {
            set["routingPolicy"] = policy.clone();
        }
        set
    }

    /// The exact match of a deletion (module documentation).
    fn matches(&self, other: &Rrset) -> bool {
        self.name == other.name
            && self.rtype == other.rtype
            && self.ttl == other.ttl
            && self.rrdatas == other.rrdatas
            && self.signature_rrdatas == other.signature_rrdatas
            && self.routing_policy == other.routing_policy
    }
}

#[derive(Debug)]
struct Inner {
    /// The seed the mock was started with, for [`Control::reset`].
    original: Seed,
    /// The seed in force; [`Control::set_token_ttl`] changes it.
    seed: Seed,
    changes: Changes,
    token_url: String,
    zones: Vec<Zone>,
    rrsets: Vec<Rrset>,
    tokens: HashMap<String, bool>,
    issued: Vec<String>,
    /// Change ID to the zone it belongs to and the looks left until it is done.
    pending: HashMap<String, (String, u32, Value)>,
    change_polls: u32,
    precondition_status: StatusCode,
    zone_page_size: Option<usize>,
    rrset_page_size: Option<usize>,
    next_id: u64,
}

impl Inner {
    /// The state of a mock started with `seed`; `token_url` is the `aud` the token endpoint
    /// requires.
    fn new(seed: Seed, changes: Changes, token_url: String) -> Inner {
        let mut inner = Inner {
            original: seed.clone(),
            seed: seed.clone(),
            changes,
            token_url,
            zones: Vec::new(),
            rrsets: Vec::new(),
            tokens: HashMap::new(),
            issued: Vec::new(),
            pending: HashMap::new(),
            change_polls: 1,
            precondition_status: StatusCode::PRECONDITION_FAILED,
            zone_page_size: None,
            rrset_page_size: None,
            next_id: 1_000_000_000_000_000_000,
        };
        for zone in &seed.zones {
            inner.add_zone(&zone.name, &zone.dns_name, zone.public);
        }
        inner
    }

    fn new_id(&mut self) -> String {
        self.next_id += 1;
        self.next_id.to_string()
    }

    /// Adds a managed zone with the NS and SOA rrsets of its apex; returns its ID.
    fn add_zone(&mut self, name: &str, dns_name: &str, public: bool) -> String {
        let id = self.new_id();
        let dns_name = fqdn(dns_name);
        self.zones.push(Zone {
            id: id.clone(),
            name: name.to_owned(),
            dns_name: dns_name.clone(),
            public,
        });
        self.add_apex(&id, &dns_name);
        id
    }

    /// The NS and SOA rrsets Cloud DNS creates at the apex of a new zone.
    fn add_apex(&mut self, zone_id: &str, dns_name: &str) {
        let servers: Vec<String> = (1..=4)
            .map(|n| format!("ns-cloud-a{n}.googledomains.com."))
            .collect();
        self.rrsets.push(Rrset {
            zone_id: zone_id.to_owned(),
            name: dns_name.to_owned(),
            rtype: "NS".into(),
            ttl: Some(21600),
            rrdatas: servers,
            signature_rrdatas: Vec::new(),
            routing_policy: None,
        });
        self.rrsets.push(Rrset {
            zone_id: zone_id.to_owned(),
            name: dns_name.to_owned(),
            rtype: "SOA".into(),
            ttl: Some(21600),
            rrdatas: vec![
                "ns-cloud-a1.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 3600 \
                 259200 300"
                    .into(),
            ],
            signature_rrdatas: Vec::new(),
            routing_policy: None,
        });
    }

    /// What a DNS server for the mock's public zones would answer (module documentation).
    fn published(&self) -> Published {
        let mut out = Published::new();
        for zone in self.zones.iter().filter(|z| z.public) {
            out.zone(&zone.dns_name);
        }
        for set in &self.rrsets {
            let Some(zone) = self.zones.iter().find(|z| z.id == set.zone_id && z.public) else {
                continue;
            };
            let name = fqdn(&set.name);
            let inside = name == zone.dns_name || name.ends_with(&format!(".{}", zone.dns_name));
            if !inside || set.routing_policy.is_some() || set.rtype == "SOA" {
                continue;
            }
            let values = set
                .rrdatas
                .iter()
                .map(|d| published_value(&set.rtype, d))
                .collect();
            out.rrset(
                &zone.dns_name,
                &name,
                &set.rtype,
                set.ttl.and_then(|t| u32::try_from(t).ok()),
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

    fn zone(&self, zone: &str) -> Option<Zone> {
        self.zones
            .iter()
            .find(|z| z.id == zone || z.name == zone)
            .cloned()
    }
}

/// An rrdata in zone-file text form (module documentation).
fn published_value(rtype: &str, data: &str) -> String {
    let host = |name: &str| {
        if name.ends_with('.') {
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
        ("TXT", _) => txt_value(data),
        _ => data.to_owned(),
    }
}

/// The character-strings of a TXT rrdata: quoted strings (with `\X` escapes kept), or the
/// unquoted text as one string. `None` when the quotes do not close or text stands between
/// quoted strings.
fn txt_strings(data: &str) -> Option<Vec<String>> {
    if !data.starts_with('"') {
        return Some(vec![data.to_owned()]);
    }
    let mut out = Vec::new();
    let mut chars = data.chars().peekable();
    loop {
        match chars.next() {
            None => return Some(out),
            Some('"') => {}
            Some(_) => return None,
        }
        let mut string = String::new();
        loop {
            match chars.next()? {
                '"' => break,
                '\\' => {
                    string.push('\\');
                    string.push(chars.next()?);
                }
                c => string.push(c),
            }
        }
        out.push(string);
        match chars.peek() {
            None => return Some(out),
            Some(' ') => {
                while chars.peek() == Some(&' ') {
                    chars.next();
                }
            }
            Some(_) => return None,
        }
    }
}

/// A TXT rrdata as quoted character-strings of at most 255 octets each.
fn txt_value(data: &str) -> String {
    let Some(strings) = txt_strings(data) else {
        return data.to_owned();
    };
    let mut out = Vec::new();
    for string in strings {
        // Kept escapes count as written; the strings the client sends hold none.
        let unescaped = string.contains('\\');
        let bytes = string.as_bytes();
        if bytes.is_empty() || unescaped {
            out.push(format!("\"{string}\""));
            continue;
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

/// A running Google Cloud DNS mock. Dereferences to its [`MockServer`] for the request log and
/// the fault queue; [`GoogleCloudMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct GoogleCloudMock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of a [`GoogleCloudMock`]. Cheap to clone, so that a fault hook
/// can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
    changes: Changes,
    log: RequestLog,
    faults: Faults,
}

impl Deref for GoogleCloudMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl GoogleCloudMock {
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
            .route(TOKEN_PATH, post(token))
            .route("/dns/v1/projects/{project}/managedZones", get(zones_list))
            .route(
                "/dns/v1/projects/{project}/managedZones/{zone}",
                get(zone_get),
            )
            .route(
                "/dns/v1/projects/{project}/managedZones/{zone}/rrsets",
                get(rrsets_list),
            )
            .route(
                "/dns/v1/projects/{project}/managedZones/{zone}/changes",
                post(change_create),
            )
            .route(
                "/dns/v1/projects/{project}/managedZones/{zone}/changes/{change}",
                get(change_get),
            )
            .with_state(state.clone());
        let server = MockServer::start_on(addr, router).await;
        lock(&state).token_url = server.url(TOKEN_PATH);
        let control = Control {
            state,
            changes,
            log: server.log().clone(),
            faults: server.faults().clone(),
        };
        Self { server, control }
    }

    /// The Cloud DNS API endpoint, for the client's `dns_url`.
    pub fn dns_url(&self) -> String {
        self.server.url(DNS_PATH)
    }

    /// The token endpoint, for the client's `token_url`; also the `aud` the mock requires.
    pub fn token_url(&self) -> String {
        self.server.url(TOKEN_PATH)
    }

    /// The state control.
    pub fn control(&self) -> &Control {
        &self.control
    }
}

impl ChangeSource for GoogleCloudMock {
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

    /// Returns the mock to the seed it was started with: its zones under their first IDs with
    /// only their apex NS and SOA, no issued tokens, the token lifetime of the seed, no pending
    /// changes, one look per change, `preconditionFailed` answered 412, no page sizes, an empty
    /// request log and no pending faults. Reports the removal of every rrset that was
    /// published.
    pub fn reset(&self) {
        self.faults.clear();
        self.change(|inner| {
            let seed = inner.original.clone();
            let token_url = inner.token_url.clone();
            *inner = Inner::new(seed, inner.changes.clone(), token_url);
        });
        self.log.clear();
    }

    /// Every managed zone.
    pub fn zones(&self) -> Vec<Zone> {
        lock(&self.state).zones.clone()
    }

    /// The ID of the public managed zone of DNS name `zone`, the first if there are several.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn zone_id(&self, zone: &str) -> String {
        let zone = fqdn(zone);
        lock(&self.state)
            .zones
            .iter()
            .find(|z| z.dns_name == zone && z.public)
            .map(|z| z.id.clone())
            .unwrap_or_else(|| panic!("no public zone {zone}"))
    }

    /// Adds a managed zone with its apex NS and SOA; returns its ID.
    pub fn insert_zone(&self, name: &str, dns_name: &str, public: bool) -> String {
        self.change(|inner| inner.add_zone(name, dns_name, public))
    }

    /// Deletes the public managed zone of DNS name `zone` and creates it again, with the same
    /// name and rrsets, under a new ID. Returns the new ID.
    pub fn recreate_zone(&self, zone: &str) -> String {
        let old = self.zone_id(zone);
        self.change(|inner| {
            let new = inner.new_id();
            for z in inner.zones.iter_mut().filter(|z| z.id == old) {
                z.id = new.clone();
            }
            for r in inner.rrsets.iter_mut().filter(|r| r.zone_id == old) {
                r.zone_id = new.clone();
            }
            new
        })
    }

    /// Every rrset.
    pub fn rrsets(&self) -> Vec<Rrset> {
        lock(&self.state).rrsets.clone()
    }

    /// The rrset of `name` and `rtype` in the public zone `zone`, if any.
    pub fn rrset(&self, zone: &str, name: &str, rtype: &str) -> Option<Rrset> {
        let zone_id = self.zone_id(zone);
        let name = fqdn(name);
        lock(&self.state)
            .rrsets
            .iter()
            .find(|r| r.zone_id == zone_id && fqdn(&r.name) == name && r.rtype == rtype)
            .cloned()
    }

    /// The TXT rrdatas of `name` in the public zone `zone`, in order.
    pub fn txt(&self, zone: &str, name: &str) -> Vec<String> {
        self.rrset(zone, name, "TXT")
            .map(|r| r.rrdatas)
            .unwrap_or_default()
    }

    /// Creates an rrset directly, as another writer would, replacing one of the same name and
    /// type. `name` is stored with the trailing dot; the data are not checked.
    pub fn insert_rrset(&self, zone: &str, name: &str, rtype: &str, ttl: i64, rrdatas: &[&str]) {
        let zone_id = self.zone_id(zone);
        let name = fqdn(name);
        self.change(|inner| {
            inner
                .rrsets
                .retain(|r| !(r.zone_id == zone_id && fqdn(&r.name) == name && r.rtype == rtype));
            inner.rrsets.push(Rrset {
                zone_id,
                name,
                rtype: rtype.to_owned(),
                ttl: Some(ttl),
                rrdatas: rrdatas.iter().map(|d| (*d).to_owned()).collect(),
                signature_rrdatas: Vec::new(),
                routing_policy: None,
            });
        });
    }

    /// Changes the rrset of `name` and `rtype` in place through `f`, as another writer would.
    ///
    /// # Panics
    ///
    /// If there is no such rrset.
    pub fn edit_rrset(&self, zone: &str, name: &str, rtype: &str, f: impl FnOnce(&mut Rrset)) {
        let zone_id = self.zone_id(zone);
        let name = fqdn(name);
        self.change(|inner| {
            let set = inner
                .rrsets
                .iter_mut()
                .find(|r| r.zone_id == zone_id && fqdn(&r.name) == name && r.rtype == rtype)
                .unwrap_or_else(|| panic!("no rrset {name} {rtype}"));
            f(set);
        });
    }

    /// Appends `rrdata` to the TXT rrset of `name`, creating it with TTL 300 if needed: a
    /// change by another writer.
    pub fn append_txt(&self, zone: &str, name: &str, rrdata: &str) {
        if self.rrset(zone, name, "TXT").is_some() {
            self.edit_rrset(zone, name, "TXT", |set| set.rrdatas.push(rrdata.to_owned()));
        } else {
            self.insert_rrset(zone, name, "TXT", 300, &[rrdata]);
        }
    }

    /// Deletes an rrset directly, as another writer would.
    pub fn delete_rrset(&self, zone: &str, name: &str, rtype: &str) {
        let zone_id = self.zone_id(zone);
        let name = fqdn(name);
        self.change(|inner| {
            inner
                .rrsets
                .retain(|r| !(r.zone_id == zone_id && fqdn(&r.name) == name && r.rtype == rtype));
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

    /// `expires_in` of tokens issued from now on, in seconds.
    pub fn set_token_ttl(&self, seconds: u64) {
        lock(&self.state).seed.token_ttl_s = seconds;
    }

    /// Number of looks a change is answered `pending` for before it is `done`; `0` answers the
    /// change `done` at once.
    pub fn set_change_polls(&self, polls: u32) {
        lock(&self.state).change_polls = polls;
    }

    /// The status of a `preconditionFailed` refusal (not documented; see the module).
    ///
    /// # Panics
    ///
    /// If `status` is not a valid HTTP status.
    pub fn set_precondition_status(&self, status: u16) {
        lock(&self.state).precondition_status =
            StatusCode::from_u16(status).expect("a valid HTTP status");
    }

    /// Page size of the managed zone listing.
    pub fn set_zone_page_size(&self, size: usize) {
        lock(&self.state).zone_page_size = Some(size);
    }

    /// Page size of the rrset listing.
    pub fn set_rrset_page_size(&self, size: usize) {
        lock(&self.state).rrset_page_size = Some(size);
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
fn error(status: StatusCode, reason: &str, message: &str) -> Response {
    let rpc = match status.as_u16() {
        400 => "INVALID_ARGUMENT",
        401 => "UNAUTHENTICATED",
        403 => "PERMISSION_DENIED",
        404 => "NOT_FOUND",
        409 => "ALREADY_EXISTS",
        _ => "FAILED_PRECONDITION",
    };
    (
        status,
        axum::Json(json!({"error": {
            "code": status.as_u16(),
            "message": message,
            "status": rpc,
            "errors": [{"domain": "global", "reason": reason, "message": message}],
        }})),
    )
        .into_response()
}

fn invalid(message: &str) -> Response {
    error(StatusCode::BAD_REQUEST, "invalidValue", message)
}

fn token_error(code: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(json!({"error": code, "error_description": description})),
    )
        .into_response()
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn b64_json(part: &str) -> Option<Value> {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).ok()?).ok()
}

/// Decodes a form body (WHATWG `application/x-www-form-urlencoded`).
fn form_pairs(body: &[u8]) -> HashMap<String, String> {
    fn decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'+' => out.push(b' '),
                b'%' if i + 2 < bytes.len() => {
                    let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                    match u8::from_str_radix(hex, 16) {
                        Ok(b) => {
                            out.push(b);
                            i += 2;
                        }
                        Err(_) => out.push(b'%'),
                    }
                }
                b => out.push(b),
            }
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
    String::from_utf8_lossy(body)
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (decode(k), decode(v)),
            None => (decode(pair), String::new()),
        })
        .collect()
}

/// Checks a JWT as the documentation describes it, signature included: `Ok`, or the OAuth
/// error code and description.
fn check_jwt(inner: &Inner, jwt: &str) -> Result<(), (&'static str, &'static str)> {
    let grant = |text| Err(("invalid_grant", text));
    let parts: Vec<&str> = jwt.split('.').collect();
    let [header, claims, sig] = parts.as_slice() else {
        return grant("Invalid JWT: the assertion is not three parts");
    };
    let (Some(h), Some(c), Ok(sig)) = (
        b64_json(header),
        b64_json(claims),
        URL_SAFE_NO_PAD.decode(sig),
    ) else {
        return grant("Invalid JWT: a part does not decode");
    };
    if h["alg"] != "RS256" || h["typ"] != "JWT" {
        return grant("Invalid JWT: alg must be RS256 and typ JWT");
    }
    let message = format!("{header}.{claims}");
    let verified = UnparsedPublicKey::new(
        &signature::RSA_PKCS1_2048_8192_SHA256,
        &inner.seed.public_key,
    )
    .verify(message.as_bytes(), &sig)
    .is_ok();
    if !verified {
        return grant("Invalid JWT Signature.");
    }
    if c["iss"] != inner.seed.client_email.as_str() {
        return grant("Invalid JWT: iss is not a known service account");
    }
    if c["aud"] != inner.token_url.as_str() {
        return grant("Invalid JWT: aud is not the token endpoint");
    }
    let (iat, exp) = (c["iat"].as_i64(), c["exp"].as_i64());
    let now = now();
    let times_ok = matches!((iat, exp), (Some(iat), Some(exp))
        if iat <= now + 60 && exp > now && exp > iat && exp - iat <= 3600);
    if !times_ok {
        return grant("Invalid JWT: Token must be a short-lived token (60 minutes)");
    }
    let scope = c["scope"].as_str().unwrap_or("");
    if scope.is_empty() || scope.contains(',') {
        return Err(("invalid_scope", "scopes must be space-delimited"));
    }
    // A token without a scope that allows writes is of no use to a client that writes.
    if !scope.split(' ').any(|s| WRITE_SCOPES.contains(&s)) {
        return Err(("invalid_scope", "the scope does not allow changes"));
    }
    Ok(())
}

async fn token(State(state): State<Shared>, body: Bytes) -> Response {
    let form = form_pairs(&body);
    if form.get("grant_type").map(String::as_str) != Some(GRANT_TYPE) {
        return token_error("unsupported_grant_type", "Invalid grant_type");
    }
    let Some(jwt) = form.get("assertion") else {
        return token_error("invalid_request", "assertion is required");
    };
    let mut inner = lock(&state);
    if let Err((code, description)) = check_jwt(&inner, jwt) {
        return token_error(code, description);
    }
    let token = format!("ya29.mock-access-token-{:04}", inner.issued.len() + 1);
    inner.tokens.insert(token.clone(), false);
    inner.issued.push(token.clone());
    axum::Json(json!({
        "access_token": token,
        "expires_in": inner.seed.token_ttl_s,
        "token_type": "Bearer",
    }))
    .into_response()
}

/// The `401` answer unless the request carries a live token, and the `403` answer for a project
/// other than the seed's.
fn authorize(inner: &Inner, headers: &HeaderMap, project: &str) -> Result<(), Response> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    match inner.tokens.get(token) {
        Some(false) => {}
        _ => {
            return Err(error(
                StatusCode::UNAUTHORIZED,
                "authError",
                "Request had invalid authentication credentials.",
            ));
        }
    }
    if project != inner.seed.project_id {
        return Err(error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "The caller does not have permission",
        ));
    }
    Ok(())
}

fn zone_json(zone: &Zone) -> Value {
    let mut out = json!({
        "kind": "dns#managedZone",
        "id": zone.id,
        "name": zone.name,
        "dnsName": zone.dns_name,
        "description": "",
        "creationTime": "2026-01-10T12:00:00.000Z",
        "nameServers": (1..=4).map(|n| format!("ns-cloud-a{n}.googledomains.com.")).collect::<Vec<_>>(),
    });
    if zone.public {
        out["visibility"] = json!("public");
    } else {
        out["visibility"] = json!("private");
        out["privateVisibilityConfig"] =
            json!({"kind": "dns#managedZonePrivateVisibilityConfig", "networks": []});
    }
    out
}

/// The offset a page token stands for, or the refusal of a token the mock did not issue.
fn page_offset(q: &HashMap<String, String>) -> Result<usize, Response> {
    match q.get("pageToken").map(|s| s.parse::<usize>()) {
        None => Ok(0),
        Some(Ok(offset)) => Ok(offset),
        Some(Err(_)) => Err(invalid("Invalid value for page token")),
    }
}

/// The page size: the mock's own, else `maxResults`, else everything.
fn page_size(
    q: &HashMap<String, String>,
    own: Option<usize>,
    total: usize,
) -> Result<usize, Response> {
    let asked = match q.get("maxResults").map(|s| s.parse::<usize>()) {
        None => total.max(1),
        Some(Ok(size)) if size >= 1 => size,
        Some(_) => return Err(invalid("Invalid value for maxResults")),
    };
    Ok(own.unwrap_or(asked).max(1))
}

/// One page of `items` under `key`; an empty page has no `key` member.
fn page(kind: &str, key: &str, items: &[Value], offset: usize, size: usize) -> Response {
    let chunk: Vec<Value> = items.iter().skip(offset).take(size).cloned().collect();
    let mut out = json!({"kind": kind});
    if !chunk.is_empty() {
        out[key] = json!(chunk);
    }
    if offset + size < items.len() {
        out["nextPageToken"] = json!((offset + size).to_string());
    }
    axum::Json(out).into_response()
}

async fn zones_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let inner = lock(&state);
    if let Err(response) = authorize(&inner, &headers, &project) {
        return response;
    }
    let wanted = q.get("dnsName").map(|n| fqdn(n));
    let all: Vec<Value> = inner
        .zones
        .iter()
        .filter(|z| wanted.as_ref().is_none_or(|w| *w == z.dns_name))
        .map(zone_json)
        .collect();
    let offset = match page_offset(&q) {
        Ok(offset) => offset,
        Err(response) => return response,
    };
    let size = match page_size(&q, inner.zone_page_size, all.len()) {
        Ok(size) => size,
        Err(response) => return response,
    };
    page(
        "dns#managedZonesListResponse",
        "managedZones",
        &all,
        offset,
        size,
    )
}

async fn zone_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((project, zone)): Path<(String, String)>,
) -> Response {
    let inner = lock(&state);
    if let Err(response) = authorize(&inner, &headers, &project) {
        return response;
    }
    match inner.zone(&zone) {
        Some(zone) => axum::Json(zone_json(&zone)).into_response(),
        None => error(
            StatusCode::NOT_FOUND,
            "notFound",
            "The 'parameters.managedZone' resource named 'zone' does not exist.",
        ),
    }
}

async fn rrsets_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((project, zone)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let inner = lock(&state);
    if let Err(response) = authorize(&inner, &headers, &project) {
        return response;
    }
    let Some(zone) = inner.zone(&zone) else {
        return error(
            StatusCode::NOT_FOUND,
            "notFound",
            "The 'parameters.managedZone' resource named 'zone' does not exist.",
        );
    };
    if q.contains_key("filter") {
        return invalid("this mock does not implement filter");
    }
    let name = q.get("name");
    let rtype = q.get("type");
    if rtype.is_some() && name.is_none() {
        return invalid("type requires name");
    }
    if name.is_some_and(|n| !n.ends_with('.')) {
        return invalid("name must be a fully qualified domain name");
    }
    let all: Vec<Value> = inner
        .rrsets
        .iter()
        .filter(|r| r.zone_id == zone.id)
        .filter(|r| name.is_none_or(|n| fqdn(n) == fqdn(&r.name)))
        .filter(|r| rtype.is_none_or(|t| *t == r.rtype))
        .map(Rrset::to_json)
        .collect();
    let offset = match page_offset(&q) {
        Ok(offset) => offset,
        Err(response) => return response,
    };
    let size = match page_size(&q, inner.rrset_page_size, all.len()) {
        Ok(size) => size,
        Err(response) => return response,
    };
    page(
        "dns#resourceRecordSetsListResponse",
        "rrsets",
        &all,
        offset,
        size,
    )
}

/// An rrset of a change, held to the schema: only its members, a string `name` and `type`, an
/// integer `ttl`, lists of strings.
fn parse_rrset(value: &Value, zone: &Zone, addition: bool) -> Result<Rrset, Response> {
    let Some(object) = value.as_object() else {
        return Err(invalid("an rrset is not an object"));
    };
    if let Some(key) = object.keys().find(|k| !RRSET_MEMBERS.contains(&k.as_str())) {
        return Err(invalid(&format!("unknown member {key}")));
    }
    let strings = |key: &str| -> Result<Vec<String>, Response> {
        match object.get(key) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| invalid(&format!("{key} holds a non-string")))
                })
                .collect(),
            Some(_) => Err(invalid(&format!("{key} is not a list"))),
        }
    };
    let name = object.get("name").and_then(Value::as_str).unwrap_or("");
    if !name.ends_with('.') || name.len() < 2 {
        return Err(invalid("name must be a fully qualified domain name"));
    }
    let lower = name.to_lowercase();
    if lower != zone.dns_name && !lower.ends_with(&format!(".{}", zone.dns_name)) {
        return Err(invalid(
            "the name of this resource record set must have the DNS name of the managed zone as its suffix",
        ));
    }
    let rtype = object.get("type").and_then(Value::as_str).unwrap_or("");
    let ttl = match object.get("ttl") {
        None | Some(Value::Null) => None,
        Some(Value::Number(n)) => match n.as_i64() {
            Some(ttl) if (0..=i64::from(i32::MAX)).contains(&ttl) => Some(ttl),
            _ => return Err(invalid("ttl is out of range")),
        },
        Some(_) => return Err(invalid("ttl is not an integer")),
    };
    if addition && ttl.is_none() {
        return Err(invalid("ttl is required"));
    }
    let routing_policy = object
        .get("routingPolicy")
        .filter(|v| !v.is_null())
        .cloned();
    let set = Rrset {
        zone_id: zone.id.clone(),
        name: lower,
        rtype: rtype.to_owned(),
        ttl,
        rrdatas: strings("rrdatas")?,
        signature_rrdatas: strings("signatureRrdatas")?,
        routing_policy,
    };
    if addition && set.rrdatas.is_empty() && set.routing_policy.is_none() {
        return Err(invalid("an rrset must hold rrdatas or a routing policy"));
    }
    Ok(set)
}

/// Checks an addition against the record pages (module documentation): the reason and message
/// of a refusal.
fn check_addition(
    set: &Rrset,
    zone: &Zone,
    kept: &[&String],
) -> Result<(), (&'static str, String)> {
    let fail = |reason: &'static str, what: &str| {
        Err((reason, format!("{} {}: {what}", set.name, set.rtype)))
    };
    if !LISTED_TYPES.contains(&set.rtype.as_str()) {
        return fail("invalidValue", "the record type is not supported");
    }
    let apex = set.name == zone.dns_name;
    if set.rtype == "CNAME" && apex {
        return fail(
            "recordTypeDisallowedAtZoneApex",
            "a CNAME is not allowed at the apex",
        );
    }
    if set.rtype == "NS" && set.name.starts_with("*.") {
        return fail("wildcardNotAllowed", "NS records cannot be wildcards");
    }
    if matches!(set.rtype.as_str(), "CNAME" | "SOA") && set.rrdatas.len() != 1 {
        return fail("invalidRecordCount", "this type holds exactly one record");
    }
    for data in set.rrdatas.iter().filter(|d| !kept.contains(d)) {
        if let Err(what) = check_data(&set.rtype, data) {
            return fail("invalidValue", &what);
        }
    }
    Ok(())
}

/// Checks one rrdata of type `rtype` (module documentation).
fn check_data(rtype: &str, text: &str) -> Result<(), String> {
    let fail = |what: &str| Err(format!("rrdata {what}"));
    if text.is_empty() {
        return fail("is empty");
    }
    let fields: Vec<&str> = text.split(' ').collect();
    let target = |name: &str| {
        name.ends_with('.')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'*'))
            && !name.contains("..")
    };
    let number = |field: &str| field.parse::<u16>().is_ok();
    let hex = |field: &str| !field.is_empty() && field.bytes().all(|b| b.is_ascii_hexdigit());
    let ok = match (rtype, fields.as_slice()) {
        ("A", [address]) => address.parse::<std::net::Ipv4Addr>().is_ok(),
        ("AAAA", [address]) => address.parse::<std::net::Ipv6Addr>().is_ok(),
        ("CNAME" | "NS", [name]) => target(name),
        ("MX", [preference, exchange]) => number(preference) && target(exchange),
        ("SRV", [priority, weight, port, name]) => {
            number(priority) && number(weight) && number(port) && target(name)
        }
        ("CAA", [flags, tag, value @ ..]) => {
            let value = value.join(" ");
            flags.parse::<u8>().is_ok()
                && !tag.is_empty()
                && tag.bytes().all(|b| b.is_ascii_alphanumeric())
                && value.len() >= 2
                && value.starts_with('"')
                && value.ends_with('"')
        }
        ("TLSA", [usage, selector, matching, data]) => {
            usage.parse::<u8>().is_ok()
                && selector.parse::<u8>().is_ok()
                && matching.parse::<u8>().is_ok()
                && hex(data)
        }
        ("SOA", [mname, rname, rest @ ..]) => target(mname) && target(rname) && rest.len() == 5,
        ("TXT", _) => return check_txt(text),
        ("A" | "AAAA" | "CNAME" | "NS" | "MX" | "SRV" | "CAA" | "TLSA" | "SOA", _) => false,
        // Listed types whose form the mock does not check.
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        fail("is not in the documented form")
    }
}

/// TXT: at most 1000 characters; one unquoted string without spaces or quotes, or quoted
/// strings of at most 255 characters separated by spaces.
fn check_txt(text: &str) -> Result<(), String> {
    if text.chars().count() > MAX_TXT {
        return Err("TXT rrdata is longer than 1000 characters".into());
    }
    if !text.starts_with('"') && text.contains([' ', '"']) {
        return Err("TXT rrdata with spaces or quotes must be quoted".into());
    }
    match txt_strings(text) {
        None => Err("TXT rrdata is not quoted character-strings".into()),
        Some(strings) if strings.iter().any(|s| s.len() > 255) => {
            Err("a TXT character-string is longer than 255 characters".into())
        }
        Some(_) => Ok(()),
    }
}

async fn change_create(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((project, zone)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let mut inner = lock(&state);
    if let Err(response) = authorize(&inner, &headers, &project) {
        return response;
    }
    let Some(zone) = inner.zone(&zone) else {
        return error(
            StatusCode::NOT_FOUND,
            "notFound",
            "The 'parameters.managedZone' resource named 'zone' does not exist.",
        );
    };
    let Ok(Value::Object(request)) = serde_json::from_slice::<Value>(&body) else {
        return invalid("malformed request body");
    };
    if let Some(key) = request
        .keys()
        .find(|k| !CHANGE_MEMBERS.contains(&k.as_str()))
    {
        return invalid(&format!("unknown member {key}"));
    }
    let list = |key: &str, addition: bool| -> Result<Vec<Rrset>, Response> {
        match request.get(key) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(items)) if items.len() <= MAX_CHANGES => items
                .iter()
                .map(|v| parse_rrset(v, &zone, addition))
                .collect(),
            Some(_) => Err(invalid("additions and deletions are lists of at most 1000")),
        }
    };
    let (deletions, additions) = match (list("deletions", false), list("additions", true)) {
        (Ok(d), Ok(a)) => (d, a),
        (Err(response), _) | (_, Err(response)) => return response,
    };
    if deletions.is_empty() && additions.is_empty() {
        return invalid("the change is empty");
    }
    let bytes: usize = deletions
        .iter()
        .chain(&additions)
        .flat_map(|r| r.rrdatas.iter())
        .map(String::len)
        .sum();
    if bytes > MAX_CHANGE_BYTES {
        return invalid("the change holds more than 100000 bytes of rrdata");
    }
    // An rrdata that the deletion of the same rrset in this change carries is the provider's
    // own data written back, and is not checked again (invented; see the module).
    for addition in &additions {
        let kept: Vec<&String> = deletions
            .iter()
            .filter(|d| d.name == addition.name && d.rtype == addition.rtype)
            .flat_map(|d| d.rrdatas.iter())
            .collect();
        if let Err((reason, message)) = check_addition(addition, &zone, &kept) {
            return error(StatusCode::BAD_REQUEST, reason, &message);
        }
    }
    let mut next = inner.rrsets.clone();
    for (index, deletion) in deletions.iter().enumerate() {
        let position = next.iter().position(|r| {
            r.zone_id == zone.id && fqdn(&r.name) == deletion.name && r.rtype == deletion.rtype
        });
        match position {
            Some(p) if next[p].matches(deletion) => {
                next.remove(p);
            }
            _ => {
                return error(
                    inner.precondition_status,
                    "preconditionFailed",
                    &format!(
                        "The resource 'entity.change.deletions[{index}]' named '{} ({})' does not exist or does not match.",
                        deletion.name, deletion.rtype
                    ),
                );
            }
        }
    }
    for (index, addition) in additions.iter().enumerate() {
        let same = |r: &Rrset| r.zone_id == zone.id && fqdn(&r.name) == addition.name;
        if next.iter().any(|r| same(r) && r.rtype == addition.rtype) {
            return error(
                StatusCode::CONFLICT,
                "alreadyExists",
                &format!(
                    "The resource 'entity.change.additions[{index}]' named '{} ({})' already exists",
                    addition.name, addition.rtype
                ),
            );
        }
        if next
            .iter()
            .any(|r| same(r) && (r.rtype == "CNAME") != (addition.rtype == "CNAME"))
        {
            return error(
                StatusCode::BAD_REQUEST,
                "cnameResourceRecordSetConflict",
                "A CNAME cannot coexist with other data at its name",
            );
        }
        next.push(addition.clone());
    }
    for rtype in ["NS", "SOA"] {
        let kept = next
            .iter()
            .any(|r| r.zone_id == zone.id && fqdn(&r.name) == zone.dns_name && r.rtype == rtype);
        if !kept {
            return invalid("the NS and SOA records at the zone apex cannot be deleted");
        }
    }
    let before = inner.published();
    inner.rrsets = next;
    inner.report(&before, Origin::Api);
    let id = inner.new_id();
    let polls = inner.change_polls;
    let mut change = json!({
        "kind": "dns#change",
        "id": id,
        "startTime": "2026-01-10T12:00:00.000Z",
        "status": if polls == 0 { "done" } else { "pending" },
        "isServing": true,
        "additions": additions.iter().map(Rrset::to_json).collect::<Vec<_>>(),
        "deletions": deletions.iter().map(Rrset::to_json).collect::<Vec<_>>(),
    });
    if let Value::Object(map) = &mut change {
        strip_empty(map);
    }
    inner
        .pending
        .insert(id, (zone.id.clone(), polls, change.clone()));
    axum::Json(change).into_response()
}

/// Leaves out empty lists, as the API's answers do.
fn strip_empty(map: &mut Map<String, Value>) {
    map.retain(|_, v| !matches!(v, Value::Array(items) if items.is_empty()));
}

async fn change_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((project, zone, change)): Path<(String, String, String)>,
) -> Response {
    let mut inner = lock(&state);
    if let Err(response) = authorize(&inner, &headers, &project) {
        return response;
    }
    let Some(zone) = inner.zone(&zone) else {
        return error(
            StatusCode::NOT_FOUND,
            "notFound",
            "The 'parameters.managedZone' resource named 'zone' does not exist.",
        );
    };
    let Some((owner, polls, body)) = inner.pending.get_mut(&change) else {
        return error(
            StatusCode::NOT_FOUND,
            "notFound",
            "The 'parameters.changeId' resource named 'change' does not exist.",
        );
    };
    if *owner != zone.id {
        return error(
            StatusCode::NOT_FOUND,
            "notFound",
            "The 'parameters.changeId' resource named 'change' does not exist.",
        );
    }
    *polls = polls.saturating_sub(1);
    let mut out = body.clone();
    out["status"] = json!(if *polls == 0 { "done" } else { "pending" });
    axum::Json(out).into_response()
}

#[cfg(test)]
mod tests {
    use super::{check_data, published_value, txt_strings};

    #[test]
    fn data_follow_the_record_pages() {
        for (rtype, text) in [
            ("A", "192.0.2.1"),
            ("AAAA", "2001:db8::1"),
            ("CNAME", "host.example.com."),
            ("MX", "10 mail.example.com."),
            ("SRV", "10 70 8080 host.example.com."),
            ("CAA", "0 issue \"ca.example.net\""),
            ("TLSA", "3 1 1 0a1b"),
            ("TXT", "\"v=spf1 -all\""),
            ("TXT", "\"a\" \"b\""),
            ("TXT", "token"),
            ("PTR", "anything"),
        ] {
            assert_eq!(check_data(rtype, text), Ok(()), "{rtype} {text}");
        }
        for (rtype, text) in [
            ("A", "192.0.2.256"),
            ("MX", "10 mail.example.com"),
            ("CNAME", "host"),
            ("TXT", "two words"),
            ("TXT", "\"a\"b"),
            ("TXT", "\"open"),
        ] {
            assert!(check_data(rtype, text).is_err(), "{rtype} {text}");
        }
        let long = format!("\"{}\"", "x".repeat(256));
        assert!(check_data("TXT", &long).is_err());
    }

    #[test]
    fn txt_is_published_quoted() {
        assert_eq!(published_value("TXT", "token"), "\"token\"");
        assert_eq!(published_value("TXT", "\"a b\" \"c\""), "\"a b\" \"c\"");
        assert_eq!(published_value("MX", "10 mail"), "10 mail.");
        assert_eq!(
            txt_strings("\"a\"  \"b\"").unwrap(),
            vec!["a".to_owned(), "b".to_owned()]
        );
    }
}
