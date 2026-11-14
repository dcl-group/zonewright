//! Mock of the Amazon Route 53 REST/XML API `2013-04-01`.
//!
//! Shapes follow the provider's documentation, the same sources the client cites:
//!
//! - API reference (<https://docs.aws.amazon.com/Route53/latest/APIReference/>):
//!   `ListHostedZonesByName` (zones sorted by name with the labels reversed, at most 100 per
//!   page, `dnsname` and `hostedzoneid` to continue, `IsTruncated`, `NextDNSName` and
//!   `NextHostedZoneId` only when truncated), `GetHostedZone` (`NoSuchHostedZone`, 404),
//!   `ListResourceRecordSets` (starts at the first rrset whose name and type are greater than or
//!   equal to the ones given, at most 300 per page, `type` without `name` is `InvalidInput`,
//!   `NoSuchHostedZone`, 404; `identifier` and `NextRecordIdentifier` for routing-policy sets of
//!   one name and type), `ChangeResourceRecordSets` (all changes or none; `CREATE` of an
//!   existing rrset, `DELETE` of one that does not match exactly, and deleting the same rrset
//!   twice are `InvalidChangeBatch`, 400; `ChangeInfo` with `PENDING`), `GetChange` (`PENDING`,
//!   then `INSYNC`; `NoSuchChange`, 404).
//! - `ResourceRecordSet`: TTL 0 to 2147483647; no wildcard NS; alias sets without TTL and
//!   records. "Supported DNS record types": no CNAME at the apex nor next to other records at
//!   its name.
//! - Developer Guide: names returned lowercase with every character other than `a-z`, `0-9`,
//!   `-` and `_` as a `\ooo` octal escape; TXT values as quoted strings of at most 255
//!   characters; quotas (400 records per rrset, 1,000 `ResourceRecord` elements and 32,000 value
//!   characters per batch, `UPSERT` counted twice; 4,000 characters per value).
//! - AWS SigV4 documentation: the signature is verified here with `aws-lc-rs` directly, by code
//!   that shares nothing with the crate under test; a mismatch answers 403
//!   `SignatureDoesNotMatch` whose message repeats the canonical request and the string to sign,
//!   as the troubleshooting page describes; a date more than 5 minutes off answers "Signature
//!   expired" or "Signature not yet current".
//!
//! Answers this mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading. A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - error bodies are `<ErrorResponse><Error><Type/><Code/><Message/></Error><RequestId/>`, and
//!   `InvalidChangeBatch` is `<InvalidChangeBatch><Messages><Message/>...</Messages>`;
//! - an unknown access key answers 403 `UnrecognizedClientException`, a missing or wrong session
//!   token 403 `InvalidClientTokenId`, a missing `Authorization` 403 `MissingAuthenticationToken`,
//!   a scope, date or signature mismatch 403 `SignatureDoesNotMatch`;
//! - the batch limits, a name outside the zone, an unquoted TXT string and a string over 255
//!   characters are refused with `InvalidChangeBatch`;
//! - a malformed batch document answers 400 `InvalidInput`;
//! - `maxitems` above the documented page size is served as the page size;
//! - a new hosted zone holds an SOA and an NS rrset at its apex;
//! - a change stays `PENDING` for [`Control::set_pending_polls`] looks (0 by default), then is
//!   `INSYNC`; the change ID is returned with the `/change/` prefix;
//! - values are stored and returned exactly as written (Route 53 may normalize them), and a
//!   `DELETE` must repeat them character for character;
//! - a value is checked against the format "Supported DNS record types" gives for its type (the
//!   checks are the mock's reading of that page), and a value outside it is `InvalidChangeBatch`;
//! - in a quoted string, an octal escape counts as one character towards the 255;
//! - `CREATE` or `DELETE` of the SOA rrset is `InvalidChangeBatch`;
//! - the elements of a listed rrset come in the order `Name`, `Type`, `SetIdentifier`, the
//!   routing elements, then `TTL` and `ResourceRecords` or `AliasTarget`; a set with an
//!   identifier and no other routing element is listed with `<Weight>10</Weight>`;
//! - routing-policy sets of one name and type are sorted by `SetIdentifier`.
//!
//! Error texts are invented.

// Handlers return finished HTTP answers as their error values and hand them straight to axum;
// boxing them would only add noise.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::{digest, hmac};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::MockServer;

/// The XML namespace of the API.
pub const XMLNS: &str = "https://route53.amazonaws.com/doc/2013-04-01/";

/// Page sizes of the two listings.
const ZONE_PAGE: usize = 100;
const RRSET_PAGE: usize = 300;

/// Quotas of a change batch and an rrset.
const MAX_RECORDS_PER_BATCH: usize = 1000;
const MAX_VALUE_CHARS_PER_BATCH: usize = 32_000;
const MAX_RECORDS_PER_SET: usize = 400;
const MAX_VALUE_CHARS: usize = 4000;

/// Largest TTL (API reference, `ResourceRecordSet.TTL`).
const MAX_TTL: u64 = 2_147_483_647;

/// Largest difference between `x-amz-date` and the mock's clock.
const MAX_SKEW_S: i64 = 300;

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The access key ID requests must be signed with.
    pub access_key_id: String,
    /// The secret access key.
    pub secret_access_key: String,
    /// The session token requests must carry, for temporary credentials.
    pub session_token: Option<String>,
    /// Hosted zones.
    pub zones: Vec<SeedZone>,
}

/// A hosted zone of the seed.
#[derive(Clone, Debug)]
pub struct SeedZone {
    /// The hosted zone ID, without the `/hostedzone/` prefix.
    pub id: String,
    /// The zone name, with or without the trailing dot.
    pub name: String,
    /// A private hosted zone.
    pub private: bool,
}

impl SeedZone {
    /// A zone of the seed.
    pub fn new(id: &str, name: &str, private: bool) -> Self {
        Self {
            id: id.to_owned(),
            name: name.to_owned(),
            private,
        }
    }
}

impl Seed {
    /// Access key `AKIAZWTEST0000000001` with a test secret and no session token; a private and
    /// a public zone `example.org.`, and a public zone `example.net.`.
    pub fn standard() -> Self {
        Self {
            access_key_id: "AKIAZWTEST0000000001".into(),
            secret_access_key: "test-only-secret/key+0000000000000000000".into(),
            session_token: None,
            zones: vec![
                SeedZone::new("ZPRIVATE0000000001", "example.org.", true),
                SeedZone::new("ZEXAMPLE0000000001", "example.org.", false),
                SeedZone::new("ZOTHER000000000001", "example.net.", false),
            ],
        }
    }
}

/// A hosted zone as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Zone {
    /// The ID, without the prefix.
    pub id: String,
    /// The name: lowercase, with the trailing dot, unescaped.
    pub name: String,
    /// A private zone.
    pub private: bool,
}

/// An rrset as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rrset {
    /// The hosted zone it belongs to.
    pub zone_id: String,
    /// The owner name: lowercase, with the trailing dot, unescaped.
    pub name: String,
    /// The record type.
    pub rtype: String,
    /// TTL in seconds.
    pub ttl: u64,
    /// The values in the API's text form.
    pub values: Vec<String>,
    /// The identifier of a routing-policy set; `None` for a simple one.
    pub set_identifier: Option<String>,
    /// Further elements of the set as XML (`<Weight>`, `<HealthCheckId>`, ...), rendered after
    /// `SetIdentifier`; `None` renders `<Weight>10</Weight>` for a set with an identifier.
    pub routing: Option<String>,
    /// The `DNSName` of an alias set, which has no TTL and no records.
    pub alias: Option<String>,
}

#[derive(Debug)]
struct Inner {
    seed: Seed,
    zones: Vec<Zone>,
    rrsets: Vec<Rrset>,
    /// Change ID to the number of `PENDING` answers left.
    changes: HashMap<String, u32>,
    batches: Vec<String>,
    pending_polls: u32,
    next_id: u64,
}

impl Inner {
    fn new_id(&mut self, prefix: char) -> String {
        self.next_id += 1;
        format!("{prefix}{:013X}", self.next_id)
    }

    fn zone(&self, id: &str) -> Option<&Zone> {
        self.zones.iter().find(|z| z.id == id)
    }

    fn add_zone(&mut self, id: &str, name: &str, private: bool) {
        let name = fqdn(name);
        self.zones.push(Zone {
            id: id.to_owned(),
            name: name.clone(),
            private,
        });
        self.rrsets.push(Rrset {
            zone_id: id.to_owned(),
            name: name.clone(),
            rtype: "SOA".into(),
            ttl: 900,
            values: vec![
                "ns-1.awsdns-00.test. hostmaster.awsdns.test. 1 7200 900 1209600 86400".into(),
            ],
            set_identifier: None,
            routing: None,
            alias: None,
        });
        self.rrsets.push(Rrset {
            zone_id: id.to_owned(),
            name,
            rtype: "NS".into(),
            ttl: 172_800,
            values: vec!["ns-1.awsdns-00.test.".into(), "ns-2.awsdns-00.test.".into()],
            set_identifier: None,
            routing: None,
            alias: None,
        });
    }
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running Route 53 mock. Dereferences to its [`MockServer`] for the request log and the
/// fault queue; [`Route53Mock::control`] reads and changes the state.
#[derive(Debug)]
pub struct Route53Mock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of a [`Route53Mock`]. Cheap to clone, so that a fault hook can
/// change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
}

impl Deref for Route53Mock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl Route53Mock {
    /// Starts the mock with `seed`.
    pub async fn start(seed: Seed) -> Self {
        let mut inner = Inner {
            seed: seed.clone(),
            zones: Vec::new(),
            rrsets: Vec::new(),
            changes: HashMap::new(),
            batches: Vec::new(),
            pending_polls: 0,
            next_id: 0,
        };
        for zone in &seed.zones {
            inner.add_zone(&zone.id, &zone.name, zone.private);
        }
        let state = Arc::new(Mutex::new(inner));
        let router = Router::new()
            .route("/2013-04-01/hostedzonesbyname", get(zones_by_name))
            .route("/2013-04-01/hostedzone/{id}", get(get_zone))
            .route("/2013-04-01/hostedzone/{id}/rrset", get(list_rrsets))
            .route("/2013-04-01/hostedzone/{id}/rrset/", post(change_rrsets))
            .route("/2013-04-01/change/{id}", get(get_change))
            .with_state(state.clone());
        Self {
            server: MockServer::start(router).await,
            control: Control { state },
        }
    }

    /// The API endpoint, for the client's `base_url`.
    pub fn base_url(&self) -> String {
        self.server.base_url()
    }

    /// The state control.
    pub fn control(&self) -> &Control {
        &self.control
    }
}

impl Control {
    /// Every hosted zone.
    pub fn zones(&self) -> Vec<Zone> {
        lock(&self.state).zones.clone()
    }

    /// The ID of the public zone `name`.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn zone_id(&self, name: &str) -> String {
        let name = fqdn(name);
        lock(&self.state)
            .zones
            .iter()
            .find(|z| z.name == name && !z.private)
            .map(|z| z.id.clone())
            .unwrap_or_else(|| panic!("no public zone {name}"))
    }

    /// Adds a hosted zone.
    pub fn insert_zone(&self, id: &str, name: &str, private: bool) {
        lock(&self.state).add_zone(id, name, private);
    }

    /// Deletes the public zone `name` and creates it again under a new ID, with the same rrsets.
    /// Returns the new ID.
    ///
    /// # Panics
    ///
    /// If there is no such zone.
    pub fn recreate_zone(&self, name: &str) -> String {
        let old = self.zone_id(name);
        let mut inner = lock(&self.state);
        let new = inner.new_id('Z');
        for zone in inner.zones.iter_mut().filter(|z| z.id == old) {
            zone.id = new.clone();
        }
        for rrset in inner.rrsets.iter_mut().filter(|r| r.zone_id == old) {
            rrset.zone_id = new.clone();
        }
        new
    }

    /// Every rrset of every zone.
    pub fn rrsets(&self) -> Vec<Rrset> {
        lock(&self.state).rrsets.clone()
    }

    /// The first rrset of `name` and `rtype` in any zone.
    pub fn rrset(&self, name: &str, rtype: &str) -> Option<Rrset> {
        let name = fqdn(name);
        lock(&self.state)
            .rrsets
            .iter()
            .find(|r| r.name == name && r.rtype == rtype)
            .cloned()
    }

    /// Creates or replaces an rrset directly, as another writer would.
    pub fn insert_rrset(&self, zone_id: &str, name: &str, rtype: &str, ttl: u64, values: &[&str]) {
        let name = fqdn(name);
        let mut inner = lock(&self.state);
        inner
            .rrsets
            .retain(|r| !(r.zone_id == zone_id && r.name == name && r.rtype == rtype));
        inner.rrsets.push(Rrset {
            zone_id: zone_id.to_owned(),
            name,
            rtype: rtype.to_owned(),
            ttl,
            values: values.iter().map(|v| (*v).to_owned()).collect(),
            set_identifier: None,
            routing: None,
            alias: None,
        });
    }

    /// Adds a routing-policy set of `name` and `rtype` with this identifier and these extra
    /// elements (`routing`, XML), next to the other sets of the name and type.
    #[allow(clippy::too_many_arguments)] // Reason: one argument per element of the set.
    pub fn insert_policy_set(
        &self,
        zone_id: &str,
        name: &str,
        rtype: &str,
        identifier: Option<&str>,
        routing: &str,
        ttl: u64,
        values: &[&str],
    ) {
        let name = fqdn(name);
        lock(&self.state).rrsets.push(Rrset {
            zone_id: zone_id.to_owned(),
            name,
            rtype: rtype.to_owned(),
            ttl,
            values: values.iter().map(|v| (*v).to_owned()).collect(),
            set_identifier: identifier.map(str::to_owned),
            routing: Some(routing.to_owned()),
            alias: None,
        });
    }

    /// Adds an alias set of `name` and `rtype` pointing at `dns_name`.
    pub fn insert_alias(&self, zone_id: &str, name: &str, rtype: &str, dns_name: &str) {
        let name = fqdn(name);
        lock(&self.state).rrsets.push(Rrset {
            zone_id: zone_id.to_owned(),
            name,
            rtype: rtype.to_owned(),
            ttl: 0,
            values: Vec::new(),
            set_identifier: None,
            routing: None,
            alias: Some(dns_name.to_owned()),
        });
    }

    /// Marks the rrsets of `name` and `rtype` as a routing-policy set with this identifier.
    pub fn set_set_identifier(&self, name: &str, rtype: &str, identifier: &str) {
        let name = fqdn(name);
        for rrset in lock(&self.state)
            .rrsets
            .iter_mut()
            .filter(|r| r.name == name && r.rtype == rtype)
        {
            rrset.set_identifier = Some(identifier.to_owned());
        }
    }

    /// Deletes the rrsets of `name` and `rtype` directly, as another writer would.
    pub fn delete_rrset(&self, name: &str, rtype: &str) {
        let name = fqdn(name);
        lock(&self.state)
            .rrsets
            .retain(|r| !(r.name == name && r.rtype == rtype));
    }

    /// The TXT values of `name` with the outer quotes removed, in rrset order.
    pub fn txt_values(&self, name: &str) -> Vec<String> {
        self.rrset(name, "TXT")
            .map(|r| {
                r.values
                    .iter()
                    .map(|v| {
                        v.strip_prefix('"')
                            .and_then(|v| v.strip_suffix('"'))
                            .unwrap_or(v)
                            .to_owned()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The bodies of the accepted change batches, in order.
    pub fn batches(&self) -> Vec<String> {
        lock(&self.state).batches.clone()
    }

    /// Number of `PENDING` answers of every change submitted from now on.
    pub fn set_pending_polls(&self, polls: u32) {
        lock(&self.state).pending_polls = polls;
    }
}

/// An error answer in the shape this mock uses (see the module documentation).
pub fn error_body(code: &str, message: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n<ErrorResponse xmlns=\"{XMLNS}\"><Error><Type>Sender</Type>\
         <Code>{}</Code><Message>{}</Message></Error><RequestId>mock-request</RequestId>\
         </ErrorResponse>",
        esc(code),
        esc(message)
    )
}

/// An `InvalidChangeBatch` answer in the shape this mock uses.
pub fn invalid_change_batch_body(messages: &[&str]) -> String {
    let messages: String = messages
        .iter()
        .map(|m| format!("<Message>{}</Message>", esc(m)))
        .collect();
    format!(
        "<?xml version=\"1.0\"?>\n<InvalidChangeBatch xmlns=\"{XMLNS}\"><Messages>{messages}\
         </Messages><RequestId>mock-request</RequestId></InvalidChangeBatch>"
    )
}

fn xml(status: StatusCode, body: String) -> Response {
    (status, [("content-type", "text/xml")], body).into_response()
}

fn aws_error(status: StatusCode, code: &str, message: &str) -> Response {
    xml(status, error_body(code, message))
}

fn invalid_batch(message: &str) -> Response {
    xml(
        StatusCode::BAD_REQUEST,
        invalid_change_batch_body(&[message]),
    )
}

fn invalid_input(message: &str) -> Response {
    aws_error(StatusCode::BAD_REQUEST, "InvalidInput", message)
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

/// A name lowercase with exactly one trailing dot, `\ooo` escapes decoded.
fn fqdn(name: &str) -> String {
    let mut out = String::new();
    let bytes = name.trim().as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && let Some(code) = name
                .trim()
                .get(i + 1..i + 4)
                .and_then(|o| u8::from_str_radix(o, 8).ok())
        {
            out.push(char::from(code));
            i += 4;
            continue;
        }
        out.push(char::from(bytes[i]));
        i += 1;
    }
    let mut out = out.to_ascii_lowercase();
    if !out.ends_with('.') {
        out.push('.');
    }
    out
}

/// A name as the API returns it: every character other than `a-z`, `0-9`, `-`, `_` and the
/// label dots as a `\ooo` octal escape.
fn render_name(name: &str) -> String {
    let mut out = String::new();
    for b in name.bytes() {
        if b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'.' {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "\\{b:03o}");
        }
    }
    out
}

/// The sort key of a name: the labels reversed, with a trailing dot.
fn sort_key(name: &str) -> String {
    let name = fqdn(name);
    let mut labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    labels.reverse();
    let mut key = labels.join(".");
    key.push('.');
    key
}

fn within(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{zone}"))
}

// ---- SigV4, verified independently of the crate under test ------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, data).as_ref())
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, data).as_ref().to_vec()
}

/// `A-Z a-z 0-9 - _ . ~` as they are, every other byte `%XX` (uppercase).
fn uri_encode(s: &[u8]) -> String {
    let mut out = String::new();
    for &b in s {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn percent_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(v) = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// The query string as decoded pairs.
fn query_pairs(raw: Option<&str>) -> Vec<(String, String)> {
    raw.unwrap_or("")
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (
                String::from_utf8_lossy(&percent_decode(k)).into_owned(),
                String::from_utf8_lossy(&percent_decode(v)).into_owned(),
            )
        })
        .collect()
}

/// Days since 1970-01-01 of a civil date (H. Hinnant, "chrono-Compatible Low-Level Date
/// Algorithms").
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Seconds since the Unix epoch of a `YYYYMMDDTHHMMSSZ` date.
fn parse_amz_date(s: &str) -> Option<i64> {
    let ok = s.len() == 16
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 => b == b'T',
            15 => b == b'Z',
            _ => b.is_ascii_digit(),
        });
    if !ok {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r).and_then(|t| t.parse::<i64>().ok());
    let days = days_from_civil(n(0..4)?, n(4..6)?, n(6..8)?);
    Some(days * 86_400 + n(9..11)? * 3600 + n(11..13)? * 60 + n(13..15)?)
}

/// Verifies the SigV4 signature of a request.
fn verify(
    state: &Shared,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), Response> {
    let seed = lock(state).seed.clone();
    let deny = |code: &str, message: &str| Err(aws_error(StatusCode::FORBIDDEN, code, message));
    let header = |name: &str| {
        headers
            .get(name)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
    };
    let Some(authorization) = header("authorization") else {
        return deny("MissingAuthenticationToken", "Missing Authentication Token");
    };
    let Some(rest) = authorization.strip_prefix("AWS4-HMAC-SHA256 ") else {
        return deny(
            "IncompleteSignature",
            "Authorization header requires the algorithm",
        );
    };
    let (mut credential, mut signed, mut signature) = ("", "", "");
    for part in rest.split(", ") {
        if let Some(v) = part.strip_prefix("Credential=") {
            credential = v;
        } else if let Some(v) = part.strip_prefix("SignedHeaders=") {
            signed = v;
        } else if let Some(v) = part.strip_prefix("Signature=") {
            signature = v;
        }
    }
    let scope: Vec<&str> = credential.split('/').collect();
    let [key_id, date, region, service, terminator] = scope.as_slice() else {
        return deny(
            "IncompleteSignature",
            "Authorization header requires 'Credential' parameter.",
        );
    };
    if *key_id != seed.access_key_id {
        return deny(
            "UnrecognizedClientException",
            "The access key ID you provided does not exist in our records.",
        );
    }
    if *region != "us-east-1" || *service != "route53" || *terminator != "aws4_request" {
        return deny(
            "SignatureDoesNotMatch",
            "Credential should be scoped to a valid Region.",
        );
    }
    let amz_date = header("x-amz-date").unwrap_or_default();
    let Some(when) = parse_amz_date(&amz_date) else {
        return deny("IncompleteSignature", "The request date is not valid.");
    };
    if !amz_date.starts_with(date) {
        return deny(
            "SignatureDoesNotMatch",
            "Date in Credential scope does not match YYYYMMDD from ISO-8601 version of date from HTTP",
        );
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    if when < now - MAX_SKEW_S {
        return deny(
            "SignatureDoesNotMatch",
            &format!("Signature expired: {amz_date} is now earlier than the allowed window."),
        );
    }
    if when > now + MAX_SKEW_S {
        return deny(
            "SignatureDoesNotMatch",
            &format!(
                "Signature not yet current: {amz_date} is still later than the allowed window."
            ),
        );
    }
    let token = header("x-amz-security-token");
    if token != seed.session_token {
        return deny(
            "InvalidClientTokenId",
            "The security token included in the request is invalid.",
        );
    }
    let names: Vec<&str> = signed.split(';').collect();
    let required_missing = !names.contains(&"host")
        || !names.contains(&"x-amz-date")
        || (token.is_some() && !names.contains(&"x-amz-security-token"));
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if required_missing || sorted != names {
        return deny(
            "SignatureDoesNotMatch",
            "The signed headers are incomplete.",
        );
    }
    // Canonical URI: each segment URI-encoded twice (services other than S3).
    let path: Vec<String> = uri
        .path()
        .split('/')
        .map(|segment| uri_encode(uri_encode(&percent_decode(segment)).as_bytes()))
        .collect();
    let path = path.join("/");
    let mut query: Vec<(String, String)> = query_pairs(uri.query())
        .iter()
        .map(|(k, v)| (uri_encode(k.as_bytes()), uri_encode(v.as_bytes())))
        .collect();
    query.sort();
    let query: Vec<String> = query.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let query = query.join("&");
    let mut canonical_headers = String::new();
    for name in &names {
        let value = header(name).unwrap_or_default();
        let collapsed = value.split_whitespace().collect::<Vec<_>>().join(" ");
        let _ = writeln!(canonical_headers, "{name}:{collapsed}");
    }
    let canonical = format!(
        "{method}\n{path}\n{query}\n{canonical_headers}\n{signed}\n{}",
        sha256_hex(body)
    );
    let scope = format!("{date}/us-east-1/route53/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    );
    let mut key = hmac_sha256(
        format!("AWS4{}", seed.secret_access_key).as_bytes(),
        date.as_bytes(),
    );
    for part in ["us-east-1", "route53", "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    if hex(&hmac_sha256(&key, string_to_sign.as_bytes())) != signature {
        return deny(
            "SignatureDoesNotMatch",
            &format!(
                "The request signature we calculated does not match the signature you provided. \
                 Check your AWS Secret Access Key and signing method. Consult the service \
                 documentation for details.\n\nThe Canonical String for this request should have \
                 been\n'{canonical}'\n\nThe String-to-Sign should have been\n'{string_to_sign}'\n"
            ),
        );
    }
    Ok(())
}

// ---- Handlers -----------------------------------------------------------------------------------

fn zone_xml(zone: &Zone) -> String {
    format!(
        "<HostedZone><Id>/hostedzone/{}</Id><Name>{}</Name><CallerReference>mock</CallerReference>\
         <Config><Comment>mock zone</Comment><PrivateZone>{}</PrivateZone></Config>\
         <ResourceRecordSetCount>2</ResourceRecordSetCount></HostedZone>",
        zone.id,
        esc(&render_name(&zone.name)),
        zone.private
    )
}

fn max_items(pairs: &[(String, String)], page: usize) -> Result<usize, Response> {
    match pairs.iter().find(|(k, _)| k == "maxitems") {
        None => Ok(page),
        Some((_, v)) => match v.parse::<usize>() {
            Ok(n) if n >= 1 => Ok(n.min(page)),
            _ => Err(invalid_input("maxitems must be a positive integer")),
        },
    }
}

fn param<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

async fn zones_by_name(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = verify(&state, &method, &uri, &headers, b"") {
        return r;
    }
    let pairs = query_pairs(uri.query());
    let max = match max_items(&pairs, ZONE_PAGE) {
        Ok(max) => max,
        Err(r) => return r,
    };
    let dnsname = param(&pairs, "dnsname");
    let start_id = param(&pairs, "hostedzoneid");
    if start_id.is_some() && dnsname.is_none() {
        return invalid_input("hostedzoneid requires dnsname");
    }
    let mut zones = lock(&state).zones.clone();
    zones.sort_by(|a, b| (sort_key(&a.name), &a.id).cmp(&(sort_key(&b.name), &b.id)));
    let rest: Vec<Zone> = zones
        .into_iter()
        .filter(|z| match dnsname {
            None => true,
            Some(name) => {
                let key = sort_key(&z.name);
                let start = sort_key(name);
                match start_id {
                    None => key >= start,
                    Some(id) => (key.as_str(), z.id.as_str()) >= (start.as_str(), id),
                }
            }
        })
        .collect();
    let page: String = rest.iter().take(max).map(zone_xml).collect();
    let truncated = rest.len() > max;
    let next = rest
        .get(max)
        .map(|z| {
            format!(
                "<NextDNSName>{}</NextDNSName><NextHostedZoneId>{}</NextHostedZoneId>",
                esc(&render_name(&z.name)),
                z.id
            )
        })
        .unwrap_or_default();
    let echo = dnsname
        .map(|n| format!("<DNSName>{}</DNSName>", esc(n)))
        .unwrap_or_default();
    xml(
        StatusCode::OK,
        format!(
            "<?xml version=\"1.0\"?>\n<ListHostedZonesByNameResponse xmlns=\"{XMLNS}\">{echo}\
             <HostedZones>{page}</HostedZones><IsTruncated>{truncated}</IsTruncated>\
             <MaxItems>{max}</MaxItems>{next}</ListHostedZonesByNameResponse>"
        ),
    )
}

fn no_zone() -> Response {
    aws_error(
        StatusCode::NOT_FOUND,
        "NoSuchHostedZone",
        "No hosted zone found with the ID that you specified.",
    )
}

async fn get_zone(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = verify(&state, &method, &uri, &headers, b"") {
        return r;
    }
    let Some(zone) = lock(&state).zone(&id).cloned() else {
        return no_zone();
    };
    xml(
        StatusCode::OK,
        format!(
            "<?xml version=\"1.0\"?>\n<GetHostedZoneResponse xmlns=\"{XMLNS}\">{}\
             <DelegationSet><NameServers><NameServer>ns-1.awsdns-00.test</NameServer>\
             </NameServers></DelegationSet></GetHostedZoneResponse>",
            zone_xml(&zone)
        ),
    )
}

fn rrset_xml(r: &Rrset) -> String {
    let values: String = r
        .values
        .iter()
        .map(|v| format!("<ResourceRecord><Value>{}</Value></ResourceRecord>", esc(v)))
        .collect();
    let identifier = r
        .set_identifier
        .as_ref()
        .map(|id| format!("<SetIdentifier>{}</SetIdentifier>", esc(id)))
        .unwrap_or_default();
    let routing = match (&r.routing, &r.set_identifier) {
        (Some(xml), _) => xml.clone(),
        (None, Some(_)) => "<Weight>10</Weight>".to_owned(),
        (None, None) => String::new(),
    };
    let body = match &r.alias {
        Some(target) => format!(
            "<AliasTarget><HostedZoneId>ZALIASTARGET0001</HostedZoneId><DNSName>{}</DNSName>\
             <EvaluateTargetHealth>false</EvaluateTargetHealth></AliasTarget>",
            esc(target)
        ),
        None => format!(
            "<TTL>{}</TTL><ResourceRecords>{values}</ResourceRecords>",
            r.ttl
        ),
    };
    format!(
        "<ResourceRecordSet><Name>{}</Name><Type>{}</Type>{identifier}{routing}{body}\
         </ResourceRecordSet>",
        esc(&render_name(&r.name)),
        r.rtype,
    )
}

async fn list_rrsets(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = verify(&state, &method, &uri, &headers, b"") {
        return r;
    }
    if lock(&state).zone(&id).is_none() {
        return no_zone();
    }
    let pairs = query_pairs(uri.query());
    let max = match max_items(&pairs, RRSET_PAGE) {
        Ok(max) => max,
        Err(r) => return r,
    };
    let name = param(&pairs, "name");
    let rtype = param(&pairs, "type").unwrap_or("");
    if name.is_none() && !rtype.is_empty() {
        return invalid_input("type requires name");
    }
    let mut all: Vec<Rrset> = lock(&state)
        .rrsets
        .iter()
        .filter(|r| r.zone_id == id)
        .cloned()
        .collect();
    all.sort_by(|a, b| {
        (sort_key(&a.name), &a.rtype, &a.set_identifier).cmp(&(
            sort_key(&b.name),
            &b.rtype,
            &b.set_identifier,
        ))
    });
    let identifier = param(&pairs, "identifier");
    if identifier.is_some() && rtype.is_empty() {
        return invalid_input("identifier requires name and type");
    }
    let from: Vec<&Rrset> = all
        .iter()
        .filter(|r| match name {
            None => true,
            Some(name) => {
                let here = (sort_key(&r.name), r.rtype.as_str());
                let start = (sort_key(name), rtype);
                match identifier {
                    Some(id) if here == start => r.set_identifier.as_deref() >= Some(id),
                    _ => here >= start,
                }
            }
        })
        .collect();
    let page: String = from.iter().take(max).map(|r| rrset_xml(r)).collect();
    let truncated = from.len() > max;
    let next = from
        .get(max)
        .map(|r| {
            let identifier = r
                .set_identifier
                .as_ref()
                .map(|id| format!("<NextRecordIdentifier>{}</NextRecordIdentifier>", esc(id)))
                .unwrap_or_default();
            format!(
                "<NextRecordName>{}</NextRecordName><NextRecordType>{}</NextRecordType>\
                 {identifier}",
                esc(&render_name(&r.name)),
                r.rtype
            )
        })
        .unwrap_or_default();
    xml(
        StatusCode::OK,
        format!(
            "<?xml version=\"1.0\"?>\n<ListResourceRecordSetsResponse xmlns=\"{XMLNS}\">\
             <ResourceRecordSets>{page}</ResourceRecordSets><IsTruncated>{truncated}</IsTruncated>\
             <MaxItems>{max}</MaxItems>{next}</ListResourceRecordSetsResponse>"
        ),
    )
}

struct ParsedChange {
    action: String,
    rrset: Rrset,
}

fn element_text(node: roxmltree::Node<'_, '_>, tag: &str) -> Option<String> {
    node.children()
        .find(|c| c.is_element() && c.tag_name().name() == tag)
        .map(|c| c.text().unwrap_or("").to_owned())
}

fn child<'a, 'i>(n: roxmltree::Node<'a, 'i>, tag: &str) -> Option<roxmltree::Node<'a, 'i>> {
    n.children()
        .find(|c| c.is_element() && c.tag_name().name() == tag)
}

fn parse_batch(zone_id: &str, body: &str) -> Option<Vec<ParsedChange>> {
    let doc = roxmltree::Document::parse(body).ok()?;
    let root = doc.root_element();
    if root.tag_name().name() != "ChangeResourceRecordSetsRequest"
        || root.tag_name().namespace() != Some(XMLNS)
    {
        return None;
    }
    let batch = child(root, "ChangeBatch")?;
    let changes = child(batch, "Changes")?;
    let mut out = Vec::new();
    for change in changes
        .children()
        .filter(|c| c.is_element() && c.tag_name().name() == "Change")
    {
        let set = child(change, "ResourceRecordSet")?;
        let records = child(set, "ResourceRecords")?;
        let values: Vec<String> = records
            .children()
            .filter(|c| c.is_element() && c.tag_name().name() == "ResourceRecord")
            .map(|r| element_text(r, "Value"))
            .collect::<Option<_>>()?;
        if values.is_empty() {
            return None;
        }
        out.push(ParsedChange {
            action: element_text(change, "Action")?,
            rrset: Rrset {
                zone_id: zone_id.to_owned(),
                name: fqdn(&element_text(set, "Name")?),
                rtype: element_text(set, "Type")?,
                ttl: element_text(set, "TTL")?.trim().parse().ok()?,
                values,
                set_identifier: element_text(set, "SetIdentifier"),
                routing: None,
                alias: None,
            },
        });
    }
    (!out.is_empty()).then_some(out)
}

/// A value in the format "Supported DNS record types" gives for `rtype`; types the page does
/// not describe are accepted as they are.
fn valid_value(rtype: &str, value: &str) -> bool {
    let fields: Vec<&str> = value.split_whitespace().collect();
    let num = |s: &str, max: u64| {
        !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            && s.parse::<u64>().is_ok_and(|n| n <= max)
    };
    let hex = |s: &str| {
        !s.is_empty() && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit())
    };
    let name = |s: &str| {
        s == "."
            || (!s.is_empty()
                && s.trim_end_matches('.').split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_*\\".contains(&b))
                }))
    };
    match rtype {
        "A" => {
            fields.len() == 1
                && value.split('.').count() == 4
                && value
                    .split('.')
                    .all(|o| num(o, 255) && (o == "0" || !o.starts_with('0')))
        }
        "AAAA" => fields.len() == 1 && value.parse::<std::net::Ipv6Addr>().is_ok(),
        "CNAME" | "NS" | "PTR" => fields.len() == 1 && name(value),
        "MX" => matches!(fields.as_slice(), [p, n] if num(p, 65_535) && name(n)),
        "SRV" => matches!(fields.as_slice(), [p, w, port, n]
            if num(p, 65_535) && num(w, 65_535) && num(port, 65_535) && name(n)),
        "CAA" => {
            let mut parts = value.splitn(3, ' ');
            match (parts.next(), parts.next(), parts.next()) {
                (Some(flags), Some(tag), Some(quoted)) => {
                    num(flags, 255)
                        && !tag.is_empty()
                        && tag.bytes().all(|b| b.is_ascii_alphanumeric())
                        && quoted.starts_with('"')
                        && valid_txt(quoted)
                }
                _ => false,
            }
        }
        "DS" => matches!(fields.as_slice(), [t, a, d, digest]
            if num(t, 65_535) && num(a, 255) && num(d, 255) && hex(digest)),
        "SSHFP" => matches!(fields.as_slice(), [a, t, f] if num(a, 255) && num(t, 255) && hex(f)),
        "TLSA" => matches!(fields.as_slice(), [u, s, m, d]
            if num(u, 255) && num(s, 255) && num(m, 255) && hex(d)),
        "SVCB" | "HTTPS" => match fields.as_slice() {
            [p, n, params @ ..] => {
                num(p, 32_767)
                    && name(n)
                    && !params.iter().any(|param| {
                        param
                            .strip_prefix("key")
                            .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()))
                    })
            }
            _ => false,
        },
        "NAPTR" => valid_naptr(value),
        "SPF" => valid_txt(value),
        _ => true,
    }
}

/// `order preference "flags" "service" "regexp" replacement`, the replacement of `a-z`, `0-9`,
/// `-` and dots.
fn valid_naptr(value: &str) -> bool {
    let mut rest = value.trim();
    for _ in 0..2 {
        let Some((n, tail)) = rest.split_once(' ') else {
            return false;
        };
        if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) || n.parse::<u16>().is_err() {
            return false;
        }
        rest = tail;
    }
    for _ in 0..3 {
        let Some(inner) = rest.strip_prefix('"') else {
            return false;
        };
        let mut end = None;
        let mut escaped = false;
        for (i, c) in inner.char_indices() {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                end = Some(i);
                break;
            }
        }
        let Some(end) = end else {
            return false;
        };
        if !valid_txt(&rest[..end + 2]) {
            return false;
        }
        let Some(tail) = inner[end + 1..].strip_prefix(' ') else {
            return false;
        };
        rest = tail;
    }
    rest == "."
        || (!rest.is_empty()
            && rest.trim_end_matches('.').split('.').all(|label| {
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            }))
}

/// A TXT value is one or more quoted strings of at most 255 characters each.
fn valid_txt(value: &str) -> bool {
    let mut rest = value.trim();
    if rest.is_empty() {
        return false;
    }
    while !rest.is_empty() {
        let Some(inner) = rest.strip_prefix('"') else {
            return false;
        };
        let mut len = 0;
        let mut end = None;
        let mut chars = inner.char_indices();
        while let Some((i, c)) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some((_, d)) if d.is_ascii_digit() => {
                        // An escape code: exactly three octal digits, one character.
                        let code: String = std::iter::once(d)
                            .chain(chars.by_ref().take(2).map(|(_, c)| c))
                            .collect();
                        if code.len() != 3 || u8::from_str_radix(&code, 8).is_err() {
                            return false;
                        }
                    }
                    Some(_) => {}
                    None => return false,
                }
            } else if c == '"' {
                end = Some(i);
                break;
            }
            len += 1;
        }
        let Some(end) = end else {
            return false;
        };
        if len > 255 {
            return false;
        }
        rest = inner[end + 1..].trim_start();
    }
    true
}

async fn change_rrsets(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(r) = verify(&state, &method, &uri, &headers, &body) {
        return r;
    }
    let Some(zone) = lock(&state).zone(&id).cloned() else {
        return no_zone();
    };
    let text = String::from_utf8_lossy(&body).into_owned();
    let Some(changes) = parse_batch(&id, &text) else {
        return invalid_input("the change batch is not a valid document");
    };
    let records: usize = changes
        .iter()
        .map(|c| c.rrset.values.len() * if c.action == "UPSERT" { 2 } else { 1 })
        .sum();
    let chars: usize = changes
        .iter()
        .map(|c| {
            c.rrset
                .values
                .iter()
                .map(|v| v.chars().count())
                .sum::<usize>()
                * if c.action == "UPSERT" { 2 } else { 1 }
        })
        .sum();
    if records > MAX_RECORDS_PER_BATCH || chars > MAX_VALUE_CHARS_PER_BATCH {
        return invalid_batch("The change batch exceeds the request limits.");
    }
    for change in &changes {
        let set = &change.rrset;
        if !within(&set.name, &zone.name) {
            return invalid_batch(&format!(
                "RRSet with DNS name {} is not permitted in zone {}",
                set.name, zone.name
            ));
        }
        if set.values.len() > MAX_RECORDS_PER_SET
            || set
                .values
                .iter()
                .any(|v| v.chars().count() > MAX_VALUE_CHARS)
        {
            return invalid_batch("The resource record set exceeds the quotas.");
        }
        if set.rtype == "TXT" && !set.values.iter().all(|v| valid_txt(v)) {
            return invalid_batch("Invalid Resource Record: TXT value is not quoted correctly.");
        }
        if !set.values.iter().all(|v| valid_value(&set.rtype, v)) {
            return invalid_batch(&format!(
                "Invalid Resource Record: the {} value is not in the documented format.",
                set.rtype
            ));
        }
        if set.ttl > MAX_TTL {
            return invalid_input("TTL is outside the valid range");
        }
        if set.rtype == "SOA" && change.action != "UPSERT" {
            return invalid_batch("The SOA record can only be changed, not created or deleted.");
        }
        if set.rtype == "NS" && set.name.starts_with("*.") {
            return invalid_batch("A wildcard cannot be used for NS records.");
        }
        if set.rtype == "CNAME" && change.action == "CREATE" && set.name == zone.name {
            return invalid_batch("RRSet of type CNAME is not permitted at apex.");
        }
    }
    let mut inner = lock(&state);
    let mut next = inner.rrsets.clone();
    for change in &changes {
        let set = &change.rrset;
        let position = next.iter().position(|x| {
            x.zone_id == set.zone_id
                && x.name == set.name
                && x.rtype == set.rtype
                && x.set_identifier == set.set_identifier
        });
        match (change.action.as_str(), position) {
            ("CREATE", Some(_)) => {
                return invalid_batch(&format!(
                    "Tried to create resource record set [name='{}', type='{}'] but it already exists",
                    set.name, set.rtype
                ));
            }
            ("CREATE", None) => next.push(set.clone()),
            ("DELETE", Some(p)) => {
                let mut current = next[p].values.clone();
                let mut given = set.values.clone();
                current.sort();
                given.sort();
                if next[p].ttl != set.ttl || current != given {
                    return invalid_batch(&format!(
                        "Tried to delete resource record set [name='{}', type='{}'] but the values provided do not match the current values",
                        set.name, set.rtype
                    ));
                }
                next.remove(p);
            }
            ("DELETE", None) => {
                return invalid_batch(&format!(
                    "Tried to delete resource record set [name='{}', type='{}'] but it was not found",
                    set.name, set.rtype
                ));
            }
            ("UPSERT", position) => {
                if let Some(p) = position {
                    next.remove(p);
                }
                next.push(set.clone());
            }
            _ => return invalid_input("unknown action"),
        }
    }
    // A CNAME and any other set at one name cannot coexist.
    for set in next
        .iter()
        .filter(|r| r.zone_id == id && r.rtype == "CNAME")
    {
        if next
            .iter()
            .any(|r| r.zone_id == id && r.name == set.name && r.rtype != "CNAME")
        {
            return invalid_batch(&format!(
                "RRSet of type CNAME with DNS name {} is not permitted as it conflicts with \
                 other records with the same DNS name",
                set.name
            ));
        }
    }
    inner.rrsets = next;
    inner.batches.push(text);
    let change_id = inner.new_id('C');
    let pending = inner.pending_polls;
    inner.changes.insert(change_id.clone(), pending);
    xml(
        StatusCode::OK,
        format!(
            "<?xml version=\"1.0\"?>\n<ChangeResourceRecordSetsResponse xmlns=\"{XMLNS}\">\
             <ChangeInfo><Id>/change/{change_id}</Id><Status>PENDING</Status>\
             <SubmittedAt>2026-01-01T00:00:00.000Z</SubmittedAt></ChangeInfo>\
             </ChangeResourceRecordSetsResponse>"
        ),
    )
}

async fn get_change(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = verify(&state, &method, &uri, &headers, b"") {
        return r;
    }
    let status = {
        let mut inner = lock(&state);
        match inner.changes.get_mut(&id) {
            None => {
                return aws_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchChange",
                    "A change with the specified change ID does not exist.",
                );
            }
            Some(0) => "INSYNC",
            Some(n) => {
                *n -= 1;
                "PENDING"
            }
        }
    };
    xml(
        StatusCode::OK,
        format!(
            "<?xml version=\"1.0\"?>\n<GetChangeResponse xmlns=\"{XMLNS}\"><ChangeInfo>\
             <Id>{id}</Id><Status>{status}</Status>\
             <SubmittedAt>2026-01-01T00:00:00.000Z</SubmittedAt></ChangeInfo></GetChangeResponse>"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_rendered_and_sorted_as_documented() {
        assert_eq!(render_name("*.example.org."), "\\052.example.org.");
        assert_eq!(fqdn("\\052.Example.ORG"), "*.example.org.");
        assert_eq!(sort_key("www.example.com"), "com.example.www.");
        assert!(sort_key("example.org") < sort_key("a.example.org"));
    }

    #[test]
    fn txt_values_must_be_quoted_strings() {
        assert!(valid_txt("\"abc\""));
        assert!(valid_txt("\"a\" \"b\""));
        assert!(valid_txt("\"a\\\"b\""));
        assert!(!valid_txt("abc"));
        assert!(!valid_txt("\"abc"));
        assert!(!valid_txt(&format!("\"{}\"", "x".repeat(256))));
        assert!(valid_txt(&format!("\"{}\"", "x".repeat(255))));
    }

    #[test]
    fn amz_dates_parse() {
        assert_eq!(parse_amz_date("19700101T000000Z"), Some(0));
        assert_eq!(parse_amz_date("20150830T123600Z"), Some(1_440_938_160));
        assert_eq!(parse_amz_date("2015-08-30"), None);
    }
}
