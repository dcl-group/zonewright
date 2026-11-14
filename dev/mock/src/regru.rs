//! Mock of the reg.ru API 2 (DNS zone functions).
//!
//! Shapes follow the provider's documentation, the same source the client cites, "Рег.API 2"
//! (<https://www.reg.ru/reseller/api2doc>, in this module "the documentation"):
//!
//! - every call is an HTTP `POST` of `application/x-www-form-urlencoded` parameters to
//!   `{base}/{function}` or `{base}/{category}/{function}` (sections 2.2.2 and 3.1); a method other
//!   than `POST` is the error `ONLY_POST_ALLOWED` and a query string is
//!   `QUERY_PARAMS_DISALLOWED` (section 2.3.3);
//! - structured parameters go in the form field `input_data` with `input_format=json`, and the
//!   authentication fields `username` and `password` are form fields of their own, "not inside
//!   `input_data`" (sections 2.2.3.2 and 2.2.4.2);
//! - every answer is a JSON object with `result` (`success` or `error`); an error has
//!   `error_code` and `error_text` (section 2.3.2). Functions that take a list of domains answer
//!   with `answer.domains`, one entry per domain with its own `result`, so there are two levels
//!   of errors (section 2.3.2);
//! - `nop` answers `{"login", "user_id"}` after authenticating and needs no domain (section 4.1);
//! - `zone/nop` answers `domains` with `result` `success` for a domain whose zone can be managed
//!   and an error code otherwise (section 9.1); `DOMAIN_NOT_FOUND` for a domain that is not
//!   found or not owned by the user and `DOMAIN_IS_NOT_USE_REGRU_NSS` for a domain whose zone is
//!   not served by the provider's name servers (section 2.3.3);
//! - `zone/add_alias` and `zone/add_aaaa` take `subdomain` and `ipaddr`, an IPv4 or an IPv6
//!   address (sections 9.2 and 9.3); neither has a TTL parameter;
//! - `zone/add_txt` takes `subdomain` and `text` ("only alphanumeric ASCII characters") and the
//!   errors `TEXT_NOT_FOUND`, `TEXT_TOOLONG` and `TEXT_CONTAINS_INVALID_CHARACTERS` (section 9.9);
//!   it has no TTL parameter;
//! - `zone/get_resource_records` answers per domain `rrs` (`subname`, `rectype`, `content`,
//!   `prio`, `state`) and `soa` (section 9.11); `subname` is `@` for the domain itself;
//! - `zone/remove_record` requires `subdomain` and `record_type`; `content` is optional and "when
//!   absent, every record that matches the other parameters is marked for deletion" (section
//!   9.18). The mock implements that, so that a client which ever leaves `content` out is
//!   caught.
//!
//! Answers this mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading. A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - HTTP status: every answer, errors included, is `200`, as the documentation's examples show no
//!   other; only injected faults change it;
//! - `add_txt` of a value the name already holds appends a second record with the same content
//!   (the documentation does not say whether it does that or refuses); the same for
//!   `add_alias` and `add_aaaa`;
//! - `add_alias` and `add_aaaa` refuse an `ipaddr` that is not an address of their family, and a
//!   missing one, with the code `IP_INVALID` (no code is documented for them); the address is
//!   stored as sent, and [`Control::add_record`] can store another spelling;
//! - `remove_record` of a content nothing holds is `success` with no effect (not documented);
//! - the order of `rrs` is the order of creation; `rrs` of a zone holds every record the mock
//!   holds, of every type, and no SOA or NS record (the documentation's example shows `soa` as a
//!   separate object);
//! - the text of a TXT record is answered as it was written, unquoted; [`Control::set_quoted`]
//!   makes it quoted, which the documentation does not exclude;
//! - a `subdomain` is matched exactly as sent, case included; the apex is `@`;
//! - the limit behind `TEXT_TOOLONG`: 255 characters (the documentation names the code and no
//!   limit);
//! - a `domains` list of more than one entry is processed in order and each entry answered; an
//!   entry without `dname` is the error `NO_DOMAIN`; a `dname` with a trailing dot is not found;
//! - a call without `input_format=json` carries no domains: the error `NO_DOMAIN`;
//! - `username` or `password` inside `input_data` is refused with `PARAMETER_INCORRECT` (the
//!   documentation says they must not be there, not what happens);
//! - the `Content-Type` of an answer is `text/plain` when `output_content_type` is `plain` and
//!   `application/json` otherwise.
//!
//! Error texts are invented.
//!
//! A test holds a [`RegruMock`]. It dereferences to the [`MockServer`], so the request log and the
//! fault queue of the shared harness work as usual:
//!
//! ```text
//! let mock = RegruMock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("POST", "/api/regru2/zone/add_txt").status(502));
//! // ... drive the client against mock.base_url() ...
//! assert_eq!(mock.control().txt("example.org", "_acme-challenge"), ["v1"]);
//! ```

use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};

use crate::MockServer;

/// Path of the API below the server's base URL.
pub const API_PATH: &str = "/api/regru2";

/// Longest `text` of `add_txt` the mock accepts: invented, see the module documentation.
const TEXT_MAX: usize = 255;

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The user name the API accepts.
    pub username: String,
    /// The password the API accepts.
    pub password: String,
    /// Domains whose zones can be managed (served by the provider's name servers), without a
    /// trailing dot.
    pub zones: Vec<String>,
    /// Domains of the account whose zone is not served by the provider's name servers.
    pub foreign_ns_zones: Vec<String>,
}

impl Seed {
    /// User `zw-test-user`, password `test-only-password`, the domain `example.org`, and the
    /// domain `elsewhere.example` on other name servers.
    pub fn standard() -> Self {
        Self {
            username: "zw-test-user".into(),
            password: "test-only-password".into(),
            zones: vec!["example.org".into()],
            foreign_ns_zones: vec!["elsewhere.example".into()],
        }
    }
}

/// One record as the mock holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The domain, without a trailing dot.
    pub zone: String,
    /// The owner name relative to the domain, `@` for the apex.
    pub sub: String,
    /// The record type.
    pub rtype: String,
    /// The content.
    pub content: String,
}

/// One call the mock received.
#[derive(Clone, Debug)]
pub struct Call {
    /// The function, such as `zone/add_txt` or `nop`.
    pub function: String,
    /// The form fields other than `username`, `password` and `input_data`, and the parsed
    /// `input_data` under the key `input_data`.
    pub fields: Value,
    /// True when the call carried the accepted credentials.
    pub authenticated: bool,
}

#[derive(Debug)]
struct Inner {
    seed: Seed,
    records: Vec<Record>,
    calls: Vec<Call>,
    quoted: bool,
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running reg.ru mock. Dereferences to its [`MockServer`] for the request log and the fault
/// queue; [`RegruMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct RegruMock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of a [`RegruMock`]. Cheap to clone, so that a fault hook
/// ([`Fault::run`](crate::Fault::run)) can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
}

impl Deref for RegruMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl RegruMock {
    /// Starts the mock with `seed`.
    pub async fn start(seed: Seed) -> Self {
        let state = Arc::new(Mutex::new(Inner {
            seed,
            records: Vec::new(),
            calls: Vec::new(),
            quoted: false,
        }));
        let router = Router::new().fallback(handle).with_state(state.clone());
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
    /// Every record, in the order of creation.
    pub fn records(&self) -> Vec<Record> {
        lock(&self.state).records.clone()
    }

    /// The contents of the TXT records at `sub` in `zone`.
    pub fn txt(&self, zone: &str, sub: &str) -> Vec<String> {
        lock(&self.state)
            .records
            .iter()
            .filter(|r| r.zone == zone && r.sub == sub && r.rtype == "TXT")
            .map(|r| r.content.clone())
            .collect()
    }

    /// The contents of the records of type `rtype` at `sub` in `zone`, in the order of creation.
    pub fn contents(&self, zone: &str, sub: &str, rtype: &str) -> Vec<String> {
        lock(&self.state)
            .records
            .iter()
            .filter(|r| r.zone == zone && r.sub == sub && r.rtype == rtype)
            .map(|r| r.content.clone())
            .collect()
    }

    /// Adds a record directly, as another writer would.
    pub fn add_record(&self, zone: &str, sub: &str, rtype: &str, content: &str) {
        lock(&self.state).records.push(Record {
            zone: zone.into(),
            sub: sub.into(),
            rtype: rtype.into(),
            content: content.into(),
        });
    }

    /// Answers TXT contents quoted (`"text"`) instead of as written.
    pub fn set_quoted(&self, quoted: bool) {
        lock(&self.state).quoted = quoted;
    }

    /// Every call received, in order, with its function and parsed parameters.
    pub fn calls(&self) -> Vec<Call> {
        lock(&self.state).calls.clone()
    }
}

/// An error answer.
fn error(code: &str, text: &str) -> Value {
    json!({"result": "error", "error_code": code, "error_text": text})
}

/// A per-domain error entry.
fn domain_error(dname: &str, code: &str, text: &str) -> Value {
    json!({"dname": dname, "result": "error", "error_code": code, "error_text": text})
}

/// Decodes `application/x-www-form-urlencoded` into pairs, as a test reads a logged request body.
pub fn parse_form(body: &[u8]) -> Vec<(String, String)> {
    fn decode(part: &[u8]) -> String {
        let mut out = Vec::with_capacity(part.len());
        let mut i = 0;
        while let Some(&b) = part.get(i) {
            match b {
                b'+' => out.push(b' '),
                b'%' => {
                    let hex = part
                        .get(i + 1..i + 3)
                        .and_then(|h| std::str::from_utf8(h).ok());
                    match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                        Some(byte) => {
                            out.push(byte);
                            i += 2;
                        }
                        None => out.push(b),
                    }
                }
                b => out.push(b),
            }
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
    body.split(|&b| b == b'&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let mut halves = pair.splitn(2, |&b| b == b'=');
            let key = halves.next().unwrap_or_default();
            let value = halves.next().unwrap_or_default();
            (decode(key), decode(value))
        })
        .collect()
}

fn respond(body: &Value, plain: bool) -> Response {
    let content_type = if plain {
        "text/plain"
    } else {
        "application/json"
    };
    (
        StatusCode::OK,
        [("content-type", content_type)],
        body.to_string(),
    )
        .into_response()
}

async fn handle(State(state): State<Shared>, method: Method, uri: Uri, body: Bytes) -> Response {
    let Some(function) = uri.path().strip_prefix(&format!("{API_PATH}/")) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if method != Method::POST {
        return respond(
            &error("ONLY_POST_ALLOWED", "Only HTTP method POST allowed"),
            false,
        );
    }
    if uri.query().is_some() {
        return respond(
            &error(
                "QUERY_PARAMS_DISALLOWED",
                "Query string parameters are disallowed. Pass parameters in form data.",
            ),
            false,
        );
    }
    let form = parse_form(&body);
    let get = |key: &str| form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
    let plain = {
        let input: Option<Value> = (get("input_format") == Some("json"))
            .then(|| get("input_data").and_then(|d| serde_json::from_str(d).ok()))
            .flatten();
        input
            .as_ref()
            .and_then(|i| i.get("output_content_type"))
            .and_then(Value::as_str)
            == Some("plain")
    };

    let mut s = lock(&state);
    let authenticated = get("username") == Some(s.seed.username.as_str())
        && get("password") == Some(s.seed.password.as_str());
    let input: Option<Value> = (get("input_format") == Some("json"))
        .then(|| get("input_data").and_then(|d| serde_json::from_str(d).ok()))
        .flatten();
    let mut fields = Map::new();
    for (key, value) in &form {
        if !matches!(key.as_str(), "username" | "password" | "input_data") {
            fields.insert(key.clone(), Value::String(value.clone()));
        }
    }
    fields.insert("input_data".into(), input.clone().unwrap_or(Value::Null));
    s.calls.push(Call {
        function: function.to_owned(),
        fields: Value::Object(fields),
        authenticated,
    });

    if get("username").is_none() {
        return respond(&error("NO_USERNAME", "No username given"), plain);
    }
    if !authenticated {
        return respond(
            &error("PASSWORD_AUTH_FAILED", "Username/password Incorrect"),
            plain,
        );
    }
    if function == "nop" {
        return respond(
            &json!({"result": "success", "answer": {"login": s.seed.username, "user_id": "1"}}),
            plain,
        );
    }
    let input = input.unwrap_or(Value::Null);
    if input.get("username").is_some() || input.get("password").is_some() {
        return respond(
            &error(
                "PARAMETER_INCORRECT",
                "username, password must not be inside input_data",
            ),
            plain,
        );
    }
    let body = zone_function(&mut s, function, &input);
    respond(&body, plain)
}

/// One `zone/...` function over the list of domains in `input`.
fn zone_function(s: &mut Inner, function: &str, input: &Value) -> Value {
    if !matches!(
        function,
        "zone/nop"
            | "zone/add_alias"
            | "zone/add_aaaa"
            | "zone/add_txt"
            | "zone/remove_record"
            | "zone/get_resource_records"
    ) {
        return error("NO_SUCH_COMMAND", "Command not found");
    }
    let text = input.get("text").and_then(Value::as_str);
    let subdomain = input.get("subdomain").and_then(Value::as_str);
    let content = input.get("content").and_then(Value::as_str);
    let record_type = input.get("record_type").and_then(Value::as_str);
    let ipaddr = input.get("ipaddr").and_then(Value::as_str);
    match function {
        "zone/add_alias" | "zone/add_aaaa" => {
            if subdomain.is_none_or(str::is_empty) {
                return error("PARAMETER_MISSING", "subdomain required");
            }
            let valid = match function {
                "zone/add_alias" => ipaddr.is_some_and(|a| a.parse::<std::net::Ipv4Addr>().is_ok()),
                _ => ipaddr.is_some_and(|a| a.parse::<std::net::Ipv6Addr>().is_ok()),
            };
            if !valid {
                return error("IP_INVALID", "IP address is invalid");
            }
        }
        "zone/add_txt" => {
            if subdomain.is_none_or(str::is_empty) {
                return error("PARAMETER_MISSING", "subdomain required");
            }
            match text {
                None | Some("") => return error("TEXT_NOT_FOUND", "Text for record not found"),
                Some(t) if t.chars().count() > TEXT_MAX => {
                    return error("TEXT_TOOLONG", "Text too long");
                }
                Some(t) if !t.chars().all(|c| c.is_ascii_alphanumeric()) => {
                    return error(
                        "TEXT_CONTAINS_INVALID_CHARACTERS",
                        "Text contains invalid characters",
                    );
                }
                Some(_) => {}
            }
        }
        "zone/remove_record" => {
            if subdomain.is_none_or(str::is_empty) || record_type.is_none_or(str::is_empty) {
                return error("PARAMETER_MISSING", "subdomain, record_type required");
            }
            let known = ["A", "AAAA", "CNAME", "MX", "NS", "SRV", "CAA", "TXT"];
            if record_type.is_some_and(|t| !known.contains(&t)) {
                return error("INVALID_ZONE_RECORD_TYPE", "Zone record type is invalid");
            }
        }
        _ => {}
    }

    let entries = input.get("domains").and_then(Value::as_array);
    let Some(entries) = entries.filter(|e| !e.is_empty()) else {
        return error("NO_DOMAIN", "domain_name not given or empty");
    };
    let mut domains = Vec::new();
    for entry in entries {
        let Some(dname) = entry.get("dname").and_then(Value::as_str) else {
            return error("NO_DOMAIN", "domain_name not given or empty");
        };
        if s.seed.foreign_ns_zones.iter().any(|z| z == dname) {
            domains.push(domain_error(
                dname,
                "DOMAIN_IS_NOT_USE_REGRU_NSS",
                "This domain not use REG.RU name services",
            ));
            continue;
        }
        if !s.seed.zones.iter().any(|z| z == dname) {
            domains.push(domain_error(
                dname,
                "DOMAIN_NOT_FOUND",
                "Domain not found or not owned by You",
            ));
            continue;
        }
        let mut done = json!({"dname": dname, "result": "success", "service_id": "12345"});
        match function {
            "zone/nop" => {}
            "zone/add_alias" | "zone/add_aaaa" => s.records.push(Record {
                zone: dname.to_owned(),
                sub: subdomain.unwrap_or_default().to_owned(),
                rtype: if function == "zone/add_alias" {
                    "A".into()
                } else {
                    "AAAA".into()
                },
                content: ipaddr.unwrap_or_default().to_owned(),
            }),
            "zone/add_txt" => s.records.push(Record {
                zone: dname.to_owned(),
                sub: subdomain.unwrap_or_default().to_owned(),
                rtype: "TXT".into(),
                content: text.unwrap_or_default().to_owned(),
            }),
            "zone/remove_record" => {
                let sub = subdomain.unwrap_or_default();
                let rtype = record_type.unwrap_or_default();
                s.records.retain(|r| {
                    !(r.zone == dname
                        && r.sub == sub
                        && r.rtype == rtype
                        && content.is_none_or(|c| r.content == c))
                });
            }
            _ => {
                let quoted = s.quoted;
                let rrs: Vec<Value> = s
                    .records
                    .iter()
                    .filter(|r| r.zone == dname)
                    .map(|r| {
                        let content = if quoted && r.rtype == "TXT" {
                            format!("\"{}\"", r.content)
                        } else {
                            r.content.clone()
                        };
                        json!({
                            "content": content, "prio": "0", "rectype": r.rtype,
                            "state": "A", "subname": r.sub,
                        })
                    })
                    .collect();
                done["rrs"] = json!(rrs);
                done["soa"] = json!({"minimum_ttl": "12h", "ttl": "1d"});
            }
        }
        domains.push(done);
    }
    json!({"result": "success", "answer": {"domains": domains}})
}
