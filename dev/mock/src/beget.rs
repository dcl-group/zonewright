//! Mock of the Beget.API DNS functions.
//!
//! Shapes follow the provider's documentation, the same sources the client cites:
//!
//! - the principles page, <https://beget.com/ru/kb/api/obshhij-princzip-raboty-s-api> ("the
//!   principles"): `https://api.beget.com/api/{section}/{method}`; the main parameters `login`
//!   and `passwd`; the additional parameters `input_format` (`plain` by default, or `json` with
//!   the arguments in `input_data`) and `output_format`, given by `GET` or `POST` "or both
//!   combined"; every answer has `status`, and on `success` an `answer` with its own `status`
//!   and `result`, or `errors` (`error_code`, `error_text`); the call-level codes `AUTH_ERROR`,
//!   `INCORRECT_REQUEST`, `NO_SUCH_METHOD`; the method-level codes `INVALID_DATA`,
//!   `LIMIT_ERROR`, `METHOD_FAILED`. Errors are answered with HTTP 200;
//! - the DNS page, <https://beget.com/ru/kb/api/funkczii-upravleniya-dns>: `dns/getData` (input
//!   `fqdn`; the result has `is_under_control`, `is_beget_dns`, `is_subdomain`, `fqdn`,
//!   `records` by type DNS, DNS_IP, A, MX, TXT, each a list of `{value, priority}`, and
//!   `set_type`) and `dns/changeRecords` (`fqdn` and `records`, one group of: A, MX, TXT; NS;
//!   CNAME; DNS and DNS_IP; up to 10 records of each type in the first two, exactly one CNAME,
//!   up to 4 DNS; priorities required; the result `true`). The documented example answer for a
//!   name without TXT records holds one TXT entry with the empty value and priority 0;
//! - the domains page, <https://beget.com/ru/kb/api/funkczii-dlya-raboty-s-domenami>:
//!   `domain/getList`, a list of objects with `id` and `fqdn` among other fields;
//! - lego `providers/dns/beget`: TXT records carry `txtdata` when read and `ttl` when written;
//!   the fixture `getData-real.json`, an answer of the live API posted in lego pull request 1879
//!   (2025-09-28), which [`Control::set_observed`] reproduces: TXT `{ttl, txtdata}`, A `{ttl,
//!   address}`, MX `{ttl, exchange, preference}`, `DNS` `{value}`, `DNS_IP` `{value: ""}`, the
//!   flags as booleans; the fixture `getData_empty.json`, no `records` key for an empty name
//!   (lego's own test fixture; not shown to be observed);
//! - lego issue 2774 (<https://github.com/go-acme/lego/issues/2774>): `changeRecords` with group
//!   A, MX and TXT REPLACES all three types of the name, a type the request leaves out is
//!   deleted (observed at an apex, and Beget's support quoted there). The mock does that, so a
//!   client that writes only TXT at a name with A or MX records loses them here.
//!
//! Answers this mock invents because the documentation is silent, each chosen so that a client
//! cannot rely on a lenient reading. A test that depends on one of them proves only how the
//! client handles that answer, not that the provider gives it:
//!
//! - a group 1 write leaves the records of the other groups (NS, CNAME, `DNS`, `DNS_IP`)
//!   alone;
//! - in the observed shape, a record the mock holds without a TTL is answered with `ttl` 300;
//! - `TXT: []` clears the TXT records of the name;
//! - the field that holds a TXT record's text in an answer is `txtdata` by default (lego); the
//!   DNS page's `value`, or both fields, can be switched on ([`TxtField`]);
//! - a name with no records at all is answered with `records` as an empty list (PHP's empty
//!   array); a name with other records and no TXT gets the documented placeholder entry
//!   ([`Control::set_placeholder`]); the apex of a domain served by the mock's name servers also
//!   lists the `DNS` and `DNS_IP` settings, as the DNS page's example does;
//! - `fqdn` is accepted for a domain of the account and any name below it, case-insensitive and
//!   without a trailing dot; any other name is `INVALID_DATA`;
//! - `is_subdomain` is 1 for a name below a domain; `set_type` is 1, or 2 when the name has NS
//!   records and 3 when it has a CNAME;
//! - a record of `changeRecords` needs a text `value` and a `priority` (a number or a string of
//!   digits), may carry an integer `ttl` of at least 1, and nothing else; a TXT `value` must not
//!   be empty; otherwise `INVALID_DATA`;
//! - the request without `input_format=json` carries no arguments for `dns/*`: `INCORRECT_REQUEST`;
//! - HTTP status: every answer is 200; only injected faults change it;
//! - the rate limit is not enforced: tests inject the `LIMIT_ERROR` answer.
//!
//! Error texts are invented.
//!
//! A test holds a [`BegetMock`]. It dereferences to the [`MockServer`], so the request log and
//! the fault queue of the shared harness work as usual:
//!
//! ```text
//! let mock = BegetMock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("POST", "/api/dns/changeRecords").status(502));
//! // ... drive the client against mock.base_url() ...
//! assert_eq!(mock.control().txt_values("_acme-challenge.example.org"), ["v1"]);
//! ```

// Reason: the error side of a handler's result is the response it answers with.
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, RawQuery, State};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use serde_json::{Map, Value, json};

use crate::{LoggedRequest, MockServer};

/// Path of the API below the server's base URL.
pub const API_PATH: &str = "/api";

/// The record groups of `changeRecords`, the types of each, and the most records of one type.
const GROUPS: [(&[&str], usize); 4] = [
    (&["A", "MX", "TXT"], 10),
    (&["NS"], 10),
    (&["CNAME"], 1),
    (&["DNS", "DNS_IP"], 4),
];

/// The order in which types are listed in an answer.
const TYPE_ORDER: [&str; 7] = ["DNS", "DNS_IP", "A", "MX", "TXT", "NS", "CNAME"];

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The account's login.
    pub login: String,
    /// The API password.
    pub password: String,
    /// The domains of the account, without a trailing dot. Each is served by the mock's name
    /// servers.
    pub domains: Vec<String>,
}

impl Seed {
    /// Login `test-only-login`, password `test-only-password` and the domain `example.org`.
    pub fn standard() -> Self {
        Self {
            login: "test-only-login".into(),
            password: "test-only-password".into(),
            domains: vec!["example.org".into()],
        }
    }
}

/// The field that holds a TXT record's text in an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxtField {
    /// `txtdata`, as lego reads it.
    Txtdata,
    /// `value`, as the DNS page's example shows it.
    Value,
    /// Both, with the same text.
    Both,
}

/// One record as the mock holds it.
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    /// The record type: `A`, `MX`, `TXT`, `NS`, `CNAME`, `DNS` or `DNS_IP`.
    pub rtype: String,
    /// The value.
    pub value: String,
    /// The priority as it was written.
    pub priority: Value,
    /// The TTL as it was written, if one was.
    pub ttl: Option<Value>,
}

#[derive(Debug)]
struct Domain {
    name: String,
    /// Served by the mock's name servers (`is_beget_dns`).
    served: bool,
}

#[derive(Debug)]
struct Inner {
    login: String,
    password: String,
    domains: Vec<Domain>,
    /// Records by lowercase name without a trailing dot, in insertion order.
    records: BTreeMap<String, Vec<Record>>,
    txt_field: TxtField,
    placeholder: bool,
    observed: bool,
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running Beget mock. Dereferences to its [`MockServer`] for the request log and the fault
/// queue; [`BegetMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct BegetMock {
    server: MockServer,
    control: Control,
}

/// Reads and changes the state of a [`BegetMock`]. Cheap to clone, so that a fault hook
/// ([`Fault::run`](crate::Fault::run)) can change the state between two requests of a client.
#[derive(Clone, Debug)]
pub struct Control {
    state: Shared,
}

impl Deref for BegetMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl BegetMock {
    /// Starts the mock with `seed`.
    pub async fn start(seed: Seed) -> Self {
        let state = Arc::new(Mutex::new(Inner {
            login: seed.login,
            password: seed.password,
            domains: seed
                .domains
                .into_iter()
                .map(|name| Domain {
                    name: name.to_lowercase(),
                    served: true,
                })
                .collect(),
            records: BTreeMap::new(),
            txt_field: TxtField::Txtdata,
            placeholder: true,
            observed: false,
        }));
        let router = Router::new()
            .route("/api/{category}/{function}", any(call))
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

/// The key of a name in the mock: lowercase, no trailing dot.
fn key(name: &str) -> String {
    let lower = name.trim().to_lowercase();
    lower.strip_suffix('.').unwrap_or(&lower).to_owned()
}

impl Control {
    /// Every record of `name`, in the order the mock holds them.
    pub fn records(&self, name: &str) -> Vec<Record> {
        lock(&self.state)
            .records
            .get(&key(name))
            .cloned()
            .unwrap_or_default()
    }

    /// The records of `name` of type `rtype`.
    pub fn records_of(&self, name: &str, rtype: &str) -> Vec<Record> {
        self.records(name)
            .into_iter()
            .filter(|r| r.rtype == rtype)
            .collect()
    }

    /// The values of the TXT records at `name`, in order.
    pub fn txt_values(&self, name: &str) -> Vec<String> {
        self.records_of(name, "TXT")
            .into_iter()
            .map(|r| r.value)
            .collect()
    }

    /// Adds a record directly, as another writer would. `priority` and `ttl` are stored as given.
    pub fn insert(
        &self,
        name: &str,
        rtype: &str,
        value: &str,
        priority: Value,
        ttl: Option<Value>,
    ) {
        lock(&self.state)
            .records
            .entry(key(name))
            .or_default()
            .push(Record {
                rtype: rtype.to_owned(),
                value: value.to_owned(),
                priority,
                ttl,
            });
    }

    /// Adds a TXT record with priority 10 and the given TTL.
    pub fn insert_txt(&self, name: &str, value: &str, ttl: u32) {
        self.insert(name, "TXT", value, json!(10), Some(json!(ttl)));
    }

    /// Removes every record of `name` of type `rtype`, as another writer would.
    pub fn remove_type(&self, name: &str, rtype: &str) {
        if let Some(records) = lock(&self.state).records.get_mut(&key(name)) {
            records.retain(|r| r.rtype != rtype);
        }
    }

    /// Chooses the field that holds a TXT record's text in answers.
    pub fn set_txt_field(&self, field: TxtField) {
        lock(&self.state).txt_field = field;
    }

    /// Whether a name with other records and no TXT records is answered with the documented
    /// placeholder entry (empty value, priority 0). On by default.
    pub fn set_placeholder(&self, on: bool) {
        lock(&self.state).placeholder = on;
    }

    /// Whether `getData` answers in the shape lego observed from the live API
    /// (`getData-real.json`, `getData_empty.json`) instead of the documented one. Off by
    /// default. The TXT field choice and the placeholder do not apply to it.
    pub fn set_observed(&self, on: bool) {
        lock(&self.state).observed = on;
    }

    /// Adds a domain to the account.
    pub fn insert_domain(&self, name: &str, served: bool) {
        lock(&self.state).domains.push(Domain {
            name: key(name),
            served,
        });
    }

    /// Sets whether the mock's name servers serve `domain` (`is_beget_dns`).
    pub fn set_served(&self, domain: &str, served: bool) {
        for d in lock(&self.state)
            .domains
            .iter_mut()
            .filter(|d| d.name == key(domain))
        {
            d.served = served;
        }
    }
}

// ---- Reading what the client sent ----------------------------------------------------------

/// The form fields of a request: the query string and the body together, decoded, in order.
pub fn params_of(request: &LoggedRequest) -> Vec<(String, String)> {
    let mut params = pairs(&format!(
        "/?{}",
        request.query.as_deref().unwrap_or_default()
    ));
    params.extend(pairs(&format!("/?{}", request.body_str())));
    params
}

/// The `input_data` of a request, parsed.
pub fn input_of(request: &LoggedRequest) -> Option<Value> {
    let params = params_of(request);
    serde_json::from_str(param(&params, "input_data")?).ok()
}

// ---- Answers -----------------------------------------------------------------------------------

fn respond(body: Value) -> Response {
    (StatusCode::OK, axum::Json(body)).into_response()
}

/// A call-level error: `status` `error` with `error_code` and `error_text`.
fn call_error(code: &str, text: &str) -> Response {
    respond(json!({"status": "error", "error_code": code, "error_text": text}))
}

/// A method-level error: the call succeeded and the method did not.
fn method_error(code: &str, text: &str) -> Response {
    respond(json!({
        "status": "success",
        "answer": {"status": "error", "errors": [{"error_code": code, "error_text": text}]}
    }))
}

fn success(result: Value) -> Response {
    respond(json!({"status": "success", "answer": {"status": "success", "result": result}}))
}

fn pairs(uri: &str) -> Vec<(String, String)> {
    uri.parse::<Uri>()
        .ok()
        .and_then(|uri| Query::<Vec<(String, String)>>::try_from_uri(&uri).ok())
        .map(|q| q.0)
        .unwrap_or_default()
}

fn param<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Every function: the parameters come from the query, the form body, or both.
async fn call(
    State(state): State<Shared>,
    Path((category, function)): Path<(String, String)>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let mut params = pairs(&format!("/?{}", query.unwrap_or_default()));
    params.extend(pairs(&format!("/?{}", String::from_utf8_lossy(&body))));
    {
        let inner = lock(&state);
        if param(&params, "login") != Some(inner.login.as_str())
            || param(&params, "passwd") != Some(inner.password.as_str())
        {
            return call_error("AUTH_ERROR", "Authorization failed");
        }
    }
    if param(&params, "output_format").is_some_and(|f| f != "json") {
        return call_error("INCORRECT_REQUEST", "Unsupported output format");
    }
    match (category.as_str(), function.as_str()) {
        ("domain", "getList") => domain_list(&state),
        ("dns", "getData") => match input(&params) {
            Ok(input) => get_data(&state, &input),
            Err(response) => response,
        },
        ("dns", "changeRecords") => match input(&params) {
            Ok(input) => change_records(&state, &input),
            Err(response) => response,
        },
        _ => call_error("NO_SUCH_METHOD", "No such method"),
    }
}

/// The arguments of a `dns/*` call: `input_format=json` and an object in `input_data`.
fn input(params: &[(String, String)]) -> Result<Map<String, Value>, Response> {
    if param(params, "input_format") != Some("json") {
        return Err(call_error(
            "INCORRECT_REQUEST",
            "Arguments need input_format=json",
        ));
    }
    match param(params, "input_data").map(serde_json::from_str::<Value>) {
        Some(Ok(Value::Object(map))) => Ok(map),
        _ => Err(call_error(
            "INCORRECT_REQUEST",
            "input_data is not a JSON object",
        )),
    }
}

fn domain_list(state: &Shared) -> Response {
    let inner = lock(state);
    let list: Vec<Value> = inner
        .domains
        .iter()
        .enumerate()
        .map(|(i, d)| {
            json!({
                "id": (100_000 + i).to_string(),
                "fqdn": d.name,
                "date_add": "2011-10-24 15:01:40",
                "auto_renew": "0",
                "is_under_control": 0,
            })
        })
        .collect();
    success(Value::Array(list))
}

/// The domain a name is at or below.
fn domain_of<'a>(inner: &'a Inner, name: &str) -> Option<&'a Domain> {
    inner
        .domains
        .iter()
        .find(|d| name == d.name || name.ends_with(&format!(".{}", d.name)))
}

fn get_data(state: &Shared, input: &Map<String, Value>) -> Response {
    let Some(fqdn) = input.get("fqdn").and_then(Value::as_str) else {
        return method_error("INVALID_DATA", "fqdn is required");
    };
    let name = key(fqdn);
    let inner = lock(state);
    let Some(domain) = domain_of(&inner, &name) else {
        return method_error("INVALID_DATA", "The domain is not on the account");
    };
    let apex = name == domain.name;
    let mut records = inner.records.get(&name).cloned().unwrap_or_default();
    if apex && domain.served {
        records.insert(
            0,
            Record {
                rtype: "DNS".into(),
                value: "ns1.example.net".into(),
                priority: json!(10),
                ttl: None,
            },
        );
        records.insert(
            1,
            Record {
                rtype: "DNS_IP".into(),
                value: String::new(),
                priority: json!(10),
                ttl: None,
            },
        );
    }
    let set_type = if records.iter().any(|r| r.rtype == "NS") {
        2
    } else if records.iter().any(|r| r.rtype == "CNAME") {
        3
    } else {
        1
    };
    if inner.observed {
        return success(observed_data(&records, fqdn, domain.served, apex, set_type));
    }
    let listed = if records.is_empty() {
        // PHP encodes an empty array as a list.
        json!([])
    } else {
        let mut by_type = Map::new();
        // The known types in the documented order, then any other type a test put in.
        let mut order: Vec<&str> = TYPE_ORDER.to_vec();
        for r in &records {
            if !order.contains(&r.rtype.as_str()) {
                order.push(r.rtype.as_str());
            }
        }
        for rtype in order {
            let entries: Vec<Value> = records
                .iter()
                .filter(|r| r.rtype == rtype)
                .map(|r| entry(r, inner.txt_field))
                .collect();
            if !entries.is_empty() {
                by_type.insert(rtype.to_owned(), Value::Array(entries));
            }
        }
        if inner.placeholder && !by_type.contains_key("TXT") {
            by_type.insert("TXT".into(), json!([{"value": "", "priority": 0}]));
        }
        Value::Object(by_type)
    };
    success(json!({
        "is_under_control": 1,
        "is_beget_dns": i32::from(domain.served),
        "is_subdomain": i32::from(!apex),
        "fqdn": fqdn,
        "records": listed,
        "set_type": set_type,
    }))
}

/// A `getData` result in the shape of lego's `getData-real.json` and `getData_empty.json`.
fn observed_data(records: &[Record], fqdn: &str, served: bool, apex: bool, set_type: u8) -> Value {
    let mut result = Map::new();
    result.insert("is_under_control".into(), json!(true));
    result.insert("is_beget_dns".into(), json!(served));
    result.insert("is_subdomain".into(), json!(!apex));
    result.insert("fqdn".into(), json!(fqdn));
    if !records.is_empty() {
        let mut by_type = Map::new();
        for record in records {
            let ttl = record.ttl.clone().unwrap_or_else(|| json!(300));
            let entry = match record.rtype.as_str() {
                "TXT" => json!({"ttl": ttl, "txtdata": record.value}),
                "A" => json!({"ttl": ttl, "address": record.value}),
                "MX" => {
                    json!({"ttl": ttl, "exchange": record.value, "preference": record.priority})
                }
                _ => json!({"value": record.value}),
            };
            if let Some(list) = by_type
                .entry(record.rtype.clone())
                .or_insert_with(|| json!([]))
                .as_array_mut()
            {
                list.push(entry);
            }
        }
        result.insert("records".into(), Value::Object(by_type));
    }
    result.insert("set_type".into(), json!(set_type));
    Value::Object(result)
}

/// A record as an answer states it.
fn entry(record: &Record, field: TxtField) -> Value {
    let mut object = Map::new();
    if record.rtype == "DNS_IP" && record.value.is_empty() {
        // An unused slot, as the DNS page's example shows it.
        object.insert("value".into(), Value::Null);
    } else if record.rtype == "TXT" {
        if matches!(field, TxtField::Txtdata | TxtField::Both) {
            object.insert("txtdata".into(), json!(record.value));
        }
        if matches!(field, TxtField::Value | TxtField::Both) {
            object.insert("value".into(), json!(record.value));
        }
    } else {
        object.insert("value".into(), json!(record.value));
    }
    object.insert("priority".into(), record.priority.clone());
    if let Some(ttl) = &record.ttl {
        object.insert("ttl".into(), ttl.clone());
    }
    Value::Object(object)
}

fn change_records(state: &Shared, input: &Map<String, Value>) -> Response {
    let Some(fqdn) = input.get("fqdn").and_then(Value::as_str) else {
        return method_error("INVALID_DATA", "fqdn is required");
    };
    let Some(Value::Object(request)) = input.get("records") else {
        return method_error("INVALID_DATA", "records must be an object");
    };
    let Some(&(types, most)) = GROUPS.iter().find(|(types, _)| {
        !request.is_empty() && request.keys().all(|k| types.contains(&k.as_str()))
    }) else {
        return method_error("INVALID_DATA", "records must hold one group of types");
    };
    let mut parsed: Vec<Record> = Vec::new();
    for (rtype, list) in request {
        let Value::Array(list) = list else {
            return method_error("INVALID_DATA", "each type must be a list");
        };
        if list.len() > most {
            return method_error("INVALID_DATA", "too many records of one type");
        }
        for item in list {
            match record(rtype, item) {
                Ok(record) => parsed.push(record),
                Err(text) => return method_error("INVALID_DATA", text),
            }
        }
    }
    let name = key(fqdn);
    let mut inner = lock(state);
    if domain_of(&inner, &name).is_none() {
        return method_error("INVALID_DATA", "The domain is not on the account");
    }
    let held = inner.records.entry(name).or_default();
    // The documented group replaces its types: a type of the group that the request leaves out
    // is emptied (an invention, see the module documentation).
    held.retain(|r| !types.contains(&r.rtype.as_str()));
    held.extend(parsed);
    success(json!(true))
}

/// One record of a request, or the reason it is refused.
fn record(rtype: &str, item: &Value) -> Result<Record, &'static str> {
    let Value::Object(object) = item else {
        return Err("a record must be an object");
    };
    if object
        .keys()
        .any(|k| !matches!(k.as_str(), "value" | "priority" | "ttl"))
    {
        return Err("a record holds only value, priority and ttl");
    }
    let value = object
        .get("value")
        .and_then(Value::as_str)
        .ok_or("a record needs a text value")?;
    if rtype == "TXT" && value.is_empty() {
        return Err("a TXT value must not be empty");
    }
    let priority = match object.get("priority") {
        Some(p @ Value::Number(n)) if n.is_u64() => p.clone(),
        Some(p @ Value::String(s)) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            p.clone()
        }
        _ => return Err("a record needs a priority"),
    };
    let ttl = match object.get("ttl") {
        None => None,
        Some(t @ Value::Number(n)) if n.as_u64().is_some_and(|n| n >= 1) => Some(t.clone()),
        Some(_) => return Err("ttl must be a positive integer"),
    };
    Ok(Record {
        rtype: rtype.to_owned(),
        value: value.to_owned(),
        priority,
        ttl,
    })
}
