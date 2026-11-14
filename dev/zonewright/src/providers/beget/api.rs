//! The Beget.API functions this client uses: the form call, the two-level answer, one function
//! per endpoint and the wire types. Nothing here knows the value layer; `client.rs` and `txt.rs`
//! build on these calls.
//!
//! Sources (hard rule 3):
//!
//! - [Principles]: <https://beget.com/ru/kb/api/obshhij-princzip-raboty-s-api> ("the principles"
//!   below): the URL `https://api.beget.com/api/{section}/{method}`, the main parameters `login`
//!   and `passwd`, the additional parameters `input_format` and `input_data` (`json`: "the
//!   arguments are in `input_data`") and `output_format`, "GET or POST ... we recommend POST",
//!   the answer envelope (`status`, `answer`, `error_code`, `error_text`; inside `answer` again
//!   `status`, `result` or `errors`), the codes `AUTH_ERROR`, `INCORRECT_REQUEST`,
//!   `NO_SUCH_METHOD`, `INVALID_DATA`, `LIMIT_ERROR` ("not more than 60 requests per minute per
//!   user") and `METHOD_FAILED`.
//! - [DNS]: <https://beget.com/ru/kb/api/funkczii-upravleniya-dns> ("the DNS page"): `getData`
//!   (input `fqdn`; the result fields `is_under_control`, `is_beget_dns`, `is_subdomain`,
//!   `fqdn`, `records` and `set_type`) and `changeRecords` (inputs `fqdn` and `records`, which
//!   "must hold one of the groups": A, MX and TXT together; NS; CNAME; DNS and DNS_IP; up to
//!   10 records of each type in the first two groups; the result `true`).
//! - [Domains]: <https://beget.com/ru/kb/api/funkczii-dlya-raboty-s-domenami> ("the domains
//!   page"): `domain/getList`, "the list of the account's domains", with `id` and `fqdn` among
//!   the fields of each.
//! - lego `providers/dns/beget` (`internal/client.go`, `internal/types.go`, `beget.go`): the
//!   same functions; the TXT record fields `value`, `txtdata`, `priority`, `ttl` (types.go
//!   lines 90 to 95); the envelope types (types.go lines 10 to 63); the fixtures
//!   `getData-real.json` (an answer of the live API, posted in lego pull request 1879 on
//!   2025-09-28) and `getData_empty.json`.
//! - lego issue 2774 (<https://github.com/go-acme/lego/issues/2774>, 2025-12-30): a TXT-only
//!   `changeRecords` at an apex deleted the A and MX records there, with Beget's support quoted
//!   on why (see [`Api::change_records`]); `getData` answering `METHOD_FAILED` for a name a
//!   wildcard CNAME covers.
//!
//! The documented `getData` answer and the observed one differ (lego's maintainer says so in
//! issue 2774): the client reads both and refuses whatever it cannot write back as it was.
//!
//! Functions used, all below the `base_url`, all sent as `POST` with a form body:
//!
//! | Call            | Request                | Success                     |
//! | --------------- | ---------------------- | --------------------------- |
//! | list domains    | `POST /domain/getList` | 200, `answer.result` a list |
//! | read a name     | `POST /dns/getData`    | 200, `answer.result` object |
//! | change a name   | `POST /dns/changeRecords` | 200, `answer.result` `true` |
//!
//! Assumption (not documented): that these functions accept `POST` with `login` and `passwd` in
//! the form body. The principles page allows `POST` for the "additional" parameters and
//! recommends it, and shows `login` and `passwd` only in a query string; lego sends everything
//! in the query of a `GET`. The client never puts the credentials in a URL, which would leave
//! them in proxy logs (design section 13.4, item 8). If the API refuses them in a body, every
//! call fails with `Error::Auth` or `Error::Rejected`, and nothing is read or written. Only a
//! live run settles it.
//!
//! The API answers errors with HTTP 200 and the error in the JSON body, on two levels: the call
//! (`status`, `error_code`, `error_text`) and the method (`answer.status`, `answer.errors`).

use std::fmt;

use reqwest::Method;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Map, Value, json};

use crate::error::Error;
use crate::http::{Endpoint, Http, Request, Response};
use crate::name::DomainName;
use crate::redact::Detail;

/// Priority of a TXT record that has none to keep.
// Source: lego providers/dns/beget/beget.go:119 (`Priority: 10` for the record it adds) and the
// TXT example of the DNS page (`"priority": 10`).
const TXT_PRIORITY: u64 = 10;

/// Most records of one type in a group that holds A, MX and TXT.
// Source: the DNS page, `changeRecords`, group 1 ("Можно передавать до 10 записей каждого
// типа").
pub(super) const MAX_RECORDS: usize = 10;

/// A function of the API: its fixed path below the endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Function {
    /// `dns/getData`.
    GetData,
    /// `dns/changeRecords`.
    ChangeRecords,
    /// `domain/getList`.
    GetList,
}

impl Function {
    fn path(self) -> &'static str {
        match self {
            Function::GetData => "/dns/getData",
            Function::ChangeRecords => "/dns/changeRecords",
            Function::GetList => "/domain/getList",
        }
    }
}

/// One TXT record of a name as the API returned it, kept so that it can be written back as it
/// was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TxtEntry {
    /// The text of the value, from `txtdata` or `value`.
    pub(super) text: String,
    /// `priority` as the answer stated it, a number or a string.
    pub(super) priority: Option<Value>,
    /// `ttl` as the answer stated it, a number or a string.
    pub(super) ttl: Option<Value>,
}

/// What a `getData` answer holds that the client uses: the TXT records of the name, placeholders
/// left out. Every other record type has been refused by [`parse_records`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Parsed {
    /// The TXT records.
    pub(super) txt: Vec<TxtEntry>,
}

/// The client's handle on the API: the transport, the endpoint and the credentials.
pub(super) struct Api {
    http: Http,
    base: Endpoint,
    login: String,
    password: SecretString,
}

impl fmt::Debug for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The login is not shown either: it is half of the credentials.
        f.debug_struct("Api")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// The API at `base`; `http` already knows the login and the password as secrets.
    pub(super) fn new(http: Http, base: Endpoint, login: String, password: SecretString) -> Api {
        Api {
            http,
            base,
            login,
            password,
        }
    }

    /// `domain/getList`: the domains of the account, and a request that tests the credentials
    /// without naming a domain. Names that cannot be parsed are left out.
    // Source: the domains page, `getList`: "Метод возвращает список доменов на аккаунте
    // пользователя", the example call carries `login`, `passwd` and `output_format=json` only,
    // and the result is a list of objects with `id` and `fqdn` ("кириллические домены передаются
    // в кириллице"). The list has no paging parameters.
    pub(super) async fn domains(&self) -> Result<Vec<DomainName>, Error> {
        let result = self.call(Function::GetList, None).await?;
        let Value::Array(list) = result else {
            return Err(protocol("the provider's domain list is not a list"));
        };
        let mut names = Vec::with_capacity(list.len());
        for item in &list {
            let fqdn = item
                .get("fqdn")
                .and_then(Value::as_str)
                .ok_or_else(|| protocol("a domain of the provider's list has no fqdn"))?;
            if let Ok(name) = DomainName::parse(fqdn) {
                names.push(name);
            }
        }
        Ok(names)
    }

    /// `dns/getData` for `name`: the `answer.result` object, checked to be about `name`. A
    /// result that is not an object or names another domain is `Error::Protocol`: it is not a
    /// read of this name, and nothing may be written after it.
    // Source: the DNS page, `getData`: input `fqdn` ("полное имя домена"), result `fqdn`
    // ("переданное доменное имя"). The name is sent in Unicode form, without its trailing dot.
    // Assumption (not documented): that a name below a domain, such as `_acme-challenge.{domain}`,
    // is accepted as `fqdn`; lego does exactly that
    // (providers/dns/beget/beget.go, `GetTXTRecords(ctx, dns01.UnFqdn(info.EffectiveFQDN))`).
    pub(super) async fn get_data(&self, name: &DomainName) -> Result<Map<String, Value>, Error> {
        let input = json!({ "fqdn": fqdn(name) });
        let result = self.call(Function::GetData, Some(&input)).await?;
        let Value::Object(result) = result else {
            return Err(protocol("the provider's answer to a read is not an object"));
        };
        let stated = result
            .get("fqdn")
            .and_then(Value::as_str)
            .ok_or_else(|| protocol("the provider's answer to a read names no domain"))?;
        if DomainName::parse(stated).as_ref() != Ok(name) {
            return Err(protocol(
                "the provider's answer to a read is about another domain than the one asked for",
            ));
        }
        Ok(result)
    }

    /// `dns/changeRecords` with group 1 holding only `txt`: replaces the A, MX and TXT records of
    /// `name` with these TXT records. Sent once; the call is not idempotent from the client's
    /// point of view, since what it replaces is what the client read.
    ///
    /// The caller must have established by a read that the name holds no A or MX record: the
    /// request leaves both types out, and the API deletes a type of the group that the request
    /// leaves out (see below). [`parse_records`] refuses every name where that is not so.
    // Source: the DNS page, `changeRecords`: "В параметр records необходимо передать одну из
    // групп параметров"; group 1 is A, MX and TXT, each a list of `{priority, value}`, up to 10
    // of each type; the result is `true` ("Возвращается признак удачного или нет выполнения");
    // lego types.go:94 adds `ttl` to a TXT record. What the request does to the types of the
    // group it leaves out is not in the documentation; it is settled by an observation: lego
    // issue 2774 (github.com/go-acme/lego/issues/2774, opened 2025-12-30) reports that a
    // TXT-only `changeRecords` at a domain's apex deleted its A and MX records, and quotes
    // Beget's support: all existing A, MX and TXT records have to be passed in their entirety,
    // "otherwise the rest will be deleted". The same issue shows, and lego's maintainer
    // confirms there, that `getData` returns A and MX records in a shape (`address`;
    // `exchange`, `preference`, `ttl`) that has no documented spelling in a `changeRecords`
    // request, so the client cannot send them back faithfully and refuses such names instead.
    pub(super) async fn change_records(
        &self,
        name: &DomainName,
        txt: Vec<Value>,
    ) -> Result<(), Error> {
        if txt.len() > MAX_RECORDS {
            return Err(Error::InvalidInput {
                detail: Detail::constant("a Beget name holds at most 10 records of one type"),
            });
        }
        // An empty list is how the last value is removed. Assumption (not documented): that
        // `"TXT": []` is accepted and clears the TXT records. lego sends `"records": {}` for an
        // empty set (types.go:86, `omitempty`; client_test.go `TestClient_ChangeTXTRecord_remove`),
        // and its live run in pull request 1879 (github.com/go-acme/lego/pull/1879, 2025-09-29)
        // cleaned up without an error, which shows that form accepted but not what it removed.
        // Either form names no A or MX record, so both clear the same group at a name that holds
        // none. A refusal of this one fails the removal and changes nothing.
        let mut records = Map::new();
        records.insert("TXT".to_owned(), Value::Array(txt));
        let input = json!({ "fqdn": fqdn(name), "records": records });
        let result = self.call(Function::ChangeRecords, Some(&input)).await?;
        match result {
            Value::Bool(true) => Ok(()),
            Value::Bool(false) => Err(Error::Rejected {
                status: None,
                detail: Detail::constant("the provider reported that the change was not made"),
            }),
            _ => Err(protocol(
                "the provider's answer to a change is not the documented success flag",
            )),
        }
    }

    /// One call: the form, the HTTP answer, the envelope. Returns `answer.result`.
    async fn call(&self, function: Function, input: Option<&Value>) -> Result<Value, Error> {
        let url = self.base.url().path(function.path()).build()?;
        // The input holds names and TXT values, never a credential; the credentials are form
        // fields of their own, in a body that is wiped when it is dropped.
        let input_text = input.map(Value::to_string);
        let mut form = vec![
            ("login", self.login.as_str()),
            ("passwd", self.password.expose_secret()),
        ];
        if let Some(text) = &input_text {
            form.push(("input_format", "json"));
            form.push(("input_data", text.as_str()));
        }
        form.push(("output_format", "json"));
        let mut request = Request::new(Method::POST, url).form(&form);
        // Reading is safe to repeat; changing is not.
        if function != Function::ChangeRecords {
            request = request.idempotent();
        }
        let response = self.http.send(&request).await?;
        if !response.is_success() {
            // 401, 403, 429 and 5xx were mapped by the transport already. The API documents no
            // HTTP status for an error; any other one is a refusal by something in front of it.
            return Err(self.http.reject(&response));
        }
        self.envelope(&response)
    }

    /// The `answer.result` of a 200 answer, or the error the envelope states.
    fn envelope(&self, response: &Response) -> Result<Value, Error> {
        let body: Value = response.json("the provider's answer is not in the expected form")?;
        let status = body
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| protocol("the provider's answer has no status"))?;
        if status != "success" {
            return Err(self.classify(&body));
        }
        let answer = body
            .get("answer")
            .filter(|answer| answer.is_object())
            .ok_or_else(|| protocol("the provider's answer has no answer object"))?;
        let inner = answer
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| protocol("the provider's answer has no method status"))?;
        if inner != "success" {
            return Err(self.classify(&body));
        }
        answer
            .get("result")
            .cloned()
            .ok_or_else(|| protocol("the provider's successful answer has no result"))
    }

    /// The error an envelope states, from every code it carries on either level.
    ///
    /// The mapping, by the codes of the principles page: `AUTH_ERROR` is `Auth`; `LIMIT_ERROR`
    /// is `RateLimited` (the API states no wait); `METHOD_FAILED`, "an internal error while the
    /// method ran", is `Transient`, since the outcome of a change is unknown (lego issue 2774
    /// shows a read answered `METHOD_FAILED` for as long as the name stood under a wildcard
    /// CNAME, so a repeat does not always help; it never writes either); everything else
    /// (`INVALID_DATA`, `INCORRECT_REQUEST`, `NO_SUCH_METHOD`, an unknown code) is `Rejected`
    /// without an HTTP status.
    fn classify(&self, body: &Value) -> Error {
        let errors = errors_of(body);
        let has = |wanted: &str| errors.iter().any(|(code, _)| code == wanted);
        let detail = if errors.is_empty() {
            Detail::constant("the provider reported an error without a code")
        } else {
            self.http.detail(&describe(&errors))
        };
        if has("AUTH_ERROR") {
            Error::Auth { detail }
        } else if has("LIMIT_ERROR") {
            Error::RateLimited { retry_after: None }
        } else if has("METHOD_FAILED") {
            Error::Transient { detail }
        } else {
            Error::Rejected {
                status: None,
                detail,
            }
        }
    }
}

fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

/// The name as the API takes it: Unicode form, no trailing dot.
fn fqdn(name: &DomainName) -> String {
    let unicode = name.to_unicode();
    unicode.strip_suffix('.').unwrap_or(&unicode).to_owned()
}

/// The JSON of one TXT record for `changeRecords`: `value`, `priority` and, when there is one,
/// `ttl`.
// Source: the DNS page (`priority`, `value`); lego types.go:90 to 95 (`ttl`).
pub(super) fn txt_json(text: &str, priority: Option<&Value>, ttl: Option<Value>) -> Value {
    let mut object = Map::new();
    object.insert("value".to_owned(), Value::String(text.to_owned()));
    object.insert(
        "priority".to_owned(),
        priority.cloned().unwrap_or_else(|| json!(TXT_PRIORITY)),
    );
    if let Some(ttl) = ttl {
        object.insert("ttl".to_owned(), ttl);
    }
    Value::Object(object)
}

/// Every `(error_code, error_text)` of an envelope: the call's own and those of the method, in
/// `answer.errors` or directly in `answer` (lego `Answer` has both,
/// providers/dns/beget/internal/types.go:36 to 44).
fn errors_of(body: &Value) -> Vec<(String, String)> {
    fn pair(object: &Value) -> Option<(String, String)> {
        let text = |key: &str| {
            object
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let (code, message) = (text("error_code"), text("error_text"));
        (!code.is_empty() || !message.is_empty()).then_some((code, message))
    }
    let mut out: Vec<(String, String)> = pair(body).into_iter().collect();
    if let Some(answer) = body.get("answer") {
        out.extend(pair(answer));
        if let Some(Value::Array(list)) = answer.get("errors") {
            out.extend(list.iter().filter_map(pair));
        }
    }
    out
}

fn describe(errors: &[(String, String)]) -> String {
    errors
        .iter()
        .map(|(code, text)| match (code.is_empty(), text.is_empty()) {
            (false, false) => format!("{code}: {text}"),
            (false, true) => code.clone(),
            _ => text.clone(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The provider's error message from a body: the codes and texts of both levels of the
/// envelope.
// Source: the principles page, "Обработка ответа": `error_text` and `error_code` beside `status`,
// and `answer.errors` with the same two fields in each error.
pub(super) fn error_message(body: &str) -> Option<String> {
    let body: Value = serde_json::from_str(body).ok()?;
    let errors = errors_of(&body);
    (!errors.is_empty()).then(|| describe(&errors))
}

/// The TXT records of a `getData` result. Every state of the name in which a TXT-only write
/// could drop or alter a record that is not one of these TXT records is refused with
/// `Error::Rejected`; a read that is not complete is `Error::Protocol`. Nothing may be written
/// after either.
///
/// - `set_type`, when stated, must be 1 ("A, MX, TXT in use"); 2 (NS records) and 3 (a CNAME)
///   mean that a group 1 write would replace them, and an unknown value is not guessed at.
/// - `records` is an object (the records by type) or an empty list (what an empty PHP array
///   encodes to). Absent, `null` or any other shape is `Error::Protocol`: lego's test fixture
///   `getData_empty.json` has no `records` key for an empty name, but nothing shows that this
///   was observed, and reading a missing key as "no records" would let a write replace TXT
///   records an incomplete answer left out. Until a live run shows the answer for an empty
///   name, adding the first value at a fresh name may fail here; it never writes.
/// - Every type other than TXT, `A`, `MX`, `NS`, `CNAME`, `DNS`, `DNS_IP` or any other, may hold
///   placeholders only. A record of the name's group (A, MX) would be deleted by the TXT-only
///   write, and its observed shape has no documented spelling in the write; NS and CNAME belong
///   to another group, which a group 1 write replaces; `DNS` and `DNS_IP` are the name server
///   settings of a domain, and nothing says that a group 1 write leaves them alone.
/// - A placeholder is an object with `value` empty or `null` and no field but `value` and
///   `priority`: the DNS page's example answer has `{"value": "", "priority": 0}` for a name
///   without TXT records and `{"value": null, "priority": 10}` for an unused `DNS_IP` slot, and
///   lego's observed answer has `{"value": ""}` for the latter.
/// - A TXT record carries its text in `txtdata` (the observed answer) or `value` (the DNS
///   page), and otherwise only `priority` and `ttl`, the attributes the write sends back. A
///   record with any other field, without text in an entry that is not a placeholder (a TXT
///   record whose text may be empty), or without a TTL (which a write without one could reset)
///   is refused: it cannot be written back as it is.
// Source: the DNS page, `getData`: `records` by type DNS, DNS_IP, A, MX and TXT, each a list of
// `{value, priority}`; `set_type` 1 "A, MX, TXT in use", 2 "NS (subdomains)", 3 "CNAME
// (subdomains)"; the `changeRecords` groups. lego providers/dns/beget/internal/fixtures/
// getData-real.json, an answer of the live API posted in lego pull request 1879 on 2025-09-28:
// TXT records `{ttl, txtdata}`, A records `{ttl, address}`, MX records `{ttl, exchange,
// preference}`, `DNS` `{value}` and `DNS_IP` `{value: ""}`.
// Assumption (not documented): an empty list as `records` means no records.
pub(super) fn parse_records(result: &Map<String, Value>) -> Result<Parsed, Error> {
    if let Some(set_type) = result.get("set_type") {
        let kind = match set_type {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => s.trim().parse().ok(),
            _ => None,
        };
        if kind != Some(1) {
            return Err(refused(
                "the name is not set up with A, MX and TXT records (set_type), and a TXT write \
                 could replace what it holds",
            ));
        }
    }
    let records = match result.get("records") {
        Some(Value::Object(records)) => records,
        Some(Value::Array(list)) if list.is_empty() => return Ok(Parsed { txt: Vec::new() }),
        None => return Err(protocol("the provider's answer to a read has no records")),
        Some(_) => {
            return Err(protocol(
                "the provider's records are not in the expected form",
            ));
        }
    };
    let mut parsed = Parsed { txt: Vec::new() };
    for (rtype, list) in records {
        let entries: &[Value] = match list {
            Value::Array(entries) => entries,
            Value::Null => &[],
            _ => {
                return Err(protocol(
                    "the provider's records of a type are not in the expected form",
                ));
            }
        };
        if rtype == "TXT" {
            for entry in entries {
                if let Some(txt) = txt_entry(entry)? {
                    parsed.txt.push(txt);
                }
            }
        } else if entries.iter().any(|entry| !is_placeholder(entry)) {
            return Err(refused(
                "the name holds records of a type other than TXT (A, MX, NS, CNAME, name server \
                 settings or another), which a TXT write could delete or replace",
            ));
        }
    }
    Ok(parsed)
}

fn refused(text: &'static str) -> Error {
    Error::Rejected {
        status: None,
        detail: Detail::constant(text),
    }
}

/// An entry without a value: an object with `value` empty or `null` and no field but `value`
/// and `priority`.
fn is_placeholder(entry: &Value) -> bool {
    let Value::Object(object) = entry else {
        return false;
    };
    let empty = match object.get("value") {
        Some(Value::Null) => true,
        Some(Value::String(text)) => text.is_empty(),
        _ => false,
    };
    empty
        && object
            .keys()
            .all(|key| matches!(key.as_str(), "value" | "priority"))
}

/// A number or a string, kept as stated; anything else is dropped.
fn kept(value: Option<&Value>) -> Option<Value> {
    match value {
        Some(v @ (Value::Number(_) | Value::String(_))) => Some(v.clone()),
        _ => None,
    }
}

/// One TXT entry: `None` for a placeholder, `Error::Rejected` for a record that cannot be
/// written back as it is, `Error::Protocol` for an entry of an unknown shape.
fn txt_entry(entry: &Value) -> Result<Option<TxtEntry>, Error> {
    let Value::Object(object) = entry else {
        return Err(protocol("a TXT record of the provider is not an object"));
    };
    if is_placeholder(entry) {
        return Ok(None);
    }
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "txtdata" | "value" | "priority" | "ttl"))
    {
        return Err(refused(
            "a TXT record of the name has an attribute the write cannot carry back",
        ));
    }
    let text_of = |key: &str| -> Result<Option<&str>, Error> {
        match object.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(text)) => Ok(Some(text.as_str()).filter(|t| !t.is_empty())),
            Some(_) => Err(protocol(
                "a TXT record of the provider has a value that is not text",
            )),
        }
    };
    // `txtdata` is what the observed answer and lego carry; the DNS page's example calls the
    // field `value`.
    let (txtdata, value) = (text_of("txtdata")?, text_of("value")?);
    let Some(text) = txtdata.or(value) else {
        if object.contains_key("txtdata") || object.contains_key("value") {
            // An empty text: an empty TXT record or a placeholder in a shape the sources do not
            // show. Dropping it from the write could delete a record.
            return Err(refused(
                "a TXT record of the name has an empty text, which may be a record of its own",
            ));
        }
        return Err(protocol("a TXT record of the provider has no text"));
    };
    let ttl = kept(object.get("ttl"));
    if ttl.is_none() {
        return Err(refused(
            "a TXT record of the name states no TTL, and writing it back without one could \
             change it",
        ));
    }
    Ok(Some(TxtEntry {
        text: text.to_owned(),
        priority: kept(object.get("priority")),
        ttl,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            other => panic!("not an object: {other}"),
        }
    }

    #[test]
    fn messages_join_both_levels() {
        for (body, expected) in [
            (
                r#"{"status":"error","error_code":"AUTH_ERROR","error_text":"bad login"}"#,
                Some("AUTH_ERROR: bad login"),
            ),
            (
                r#"{"status":"success","answer":{"status":"error","errors":[
                    {"error_code":"INVALID_DATA","error_text":"a"},
                    {"error_code":"LIMIT_ERROR","error_text":"b"}]}}"#,
                Some("INVALID_DATA: a; LIMIT_ERROR: b"),
            ),
            (
                r#"{"status":"success","answer":{"status":"error","error_code":"X"}}"#,
                Some("X"),
            ),
            (
                r#"{"status":"success","answer":{"status":"success"}}"#,
                None,
            ),
            ("<html>nope</html>", None),
        ] {
            assert_eq!(error_message(body).as_deref(), expected, "{body}");
        }
    }

    #[test]
    fn records_shapes() {
        let parsed = |v: Value| parse_records(&object(v));
        // An empty PHP array.
        assert!(parsed(json!({"records": []})).unwrap().txt.is_empty());
        // The documented placeholders: no TXT record, unused name server slots.
        let p = parsed(json!({"records": {
            "DNS_IP": [{"value": null, "priority": 10}, {"value": ""}],
            "A": [],
            "MX": null,
            "TXT": [{"value": "", "priority": 0}]
        }, "set_type": 1}))
        .unwrap();
        assert!(p.txt.is_empty());
        // The observed shape: `txtdata` and `ttl`; `txtdata` wins over `value`; priority and
        // ttl are kept as stated.
        let p = parsed(json!({"records": {"TXT": [
            {"ttl": 300, "txtdata": "v=spf1 redirect=example.net"},
            {"txtdata": "one", "value": "other", "priority": "10", "ttl": "600"},
            {"value": "two", "ttl": 60}
        ]}}))
        .unwrap();
        assert_eq!(p.txt[0].text, "v=spf1 redirect=example.net");
        assert_eq!(p.txt[0].priority, None);
        assert_eq!(p.txt[1].text, "one");
        assert_eq!(p.txt[1].ttl, Some(json!("600")));
        assert_eq!(p.txt[2].text, "two");
        // Incomplete answers are protocol errors; names a TXT-only write could damage are
        // refused.
        for (v, kind) in [
            (json!({"set_type": 1}), "protocol"),
            (json!({"records": null}), "protocol"),
            (json!({"records": "x"}), "protocol"),
            (json!({"records": [1]}), "protocol"),
            (json!({"records": {"TXT": "x"}}), "protocol"),
            (json!({"records": {"TXT": ["x"]}}), "protocol"),
            (
                json!({"records": {"TXT": [{"value": 5, "ttl": 1}]}}),
                "protocol",
            ),
            (json!({"records": {"TXT": [{"priority": 10}]}}), "protocol"),
            // The observed A and MX shapes, and the documented ones.
            (
                json!({"records": {"A": [{"ttl": 300, "address": "192.0.2.1"}]}}),
                "rejected",
            ),
            (
                json!({"records": {"MX": [{"ttl": 300, "exchange": "mx.example.org.",
                    "preference": 10}]}}),
                "rejected",
            ),
            (
                json!({"records": {"A": [{"value": "192.0.2.1", "priority": "0"}]}}),
                "rejected",
            ),
            (
                json!({"records": {"CNAME": [{"value": "t.example.org"}]}}),
                "rejected",
            ),
            (
                json!({"records": {"NS": [{"value": "ns.example.org"}]}}),
                "rejected",
            ),
            (
                json!({"records": {"DNS": [{"value": "ns1.example.net"}]}}),
                "rejected",
            ),
            (
                json!({"records": {"DNS_IP": [{"value": "192.0.2.53"}]}}),
                "rejected",
            ),
            (json!({"records": {"CAA": [{"data": "x"}]}}), "rejected"),
            // A placeholder-looking entry with another field is not a placeholder.
            (
                json!({"records": {"A": [{"value": "", "ttl": 300}]}}),
                "rejected",
            ),
            // TXT records that cannot be written back as they are.
            (
                json!({"records": {"TXT": [{"txtdata": "", "ttl": 300}]}}),
                "rejected",
            ),
            (
                json!({"records": {"TXT": [{"value": "", "priority": 0, "ttl": 300}]}}),
                "rejected",
            ),
            (json!({"records": {"TXT": [{"txtdata": "x"}]}}), "rejected"),
            (
                json!({"records": {"TXT": [{"txtdata": "x", "ttl": 300, "weight": 1}]}}),
                "rejected",
            ),
            (json!({"records": {"TXT": []}, "set_type": 3}), "rejected"),
            (json!({"records": {"TXT": []}, "set_type": "2"}), "rejected"),
            (json!({"records": {"TXT": []}, "set_type": 4}), "rejected"),
            (
                json!({"records": {"TXT": []}, "set_type": null}),
                "rejected",
            ),
        ] {
            let e = parsed(v.clone()).unwrap_err();
            let ok = match kind {
                "protocol" => matches!(e, Error::Protocol { .. }),
                _ => matches!(e, Error::Rejected { .. }),
            };
            assert!(ok, "{v}: {e:?}");
        }
        // Empty lists of other types are not records.
        assert!(parsed(json!({"records": {"NS": [], "CNAME": null, "TXT": []}})).is_ok());
    }

    #[test]
    fn txt_json_keeps_priority_and_ttl() {
        let v = txt_json("x", Some(&json!("0")), Some(json!(600)));
        assert_eq!(v, json!({"value": "x", "priority": "0", "ttl": 600}));
        assert_eq!(
            txt_json("x", None, None),
            json!({"value": "x", "priority": 10})
        );
    }
}
