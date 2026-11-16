//! The Porkbun API v3 as this client uses it: one function per endpoint, the wire types, paging
//! and the classification of answers. Nothing here knows the value layer; `client.rs`, `txt.rs`
//! and `records.rs` build on these calls.
//!
//! Sources (hard rule 3), read 2026-11-16:
//!
//! - [Spec]: the OpenAPI description, <https://porkbun.com/api/json/v3/spec>, version 3.79
//!   ("the spec" below): the base URL (`servers`), authentication (`securitySchemes`
//!   `X-API-Key` and `X-Secret-API-Key`, applied to every operation by the top-level
//!   `security`; the description's "Authentication": the keys in the JSON body or as these two
//!   headers, "Header auth takes effect only when no body credentials are present"), the
//!   operations `GET /ping`, `GET /domain/listAll`, `GET /dns/retrieve/{domain}`,
//!   `POST /dns/create/{domain}`, `POST /dns/edit/{domain}/{id}` and
//!   `POST /dns/delete/{domain}/{id}` with their schemas (`DnsRecordsResponse`,
//!   `DomainListAllResponse`, `CreateDnsRequest`, `EditDnsRequest`, `AuthRequest`,
//!   `BasicResponse`, `ErrorResponse`), the "HTTP status codes" and "Error codes" sections, and
//!   the "Rate limiting" section.
//! - [Topic page]: <https://porkbun.com/llms/dns> (generated from the spec): the same operations,
//!   and "send `X-API-Key` / `X-Secret-API-Key` headers (preferred) or `apikey` /
//!   `secretapikey` in the JSON body".
//! - lego `providers/dns/porkbun/porkbun.go` and the client it uses, nrdcg/porkbun
//!   (`client.go`, `types.go`, commit `b8c9c69`): create by `POST /dns/create/{domain}` with
//!   the record's `name` relative to the domain, delete by `POST /dns/delete/{domain}/{id}`; a
//!   `200` answer whose `status` is not `SUCCESS` is an error.
//!
//! Endpoints used, all below the `base_url`:
//!
//! | Call          | Request                             | Success                |
//! | ------------- | ----------------------------------- | ---------------------- |
//! | ping          | `GET /ping`                         | 200, `credentialsValid` |
//! | list domains  | `GET /domain/listAll?start=`        | 200, `domains`         |
//! | one domain    | `GET /domain/listAll?domain=`       | 200, 0 or 1 `domains`  |
//! | list records  | `GET /dns/retrieve/{domain}`        | 200, `records`         |
//! | create record | `POST /dns/create/{domain}`         | 200, `SUCCESS`         |
//! | edit record   | `POST /dns/edit/{domain}/{id}`      | 200, `SUCCESS`         |
//! | delete record | `POST /dns/delete/{domain}/{id}`    | 200, `SUCCESS`         |
//!
//! # Credentials
//!
//! The client sends the two keys as the documented headers `X-API-Key` and `X-Secret-API-Key`
//! and never in a request body, on every call. The spec documents both ways for every operation
//! and lego's client uses the body; the headers are chosen because a request body is ordinary
//! data (logged by proxies, echoed by APIs that quote the request), while the transport marks
//! both header values sensitive and builds them in wiped memory. Both keys are registered with
//! the client's scrubber, so an answer that echoes either one has it replaced before it reaches
//! an error. Reads use `GET` (the spec: "All read-only endpoints accept `GET` requests", "Supports
//! both GET (with header auth) and POST"); writes use `POST` with a JSON body that holds only the
//! record's fields, `{}` for the delete (the spec's `INVALID_OR_EMPTY_JSON`: "Request body is
//! missing or not valid JSON").
//!
//! Assumption (not documented by an example): that the write operations take the header
//! credentials. The spec states the headers for every operation, and its examples of header
//! authentication on a `POST` are other operations (`/domain/create`, the "Idempotency"
//! section). If the API refused them, every write would fail with `Error::Auth`, and nothing
//! would be written. `porkbun_live_assumptions` checks it.
//!
//! # Answers
//!
//! "Every refusal now returns HTTP 400 with a proper code" (the spec's changelog, v3.20), with
//! the body `{"status":"ERROR","code":…,"message":…}` (`ErrorResponse`); 403 for key
//! restrictions and 429 for rate limits are mapped by the transport. The `code` is carried as
//! the provider code of `Error::Rejected` and `Error::InvalidInput`, and decides the kind for
//! the codes whose meaning the spec states (see [`classify`]).

use std::fmt;
use std::sync::Mutex;

use reqwest::Method;
use reqwest::header::{HeaderName, HeaderValue};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Error;
use crate::http::pager::{self, Page};
use crate::http::request::sensitive_value;
use crate::http::url::UrlBuilder;
use crate::http::{Endpoint, Http, Request, Response};
use crate::name::DomainName;
use crate::record::{RecordType, RrsetTtl};
use crate::redact::Detail;

/// The header that carries the API key.
// Source: the spec, `securitySchemes.ApiKeyHeader` (`X-API-Key`).
pub(super) const API_KEY_HEADER: HeaderName = HeaderName::from_static("x-api-key");

/// The header that carries the secret API key.
// Source: the spec, `securitySchemes.SecretApiKeyHeader` (`X-Secret-API-Key`).
pub(super) const SECRET_KEY_HEADER: HeaderName = HeaderName::from_static("x-secret-api-key");

/// The record type name as the API spells it.
pub(super) const TXT: &str = "TXT";

/// Most domains one page of `/domain/listAll` holds.
// Source: the spec, `/domain/listAll`: "Results are returned in chunks of up to 1000 domains.
// Use `start` to paginate"; `start`: "Zero-based offset for pagination. Returns up to 1000
// domains per call." No page size can be requested.
const PAGE_SIZE: usize = 1000;

/// The `status` of a successful answer.
// Source: the spec, every success schema (`"status": "SUCCESS"`); nrdcg client.go
// (`statusSuccess`).
const SUCCESS: &str = "SUCCESS";

/// A record as `/dns/retrieve/{domain}` returns it; other fields (`notes`) are ignored.
// Source: the spec, `DnsRecordsResponse.records[]`: `id` ("Numeric record ID", a string),
// `name` ("Fully-qualified record name", example `www.example.com`), `type`, `content`, `ttl`
// (a string), `prio` (a string, "Null if not applicable"), `notes`. The item schema lists no
// required member, so each is optional here; `id`, `ttl` and `prio` are taken as a string or a
// number ("some write paths sent numbers", the spec's changelog v3.62 on the same fields of
// webhook events).
#[derive(Debug, Deserialize)]
pub(super) struct Record {
    /// The record's identifier.
    #[serde(default)]
    id: Option<Value>,
    /// The owner name, fully qualified.
    #[serde(default)]
    pub(super) name: Option<String>,
    /// The record type.
    #[serde(default, rename = "type")]
    pub(super) rtype: Option<String>,
    /// The value.
    #[serde(default)]
    pub(super) content: Option<String>,
    /// TTL in seconds.
    #[serde(default)]
    ttl: Option<Value>,
    /// The priority of MX and SRV records.
    #[serde(default)]
    prio: Option<Value>,
}

impl Record {
    /// The identifier, when the answer states one as a decimal number.
    pub(super) fn id(&self) -> Option<u64> {
        number(self.id.as_ref())
    }

    /// The TTL, when the answer states one the model can hold.
    pub(super) fn ttl(&self) -> Option<RrsetTtl> {
        number(self.ttl.as_ref())
            .and_then(|secs| u32::try_from(secs).ok())
            .and_then(|secs| RrsetTtl::from_secs(secs).ok())
    }

    /// The priority, when the answer states one.
    pub(super) fn prio(&self) -> Option<u64> {
        number(self.prio.as_ref())
    }

    /// The record type, when it maps to one.
    pub(super) fn record_type(&self) -> Option<RecordType> {
        self.rtype.as_deref()?.parse().ok()
    }

    /// The owner name: the stated fully qualified name, when it is a valid name inside `zone`.
    /// A name in any other form is never taken for a name of the zone, so a record read wrongly
    /// cannot be taken for ours.
    // Source: the spec, `DnsRecordsResponse.records[].name`, "Fully-qualified record name"
    // (example `www.example.com`); the webhook notes ("`name` is the full hostname
    // (`www.example.com`, or `example.com` for the apex) ... the same as in `/dns/retrieve`").
    pub(super) fn owner(&self, zone: &DomainName) -> Option<DomainName> {
        let name = DomainName::parse(self.name.as_deref()?).ok()?;
        name.is_within(zone).then_some(name)
    }
}

/// A non-negative integer stated as a JSON number or as a string of decimal digits.
fn number(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse().ok()
        }
        _ => None,
    }
}

/// A flag of `/domain/listAll`: `1` or `0`.
// Source: the spec, `DomainListAllResponse.domains[]`: `apiAccess` and `notLocal` are integers,
// 1 or 0; the changelog (v3.36) says they "previously came back as the string "1"", so that form
// is read too.
fn flag(value: Option<&Value>) -> Option<bool> {
    match value? {
        Value::Number(n) => n.as_u64().map(|n| n == 1),
        Value::String(s) => match s.as_str() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        },
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}

/// A domain as `/domain/listAll` returns it; other fields are ignored.
// Source: the spec, `DomainListAllResponse.domains[]`: `domain`, `apiAccess` ("1 if the domain is
// opted in to API access"), `notLocal` ("1 if the domain is externally managed (not
// authoritative)").
#[derive(Debug, Deserialize)]
pub(super) struct Domain {
    /// The domain name.
    pub(super) domain: String,
    #[serde(default, rename = "apiAccess")]
    api_access: Option<Value>,
    #[serde(default, rename = "notLocal")]
    not_local: Option<Value>,
}

impl Domain {
    /// The domain is opted in to API access. `None` when the answer does not say.
    pub(super) fn api_access(&self) -> Option<bool> {
        flag(self.api_access.as_ref())
    }

    /// The domain is served by other name servers. `None` when the answer does not say.
    pub(super) fn not_local(&self) -> Option<bool> {
        flag(self.not_local.as_ref())
    }
}

/// The body of `POST /dns/create/{domain}`.
// Source: the spec, `CreateDnsRequest`: `name` ("Subdomain for the record (e.g. 'www', '*' for
// wildcard, blank for root). Do not include the domain name itself."), `type` and `content`
// (required), `ttl` (integer), `prio` (integer, "Priority for MX and SRV records. Defaults to 0
// if omitted."). The keys are sent in headers, not here (module documentation).
#[derive(Serialize)]
pub(super) struct NewRecord<'a> {
    /// The owner name relative to the domain, empty for the apex.
    pub(super) name: &'a str,
    /// The record type.
    #[serde(rename = "type")]
    pub(super) rtype: &'a str,
    /// The value.
    pub(super) content: &'a str,
    /// TTL in seconds. Always sent: without it the provider applies the account's minimum.
    pub(super) ttl: u32,
    /// MX preference or SRV priority; left out for other types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) prio: Option<u16>,
}

/// The body of `POST /dns/edit/{domain}/{id}`: only the fields that change.
// Source: the spec, `/dns/edit`: "Send only the fields you want to change: any field left out
// keeps its current value"; `EditDnsRequest` (`content`, `ttl`, `prio`, `notes`, all
// optional). Left out, `notes` keeps the record's notes.
#[derive(Default, Serialize)]
pub(super) struct RecordEdit<'a> {
    /// The new value; left out when it stays.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) content: Option<&'a str>,
    /// The new TTL; left out when it stays.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ttl: Option<u32>,
    /// The new priority; left out when it stays.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) prio: Option<u16>,
}

/// The answer to a create.
#[derive(Debug)]
pub(super) enum Created {
    /// The provider created the record.
    Done,
    /// `DUPLICATE_RECORD`: "A record with this exact name, type and content already exists, so
    /// nothing was created" (the spec's "Error codes"). Carries the refusal as an error, for
    /// the caller to return when a new read does not confirm it.
    Duplicate(Error),
}

/// The answer to an edit or a delete.
#[derive(Debug)]
pub(super) enum Written {
    /// The provider accepted the write.
    Done,
    /// `INVALID_RECORD_ID`: "DNS record ID was not found or is not owned by your account" (the
    /// spec's "Error codes"); nothing was written.
    Gone,
}

/// How the client treats a refusal, by its code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
    /// The keys are not accepted.
    Auth,
    /// The keys are accepted but may not do this.
    Forbidden,
    /// The domain is not in the account.
    ZoneNotFound,
    /// The record is not in the domain.
    RecordNotFound,
    /// The record exists already.
    Duplicate,
    /// The request itself is malformed.
    InvalidInput,
    /// Any other refusal.
    Rejected,
}

/// The kind of a refusal with `code`.
// Source: the spec, "Error codes": `API_KEY_REQUIRED` ("No API key or token was provided"),
// `INVALID_API_KEYS_001` ("API key and secret combination is invalid"), `INVALID_USER`
// ("Account associated with the API key was not found or is not active"); `IP_NOT_ALLOWED`,
// `DOMAIN_NOT_ALLOWED`, `INSUFFICIENT_SCOPE` (all HTTP 403, mapped by the transport as well),
// `API_ACCESS_DISABLED` ("The domain is not opted in to API access. Only the account holder can
// turn it on"); `INVALID_DOMAIN` ("Domain parameter is invalid or not in your account") and
// `DOMAIN_NOT_FOUND` ("The domain is not in this account"); `INVALID_RECORD_ID`;
// `DUPLICATE_RECORD`; `INVALID_TYPE` ("DNS record type is not supported"), `INVALID_INPUT` ("A
// parameter is missing, the wrong type, or out of range") and `MISSING_PARAMETER`. A code that
// is not listed here is a refusal like any other.
pub(super) fn classify(code: &str) -> Class {
    match code {
        "API_KEY_REQUIRED" | "INVALID_API_KEYS_001" | "INVALID_USER" => Class::Auth,
        "IP_NOT_ALLOWED" | "DOMAIN_NOT_ALLOWED" | "INSUFFICIENT_SCOPE" | "API_ACCESS_DISABLED" => {
            Class::Forbidden
        }
        "INVALID_DOMAIN" | "DOMAIN_NOT_FOUND" => Class::ZoneNotFound,
        "INVALID_RECORD_ID" => Class::RecordNotFound,
        "DUPLICATE_RECORD" => Class::Duplicate,
        "INVALID_TYPE" | "INVALID_INPUT" | "MISSING_PARAMETER" => Class::InvalidInput,
        _ => Class::Rejected,
    }
}

/// A refusal: its class and the error the caller returns unless it handles the class.
struct Refusal {
    class: Class,
    error: Error,
}

/// The client's handle on the API: the transport, the endpoint and the API key header.
pub(super) struct Api {
    http: Http,
    base: Endpoint,
    /// `X-API-Key` with the API key, marked sensitive.
    key: HeaderValue,
}

impl fmt::Debug for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// The API at `base`. `http` sends the secret API key with every request; `api_key` is sent
    /// as its own header. `None` when the API key cannot be a header value.
    pub(super) fn new(http: Http, base: Endpoint, api_key: &str) -> Option<Api> {
        let key = sensitive_value("", api_key.as_bytes())?;
        Some(Api { http, base, key })
    }

    /// A request with the API key header; the transport adds the secret API key header.
    fn request(&self, method: Method, url: reqwest::Url) -> Request {
        let request = if method == Method::GET {
            Request::get(url)
        } else {
            Request::new(method, url)
        };
        request.header(API_KEY_HEADER, self.key.clone())
    }

    /// `GET /ping` with the keys: a success with `credentialsValid: true` proves that the keys
    /// are accepted now.
    // Source: the spec, `/ping`: "Valid credentials supplied — returns IP with
    // `credentialsValid: true`. Invalid credentials supplied — returns an error"; the 400 answer
    // "Invalid credentials".
    pub(super) async fn ping(&self) -> Result<(), Error> {
        #[derive(Deserialize)]
        struct Pong {
            #[serde(default, rename = "credentialsValid")]
            credentials_valid: Option<bool>,
        }
        let url = self.base.url().path("/ping").build()?;
        let response = self.http.send(&self.request(Method::GET, url)).await?;
        let pong: Pong = self
            .success(
                &response,
                None,
                "the provider's ping answer is not in the expected form",
            )
            .map_err(|refusal| refusal.error)?;
        if pong.credentials_valid == Some(true) {
            Ok(())
        } else {
            // The answer did not confirm the keys: they were not taken.
            Err(Error::Auth {
                detail: Detail::constant("the provider did not confirm the API key pair"),
            })
        }
    }

    /// The domain `zone` as `/domain/listAll` states it, or `None` when the account has no such
    /// domain.
    // Source: the spec, `/domain/listAll`, `domain`: "Exact domain name match. Returns 0 or 1
    // result."
    pub(super) async fn domain(&self, zone: &DomainName) -> Result<Option<Domain>, Error> {
        let url = self
            .base
            .url()
            .path("/domain/listAll")
            .query("domain", zone.without_dot())
            .build()?;
        let response = self.http.send(&self.request(Method::GET, url)).await?;
        let list: DomainList = self
            .success(
                &response,
                None,
                "the provider's domain listing is not in the expected form",
            )
            .map_err(|refusal| refusal.error)?;
        let mut domains = list.domains.into_iter();
        let found = domains.next();
        if domains.next().is_some() {
            return Err(protocol(
                "the provider answered an exact domain match with more than one domain",
            ));
        }
        match found {
            None => Ok(None),
            Some(domain) if DomainName::parse(&domain.domain).as_ref() == Ok(zone) => {
                Ok(Some(domain))
            }
            Some(_) => Err(protocol(
                "the provider answered with a domain other than the one asked for",
            )),
        }
    }

    /// Every domain of the account, all pages.
    ///
    /// The offset advances by the domains received; a page with fewer than 1000 domains is the
    /// last. A page that repeats the previous one (a server that does not take `start`), or a
    /// `count` that differs from the domains on the page, is `Error::Protocol`; the number of
    /// pages is bounded by the shared pager.
    // Source: the spec, `/domain/listAll`: "chunks of up to 1000 domains. Use `start` to
    // paginate"; `count`: "Number of domains returned in this page." Assumption (not
    // documented): that only the last page holds fewer than 1000 domains, which is how "chunks
    // of up to 1000" reads. Being wrong makes a listing shorter, never longer; no write depends
    // on this listing.
    pub(super) async fn domains(&self) -> Result<Vec<Domain>, Error> {
        let previous: Mutex<Option<String>> = Mutex::new(None);
        pager::collect(0usize, |start| {
            let previous = &previous;
            async move {
                let url = self
                    .base
                    .url()
                    .path("/domain/listAll")
                    .query("start", &start.to_string())
                    .build()?;
                let response = self.http.send(&self.request(Method::GET, url)).await?;
                let list: DomainList = self
                    .success(
                        &response,
                        None,
                        "the provider's domain listing is not in the expected form",
                    )
                    .map_err(|refusal| refusal.error)?;
                if let Some(count) = list.count
                    && usize::try_from(count).ok() != Some(list.domains.len())
                {
                    return Err(protocol(
                        "the provider's domain listing states a count other than its domains",
                    ));
                }
                let first = list.domains.first().map(|d| d.domain.clone());
                {
                    let mut previous = previous.lock().unwrap_or_else(|e| e.into_inner());
                    if first.is_some() && *previous == first {
                        return Err(protocol(
                            "the provider's domain listing repeated a page instead of advancing",
                        ));
                    }
                    *previous = first;
                }
                let next = (list.domains.len() >= PAGE_SIZE)
                    .then(|| start.saturating_add(list.domains.len()));
                Ok(Page {
                    items: list.domains,
                    next,
                })
            }
        })
        .await
    }

    /// Every record of the domain. A refusal that says the domain is not in the account is
    /// `Error::ZoneNotFound` for `zone`.
    // Source: the spec, `/dns/retrieve/{domain}`: "Retrieve all editable DNS records for a
    // domain. SOA records and Porkbun default NS records are excluded." No paging is
    // documented; the answer holds every record.
    pub(super) async fn records(&self, zone: &DomainName) -> Result<Vec<Record>, Error> {
        #[derive(Deserialize)]
        struct Records {
            records: Vec<Record>,
        }
        let url = self
            .base
            .url()
            .path("/dns/retrieve")
            .segment(zone.without_dot())
            .build()?;
        let response = self.http.send(&self.request(Method::GET, url)).await?;
        let records: Records = self
            .success(
                &response,
                Some(zone),
                "the provider's record listing is not in the expected form",
            )
            .map_err(|refusal| refusal.error)?;
        Ok(records.records)
    }

    /// Creates a record. Sent once: a create is not idempotent, and a repeat after an unknown
    /// outcome could add a second copy (design section 5.3).
    // Source: the spec, `/dns/create/{domain}`: 200 with `status` and the new `id`; 400
    // "Validation error" with the `ErrorResponse`.
    pub(super) async fn create(
        &self,
        zone: &DomainName,
        record: &NewRecord<'_>,
    ) -> Result<Created, Error> {
        let url = self
            .base
            .url()
            .path("/dns/create")
            .segment(zone.without_dot())
            .build()?;
        let response = self
            .http
            .send(&self.request(Method::POST, url).json(record)?)
            .await?;
        match self.success::<Status>(
            &response,
            Some(zone),
            "the provider's answer to a create is not in the expected form",
        ) {
            Ok(_) => Ok(Created::Done),
            Err(Refusal {
                class: Class::Duplicate,
                error,
            }) => Ok(Created::Duplicate(error)),
            Err(refusal) => Err(refusal.error),
        }
    }

    /// Changes the fields of one record that `edit` names. Sent once: design section 5.3
    /// retries only reads and deletes by identifier.
    // Source: the spec, `/dns/edit/{domain}/{id}`: 200 `BasicResponse`; 400 with the
    // `ErrorResponse`; the changelog (v3.20): a no-op edit "is now a success".
    pub(super) async fn edit(
        &self,
        zone: &DomainName,
        id: u64,
        edit: &RecordEdit<'_>,
    ) -> Result<Written, Error> {
        let url = self.record_url("/dns/edit", zone, id).build()?;
        let response = self
            .http
            .send(&self.request(Method::POST, url).json(edit)?)
            .await?;
        self.written(&response, zone)
    }

    /// Deletes one record by its identifier. Idempotent: repeating it leaves the same state, so
    /// the transport may retry it; a repeat after the record went is answered
    /// `INVALID_RECORD_ID`, which the caller confirms by a new read.
    // Source: the spec, `/dns/delete/{domain}/{id}`: "Delete a specific DNS record"; 200
    // `BasicResponse`; 400 with the `ErrorResponse`.
    pub(super) async fn delete(&self, zone: &DomainName, id: u64) -> Result<Written, Error> {
        let url = self.record_url("/dns/delete", zone, id).build()?;
        let empty = serde_json::Map::new();
        let response = self
            .http
            .send(&self.request(Method::POST, url).json(&empty)?.idempotent())
            .await?;
        self.written(&response, zone)
    }

    /// `{path}/{domain}/{id}`.
    fn record_url(&self, path: &'static str, zone: &DomainName, id: u64) -> UrlBuilder {
        self.base
            .url()
            .path(path)
            .segment(zone.without_dot())
            .id(&id.to_string())
    }

    /// The answer to an edit or a delete.
    fn written(&self, response: &Response, zone: &DomainName) -> Result<Written, Error> {
        match self.success::<Status>(
            response,
            Some(zone),
            "the provider's answer to a write is not in the expected form",
        ) {
            Ok(_) => Ok(Written::Done),
            Err(Refusal {
                class: Class::RecordNotFound,
                ..
            }) => Ok(Written::Gone),
            Err(refusal) => Err(refusal.error),
        }
    }

    /// Reads a success answer as `T`, or classifies the refusal. A `2xx` answer whose `status`
    /// is `ERROR` is a refusal like a `400`; one whose `status` is neither is `Protocol`.
    // Source: the spec, success schemas (`status` "SUCCESS") and `ErrorResponse` (`status`
    // "ERROR", `code`, `message`); nrdcg client.go: "a `200` whose status is not `SUCCESS` is an
    // error".
    fn success<T: DeserializeOwned>(
        &self,
        response: &Response,
        zone: Option<&DomainName>,
        what: &'static str,
    ) -> Result<T, Refusal> {
        if response.is_success() {
            let status: Status = response.json(what).map_err(unclassified)?;
            match status.status.as_deref() {
                Some(SUCCESS) => return response.json(what).map_err(unclassified),
                Some("ERROR") => {}
                _ => return Err(unclassified(protocol(what))),
            }
        } else if !(400..=499).contains(&response.status()) {
            return Err(unclassified(Error::Protocol {
                detail: self.http.detail(&format!(
                    "status {}: {}",
                    response.status(),
                    self.http.body_detail(response)
                )),
            }));
        }
        Err(self.refusal(response, zone))
    }

    /// The error of a refusal, by its code.
    fn refusal(&self, response: &Response, zone: Option<&DomainName>) -> Refusal {
        let class = error_code(&response.text()).map_or(Class::Rejected, |code| classify(&code));
        let detail = || self.http.body_detail(response);
        let error = match class {
            Class::Auth => Error::Auth { detail: detail() },
            Class::Forbidden => Error::Forbidden { detail: detail() },
            Class::ZoneNotFound => match zone {
                Some(zone) => Error::zone_not_found(zone.clone()),
                None => self.http.reject(response),
            },
            Class::InvalidInput => Error::InvalidInput {
                detail: detail(),
                code: self.http.body_code(response),
            },
            Class::RecordNotFound | Class::Duplicate | Class::Rejected => {
                self.http.reject(response)
            }
        };
        Refusal { class, error }
    }
}

/// The `status` of an answer.
#[derive(Deserialize)]
struct Status {
    #[serde(default)]
    status: Option<String>,
}

/// The answer of `/domain/listAll`.
// Source: the spec, `DomainListAllResponse` (`status` and `domains` required, `count`).
#[derive(Deserialize)]
struct DomainList {
    domains: Vec<Domain>,
    #[serde(default)]
    count: Option<u64>,
}

fn unclassified(error: Error) -> Refusal {
    Refusal {
        class: Class::Rejected,
        error,
    }
}

fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

/// The error body of the API.
// Source: the spec, `ErrorResponse`: `status`, `message` (required), `code` ("Machine-readable
// error code").
#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

/// The provider's error message: `code` and `message` of the documented error body.
pub(super) fn error_message(body: &str) -> Option<String> {
    let body: ErrorBody = serde_json::from_str(body).ok()?;
    let message = body.message.filter(|text| !text.is_empty())?;
    Some(match body.code.filter(|code| !code.is_empty()) {
        Some(code) => format!("{code}: {message}"),
        None => message,
    })
}

/// The provider's error code: the `code` of the documented error body, such as
/// `INVALID_DOMAIN`.
pub(super) fn error_code(body: &str) -> Option<String> {
    serde_json::from_str::<ErrorBody>(body)
        .ok()?
        .code
        .filter(|code| !code.is_empty())
}

/// An answer that refuses the request rate, whatever its status: treated like a `429`.
// Source: the spec, "Rate limiting": "the API returns HTTP 429 with a `RATE_LIMIT_EXCEEDED`
// body and a `Retry-After` header"; the code is listed under "Rate limiting" in "Error codes".
pub(super) fn throttled(response: &Response) -> bool {
    !response.is_success() && error_code(&response.text()).as_deref() == Some("RATE_LIMIT_EXCEEDED")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Class, Record, classify, error_code, error_message, flag, number};
    use crate::name::DomainName;

    #[test]
    fn error_bodies_give_code_and_message() {
        let body = r#"{"status":"ERROR","code":"INVALID_DOMAIN","message":"Invalid domain."}"#;
        assert_eq!(error_code(body).as_deref(), Some("INVALID_DOMAIN"));
        assert_eq!(
            error_message(body).as_deref(),
            Some("INVALID_DOMAIN: Invalid domain.")
        );
        assert_eq!(error_message(r#"{"message":"m"}"#).as_deref(), Some("m"));
        assert_eq!(error_code(r#"{"message":"m"}"#), None);
        assert_eq!(error_code(r#"{"code":""}"#), None);
        assert_eq!(error_code("<html>oops</html>"), None);
    }

    #[test]
    fn codes_are_classified() {
        for (code, class) in [
            ("INVALID_API_KEYS_001", Class::Auth),
            ("API_KEY_REQUIRED", Class::Auth),
            ("API_ACCESS_DISABLED", Class::Forbidden),
            ("INSUFFICIENT_SCOPE", Class::Forbidden),
            ("INVALID_DOMAIN", Class::ZoneNotFound),
            ("DOMAIN_NOT_FOUND", Class::ZoneNotFound),
            ("INVALID_RECORD_ID", Class::RecordNotFound),
            ("DUPLICATE_RECORD", Class::Duplicate),
            ("INVALID_INPUT", Class::InvalidInput),
            ("RECORD_CONFLICT", Class::Rejected),
            ("something_else", Class::Rejected),
        ] {
            assert_eq!(classify(code), class, "{code}");
        }
    }

    #[test]
    fn numbers_and_flags_in_either_form() {
        assert_eq!(number(Some(&json!("600"))), Some(600));
        assert_eq!(number(Some(&json!(600))), Some(600));
        assert_eq!(number(Some(&json!(""))), None);
        assert_eq!(number(Some(&json!("-1"))), None);
        assert_eq!(number(Some(&json!(null))), None);
        assert_eq!(number(None), None);
        assert_eq!(flag(Some(&json!(1))), Some(true));
        assert_eq!(flag(Some(&json!("1"))), Some(true));
        assert_eq!(flag(Some(&json!(0))), Some(false));
        assert_eq!(flag(Some(&json!("x"))), None);
    }

    #[test]
    fn owner_names_are_fully_qualified_inside_the_zone() {
        let zone = DomainName::parse("example.org").unwrap();
        let owner = |name: serde_json::Value| {
            let record: Record = serde_json::from_value(json!({ "name": name })).unwrap();
            record.owner(&zone).map(|n| n.as_str().to_owned())
        };
        assert_eq!(
            owner(json!("www.example.org")).as_deref(),
            Some("www.example.org.")
        );
        assert_eq!(owner(json!("example.org")).as_deref(), Some("example.org."));
        assert_eq!(
            owner(json!("Example.ORG.")).as_deref(),
            Some("example.org.")
        );
        // A relative or foreign name is never a name of the zone.
        assert_eq!(owner(json!("www")), None);
        assert_eq!(owner(json!("www.example.net")), None);
        assert_eq!(owner(json!("bad name.example.org")), None);
        assert_eq!(owner(json!(null)), None);
    }
}
