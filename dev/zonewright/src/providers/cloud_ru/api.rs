//! The Cloud.ru Evolution DNS public API and the token service in front of it, as this client
//! uses them: the access-key exchange, one function per endpoint, the wire types, token paging,
//! operation polling and the classification of answers. Nothing here knows the value layer or
//! the zone cache; `client.rs` and `txt.rs` build on these calls.
//!
//! Sources (hard rule 3):
//!
//! - [OpenAPI]: the Evolution DNS Public API specification (OpenAPI 3.0.3, version 0.0.1):
//!   paths, parameters, the schemas `v1PublicZoneSole`, `v1PublicRecordSole`,
//!   `v1CreatePublicRecordSoleRequest`, `v1PublicRecordSoleServiceUpdateBody`,
//!   `v1ListPublicZonesSoleResponse`, `v1ListPublicRecordsSoleResponse`, `dnsv1Operation` and
//!   `rpcStatus`. Every path documents `200` and a `default` error answer with an `rpcStatus`
//!   body; no other status is documented.
//! - [Authentication] and [Authentication in the Cloud.ru API]: the token exchange `POST
//!   https://iam.api.cloud.ru/api/v1/auth/token` with `{"keyId", "secret"}`, the answer with
//!   `access_token` and `expires_in` (3600 in the example), "the token lives 1 hour", and the
//!   header `Authorization: Bearer <access_token>`.
//! - [Limitations]: one record per name and type in a zone, with several values; TTL 60 to 86400
//!   seconds; a quota of 500 records per zone by default (SOA and NS not counted); IDN not
//!   supported.
//! - [Proto3 JSON]: the specification is generated from protobuf (`google.rpc.Status`,
//!   `googleprotobufAny`); an int64 field is a JSON string on output, and a parser accepts a
//!   string or a number.
//!
//! Endpoints used:
//!
//! | Call          | Request                                                       | Success       |
//! | ------------- | ------------------------------------------------------------- | ------------- |
//! | token         | `POST {iam_url}` `{"keyId","secret"}`                         | 2xx, token    |
//! | list zones    | `GET /v1/publicZonesSole?projectId&pageSize&pageToken`        | 200, page     |
//! | list records  | `GET /v1/publicRecordsSole?publicZoneId&pageSize&pageToken`   | 200, page     |
//! | create record | `POST /v1/publicRecordsSole`                                  | 200, operation |
//! | update record | `PATCH /v1/publicRecordsSole/{publicRecordId}`                | 200, operation |
//! | delete record | `DELETE /v1/publicRecordsSole/{publicRecordId}`               | 200, operation |
//! | get operation | `GET /v1/operations/{operationId}`                            | 200, operation |
//!
//! [OpenAPI]: https://cloud.ru/docs/api/specs/evolution-dns/ug/_specs/openapi.yaml
//! [Authentication]: https://cloud.ru/docs/evolution-dns/ug/topics/api-ref__authentication
//! [Authentication in the Cloud.ru API]: https://cloud.ru/docs/console_api/ug/topics/guides__auth_api
//! [Limitations]: https://cloud.ru/docs/evolution-dns/ug/topics/overview__limitations
//! [Proto3 JSON]: https://protobuf.dev/programming-guides/json/

use std::fmt;
use std::time::Duration;

use reqwest::{Method, Url};
use secrecy::{ExposeSecret as _, SecretString};
use serde::de::{self, DeserializeOwned, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::Error;
use crate::http::pager::{self, Page};
use crate::http::{
    Endpoint, Http, PollStep, Poller, Request, Response, Token, TokenAuth, TokenSource, path_id,
};
use crate::name::DomainName;
use crate::redact::Detail;

/// Page size of every listing: the documented default of `pageSize`.
// Source: the OpenAPI, `pageSize` of `GET /v1/publicZonesSole` and `GET /v1/publicRecordsSole`
// ("Значение [page_size] по умолчанию 100"; no maximum is stated, so the client does not ask
// for more).
const PAGE_SIZE: &str = "100";

/// Most polls of one provider-side operation (design section 3.7).
const MAX_POLLS: u32 = 60;

/// Record type names as the API spells them: lowercase.
// Source: the OpenAPI, `v1CreatePublicRecordSoleRequest.type` ("Возможные значения: a, aaaa,
// srv, cname, mx, ns, spf, txt, caa").
pub(super) const TXT: &str = "txt";

/// `google.rpc.Code` `NOT_FOUND`.
// Source: the OpenAPI, `rpcStatus.code` ("an enum value of google.rpc.Code"); google.rpc.Code
// defines NOT_FOUND = 5 (https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto).
const CODE_NOT_FOUND: i64 = 5;

/// A zone as `GET /v1/publicZonesSole` returns it; other fields are ignored.
// Source: the OpenAPI, `v1PublicZoneSole` (`projectId`, `name`, `domain` required; `id` and
// `readOnly` optional). Optional here as well: an entry without a usable identifier is an error
// only when it is the zone the client looks for.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Zone {
    /// The zone's identifier.
    #[serde(default)]
    pub(super) id: Option<String>,
    /// The project that owns the zone.
    #[serde(default)]
    pub(super) project_id: Option<String>,
    /// The zone's domain name.
    #[serde(default)]
    pub(super) domain: Option<String>,
    /// "The public zone is read-only."
    #[serde(default)]
    pub(super) read_only: bool,
}

impl Zone {
    /// The domain as a name, or `None` when it is not a valid one.
    pub(super) fn name(&self) -> Option<DomainName> {
        self.domain
            .as_deref()
            .and_then(|d| DomainName::parse(d).ok())
    }
}

/// One page of a listing: the list under `key` (`zones` or `records`) and the next page token.
///
/// The list field is optional in the OpenAPI (`v1ListPublicZonesSoleResponse` and
/// `v1ListPublicRecordsSoleResponse` mark nothing required), and Proto3 JSON omits a repeated
/// field that is empty, so an absent list is an empty page. A list that is present but not an
/// array (`null` included, which a Proto3 JSON printer never writes for a repeated field) is
/// `Error::Protocol`, never an empty result; so is a next page token that is not a string.
fn page_of<T: DeserializeOwned>(
    response: &Response,
    key: &str,
) -> Result<Page<T, Option<String>>, Error> {
    let protocol = || Error::Protocol {
        detail: Detail::constant("the provider's listing is not in the expected form"),
    };
    let mut page: Map<String, Value> =
        response.json("the provider's listing is not in the expected form")?;
    let items = match page.remove(key) {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .into_iter()
            .map(|item| serde_json::from_value(item).map_err(|_| protocol()))
            .collect::<Result<Vec<T>, Error>>()?,
        Some(_) => return Err(protocol()),
    };
    let token = match page.remove("nextPageToken") {
        None => None,
        Some(Value::String(token)) => Some(token),
        Some(_) => return Err(protocol()),
    };
    Ok(Page {
        items,
        next: pager::next_token(token).map(Some),
    })
}

/// A record of a public zone, one per name and type, holding all values of that name and type.
/// Other fields are ignored.
// Source: the OpenAPI, `v1PublicRecordSole` (`publicZoneId`, `name`, `type`, `values`, `ttl`
// required; `id`, `readOnly`, `description`, `tags`, `wildcard`, `gslbData` optional). `id` and
// `values` are required here: a record without them cannot be changed or compared.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Record {
    /// The record's identifier.
    pub(super) id: String,
    /// The values in the API's text form.
    pub(super) values: Vec<String>,
    /// TTL in seconds; an int64, which Proto3 JSON may write as a string.
    #[serde(deserialize_with = "int64")]
    pub(super) ttl: u64,
    /// A read-only record cannot be changed through the API.
    #[serde(default)]
    pub(super) read_only: bool,
    /// The wildcard flag: the record applies to the names below `name`.
    #[serde(default)]
    pub(super) wildcard: bool,
    /// Kept on every update.
    #[serde(default)]
    pub(super) description: Option<Value>,
    /// Kept on every update.
    #[serde(default)]
    pub(super) tags: Option<Value>,
    /// Kept on every update.
    #[serde(default)]
    pub(super) gslb_data: Option<Value>,
}

/// Two reads of a record are the same when nothing a write would carry differs. The values are
/// compared as a multiset: their order in an answer is not documented.
impl PartialEq for Record {
    fn eq(&self, other: &Record) -> bool {
        let sorted = |r: &Record| {
            let mut values = r.values.clone();
            values.sort_unstable();
            values
        };
        self.id == other.id
            && self.ttl == other.ttl
            && self.read_only == other.read_only
            && self.wildcard == other.wildcard
            && self.description == other.description
            && self.tags == other.tags
            && self.gslb_data == other.gslb_data
            && sorted(self) == sorted(other)
    }
}

/// An int64 as a JSON number or a decimal string.
fn int64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Int64 {
        Number(u64),
        Text(String),
    }
    match Int64::deserialize(deserializer)? {
        Int64::Number(n) => Ok(n),
        Int64::Text(text) => text
            .trim()
            .parse()
            .map_err(|_| de::Error::custom("not an integer")),
    }
}

/// The body of `POST /v1/publicRecordsSole`.
// Source: the OpenAPI, `v1CreatePublicRecordSoleRequest` (`publicZoneId`, `name`, `type`,
// `values`, `ttl` required; `ttl` an int64).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NewRecord<'a> {
    /// The zone's identifier.
    pub(super) public_zone_id: &'a str,
    /// The owner name.
    pub(super) name: &'a str,
    /// The type, lowercase.
    #[serde(rename = "type")]
    pub(super) rtype: &'a str,
    /// The values.
    pub(super) values: &'a [String],
    /// TTL in seconds.
    pub(super) ttl: u64,
}

/// The body of `PATCH /v1/publicRecordsSole/{id}`: no name and no type.
// Source: the OpenAPI, `v1PublicRecordSoleServiceUpdateBody` (`values`, `ttl`, `description`,
// `tags`, `gslbData`, none marked required). Whether a field left out keeps its value or is
// cleared is not documented, so the client sends the attributes it read, and the record keeps
// them either way.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RecordUpdate<'a> {
    /// The complete new list of values.
    pub(super) values: &'a [String],
    /// TTL in seconds, as read.
    pub(super) ttl: u64,
    /// As read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) description: Option<&'a Value>,
    /// As read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) tags: Option<&'a Value>,
    /// As read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) gslb_data: Option<&'a Value>,
}

/// An operation as a write and `GET /v1/operations/{id}` return it.
// Source: the OpenAPI, `dnsv1Operation` (`id` required; `done`: "if false, the operation is in
// progress; if true, it is finished and `error` may be filled"; `error` an `rpcStatus`). Proto3
// JSON omits `done: false`, so it defaults to false.
#[derive(Debug, Deserialize)]
struct Operation {
    id: String,
    #[serde(default)]
    done: bool,
    #[serde(default)]
    error: Option<Status>,
}

/// An `rpcStatus`.
// Source: the OpenAPI, `rpcStatus` (`code`, `message`, `details`).
#[derive(Debug, Deserialize)]
struct Status {
    #[serde(default)]
    code: Option<i64>,
    #[serde(default)]
    message: Option<String>,
}

/// The answer to a write, once its operation finished.
#[derive(Debug)]
pub(super) enum Written {
    /// The operation finished without an error.
    Done,
    /// `404`, or an operation that finished with `NOT_FOUND`: the record or the zone does not
    /// exist (any more).
    NotFound,
    /// Another refusal, as the error it maps to: an HTTP refusal, or an operation that finished
    /// with an error.
    Refused(Error),
}

/// The client's handle on the API: the transport, the endpoints, the access key and the token.
pub(super) struct Api {
    http: Http,
    dns: Endpoint,
    iam: Url,
    key_id: String,
    secret: SecretString,
    tokens: TokenSource,
    poller: Poller,
}

impl fmt::Debug for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Api")
            .field("dns", &self.dns)
            .field("poller", &self.poller)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// The API at `dns`, authenticated with tokens from `iam` for the access key `key_id` /
    /// `secret`; operations polled every `poll_interval`.
    pub(super) fn new(
        http: Http,
        dns: Endpoint,
        iam: &Endpoint,
        key_id: String,
        secret: SecretString,
        poll_interval: Duration,
    ) -> Api {
        Api {
            http,
            dns,
            iam: iam.as_url().clone(),
            key_id,
            secret,
            // The answer states the lifetime (`expires_in`), which is fixed at one hour; no cap
            // beyond it is needed.
            tokens: TokenSource::new(None),
            poller: Poller::new(poll_interval, MAX_POLLS),
        }
    }

    /// The token exchange. The token request is idempotent (design section 5.3). The body,
    /// which carries the secret, is encoded into a zeroizing buffer.
    ///
    /// Answers: 2xx with `access_token` is the token, its lifetime from `expires_in` (one hour
    /// when absent); 400 and 401 are `Error::Auth`; 403, 429 and 5xx follow the shared mapping;
    /// anything else is a refusal.
    // Source: Authentication in the Cloud.ru API (request and answer shape; "Срок жизни токена
    // — 1 час"). Assumption (not documented): an access key the service does not accept is
    // answered `400` or `401`, both reported as an authentication error. A token request writes
    // nothing, so a wrong classification changes only the kind of the error.
    async fn fetch(&self) -> Result<Token, Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Exchange<'a> {
            key_id: &'a str,
            secret: &'a str,
        }
        #[derive(Deserialize)]
        struct Issued {
            #[serde(default)]
            access_token: Option<String>,
            #[serde(default)]
            expires_in: Option<u64>,
        }
        let request = Request::new(Method::POST, self.iam.clone())
            .idempotent()
            .anonymous()
            .json(&Exchange {
                key_id: &self.key_id,
                secret: self.secret.expose_secret(),
            })?
            .keep_status(400);
        let response = self.http.send(&request).await?;
        if response.status() == 400 {
            return Err(Error::Auth {
                detail: self.http.body_detail(&response),
            });
        }
        if !response.is_success() {
            return Err(self.http.reject(&response));
        }
        let issued: Issued =
            response.json("the token service's answer is not in the expected form")?;
        let token = issued
            .access_token
            .filter(|t| !t.is_empty())
            .ok_or(Error::Protocol {
                detail: Detail::constant("the token service answered without an access_token"),
            })?;
        let lifetime = issued
            .expires_in
            .filter(|&s| s > 0)
            .map(Duration::from_secs);
        Ok(Token::new(SecretString::from(token), lifetime))
    }

    /// Exchanges the access key for a new token, even when a valid one is cached: proves that
    /// the key is accepted now. The new token replaces the cached one.
    pub(super) async fn authenticate(&self) -> Result<(), Error> {
        self.tokens.renew(|| self.fetch()).await?;
        Ok(())
    }

    /// Sends `request` with the token as a bearer token.
    // Source: Authentication ("Authorization: Bearer $TOKEN").
    async fn send(&self, request: &Request) -> Result<Response, Error> {
        self.http
            .send_with_token(request, &self.tokens, &TokenAuth::BEARER, || self.fetch())
            .await
    }

    /// Every public zone of project `project`, all pages. A listing is complete or it fails.
    // Source: the OpenAPI, `GET /v1/publicZonesSole` (`projectId` required, `pageSize`,
    // `pageToken`; `nextPageToken` names the next page). The `filter` parameter takes a CEL
    // expression whose exact syntax for this API is not documented, so it is not used.
    pub(super) async fn zones(&self, project: &str) -> Result<Vec<Zone>, Error> {
        pager::collect(None::<String>, |token| async move {
            let mut url = self
                .dns
                .url()
                .path("/v1/publicZonesSole")
                .query("projectId", project)
                .query("pageSize", PAGE_SIZE);
            if let Some(token) = &token {
                url = url.query("pageToken", token);
            }
            let response = self.send(&Request::get(url.build()?)).await?;
            if !response.is_success() {
                return Err(self.http.reject(&response));
            }
            page_of(&response, "zones")
        })
        .await
    }

    /// Every record of zone `zone_id`, all pages, as JSON values (the client reads only the
    /// records it is interested in). A listing is complete or it fails. A "not found" answer is
    /// `Error::ZoneNotFound` for `zone`: the zone identifier may be stale.
    // Source: the OpenAPI, `GET /v1/publicRecordsSole` (`publicZoneId` required, `pageSize`,
    // `pageToken`, `nextPageToken`). Assumption (not documented): an unknown zone identifier is
    // answered `404` or with an `rpcStatus` of code `NOT_FOUND`. Being wrong costs a second zone
    // lookup before the error is returned; nothing is written on the strength of it.
    pub(super) async fn records(
        &self,
        zone: &DomainName,
        zone_id: &str,
    ) -> Result<Vec<Value>, Error> {
        pager::collect(None::<String>, |token| async move {
            let mut url = self
                .dns
                .url()
                .path("/v1/publicRecordsSole")
                .query("publicZoneId", zone_id)
                .query("pageSize", PAGE_SIZE);
            if let Some(token) = &token {
                url = url.query("pageToken", token);
            }
            let response = self.send(&Request::get(url.build()?)).await?;
            if is_not_found(&response) {
                return Err(Error::zone_not_found(zone.clone()));
            }
            if !response.is_success() {
                return Err(self.http.reject(&response));
            }
            page_of(&response, "records")
        })
        .await
    }

    /// Creates a record and waits for its operation. Sent once: a create is not idempotent.
    // Source: the OpenAPI, `POST /v1/publicRecordsSole` (200 with a `dnsv1Operation`). What the
    // service answers to a create of a name and type that exists is not documented; the caller
    // reads again before it concludes anything from a refusal.
    pub(super) async fn create_record(&self, record: &NewRecord<'_>) -> Result<Written, Error> {
        let url = self.dns.url().path("/v1/publicRecordsSole").build()?;
        let response = self
            .send(&Request::new(Method::POST, url).json(record)?)
            .await?;
        self.written(&response).await
    }

    /// Replaces the values of a record and waits for its operation. Sent once: the write carries
    /// no condition, and a repeat would widen the window in which another writer's change is
    /// overwritten (design section 5.3).
    // Source: the OpenAPI, `PATCH /v1/publicRecordsSole/{publicRecordId}` (200 with a
    // `dnsv1Operation`).
    pub(super) async fn update_record(
        &self,
        record_id: &str,
        update: &RecordUpdate<'_>,
    ) -> Result<Written, Error> {
        let url = self.record_url(record_id)?;
        let response = self
            .send(&Request::new(Method::PATCH, url).json(update)?)
            .await?;
        self.written(&response).await
    }

    /// Deletes a record with all its values and waits for its operation. Sent once: the record
    /// can hold values of other writers that arrived after the read, and a repeat would widen
    /// that window like a repeated update (design section 5.3).
    // Source: the OpenAPI, `DELETE /v1/publicRecordsSole/{publicRecordId}` (200 with a
    // `dnsv1Operation`).
    pub(super) async fn delete_record(&self, record_id: &str) -> Result<Written, Error> {
        let url = self.record_url(record_id)?;
        let response = self.send(&Request::new(Method::DELETE, url)).await?;
        self.written(&response).await
    }

    fn record_url(&self, record_id: &str) -> Result<Url, Error> {
        self.dns
            .url()
            .path("/v1/publicRecordsSole")
            .id(record_id)
            .build()
    }

    /// The answer to a write: a refusal, or the operation it started, awaited.
    async fn written(&self, response: &Response) -> Result<Written, Error> {
        if is_not_found(response) {
            return Ok(Written::NotFound);
        }
        if !response.is_success() {
            return Ok(Written::Refused(self.http.reject(response)));
        }
        let operation: Operation = response
            .json("the provider's operation is not in the expected form")
            .map_err(|_| accepted_unreadable())?;
        self.finish(operation).await
    }

    /// Waits until `operation` is done (design section 3.7). An operation still running after
    /// the last poll, or a poll that fails, is `Error::Transient`: the write was accepted and its
    /// outcome is unknown.
    async fn finish(&self, operation: Operation) -> Result<Written, Error> {
        if operation.done {
            return Ok(self.outcome(operation));
        }
        let id = path_id(&operation.id)
            .map_err(|_| accepted_unreadable())?
            .to_owned();
        self.poller
            .run(|| {
                let id = id.clone();
                async move {
                    let operation = self.operation(&id).await?;
                    Ok(if operation.done {
                        PollStep::Done(self.outcome(operation))
                    } else {
                        PollStep::Pending
                    })
                }
            })
            .await
    }

    /// One look at operation `id`.
    // Source: the OpenAPI, `GET /v1/operations/{operationId}` (200 with a `dnsv1Operation`).
    async fn operation(&self, id: &str) -> Result<Operation, Error> {
        let url = self.dns.url().path("/v1/operations").id(id).build()?;
        let response = self.send(&Request::get(url)).await?;
        if !response.is_success() {
            return Err(self.http.reject(&response));
        }
        response.json("the provider's operation is not in the expected form")
    }

    /// A finished operation: no `error`, or an `error` with code `OK` (0), is success; `NOT_FOUND`
    /// is [`Written::NotFound`]; any other code is a refusal with the provider's message. An
    /// `error` without a code is `OK` by Proto3 JSON (a zero is omitted) when it is empty, but a
    /// refusal when it carries a message: success is not reported for an answer that describes an
    /// error, and a refusal is safe to repeat (the repeat starts with a read).
    // Source: the OpenAPI, `dnsv1Operation.error` and `rpcStatus.code` (google.rpc.Code, where 0
    // is OK); Proto3 JSON (default values are omitted).
    fn outcome(&self, operation: Operation) -> Written {
        let Some(status) = operation.error else {
            return Written::Done;
        };
        let message = status.message.as_deref().is_some_and(|m| !m.is_empty());
        match status.code {
            Some(0) => Written::Done,
            None if !message => Written::Done,
            Some(CODE_NOT_FOUND) => Written::NotFound,
            _ => Written::Refused(Error::Rejected {
                status: None,
                detail: match status.message.filter(|m| !m.is_empty()) {
                    Some(message) => self.http.detail(&message),
                    None => Detail::constant("the provider's operation failed"),
                },
            }),
        }
    }
}

/// `404`, or an error answer whose `rpcStatus` code is `NOT_FOUND`.
fn is_not_found(response: &Response) -> bool {
    if response.status() == 404 {
        return true;
    }
    !response.is_success()
        && serde_json::from_slice::<Status>(response.body())
            .ok()
            .and_then(|s| s.code)
            == Some(CODE_NOT_FOUND)
}

/// The provider accepted a write, but what it answered cannot be read: the write may have
/// happened (design section 3.7).
fn accepted_unreadable() -> Error {
    Error::Transient {
        detail: Detail::constant(
            "the provider accepted the change, but its operation could not be read",
        ),
    }
}

/// The provider's error message: `message` of the `rpcStatus` body.
// Source: the OpenAPI, `rpcStatus` (`code`, `message`, `details`).
pub(super) fn error_message(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        #[serde(default)]
        message: Option<String>,
    }
    serde_json::from_str::<ErrorBody>(body)
        .ok()?
        .message
        .filter(|m| !m.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{Record, error_message};

    #[test]
    fn error_messages_are_read_from_message() {
        for (body, expected) in [
            (
                r#"{"code":5,"message":"record not found","details":[]}"#,
                Some("record not found"),
            ),
            (r#"{"code":3,"message":""}"#, None),
            (r#"{"code":3}"#, None),
            ("<html>oops</html>", None),
        ] {
            assert_eq!(error_message(body).as_deref(), expected, "{body}");
        }
    }

    #[test]
    fn ttl_is_a_number_or_a_string() {
        let record = |ttl: &str| {
            serde_json::from_str::<Record>(&format!(
                r#"{{"id":"r1","name":"a","type":"txt","values":["x"],"ttl":{ttl}}}"#
            ))
        };
        assert_eq!(record("300").unwrap().ttl, 300);
        assert_eq!(record("\"120\"").unwrap().ttl, 120);
        assert!(record("\"soon\"").is_err());
        assert!(record("null").is_err());
    }

    #[test]
    fn reads_compare_values_as_a_multiset() {
        let record = |values: &str, ttl: u32| {
            serde_json::from_str::<Record>(&format!(
                r#"{{"id":"r1","name":"a","type":"txt","values":{values},"ttl":{ttl}}}"#
            ))
            .unwrap()
        };
        assert_eq!(record(r#"["a","b"]"#, 60), record(r#"["b","a"]"#, 60));
        assert_ne!(record(r#"["a","b"]"#, 60), record(r#"["a"]"#, 60));
        assert_ne!(record(r#"["a"]"#, 60), record(r#"["a"]"#, 120));
        assert_ne!(record(r#"["a","a"]"#, 60), record(r#"["a"]"#, 60));
    }
}
