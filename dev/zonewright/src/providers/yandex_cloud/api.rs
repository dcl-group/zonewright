//! The Yandex Cloud DNS, IAM and Operation APIs as this client uses them: the JWT exchange, one
//! function per endpoint, the wire types, paging, operation polling and the classification of
//! answers. Nothing here knows the value layer or the zone cache; `client.rs` and `txt.rs` build
//! on these calls.
//!
//! Sources (hard rule 3):
//!
//! - [IAM token for a service account]: the JWT (`typ`, `alg` PS256 only, `kid`; `iss`, `aud`,
//!   `iat`, `exp` with `exp - iat <= 3600`), the exchange `POST /iam/v1/tokens` with
//!   `{"jwt": ...}`, and the token lifetime of at most 12 hours.
//! - [IamToken.create]: the answer `200` with `iamToken` and `expiresAt` (RFC 3339).
//! - [DnsZone.list], [DnsZone.get], [DnsZone.getRecordSet], [DnsZone.updateRecordSets]: paths,
//!   parameters, the `RecordSet` and `Operation` shapes and their limits.
//! - [Operation]: `GET /operations/{id}`; `done`, and `error` or `response`.
//! - [Errors]: the error body `{code, message, details}` and the mapping of gRPC codes to HTTP
//!   statuses (`NOT_FOUND` 404, `ALREADY_EXISTS` 409, `INVALID_ARGUMENT` and
//!   `FAILED_PRECONDITION` 400, ...).
//! - [Proto3 JSON]: fields with default values (an empty list, a zero) may be omitted.
//! - lego `providers/dns/yandexcloud/yandexcloud.go`.
//!
//! Endpoints used:
//!
//! | Call               | Request                                                     | Success          |
//! | ------------------ | ----------------------------------------------------------- | ---------------- |
//! | IAM token          | `POST {iam_url}` `{"jwt"}`                                  | 200, token       |
//! | list zones         | `GET {dns_url}/zones?folderId&pageSize&pageToken`           | 200, page        |
//! | get zone           | `GET {dns_url}/zones/{zone}`                                | 200, zone        |
//! | get record set     | `GET {dns_url}/zones/{zone}:getRecordSet?name&type`         | 200, record set  |
//! | update record sets | `POST {dns_url}/zones/{zone}:updateRecordSets`              | 200, operation   |
//! | get operation      | `GET {operation_url}/{operation}`                           | 200, operation   |
//!
//! Record-level operations, when they are added, put `listRecordSets` next to `record_set` and
//! reuse [`Api::update_record_sets`] for every change.
//!
//! [IAM token for a service account]: https://yandex.cloud/en/docs/iam/operations/iam-token/create-for-sa
//! [IamToken.create]: https://yandex.cloud/en/docs/iam/api-ref/IamToken/create
//! [DnsZone.list]: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/list
//! [DnsZone.get]: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/get
//! [DnsZone.getRecordSet]: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/getRecordSet
//! [DnsZone.updateRecordSets]: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/updateRecordSets
//! [Operation]: https://yandex.cloud/en/docs/api-design-guide/concepts/operation
//! [Errors]: https://yandex.cloud/en/docs/api-design-guide/concepts/errors
//! [Proto3 JSON]: https://protobuf.dev/programming-guides/json/

use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::{Method, Url};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::crypto::Ps256Key;
use crate::error::Error;
use crate::http::pager::{self, Page};
use crate::http::{
    Endpoint, Http, PollStep, Poller, Request, Response, Token, TokenAuth, TokenSource,
    lifetime_until, path_id,
};
use crate::name::DomainName;
use crate::redact::{Detail, SecretSlot};

/// Page size of the zone listing: the documented maximum.
// Source: DnsZone.list, `pageSize` ("The maximum value is 1000").
const PAGE_SIZE: &str = "1000";

/// Lifetime of a signed JWT: the documented maximum.
// Source: IAM token for a service account ("exp - iat ≤ 3600").
const JWT_LIFETIME_S: i64 = 3600;

/// Longest the client uses one IAM token. A token lives at most 12 hours and the documentation
/// recommends requesting one more often (design section 5.7: 50 minutes).
// Source: IAM token for a service account ("does not exceed 12 hours; however, we recommend
// requesting a token more often").
const TOKEN_MAX_AGE: Duration = Duration::from_secs(50 * 60);

/// Most polls of one provider-side operation (design section 3.7).
const MAX_POLLS: u32 = 60;

/// A zone as `DnsZone.list` and `DnsZone.get` return it; other fields are ignored.
// Source: DnsZone.list and DnsZone.get, `DnsZone`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Zone {
    /// The zone's identifier.
    pub(super) id: String,
    /// The DNS zone suffix, absolute (`example.org.`).
    #[serde(default)]
    pub(super) zone: String,
    /// Present for a publicly visible zone. A folder can hold a private zone of the same name.
    #[serde(default)]
    pub(super) public_visibility: Option<Value>,
}

impl Zone {
    /// True for a publicly visible zone.
    pub(super) fn is_public(&self) -> bool {
        self.public_visibility
            .as_ref()
            .is_some_and(Value::is_object)
    }

    /// The DNS suffix as a name, or `None` when it is not a valid one.
    pub(super) fn zone_name(&self) -> Option<DomainName> {
        DomainName::parse(&self.zone).ok()
    }
}

/// One page of `DnsZone.list`.
// Source: DnsZone.list, `ListDnsZonesResponse`: `dnsZones` and `nextPageToken`. Proto3 JSON may
// omit an empty list and an empty token, so both are optional here; a page with neither is the
// last, empty page.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ZonePage {
    #[serde(default)]
    dns_zones: Vec<Zone>,
    #[serde(default)]
    next_page_token: Option<String>,
}

/// An operation as the Operation API and `updateRecordSets` return it; other fields ignored.
// Source: Operation (`id`, `done`, `error` or `response`) and Errors (`Status`: `code`,
// `message`, `details`).
#[derive(Debug, Deserialize)]
struct Operation {
    #[serde(default)]
    id: String,
    #[serde(default)]
    done: bool,
    #[serde(default)]
    error: Option<Status>,
}

#[derive(Debug, Deserialize)]
struct Status {
    #[serde(default)]
    message: Option<String>,
}

/// The body of `updateRecordSets`.
// Source: DnsZone.updateRecordSets: `deletions[]` and `additions[]` (record sets, at most 1000
// each).
#[derive(Serialize)]
struct Update<'a> {
    deletions: &'a [Value],
    additions: &'a [Value],
}

/// What a read of one record set found.
#[derive(Debug)]
pub(super) enum Found {
    /// The record set as the API returned it, the whole JSON object.
    Set(Value),
    /// `404`: no such record set, or no such zone.
    NotFound,
}

/// The answer to a write.
#[derive(Debug)]
pub(super) enum Written {
    /// The provider applied the change: the operation finished without an error.
    Done,
    /// The provider refused the change, synchronously or through the operation's error, and
    /// nothing was written. `not_found` is true for a `404`, which can also mean that the zone
    /// identifier went stale. The caller reads again before it concludes anything: which status
    /// or operation error a failed condition of the strict call produces is not documented.
    Refused {
        /// The refusal as the error it maps to.
        error: Error,
        /// The refusal was a `404`.
        not_found: bool,
    },
}

/// Signs the JWTs that are exchanged for IAM tokens.
struct Signer {
    key: Ps256Key,
    /// `kid`: the authorized key's ID.
    key_id: SecretString,
    /// `iss`: the service account's ID.
    service_account_id: SecretString,
    /// `aud`: the token endpoint the JWT is sent to.
    audience: String,
    /// The scrubber slot of the signed JWTs.
    slot: SecretSlot,
}

#[derive(Serialize)]
struct JwtHeader<'a> {
    typ: &'static str,
    alg: &'static str,
    kid: &'a str,
}

#[derive(Serialize)]
struct JwtClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

impl Signer {
    /// A signed JWT for `now` (Unix seconds), in a zeroizing buffer.
    fn jwt(&self, now: i64) -> Result<Zeroizing<String>, Error> {
        let header = JwtHeader {
            typ: "JWT",
            alg: "PS256",
            kid: self.key_id.expose_secret(),
        };
        let claims = JwtClaims {
            iss: self.service_account_id.expose_secret(),
            aud: &self.audience,
            iat: now,
            exp: now.saturating_add(JWT_LIFETIME_S),
        };
        let fail = || Error::InvalidInput {
            detail: Detail::constant("the JWT could not be encoded"),
        };
        let header = Zeroizing::new(serde_json::to_vec(&header).map_err(|_| fail())?);
        let claims = Zeroizing::new(serde_json::to_vec(&claims).map_err(|_| fail())?);
        let mut jwt = Zeroizing::new(String::new());
        URL_SAFE_NO_PAD.encode_string(&*header, &mut jwt);
        jwt.push('.');
        URL_SAFE_NO_PAD.encode_string(&*claims, &mut jwt);
        let signature = self.key.sign(jwt.as_bytes()).map_err(|_| Error::Config {
            detail: Detail::constant("the JWT could not be signed with the authorized key"),
        })?;
        jwt.push('.');
        URL_SAFE_NO_PAD.encode_string(&signature, &mut jwt);
        Ok(jwt)
    }
}

/// The client's handle on the APIs: the transport, the endpoints, the signer and the token.
pub(super) struct Api {
    http: Http,
    dns: Endpoint,
    iam: Url,
    operation: Endpoint,
    signer: Signer,
    tokens: TokenSource,
    poller: Poller,
}

impl fmt::Debug for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Api")
            .field("dns", &self.dns)
            .field("operation", &self.operation)
            .field("poller", &self.poller)
            .finish_non_exhaustive()
    }
}

/// The endpoints of the client.
pub(super) struct Endpoints {
    /// The DNS API.
    pub(super) dns: Endpoint,
    /// The IAM token endpoint.
    pub(super) iam: Endpoint,
    /// The Operation API.
    pub(super) operation: Endpoint,
}

impl Api {
    /// The APIs at `endpoints`, authenticated with JWTs signed by `key` for the key `key_id` of
    /// service account `service_account_id`; operations polled every `poll_interval`.
    pub(super) fn new(
        http: Http,
        endpoints: Endpoints,
        key: Ps256Key,
        key_id: SecretString,
        service_account_id: SecretString,
        poll_interval: Duration,
    ) -> Api {
        let iam = endpoints.iam.as_url().clone();
        Api {
            http,
            dns: endpoints.dns,
            operation: endpoints.operation,
            signer: Signer {
                key,
                key_id,
                service_account_id,
                // The documentation names the token URL as the audience; the configured token
                // endpoint is that URL unless the client is pointed at a test server.
                audience: iam.as_str().to_owned(),
                slot: SecretSlot::new(),
            },
            iam,
            tokens: TokenSource::new(Some(TOKEN_MAX_AGE)),
            poller: Poller::new(poll_interval, MAX_POLLS),
        }
    }

    /// The token exchange: signs a JWT, registers it with the scrubber before it is sent, and
    /// exchanges it for an IAM token. The token request is idempotent (design section 5.3).
    ///
    /// Answers: 2xx with `iamToken` is the token, its lifetime from `expiresAt`; 400 and 401 are
    /// `Error::Auth`; 403, 429 and 5xx follow the shared mapping; anything else is a refusal.
    // Source: IamToken.create (200, `iamToken`, `expiresAt`). Assumption (not documented): a JWT
    // the service cannot accept (signature, `kid`, `iss`, `aud`, times) is answered `400`
    // (`INVALID_ARGUMENT`) or `401` (`UNAUTHENTICATED`), both reported as an authentication
    // error. A token request writes nothing, so a wrong classification changes only the kind of
    // the error.
    async fn fetch(&self) -> Result<Token, Error> {
        #[derive(Serialize)]
        struct Exchange<'a> {
            jwt: &'a str,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Issued {
            #[serde(default)]
            iam_token: Option<String>,
            #[serde(default)]
            expires_at: Option<String>,
        }
        let jwt = self.signer.jwt(jiff::Timestamp::now().as_second())?;
        self.http.remember(&self.signer.slot, jwt.as_str());
        let request = Request::new(Method::POST, self.iam.clone())
            .idempotent()
            .anonymous()
            .json(&Exchange { jwt: &jwt })?
            .keep_status(400);
        drop(jwt);
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
            response.json("the IAM service's token answer is not in the expected form")?;
        let token = issued
            .iam_token
            .filter(|t| !t.is_empty())
            .ok_or(Error::Protocol {
                detail: Detail::constant("the IAM service answered without an iamToken"),
            })?;
        let lifetime = issued.expires_at.as_deref().and_then(lifetime_until);
        Ok(Token::new(SecretString::from(token), lifetime))
    }

    /// Exchanges a new JWT for a new token, even when a valid one is cached: proves that the key
    /// is accepted now. The new token replaces the cached one.
    pub(super) async fn authenticate(&self) -> Result<(), Error> {
        let lease = self.tokens.get(|| self.fetch()).await?;
        if !lease.fresh {
            // The cached token proves nothing about the key as it is now.
            self.tokens.invalidate(lease.generation).await;
            self.tokens.get(|| self.fetch()).await?;
        }
        Ok(())
    }

    /// Sends `request` with the IAM token as a bearer token.
    // Source: IamToken.create ("Pass it in the Authorization header"); lego and the provider's
    // examples send `Authorization: Bearer <token>`.
    async fn send(&self, request: &Request) -> Result<Response, Error> {
        self.http
            .send_with_token(request, &self.tokens, &TokenAuth::BEARER, || self.fetch())
            .await
    }

    /// Every zone of folder `folder`, all pages. A listing is complete or it fails.
    // Source: DnsZone.list (`folderId`, `pageSize`, `pageToken`; `nextPageToken` while more
    // results exist). The `filter` parameter matches the zone's resource name, not its DNS
    // suffix, so it is not used.
    pub(super) async fn zones(&self, folder: &str) -> Result<Vec<Zone>, Error> {
        pager::collect(None::<String>, |token| async move {
            let mut url = self
                .dns
                .url()
                .path("/zones")
                .query("folderId", folder)
                .query("pageSize", PAGE_SIZE);
            if let Some(token) = &token {
                url = url.query("pageToken", token);
            }
            let response = self.send(&Request::get(url.build()?)).await?;
            if !response.is_success() {
                return Err(self.refusal(&response));
            }
            let page: ZonePage =
                response.json("the provider's zone listing is not in the expected form")?;
            Ok(Page {
                items: page.dns_zones,
                next: pager::next_token(page.next_page_token).map(Some),
            })
        })
        .await
    }

    /// The zone with identifier `id`, or `None` for a `404`.
    // Source: DnsZone.get; Errors (`NOT_FOUND` is 404).
    pub(super) async fn zone(&self, id: &str) -> Result<Option<Zone>, Error> {
        let url = self.dns.url().path("/zones").id(id).build()?;
        let response = self.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        response
            .json("the provider's zone is not in the expected form")
            .map(Some)
    }

    /// The record set `name` of type `rtype` in zone `zone_id`. `name` is relative to the zone.
    // Source: DnsZone.getRecordSet (`name`, `type`); Errors (`NOT_FOUND` is 404, for the zone and
    // for the record set alike); lego yandexcloud.go:211-222 sends the name relative to the zone
    // and reads "RecordSet not found" as an absent record set.
    pub(super) async fn record_set(
        &self,
        zone_id: &str,
        name: &str,
        rtype: &str,
    ) -> Result<Found, Error> {
        let url = self
            .dns
            .url()
            .path("/zones")
            .id(zone_id)
            .path(":getRecordSet")
            .query("name", name)
            .query("type", rtype)
            .build()?;
        let response = self.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(Found::NotFound);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let set: Value = response.json("the provider's record set is not in the expected form")?;
        if !set.is_object() {
            return Err(Error::Protocol {
                detail: Detail::constant("the provider's record set is not in the expected form"),
            });
        }
        Ok(Found::Set(set))
    }

    /// The strict change: deletes `deletions`, each of which must match the record set at the
    /// provider exactly, then adds `additions`, each of which must not exist; and waits for the
    /// operation. Sent once: a repeat after an unknown outcome would be refused by the strict
    /// check or, worse, apply against a state read before another writer's change (design
    /// section 5.3). The caller's repeat of the operation starts with a read.
    // Source: DnsZone.updateRecordSets ("Method with strict control ... Returns error when:
    // Deleted record is not found; Found record with matched type and name but different TTL,
    // value, or description; Attempted to add record with existing name and type"; 200 with an
    // Operation). Upsert (`upsertRecordSets`) is not used: it carries no condition.
    pub(super) async fn update_record_sets(
        &self,
        zone_id: &str,
        deletions: &[Value],
        additions: &[Value],
    ) -> Result<Written, Error> {
        let url = self
            .dns
            .url()
            .path("/zones")
            .id(zone_id)
            .path(":updateRecordSets")
            .build()?;
        let request = Request::new(Method::POST, url).json(&Update {
            deletions,
            additions,
        })?;
        let response = self.send(&request).await?;
        if !response.is_success() {
            return Ok(Written::Refused {
                error: self.refusal(&response),
                not_found: response.status() == 404,
            });
        }
        let operation: Operation =
            response.json("the provider's operation is not in the expected form")?;
        self.finish(operation).await
    }

    /// Waits until `operation` is done (design section 3.7). An operation still running after
    /// the last poll, or a poll that fails, is `Error::Transient`.
    async fn finish(&self, operation: Operation) -> Result<Written, Error> {
        if operation.done {
            return Ok(self.outcome(operation));
        }
        let id = path_id(&operation.id)?.to_owned();
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
    // Source: Operation ("GET https://operation.api.cloud.yandex.net/operations/{operationId}").
    async fn operation(&self, id: &str) -> Result<Operation, Error> {
        let url = self.operation.url().id(id).build()?;
        let response = self.send(&Request::get(url)).await?;
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        response.json("the provider's operation is not in the expected form")
    }

    /// A finished operation: an `error` is a refusal with the provider's message.
    // Source: Operation ("an operation with an error still counts as completed"; `response` and
    // `error` are mutually exclusive).
    fn outcome(&self, operation: Operation) -> Written {
        match operation.error {
            None => Written::Done,
            Some(status) => Written::Refused {
                error: Error::Rejected {
                    status: None,
                    detail: match status.message.filter(|m| !m.is_empty()) {
                        Some(message) => self.http.detail(&message),
                        None => Detail::constant("the provider's operation failed"),
                    },
                },
                not_found: false,
            },
        }
    }

    /// An answer the client does not expect. 401, 403, 429 and 5xx were mapped by the transport
    /// already. The refusals of the documented error mapping are `Rejected`; anything else is an
    /// answer the client cannot interpret.
    // Source: Errors (400 `INVALID_ARGUMENT`, `FAILED_PRECONDITION`, `OUT_OF_RANGE`; 404
    // `NOT_FOUND`; 409 `ALREADY_EXISTS`, `ABORTED`).
    fn refusal(&self, response: &Response) -> Error {
        match response.status() {
            400 | 404 | 409 => self.http.reject(response),
            status => Error::Protocol {
                detail: self.http.detail(&format!(
                    "status {status}: {}",
                    self.http.body_detail(response)
                )),
            },
        }
    }
}

/// The provider's error message: `message` of the error body.
// Source: Errors (`Status`: `code`, `message`, `details`).
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
    use super::error_message;

    #[test]
    fn error_messages_are_read_from_message() {
        for (body, expected) in [
            (
                r#"{"code":5,"message":"RecordSet not found","details":[]}"#,
                Some("RecordSet not found"),
            ),
            (r#"{"code":3,"message":""}"#, None),
            (r#"{"code":3}"#, None),
            ("<html>oops</html>", None),
        ] {
            assert_eq!(error_message(body).as_deref(), expected, "{body}");
        }
    }
}
