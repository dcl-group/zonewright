//! The Azure DNS API as this client uses it: the token exchange, one function per endpoint, the
//! wire types, paging and the classification of answers. Nothing here knows the value layer or
//! the record layer.
//!
//! Sources (hard rule 3), all read 2026-11-16:
//!
//! - Create Or Update,
//!   <https://learn.microsoft.com/en-us/rest/api/dns/record-sets/create-or-update?view=rest-dns-2018-05-01>:
//!   the record set object, its properties per type, `If-Match` and `If-None-Match`, `200`/`201`,
//!   the `CloudError` body.
//! - Get, <https://learn.microsoft.com/en-us/rest/api/dns/record-sets/get?view=rest-dns-2018-05-01>.
//! - Delete, <https://learn.microsoft.com/en-us/rest/api/dns/record-sets/delete?view=rest-dns-2018-05-01>
//!   ("200 OK: The record set has been deleted"; "204 No Content: The record set was not
//!   found"; `If-Match`).
//! - List By DNS Zone,
//!   <https://learn.microsoft.com/en-us/rest/api/dns/record-sets/list-by-dns-zone?view=rest-dns-2018-05-01>.
//! - Zones Get, <https://learn.microsoft.com/en-us/rest/api/dns/zones/get?view=rest-dns-2018-05-01>;
//!   Zones List By Resource Group,
//!   <https://learn.microsoft.com/en-us/rest/api/dns/zones/list-by-resource-group?view=rest-dns-2018-05-01>
//!   (`value`, `nextLink`; the `zoneType` `Public` or `Private`).
//! - Records, <https://learn.microsoft.com/en-us/azure/dns/dns-zones-records> (names, `@`, TTL
//!   range, etags and the conditional headers, TXT strings, limits).
//! - Azure REST, <https://learn.microsoft.com/en-us/rest/api/azure/> (`Authorization: Bearer`,
//!   `api-version`, "Continue sending requests to the nextLink URL until it no longer contains a
//!   URL").
//! - Client credentials,
//!   <https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow>
//!   (the token request with a shared secret, its answer and its error answer).
//! - Throttling,
//!   <https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling>
//!   (`429` with `Retry-After`, also with the code `RetryableErrorDueToAnotherOperation`).
//! - The Go SDK lego uses, `armdns` v1.2.0, `recordsets_client.go`
//!   (<https://raw.githubusercontent.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns/v1.2.0/sdk/resourcemanager/dns/armdns/recordsets_client.go>):
//!   `api-version=2018-05-01`, the paths, `If-Match` and `If-None-Match` sent as given; lego
//!   `providers/dns/azuredns/` (`azuredns.go`, `public.go`).
//!
//! Endpoints used. `{rg}` is `/subscriptions/{subscription}/resourceGroups/{resource group}
//! /providers/Microsoft.Network/dnsZones` below the `management_url`; every call carries
//! `api-version=2018-05-01`:
//!
//! | Call            | Request                                        | Success                  |
//! | --------------- | ---------------------------------------------- | ------------------------ |
//! | token           | `POST {login_url}/{tenant}/oauth2/v2.0/token`  | 200, `access_token`      |
//! | list zones      | `GET {rg}`                                     | 200, `value`, `nextLink` |
//! | one zone        | `GET {rg}/{zone}`                              | 200, the zone            |
//! | list rrsets     | `GET {rg}/{zone}/recordsets`                   | 200, `value`, `nextLink` |
//! | one rrset       | `GET {rg}/{zone}/{type}/{name}`                | 200, the record set      |
//! | create, replace | `PUT {rg}/{zone}/{type}/{name}`                | 201 created, 200 updated |
//! | delete          | `DELETE {rg}/{zone}/{type}/{name}`             | 200; 204 not found       |
//!
//! The zone is its name without the trailing dot ("The name of the DNS zone (without a
//! terminating dot)", Create Or Update). The record set name is relative to the zone, `@` at the
//! apex ("By convention, the relative name '@' is used to represent apex records", Records). A
//! wildcard name's `*` is percent-encoded (`%2A`) in a path, which the service decodes before it
//! routes: an assumption, not observed against the live API.
//!
//! A `404` to a read of a record set or a zone is taken as "not found", as lego does
//! (`public.go`, Present: `respErr.StatusCode == http.StatusNotFound`); the reference names no
//! status other than the successes ("Other Status Codes: CloudError"): an assumption for the
//! zone read, not observed against the live API.

use std::sync::{Mutex, PoisonError};

use bytes::Bytes;
use reqwest::header::{HeaderName, IF_MATCH, IF_NONE_MATCH};
use reqwest::{Method, Url};
use secrecy::SecretString;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::error::Error;
use crate::http::encode;
use crate::http::pager::{self, Page};
use crate::http::url::UrlBuilder;
use crate::http::{Endpoint, Http, Request, Response, Token, TokenAuth, TokenSource};
use crate::name::DomainName;
use crate::redact::Detail;

/// The API version of every call: the only stable version of the DNS API.
// Source: the reference pages above ("API Version: 2018-05-01"); armdns v1.2.0
// (`reqQP.Set("api-version", "2018-05-01")`); the stable directory of the specification,
// https://github.com/Azure/azure-rest-api-specs/tree/main/specification/dns/resource-manager/Microsoft.Network/Dns/stable
// (2016-04-01, 2017-09-01, 2017-10-01, 2018-05-01).
pub(super) const API_VERSION: &str = "2018-05-01";

/// The prefix of a record set's `type`: `Microsoft.Network/dnsZones/A` (Create Or Update, every
/// sample answer).
const TYPE_PREFIX: &str = "microsoft.network/dnszones/";

/// A zone as the listing returns it; other members are ignored.
// Source: Zones Get / List By Resource Group, definition `Zone` (`name`, `properties.zoneType`
// with the default `Public`).
#[derive(Debug, Deserialize)]
pub(super) struct Zone {
    /// The zone name, without the trailing dot.
    pub(super) name: String,
    #[serde(default)]
    properties: Option<ZoneProperties>,
}

#[derive(Debug, Deserialize)]
struct ZoneProperties {
    #[serde(default, rename = "zoneType")]
    zone_type: Option<String>,
}

impl Zone {
    /// A public zone: `zoneType` absent (the default is `Public`) or `Public`. Private zones are
    /// a separate resource type and not expected in this listing; a zone that says `Private` is
    /// left out all the same.
    pub(super) fn is_public(&self) -> bool {
        self.properties
            .as_ref()
            .and_then(|p| p.zone_type.as_deref())
            .is_none_or(|t| t.eq_ignore_ascii_case("Public"))
    }
}

/// A record set as the API returns it. No member is marked required in the reference; a single
/// record set's answer may leave out what its path states (a stated name or type must match it),
/// and a listing item, where they are its only identification, must state its name and type.
#[derive(Deserialize)]
struct WireRecordSet {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "type")]
    rtype: Option<String>,
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    properties: Option<Map<String, Value>>,
}

/// A record set as read: everything a write needs to send it back, attributes the model does
/// not carry (`metadata`) included.
// `pub(crate)`: it is the `Snapshot` of the client's `WholeSet` implementations, crate-wide
// traits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecordSet {
    /// The owner, fully qualified, as the client resolved it from `name`; `None` when the
    /// answer spells a name the crate cannot hold.
    pub(super) owner: Option<DomainName>,
    /// The type as the API spells it (`A`, `TXT`, …).
    pub(super) type_name: String,
    /// The etag; `None` when the answer has none.
    pub(super) etag: Option<String>,
    /// The `properties` object as returned.
    pub(super) properties: Map<String, Value>,
}

/// One page of a listing.
#[derive(Deserialize)]
struct ListPage {
    #[serde(default)]
    value: Option<Vec<Value>>,
    #[serde(default, rename = "nextLink")]
    next_link: Option<String>,
}

/// The JSON answer of the token endpoint; other fields are ignored.
// Source: Client credentials, "Successful response example": `token_type`, `expires_in`,
// `access_token`.
#[derive(Deserialize)]
struct TokenAnswer {
    access_token: String,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<Value>,
}

/// The condition of a write.
#[derive(Clone, Debug)]
pub(super) enum Condition<'a> {
    /// `If-None-Match: *`: only if no record set exists ("Set to '*' to allow a new record set
    /// to be created, but to prevent updating an existing record set", Create Or Update).
    Absent,
    /// `If-Match: <etag>`: only if the record set still has the etag read ("Specify the
    /// last-seen etag value to prevent accidentally overwriting any concurrent changes").
    Etag(&'a str),
}

/// The answer to a write.
#[derive(Debug)]
pub(super) enum Written {
    /// The service accepted the write.
    Done,
    /// `204` to a delete: "The record set was not found".
    NotFound,
    /// A refusal, as the error it maps to.
    Refused(Error),
}

/// The client's handle on the API: the transport, the endpoints and the token.
pub(super) struct Api {
    http: Http,
    management: Endpoint,
    subscription: String,
    group: String,
    token_url: Url,
    /// The form body of the token request, built once in a zeroizing buffer.
    grant: Bytes,
    tokens: TokenSource,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("management", &self.management)
            .finish_non_exhaustive()
    }
}

/// The relative name of `name` in `zone`: `@` for the apex. The layers refuse a name outside the
/// zone before any request; this refuses it once more rather than build a wrong path.
pub(super) fn relative<'a>(zone: &DomainName, name: &'a DomainName) -> Result<&'a str, Error> {
    match name.relative_to(zone) {
        Some("") => Ok("@"),
        Some(relative) => Ok(relative),
        None => Err(Error::InvalidInput {
            detail: Detail::constant("the name is not within the zone"),
            code: None,
        }),
    }
}

/// The record type in a record set's `type` member, or `None` for another form.
fn type_of(stated: &str) -> Option<&str> {
    let prefix = stated.get(..TYPE_PREFIX.len())?;
    prefix
        .eq_ignore_ascii_case(TYPE_PREFIX)
        .then(|| stated.get(TYPE_PREFIX.len()..))
        .flatten()
        .filter(|t| !t.is_empty() && !t.contains('/'))
}

impl Api {
    /// The API at `management`, for the zones of `group` in `subscription`, with tokens from
    /// `token_url` obtained with the form body `grant` (built by [`grant`]).
    pub(super) fn new(
        http: Http,
        management: Endpoint,
        subscription: String,
        group: String,
        token_url: Url,
        grant: Bytes,
    ) -> Api {
        Api {
            http,
            management,
            subscription,
            group,
            token_url,
            grant,
            tokens: TokenSource::new(None),
        }
    }

    /// The client credentials grant. A `400` is `Error::Auth`, as a `401` is in the transport.
    // Source: Client credentials, "Request an access token" and "Error response example" (`400`
    // with `error` and `error_description`). The answer is read as the documentation shows it; a
    // token without `expires_in` is assumed to live an hour (design section 5.7). Exchanging the
    // same credentials again issues another token and changes nothing, so the request is
    // repeated after a failure like a read.
    async fn fetch(&self) -> Result<Token, Error> {
        let request = Request::new(Method::POST, self.token_url.clone())
            .idempotent()
            .anonymous()
            .body(encode::FORM, self.grant.clone())
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
        let answer: TokenAnswer =
            response.json("the token endpoint's answer is not in the expected form")?;
        if answer.access_token.is_empty() {
            return Err(protocol("the token endpoint issued an empty token"));
        }
        if answer
            .token_type
            .as_deref()
            .is_some_and(|t| !t.eq_ignore_ascii_case("Bearer"))
        {
            return Err(protocol(
                "the token endpoint issued a token of a type other than Bearer",
            ));
        }
        let lifetime = match answer.expires_in {
            Some(Value::Number(n)) => n.as_u64(),
            Some(Value::String(s)) => s.trim().parse::<u64>().ok(),
            _ => None,
        }
        .map(std::time::Duration::from_secs);
        Ok(Token::new(
            SecretString::from(answer.access_token),
            lifetime,
        ))
    }

    /// Exchanges the credentials for a new token, even when a valid one is cached: proves that
    /// they are accepted now. The new token replaces the cached one.
    pub(super) async fn authenticate(&self) -> Result<(), Error> {
        self.tokens.renew(|| self.fetch()).await?;
        Ok(())
    }

    /// Sends `request` with the token as `Authorization: Bearer` (Azure REST).
    async fn send(&self, request: &Request) -> Result<Response, Error> {
        self.http
            .send_with_token(request, &self.tokens, &TokenAuth::BEARER, || self.fetch())
            .await
    }

    /// Every public zone of the resource group, all pages.
    pub(super) async fn zones(&self) -> Result<Vec<Zone>, Error> {
        let zones: Vec<Zone> = self.list(|| self.zones_url(), None).await?;
        Ok(zones.into_iter().filter(Zone::is_public).collect())
    }

    /// Whether the resource group holds the public zone `zone`.
    // Source: Zones Get (`200` with the zone). A `404` for a zone that does not exist is an
    // assumption (module documentation), checked by `azure_dns_live_assumptions`.
    pub(super) async fn zone_exists(&self, zone: &DomainName) -> Result<bool, Error> {
        let url = self.zone_url(zone).build()?;
        let response = self.send(&Request::get(api_version(url))).await?;
        if response.status() == 404 {
            return Ok(false);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let found: Zone = response.json("the provider's zone is not in the expected form")?;
        if DomainName::parse(&found.name).as_ref() != Ok(zone) {
            return Err(protocol(
                "the provider answered with a zone other than the one asked for",
            ));
        }
        Ok(found.is_public())
    }

    /// Every record set of `zone`, all pages. A `404` is `None`: the caller finds out whether
    /// the zone exists. An item must state its name and type: in a listing they are its only
    /// identification.
    // Source: List By DNS Zone (`200` with `value` and `nextLink`).
    pub(super) async fn record_sets(
        &self,
        zone: &DomainName,
    ) -> Result<Option<Vec<RecordSet>>, Error> {
        let missing = std::sync::atomic::AtomicBool::new(false);
        let wire: Vec<WireRecordSet> = match self
            .list(|| self.zone_url(zone).path("/recordsets"), Some(&missing))
            .await
        {
            Ok(wire) => wire,
            Err(_) if missing.load(std::sync::atomic::Ordering::SeqCst) => return Ok(None),
            Err(e) => return Err(e),
        };
        wire.into_iter()
            .map(|wire| {
                let type_name = wire
                    .rtype
                    .as_deref()
                    .and_then(type_of)
                    .ok_or_else(nameless)?
                    .to_owned();
                let name = wire.name.as_deref().ok_or_else(nameless)?;
                Ok(RecordSet {
                    owner: DomainName::from_relative(name, zone).ok(),
                    type_name,
                    etag: wire.etag,
                    properties: wire.properties.unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>, Error>>()
            .map(Some)
    }

    /// The record set of `name` and `type_name` (the API's spelling), or `None` for a `404`,
    /// which may also mean that the zone does not exist.
    // Source: Get (`200` with the record set); lego `public.go` (a `404` is "no record set").
    pub(super) async fn record_set(
        &self,
        zone: &DomainName,
        name: &DomainName,
        type_name: &str,
    ) -> Result<Option<RecordSet>, Error> {
        let rel = relative(zone, name)?;
        let url = self.record_set_url(zone, type_name, rel)?;
        let response = self.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let wire: WireRecordSet =
            response.json("the provider's record set is not in the expected form")?;
        // The answer must be about the record set asked for; what it leaves out, the path says.
        let other = wire
            .name
            .as_deref()
            .is_some_and(|stated| !stated.eq_ignore_ascii_case(rel))
            || wire
                .rtype
                .as_deref()
                .is_some_and(|stated| type_of(stated).is_none_or(|t| t != type_name));
        if other {
            return Err(protocol(
                "the provider answered with a record set other than the one asked for",
            ));
        }
        Ok(Some(RecordSet {
            owner: Some(name.clone()),
            type_name: type_name.to_owned(),
            etag: wire.etag,
            properties: wire.properties.unwrap_or_default(),
        }))
    }

    /// Creates or replaces a record set with `body` under `condition`. Sent once: a refused
    /// condition must reach the caller, which reads again to tell a concurrent change from any
    /// other refusal.
    // Source: Create Or Update (`PUT`, `If-Match`, `If-None-Match`, `200`/`201`).
    pub(super) async fn put(
        &self,
        zone: &DomainName,
        name: &DomainName,
        type_name: &str,
        body: &Value,
        condition: &Condition<'_>,
    ) -> Result<Written, Error> {
        let url = self.record_set_url(zone, type_name, relative(zone, name)?)?;
        let request = conditional(Request::new(Method::PUT, url).json(body)?, condition)?;
        let response = self.send(&request).await?;
        Ok(match response.status() {
            200 | 201 => Written::Done,
            _ if response.is_success() => Written::Done,
            _ => Written::Refused(self.refusal(&response)),
        })
    }

    /// Deletes a record set if it still has `etag`. Sent once, like a write.
    // Source: Delete (`If-Match`: "Specify the last-seen etag value to prevent accidentally
    // deleting any concurrent changes"; `200` deleted, `204` not found).
    pub(super) async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        type_name: &str,
        etag: &str,
    ) -> Result<Written, Error> {
        let url = self.record_set_url(zone, type_name, relative(zone, name)?)?;
        let request = conditional(Request::new(Method::DELETE, url), &Condition::Etag(etag))?;
        let response = self.send(&request).await?;
        Ok(match response.status() {
            204 => Written::NotFound,
            _ if response.is_success() => Written::Done,
            _ => Written::Refused(self.refusal(&response)),
        })
    }

    /// `/subscriptions/{subscription}/resourceGroups/{group}/providers/Microsoft.Network/dnsZones`.
    // Source: Zones List By Resource Group (the path); the provider namespace and resource type
    // as every reference page spells them.
    fn zones_url(&self) -> UrlBuilder {
        self.management
            .url()
            .path("/subscriptions")
            .segment(&self.subscription)
            .path("/resourceGroups")
            .segment(&self.group)
            .path("/providers/Microsoft.Network/dnsZones")
    }

    fn zone_url(&self, zone: &DomainName) -> UrlBuilder {
        self.zones_url().segment(zone.without_dot())
    }

    fn record_set_url(&self, zone: &DomainName, type_name: &str, rel: &str) -> Result<Url, Error> {
        let url = self.zone_url(zone).segment(type_name);
        let url = if rel == "@" {
            url.path("/@")
        } else {
            url.segment(rel)
        };
        Ok(api_version(url.build()?))
    }

    /// Reads every page of a listing at the path `url` builds. A `404` sets `missing` (when
    /// given) and fails.
    ///
    /// Paging (Azure REST, "Continue sending requests to the nextLink URL until it no longer
    /// contains a URL"; Zones List, the example `nextLink` with `$skipToken`): an answer holds
    /// `value` and, when more items exist, `nextLink`. The link itself is never requested
    /// (design section 5.4): only its `$skipToken` is taken and sent with this client's own
    /// path. No page size is sent (`$top` has a default of 100 and no documented maximum).
    ///
    /// The listing ends at a page without `nextLink`, and at an empty page. A `nextLink` without
    /// `$skipToken`, a token equal to the one just used, and a page that repeats the one before
    /// it are `Error::Protocol`, and `pager::collect` stops at its page limit.
    async fn list<T, U>(
        &self,
        url: U,
        missing: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<Vec<T>, Error>
    where
        T: DeserializeOwned,
        U: Fn() -> UrlBuilder,
    {
        let previous: Mutex<Option<Vec<Value>>> = Mutex::new(None);
        pager::collect(String::new(), |token| {
            let request = url().build();
            let previous = &previous;
            async move {
                let request = with_skip_token(request?, &token);
                let response = self.send(&Request::get(request.clone())).await?;
                if response.status() == 404
                    && let Some(missing) = missing
                {
                    missing.store(true, std::sync::atomic::Ordering::SeqCst);
                    return Err(self.refusal(&response));
                }
                if !response.is_success() {
                    return Err(self.refusal(&response));
                }
                let page: ListPage =
                    response.json("the provider's listing is not in the expected form")?;
                let items = page.value.unwrap_or_default();
                {
                    let mut previous = previous.lock().unwrap_or_else(PoisonError::into_inner);
                    if !items.is_empty() && previous.as_ref() == Some(&items) {
                        return Err(protocol(
                            "the provider's listing repeated a page instead of moving on",
                        ));
                    }
                    *previous = Some(items.clone());
                }
                let next = if items.is_empty() {
                    None
                } else {
                    next_token(page.next_link.as_deref(), &request)?
                };
                let items: Vec<T> =
                    serde_json::from_value(Value::Array(items)).map_err(|_| malformed_listing())?;
                Ok(Page { items, next })
            }
        })
        .await
    }

    /// An answer the client does not expect. 401, 403, 429 and 5xx were mapped by the
    /// transport already. Every other refusal carries a `CloudError` ("Other Status Codes:
    /// CloudError", every reference page): `Error::Rejected` with its message and its `code`.
    fn refusal(&self, response: &Response) -> Error {
        self.http.reject(response)
    }
}

/// `url` with `api-version` as its only query parameter.
fn api_version(mut url: Url) -> Url {
    url.set_query(Some(&format!("api-version={API_VERSION}")));
    url
}

/// `url` with `api-version` and, for a page after the first, `$skipToken`. The parameter is
/// spelled with a literal `$`, as the documentation's `nextLink` example spells it; the value is
/// percent-encoded.
fn with_skip_token(url: Url, token: &str) -> Url {
    let mut url = api_version(url);
    if !token.is_empty() {
        let query = format!(
            "api-version={API_VERSION}&$skipToken={}",
            encode::percent(token)
        );
        url.set_query(Some(&query));
    }
    url
}

/// The `$skipToken` of `next_link`, or `None` when there is no link. A relative link is resolved
/// against the URL of the request.
fn next_token(next_link: Option<&str>, request: &Url) -> Result<Option<String>, Error> {
    let Some(link) = next_link.map(str::trim).filter(|l| !l.is_empty()) else {
        return Ok(None);
    };
    let bad = || protocol("the provider's nextLink is not in the expected form");
    let url = request.join(link).map_err(|_| bad())?;
    let token = url
        .query_pairs()
        .find(|(key, _)| key.eq_ignore_ascii_case("$skipToken"))
        .map(|(_, value)| value.into_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(bad)?;
    Ok(Some(token))
}

/// Adds the condition header. The etag is sent as the API returned it, as the Go SDK does
/// (`req.Raw().Header["If-Match"] = []string{*options.IfMatch}`, armdns v1.2.0).
fn conditional(request: Request, condition: &Condition<'_>) -> Result<Request, Error> {
    let (name, value): (HeaderName, &str) = match condition {
        Condition::Absent => (IF_NONE_MATCH, "*"),
        Condition::Etag(etag) => (IF_MATCH, etag),
    };
    request.header_text(name, value).map_err(|_| {
        protocol("the provider returned an etag that cannot be sent in a request header")
    })
}

/// The form body of the token request, in a zeroizing buffer.
// Source: Client credentials, "First case: Access token request with a shared secret":
// `client_id`, `scope`, `client_secret` ("The client secret … must be URL-encoded"),
// `grant_type=client_credentials`, form-encoded in the body of a POST.
pub(super) fn grant(client_id: &str, scope: &str, client_secret: &SecretString) -> Bytes {
    use secrecy::ExposeSecret as _;
    encode::wiped_text(encode::form(&[
        ("client_id", client_id),
        ("scope", scope),
        ("client_secret", client_secret.expose_secret()),
        ("grant_type", "client_credentials"),
    ]))
}

/// The provider's error code: `error.code` of a `CloudError`, a string ("An identifier for the
/// error. Codes are invariant and are intended to be consumed programmatically", Create Or
/// Update, definition `CloudErrorBody`).
pub(super) fn error_code(body: &str) -> Option<String> {
    let body: Value = serde_json::from_str(body).ok()?;
    match body.get("error")?.get("code")? {
        Value::String(code) if !code.is_empty() => Some(code.clone()),
        _ => None,
    }
}

fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

fn nameless() -> Error {
    protocol("the provider's listing holds a record set without a name or a type")
}

fn malformed_listing() -> Error {
    protocol("the provider's listing is not in the expected form")
}

#[cfg(test)]
mod tests {
    use reqwest::Url;

    use super::{error_code, next_token, type_of, with_skip_token};
    use crate::error::ErrorKind;

    fn request() -> Url {
        Url::parse("https://management.azure.com/subscriptions/s/resourceGroups/g/providers/Microsoft.Network/dnsZones?api-version=2018-05-01").unwrap()
    }

    #[test]
    fn error_codes_are_the_cloud_error_code() {
        let body = r#"{"error":{"code":"BadRequest","message":"m","details":[]}}"#;
        assert_eq!(error_code(body).as_deref(), Some("BadRequest"));
        // An identity platform error has a string `error`, not a code object.
        assert_eq!(error_code(r#"{"error":"invalid_client"}"#), None);
        assert_eq!(error_code(r#"{"error":{"code":7}}"#), None);
        assert_eq!(error_code("<html/>"), None);
    }

    #[test]
    fn types_are_read_from_the_resource_type() {
        assert_eq!(type_of("Microsoft.Network/dnsZones/TXT"), Some("TXT"));
        assert_eq!(type_of("microsoft.network/dnszones/A"), Some("A"));
        assert_eq!(type_of("Microsoft.Network/dnsZones"), None);
        assert_eq!(type_of("Microsoft.Network/privateDnsZones/A"), None);
        assert_eq!(type_of("Microsoft.Network/dnsZones/A/x"), None);
    }

    #[test]
    fn the_skip_token_is_taken_from_the_next_link() {
        let link = "https://servicehost/subscriptions/subid/providers/Microsoft.Network/dnsZones?api-version=2018-05-01&$skipToken=skipToken";
        assert_eq!(
            next_token(Some(link), &request()).unwrap().as_deref(),
            Some("skipToken")
        );
        assert_eq!(next_token(None, &request()).unwrap(), None);
        assert_eq!(next_token(Some(""), &request()).unwrap(), None);
        let encoded = "/x?%24skipToken=a%2Bb&api-version=2018-05-01";
        assert_eq!(
            next_token(Some(encoded), &request()).unwrap().as_deref(),
            Some("a+b")
        );
        for bad in [
            "https://h/x?api-version=2018-05-01",
            "https://h/x?$skipToken=",
        ] {
            let e = next_token(Some(bad), &request()).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Protocol, "{bad}");
        }
        let url = with_skip_token(request(), "a+b c");
        assert_eq!(
            url.query(),
            Some("api-version=2018-05-01&$skipToken=a%2Bb%20c")
        );
        assert_eq!(
            with_skip_token(request(), "").query(),
            Some("api-version=2018-05-01")
        );
    }
}
