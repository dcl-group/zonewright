//! The Selectel DNS v2 API as this client uses it: authentication, one function per endpoint,
//! the wire types, paging and the classification of answers. Nothing here knows the value layer
//! or the zone cache; `client.rs` and `txt.rs` build on these calls.
//!
//! Sources (hard rule 3):
//!
//! - [DNS v2]: <https://docs.selectel.ru/api/docs/cloud-services/dns_api/dns_api_actual/>, and
//!   the OpenAPI document behind that page, <https://docs.selectel.ru/api/dns-actual.json>
//!   ("the OpenAPI" below): paths, parameters, request and answer schemas, status codes.
//! - [Authorization]: <https://docs.selectel.ru/api/authorization/>.
//! - The provider's Go client `github.com/selectel/domains-go`, `pkg/v2` (`client.go`,
//!   `model.go`, `error.go`, `rrsetManager.go`, `zoneManager.go`).
//! - lego `providers/dns/selectelv2/selectelv2.go`.
//!
//! Endpoints used, all below the `base_url`:
//!
//! | Call            | Request                               | Success                  |
//! | --------------- | ------------------------------------- | ------------------------ |
//! | list zones      | `GET /zones?filter&limit&offset`      | 200, page                |
//! | list rrsets     | `GET /zones/{zone}/rrset?name&rrset_types&limit&offset` | 200, page |
//! | list all rrsets | `GET /zones/{zone}/rrset?limit&offset`  | 200, page                |
//! | create rrset    | `POST /zones/{zone}/rrset`            | 200, the new rrset       |
//! | update rrset    | `PATCH /zones/{zone}/rrset/{rrset}`   | 204                      |
//! | delete rrset    | `DELETE /zones/{zone}/rrset/{rrset}`  | 204                      |
//!
//! [DNS v2]: https://docs.selectel.ru/api/docs/cloud-services/dns_api/dns_api_actual/
//! [Authorization]: https://docs.selectel.ru/api/authorization/

use std::fmt;
use std::sync::{Mutex, PoisonError};

use reqwest::{Method, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::http::keystone::X_AUTH_TOKEN;
use crate::http::pager::{self, Page};
use reqwest::header::HeaderName;

use crate::http::url::UrlBuilder;
use crate::http::{Endpoint, Http, Keystone, Request, Response, Token, TokenSource};
use crate::name::DomainName;
use crate::redact::Detail;

/// Page size of every listing: the documented default of `limit`.
// Source: the OpenAPI, query parameter `limit` (integer, minimum 1, default 1000; no maximum is
// stated, so the client does not ask for more than the default).
const PAGE_LIMIT: u64 = 1000;

/// The header that names the web resource managing an rrset.
// Source: the OpenAPI, header parameter `X-Managed-By` of `PATCH` and `DELETE
// /zones/{zone_id}/rrset/{rrset_id}`.
const X_MANAGED_BY: HeaderName = HeaderName::from_static("x-managed-by");

/// The API's spelling of the TXT type.
// Source: the OpenAPI, `AllowedRecordTypes`.
pub(super) const TXT: &str = "TXT";

/// One page of a listing.
// Source: the OpenAPI, `ZonePaginationResponse` and `RRSetPaginationResponse`: `count`,
// `next_offset` and `result`, all three required.
#[derive(Deserialize)]
struct Listing<T> {
    /// Items under the filter, all pages together.
    count: u64,
    /// Offset of the next page. What it holds on the last page is not documented.
    next_offset: u64,
    /// The items.
    result: Vec<T>,
}

/// A zone as `GET /zones` returns it; other fields are ignored.
// Source: the OpenAPI, `ZoneResponse`.
#[derive(Debug, Deserialize)]
pub(super) struct Zone {
    /// The zone's identifier.
    pub(super) id: String,
    /// The zone name: absolute, with the trailing dot, in Unicode.
    pub(super) name: String,
    /// A disabled zone is not served.
    #[serde(default)]
    pub(super) disabled: Option<bool>,
    /// The project that owns the zone. `GET /zones` may list zones of other projects, which the
    /// token cannot change (`403`).
    #[serde(default)]
    pub(super) project_id: Option<String>,
}

/// An rrset as the API returns it; other fields are ignored.
// Source: the OpenAPI, `RRSetSchemaResponse`; `comment` and `managed_by` can be `null`
// (observed in the log of lego issue #3208).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct Rrset {
    /// The rrset's identifier.
    pub(super) id: String,
    /// The owner name: absolute, with the trailing dot, in Unicode.
    pub(super) name: String,
    /// The record type.
    #[serde(rename = "type")]
    pub(super) rtype: String,
    /// TTL in seconds.
    pub(super) ttl: u32,
    /// Free text, kept on every update.
    #[serde(default)]
    pub(super) comment: Option<String>,
    /// The web resource that manages the rrset, if any; kept on every update.
    // Source: the OpenAPI, `RRSetSchemaResponse.managed_by` (a UUID or null).
    #[serde(default)]
    pub(super) managed_by: Option<String>,
    /// The records. Required: an rrset without it is not a complete read.
    pub(super) records: Vec<Record>,
}

/// One record of an rrset. Written back exactly as read.
// Source: the OpenAPI, `Records`: `content` (required) and `disabled` (default false).
// `pub(crate)`: it is the `Handle` of the client's `WholeSet` implementation, a crate-wide trait.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Record {
    /// The value in the API's text form.
    pub(super) content: String,
    /// A disabled record is kept but not published.
    #[serde(default)]
    pub(super) disabled: bool,
}

/// The body of `POST /zones/{zone}/rrset`.
// Source: the OpenAPI, `RRSetCreateForm` (`name`, `type`, `ttl`, `records` required).
#[derive(Serialize)]
pub(super) struct NewRrset<'a> {
    /// The owner name, absolute, in Unicode.
    pub(super) name: &'a str,
    /// The record type.
    #[serde(rename = "type")]
    pub(super) rtype: &'a str,
    /// TTL in seconds.
    pub(super) ttl: u32,
    /// The records; 1 to 100.
    pub(super) records: &'a [Record],
}

/// The body of `PATCH /zones/{zone}/rrset/{rrset}`: no `name` and no `type`.
// Source: the OpenAPI, `RRSetUpdateForm`: `ttl` and `records` required, `comment` optional (at
// most 255 characters). `managed_by` is not part of the form; the `X-Managed-By` header
// carries it (see `update_rrset`).
#[derive(Serialize)]
pub(super) struct RrsetUpdate<'a> {
    /// TTL in seconds.
    pub(super) ttl: u32,
    /// The complete new list of records; 1 to 100.
    pub(super) records: &'a [Record],
    /// The rrset's comment, sent back so that it is kept.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) comment: Option<&'a str>,
}

/// The answer to a write.
#[derive(Debug)]
pub(super) enum Written {
    /// The provider accepted the write.
    Done,
    /// `404`: the zone or the rrset does not exist (any more).
    NotFound,
    /// Another refusal, as the error it maps to. Only a create returns it: what the API answers
    /// to a create of a name and type that exists is not documented, so the caller reads again
    /// before it concludes anything.
    Refused(Error),
}

/// The client's handle on the API: the transport, the endpoint and the token.
pub(super) struct Api {
    http: Http,
    base: Endpoint,
    keystone: Keystone,
    tokens: TokenSource,
    /// The project of the last token, as the identity service stated it.
    project: Mutex<Option<String>>,
}

impl fmt::Debug for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// The API at `base`, authenticated with tokens from `keystone`.
    pub(super) fn new(http: Http, base: Endpoint, keystone: Keystone) -> Api {
        Api {
            http,
            base,
            keystone,
            // Keystone tokens state their expiry (24 hours at Selectel, per the authorization
            // documentation); no cap beyond it is needed.
            tokens: TokenSource::new(None),
            project: Mutex::new(None),
        }
    }

    /// The ID of the project the last token is scoped to, if the identity service stated it.
    /// Known once a token was obtained.
    pub(super) fn token_project(&self) -> Option<String> {
        self.project
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The token exchange: remembers the project the token is scoped to.
    async fn fetch(&self) -> Result<Token, Error> {
        let issued = self.keystone.fetch(&self.http).await?;
        if let Some(id) = issued.project_id {
            // Every state of the slot is valid; a panic elsewhere cannot corrupt it.
            *self.project.lock().unwrap_or_else(PoisonError::into_inner) = Some(id);
        }
        Ok(issued.token)
    }

    /// Exchanges the credentials for a new token, even when a valid one is cached: proves that
    /// they are accepted now. The new token replaces the cached one.
    pub(super) async fn authenticate(&self) -> Result<(), Error> {
        self.tokens.renew(|| self.fetch()).await?;
        Ok(())
    }

    /// Sends `request` with the project-scoped token in `X-Auth-Token`.
    // Source: authorization documentation (the DNS API takes the token in `X-Auth-Token`).
    async fn send(&self, request: &Request) -> Result<Response, Error> {
        self.http
            .send_with_token(request, &self.tokens, &X_AUTH_TOKEN, || self.fetch())
            .await
    }

    /// Every zone whose name contains `filter` (all zones for `None`). The filter is a
    /// substring search, so the caller compares names exactly.
    // Source: the OpenAPI, `GET /zones` with `filter` ("Filter zones by the specified name";
    // whether it matches exactly is not stated); lego `getZone` compares
    // `zone.Name` with the FQDN after filtering.
    pub(super) async fn zones(&self, filter: Option<&str>) -> Result<Vec<Zone>, Error> {
        let url = |offset: u64| {
            let mut url = self.base.url().path("/zones");
            if let Some(filter) = filter {
                url = url.query("filter", filter);
            }
            page_query(url, offset).build()
        };
        self.list(url, None).await
    }

    /// Every rrset of type `rtype` (the API's spelling) in zone `zone_id` whose name contains
    /// `name` (the API's filter is not exact; the caller compares). A `404` means the zone does
    /// not exist (a stale identifier) and is `Error::ZoneNotFound` for `zone`.
    // Source: the OpenAPI, `GET /zones/{zone_id}/rrset` with `name` and `rrset_types` (an
    // array); 404 when the zone is not found;
    // lego sends the name without the trailing dot and compares `rrset.Name` exactly.
    pub(super) async fn rrsets(
        &self,
        zone: &DomainName,
        zone_id: &str,
        name: &str,
        rtype: &str,
    ) -> Result<Vec<Rrset>, Error> {
        let url = |offset: u64| {
            let url = self
                .base
                .url()
                .path("/zones")
                .id(zone_id)
                .path("/rrset")
                .query("name", name)
                .query("rrset_types", rtype);
            page_query(url, offset).build()
        };
        self.list(url, Some(zone)).await
    }

    /// Every rrset of zone `zone_id`, of every type, all pages. A `404` is
    /// `Error::ZoneNotFound` for `zone`, as for [`Api::rrsets`].
    // Source: the OpenAPI, `GET /zones/{zone_id}/rrset`: every filter (`name`, `rrset_types`,
    // `search`, `managed_by`) is optional; `limit` and `offset` page through the result.
    pub(super) async fn all_rrsets(
        &self,
        zone: &DomainName,
        zone_id: &str,
    ) -> Result<Vec<Rrset>, Error> {
        let url = |offset: u64| {
            let url = self.base.url().path("/zones").id(zone_id).path("/rrset");
            page_query(url, offset).build()
        };
        self.list(url, Some(zone)).await
    }

    /// Creates an rrset. Sent once: a create is not idempotent. A refusal is returned as
    /// [`Written::Refused`] for the caller to interpret after a new read.
    // Source: the OpenAPI, `POST /zones/{zone_id}/rrset`: 200 with the rrset; 400, 401, 404,
    // 422 and 500. The answer to a duplicate name and type is not documented.
    pub(super) async fn create_rrset(
        &self,
        zone_id: &str,
        rrset: &NewRrset<'_>,
    ) -> Result<Written, Error> {
        let url = self
            .base
            .url()
            .path("/zones")
            .id(zone_id)
            .path("/rrset")
            .build()?;
        let response = self
            .send(&Request::new(Method::POST, url).json(rrset)?)
            .await?;
        Ok(match response.status() {
            _ if response.is_success() => Written::Done,
            404 => Written::NotFound,
            _ => Written::Refused(self.refusal(&response)),
        })
    }

    /// Replaces the records, TTL and comment of an rrset. Sent once: the write carries no
    /// condition, and a repeat would widen the window in which another writer's change is
    /// overwritten (design section 5.3).
    ///
    /// `managed_by` is the value read. The update form has no field for it; the documented
    /// `X-Managed-By` header names it. Whether an update without the header clears it is not
    /// established, so the client sends the value it read and the rrset keeps it either way.
    // Source: the OpenAPI, `PATCH /zones/{zone_id}/rrset/{rrset_id}`: 204; 401, 403, 404, 422,
    // 500.
    pub(super) async fn update_rrset(
        &self,
        zone_id: &str,
        rrset_id: &str,
        managed_by: Option<&str>,
        update: &RrsetUpdate<'_>,
    ) -> Result<Written, Error> {
        let url = self.rrset_url(zone_id, rrset_id)?;
        let mut request = Request::new(Method::PATCH, url).json(update)?;
        if let Some(managed_by) = managed_by {
            request = request.header_text(X_MANAGED_BY, managed_by)?;
        }
        let response = self.send(&request).await?;
        self.written(&response)
    }

    /// Deletes an rrset. Sent once: the rrset can hold values of other writers that arrived
    /// after the read, and a repeat would widen that window like a repeated update (design
    /// section 5.3).
    // Source: the OpenAPI, `DELETE /zones/{zone_id}/rrset/{rrset_id}`: 204; 401, 403, 404, 422,
    // 500.
    pub(super) async fn delete_rrset(
        &self,
        zone_id: &str,
        rrset_id: &str,
    ) -> Result<Written, Error> {
        let url = self.rrset_url(zone_id, rrset_id)?;
        let response = self.send(&Request::new(Method::DELETE, url)).await?;
        self.written(&response)
    }

    fn rrset_url(&self, zone_id: &str, rrset_id: &str) -> Result<Url, Error> {
        self.base
            .url()
            .path("/zones")
            .id(zone_id)
            .path("/rrset")
            .id(rrset_id)
            .build()
    }

    fn written(&self, response: &Response) -> Result<Written, Error> {
        match response.status() {
            _ if response.is_success() => Ok(Written::Done),
            404 => Ok(Written::NotFound),
            _ => Err(self.refusal(response)),
        }
    }

    /// Reads every page of a listing. `url` builds the URL of the page at an offset. A `404`
    /// is `Error::ZoneNotFound` for `zone` when one is given, else a refusal.
    async fn list<T, U>(&self, url: U, zone: Option<&DomainName>) -> Result<Vec<T>, Error>
    where
        T: DeserializeOwned,
        U: Fn(u64) -> Result<Url, Error>,
    {
        pager::collect(0, |offset| {
            let url = url(offset);
            async move { self.page(url?, offset, zone).await }
        })
        .await
    }

    async fn page<T: DeserializeOwned>(
        &self,
        url: Url,
        offset: u64,
        zone: Option<&DomainName>,
    ) -> Result<Page<T, u64>, Error> {
        let response = self.send(&Request::get(url)).await?;
        if response.status() == 404
            && let Some(zone) = zone
        {
            return Err(Error::zone_not_found(zone.clone()));
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let listing: Listing<T> =
            response.json("the provider's listing is not in the expected form")?;
        let next = next_offset(offset, &listing)?;
        Ok(Page {
            items: listing.result,
            next,
        })
    }

    /// An answer the client does not expect. 401, 403, 429 and 5xx were mapped by the
    /// transport already. The documented refusals are `Rejected`; anything else is an answer
    /// the client cannot interpret.
    // Source: the OpenAPI, status codes 400 ("Bad request") and 422 ("Validation error") with
    // `ErrorResponse` bodies; 409 is documented for the zone calls only and is treated alike.
    fn refusal(&self, response: &Response) -> Error {
        match response.status() {
            400 | 409 | 422 => self.http.reject(response),
            status => Error::Protocol {
                detail: self.http.detail(&format!(
                    "status {status}: {}",
                    self.http.body_detail(response)
                )),
            },
        }
    }
}

/// Appends `limit` and `offset`.
fn page_query(url: UrlBuilder, offset: u64) -> UrlBuilder {
    url.query("limit", &PAGE_LIMIT.to_string())
        .query("offset", &offset.to_string())
}

/// The offset of the page after the one at `offset`, or `None` when the listing is complete.
///
/// Neither `count` nor `next_offset` is described beyond being required integers, and what
/// `next_offset` holds on the last page is not documented, so both are taken as stated and the
/// listing ends only where they agree:
///
/// - Before `count` is reached, a positive `next_offset` is followed (or the end of what was
///   received, if further). A page without one, or one that would not move on (no items and no
///   next offset beyond this one), is `Error::Protocol`, never a shorter result.
/// - Once the items received reach `count`, a page that brought items and names a next offset at
///   or beyond its end is followed all the same: the `count` of an earlier page may be stale
///   (items added while paging), and the next offset says there is more. The listing ends at a
///   `next_offset` of `0` (or one behind the end of what was received) or at an empty page.
fn next_offset<T>(offset: u64, listing: &Listing<T>) -> Result<Option<u64>, Error> {
    let received = u64::try_from(listing.result.len()).unwrap_or(u64::MAX);
    let after = offset.saturating_add(received);
    let next = listing.next_offset;
    if after >= listing.count {
        return Ok((received > 0 && next >= after).then_some(after.max(next)));
    }
    let further = after.max(next);
    if next > 0 && further > offset {
        return Ok(Some(further));
    }
    Err(Error::Protocol {
        detail: Detail::constant(
            "the provider's listing ended before the number of items it stated",
        ),
    })
}

/// The provider's error message: `error` (a string, or an object with `message` as Keystone
/// sends it) and `description`, joined by `: `.
// Source: the OpenAPI, `ErrorResponse` (`error` required, `description` and `location`
// optional); OpenStack Identity API v3 error body (`{"error": {"code", "message", "title"}}`).
pub(super) fn error_message(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        #[serde(default)]
        error: Option<serde_json::Value>,
        #[serde(default)]
        description: Option<String>,
    }
    let body: ErrorBody = serde_json::from_str(body).ok()?;
    let error = match body.error {
        Some(serde_json::Value::String(text)) => Some(text),
        Some(serde_json::Value::Object(object)) => object
            .get("message")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        _ => None,
    }
    .filter(|text| !text.is_empty());
    let description = body.description.filter(|text| !text.is_empty());
    match (error, description) {
        (Some(error), Some(description)) => Some(format!("{error}: {description}")),
        (Some(text), None) | (None, Some(text)) => Some(text),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{Listing, error_message, next_offset};

    #[test]
    fn error_messages_join_error_and_description() {
        for (body, expected) in [
            (
                r#"{"error":"Zone not found","description":"no such zone"}"#,
                Some("Zone not found: no such zone"),
            ),
            (r#"{"error":"bad request"}"#, Some("bad request")),
            (
                r#"{"error":{"code":401,"message":"nope","title":"Unauthorized"}}"#,
                Some("nope"),
            ),
            (r#"{"description":"only this"}"#, Some("only this")),
            (r#"{"error":7}"#, None),
            ("<html>oops</html>", None),
        ] {
            assert_eq!(error_message(body).as_deref(), expected, "{body}");
        }
    }

    fn listing(count: u64, next: u64, items: usize) -> Listing<u8> {
        Listing {
            count,
            next_offset: next,
            result: vec![0; items],
        }
    }

    #[test]
    fn pages_end_at_the_count() {
        assert_eq!(
            next_offset(0, &listing(2500, 1000, 1000)).unwrap(),
            Some(1000)
        );
        assert_eq!(next_offset(2000, &listing(2500, 0, 500)).unwrap(), None);
        // The count is reached and the last page says so (`0`, or an offset behind its end).
        assert_eq!(next_offset(0, &listing(1000, 0, 1000)).unwrap(), None);
        assert_eq!(next_offset(1000, &listing(1500, 500, 500)).unwrap(), None);
        assert_eq!(next_offset(0, &listing(0, 0, 0)).unwrap(), None);
        // The count is reached, but the page names a next offset: the count may be stale, the
        // next page is read, and an empty page ends the listing.
        assert_eq!(
            next_offset(0, &listing(1000, 1000, 1000)).unwrap(),
            Some(1000)
        );
        assert_eq!(
            next_offset(1000, &listing(1000, 2000, 1000)).unwrap(),
            Some(2000)
        );
        assert_eq!(next_offset(1000, &listing(1000, 2000, 0)).unwrap(), None);
        // A next offset beyond the items received is followed.
        assert_eq!(
            next_offset(0, &listing(3000, 1500, 1000)).unwrap(),
            Some(1500)
        );
        // An empty page before the count, with a next offset: the next offset is followed.
        assert_eq!(
            next_offset(1000, &listing(2500, 2000, 0)).unwrap(),
            Some(2000)
        );
    }

    #[test]
    fn a_listing_short_of_its_count_is_an_error() {
        for (offset, page) in [
            (0, listing(3, 0, 1)),
            (1000, listing(2500, 0, 0)),
            (2000, listing(2500, 0, 499)),
            // An empty page whose next offset does not move on.
            (1000, listing(2500, 1000, 0)),
            (1000, listing(2500, 500, 0)),
        ] {
            let e = next_offset(offset, &page).unwrap_err();
            assert_eq!(e.kind(), crate::error::ErrorKind::Protocol);
        }
    }
}
