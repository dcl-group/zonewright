//! The Cloudflare API v4 as this client uses it: one function per endpoint, the wire types,
//! paging and the classification of answers. Nothing here knows the value layer or the zone
//! cache; `client.rs` and `txt.rs` build on these calls.
//!
//! Sources (hard rule 3):
//!
//! - [API]: <https://developers.cloudflare.com/api/> and the OpenAPI document Cloudflare
//!   publishes, <https://github.com/cloudflare/api-schemas> (`openapi.json`, read on
//!   2026-11-14; "the schema" below): paths, parameters, request and answer schemas.
//! - lego `providers/dns/cloudflare/internal/client.go` and `cloudflare.go`.
//!
//! Endpoints used, all below the `base_url`:
//!
//! | Call          | Request                                                    | Success |
//! | ------------- | ---------------------------------------------------------- | ------- |
//! | list zones    | `GET /zones?name&per_page&page`                            | 200     |
//! | list records  | `GET /zones/{zone}/dns_records?type&name&per_page&page`    | 200     |
//! | create record | `POST /zones/{zone}/dns_records`                           | 200     |
//! | update record | `PATCH /zones/{zone}/dns_records/{record}`                 | 200     |
//! | delete record | `DELETE /zones/{zone}/dns_records/{record}`                | 200     |
//!
//! The schema documents the answers of a failed call as the failure envelope under the
//! status class `4XX` and names no status for any particular refusal. Every answer carries the
//! envelope `{success, errors[{code, message}], messages, result}`; listings add `result_info`.

use std::fmt;

use reqwest::{Method, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::http::pager::{self, Page};
use crate::http::{Endpoint, Http, Request, Response};
use crate::name::DomainName;
use crate::redact::Detail;

/// Page size of the zone listing: the documented maximum.
// Source: the schema, `GET /zones` query parameter `per_page` (minimum 5, maximum 50, default
// 20); lego uses 50 (client.go, `ZonesByName`).
const ZONE_PAGE: u32 = 50;

/// Page size of the record listing: the documented default of `per_page`.
// Source: the schema, `GET /zones/{zone_id}/dns_records` query parameter `per_page` (minimum 1,
// maximum 5000000, default 100).
const RECORD_PAGE: u32 = 100;

/// Record type name as the API spells it.
pub(super) const TXT: &str = "TXT";

/// The envelope of every answer.
// Source: the schema, `api-response-common` (`success`, `errors`, `messages` required) and
// `api-response-collection` (`result_info`).
#[derive(Deserialize)]
struct Envelope<T> {
    /// Whether the call succeeded.
    #[serde(default)]
    success: Option<bool>,
    /// The failures, if any.
    #[serde(default)]
    errors: Vec<ApiError>,
    /// The payload. A listing without it is not a complete read.
    #[serde(default)]
    result: Option<T>,
    /// Paging information of a listing.
    #[serde(default)]
    result_info: Option<ResultInfo>,
}

/// One entry of `errors`.
#[derive(Deserialize)]
struct ApiError {
    /// The provider's error code.
    #[serde(default)]
    code: Option<i64>,
    /// The provider's message.
    #[serde(default)]
    message: Option<String>,
}

/// Paging information.
// Source: the schema, `api-response-collection.result_info`: `page`, `per_page`, `count`,
// `total_count` ("Total results available without any search parameters") and `total_pages`
// ("The number of total pages in the entire result set"), all optional numbers.
#[derive(Deserialize)]
struct ResultInfo {
    /// Pages in the whole result set.
    #[serde(default)]
    total_pages: Option<u64>,
}

/// A zone as `GET /zones` returns it; other fields are ignored.
// Source: the schema, `zones_zone`: `id` (at most 32 characters), `name`, `status` (one of
// `initializing`, `pending`, `active`, `moved`).
#[derive(Debug, Deserialize)]
pub(super) struct Zone {
    /// The zone's identifier.
    pub(super) id: String,
    /// The zone name, in Punycode.
    pub(super) name: String,
    /// The zone status; records are served only for `active`.
    #[serde(default)]
    pub(super) status: Option<String>,
}

impl Zone {
    /// True unless the provider states a status other than `active`.
    pub(super) fn is_active(&self) -> bool {
        self.status.as_deref().is_none_or(|s| s == "active")
    }
}

/// A DNS record as the listing returns it; other fields are ignored.
// Source: the schema, `dns-records_dns-record-response`: every record has `id`, `type`, `name`
// ("Complete DNS record name, including the zone name, in Punycode"), `content`, `data`, `ttl`,
// `proxied` and `settings` (all required in the answer); `priority` is shared by MX
// (`dns-records_MXRecord`), `private_routing` by A and AAAA (`dns-records_ARecord`,
// `dns-records_AAAARecord`). Everything but `id`, `type` and `name` is optional here, so that one
// odd record cannot fail a whole listing: what is missing makes that record's value
// non-canonical (`records.rs`).
#[derive(Clone, Debug, Deserialize)]
pub(super) struct Record {
    /// The record's identifier.
    pub(super) id: String,
    /// The record type.
    #[serde(rename = "type")]
    pub(super) rtype: String,
    /// The owner name, in Punycode, without the trailing dot.
    pub(super) name: String,
    /// The value in the API's text form; for the types with `data` a formatted, read-only text.
    #[serde(default)]
    pub(super) content: Option<String>,
    /// The MX preference.
    #[serde(default)]
    pub(super) priority: Option<serde_json::Value>,
    /// The components of a structured type (CAA, SRV, TLSA, ...).
    #[serde(default)]
    pub(super) data: Option<serde_json::Value>,
    /// TTL in seconds; `1` means automatic.
    #[serde(default)]
    pub(super) ttl: Option<u32>,
    /// Whether the record is proxied by the provider.
    #[serde(default)]
    pub(super) proxied: Option<bool>,
    /// Private network routing to the origin (A and AAAA).
    #[serde(default)]
    pub(super) private_routing: Option<bool>,
    /// The record's settings object.
    #[serde(default)]
    pub(super) settings: Option<serde_json::Value>,
}

/// The body of `POST /zones/{zone}/dns_records`. Absent fields are not sent.
// Source: the schema, `dns-records_dns-record-post` (one of the per-type record schemas, each
// `dns-records_dns-record-shared-fields` plus `type`, and `content`, `data` or `priority` by
// type).
#[derive(Serialize)]
pub(super) struct NewRecord<'a> {
    /// The record type.
    #[serde(rename = "type")]
    pub(super) rtype: &'a str,
    /// The owner name, in Punycode.
    pub(super) name: &'a str,
    /// The value, for the types that take `content`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) content: Option<&'a str>,
    /// The MX preference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) priority: Option<u16>,
    /// The components, for the types that take `data`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) data: Option<&'a serde_json::Value>,
    /// TTL in seconds, or `1` for automatic.
    pub(super) ttl: u32,
    /// Proxied, sent only when taken over from the existing records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) proxied: Option<bool>,
    /// Private routing, sent only when taken over from the existing records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) private_routing: Option<bool>,
    /// Settings, sent only when taken over from the existing records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) settings: Option<&'a serde_json::Value>,
}

/// The body of `PATCH /zones/{zone}/dns_records/{record}`: the type and only the fields that
/// change. Absent fields are not sent and keep their value.
// Source: the schema, `PATCH /zones/{zone_id}/dns_records/{dns_record_id}` ("Update an existing
// DNS record", as opposed to `PUT`, "Overwrite an existing DNS record"); its body
// `dns-records_dns-record-patch` has the same per-type schemas as a create, none of whose
// fields is required.
#[derive(Serialize)]
pub(super) struct RecordPatch<'a> {
    /// The record type, unchanged.
    #[serde(rename = "type")]
    pub(super) rtype: &'a str,
    /// New content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) content: Option<&'a str>,
    /// New MX preference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) priority: Option<u16>,
    /// New components.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) data: Option<&'a serde_json::Value>,
    /// New TTL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ttl: Option<u32>,
}

/// The answer to a write.
#[derive(Debug)]
pub(super) enum Written {
    /// The provider accepted the write.
    Done,
    /// `404`: the zone or the record does not exist (any more).
    NotFound,
    /// Another refusal, as the error it maps to.
    Refused(Error),
}

/// The client's handle on the API: the transport and the endpoint.
pub(super) struct Api {
    http: Http,
    base: Endpoint,
}

impl fmt::Debug for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// The API at `base`.
    pub(super) fn new(http: Http, base: Endpoint) -> Api {
        Api { http, base }
    }

    /// Exercises the credentials: one listing request of the smallest page the API allows. It
    /// works for user and account tokens alike and names no zone.
    // Source: the schema, `GET /zones` (`per_page` minimum 5); lego lists zones to find one.
    // The token-verification endpoints are not used: the schema has one for user tokens
    // (`GET /user/tokens/verify`) and one for account tokens
    // (`GET /accounts/{account_id}/tokens/verify`), and the second needs an account identifier
    // the settings do not carry.
    pub(super) async fn probe(&self) -> Result<(), Error> {
        let url = self
            .base
            .url()
            .path("/zones")
            .query("per_page", "5")
            .query("page", "1")
            .build()?;
        let response = self.http.send(&Request::get(url)).await?;
        self.listing::<Zone>(&response)?;
        Ok(())
    }

    /// Every zone whose name equals `name` (all zones for `None`), all pages. The caller
    /// compares names exactly.
    // Source: the schema, `GET /zones` with `name` (operator `equal` by default), `per_page`
    // and `page`.
    pub(super) async fn zones(&self, name: Option<&str>) -> Result<Vec<Zone>, Error> {
        let url = |page: u32| {
            let mut url = self.base.url().path("/zones");
            if let Some(name) = name {
                url = url.query("name", name);
            }
            url.query("per_page", &ZONE_PAGE.to_string())
                .query("page", &page.to_string())
                .build()
        };
        self.list(url, None).await
    }

    /// Every record in zone `zone_id`, all pages, of type `rtype` and at `name` where they are
    /// given. The caller compares names and types exactly. A `404` means the zone does not
    /// exist (a stale identifier) and is `Error::ZoneNotFound` for `zone`.
    // Source: the schema, `GET /zones/{zone_id}/dns_records` with `type`, `name`, `per_page`,
    // `page`. The description of the query parameter `name` ("Exact value of the DNS record
    // name. This is a convenience alias for `name.exact`") is in the published OpenAPI file,
    // <https://github.com/cloudflare/api-schemas/blob/main/openapi.json> (read 2026-11-14),
    // not on the rendered API reference page.
    // Assumption (not documented): a missing zone is answered `404`; the schema names the
    // failure class `4XX` only. If the API answers otherwise, the read phase in `txt.rs` and
    // `records.rs` still looks the zone up again after any refusal under a cached identifier;
    // nothing is written.
    pub(super) async fn records(
        &self,
        zone: &DomainName,
        zone_id: &str,
        name: Option<&str>,
        rtype: Option<&str>,
    ) -> Result<Vec<Record>, Error> {
        let url = |page: u32| {
            let mut url = self
                .base
                .url()
                .path("/zones")
                .id(zone_id)
                .path("/dns_records");
            if let Some(rtype) = rtype {
                url = url.query("type", rtype);
            }
            if let Some(name) = name {
                url = url.query("name", name);
            }
            url.query("per_page", &RECORD_PAGE.to_string())
                .query("page", &page.to_string())
                .build()
        };
        self.list(url, Some(zone)).await
    }

    /// Creates a record. Sent once: a create is not idempotent.
    // Source: the schema, `POST /zones/{zone_id}/dns_records`; the success answer is `200`.
    pub(super) async fn create_record(
        &self,
        zone_id: &str,
        record: &NewRecord<'_>,
    ) -> Result<Written, Error> {
        let url = self
            .base
            .url()
            .path("/zones")
            .id(zone_id)
            .path("/dns_records")
            .build()?;
        let response = self
            .http
            .send(&Request::new(Method::POST, url).json(record)?)
            .await?;
        Ok(self.written(&response))
    }

    /// Changes the fields of one record that `patch` names. Sent once, like every write that is
    /// not a delete by identifier (design section 5.3).
    // Source: the schema, `PATCH /zones/{zone_id}/dns_records/{dns_record_id}`; the success
    // answer is `200`.
    pub(super) async fn update_record(
        &self,
        zone_id: &str,
        record_id: &str,
        patch: &RecordPatch<'_>,
    ) -> Result<Written, Error> {
        let url = self
            .base
            .url()
            .path("/zones")
            .id(zone_id)
            .path("/dns_records")
            .id(record_id)
            .build()?;
        let response = self
            .http
            .send(&Request::new(Method::PATCH, url).json(patch)?)
            .await?;
        Ok(self.written(&response))
    }

    /// Deletes one record by its identifier. Repeating it is safe, so the transport may.
    // Source: the schema, `DELETE /zones/{zone_id}/dns_records/{dns_record_id}`; the success
    // answer is `200` with `result.id`.
    pub(super) async fn delete_record(
        &self,
        zone_id: &str,
        record_id: &str,
    ) -> Result<Written, Error> {
        let url = self
            .base
            .url()
            .path("/zones")
            .id(zone_id)
            .path("/dns_records")
            .id(record_id)
            .build()?;
        let response = self
            .http
            .send(&Request::new(Method::DELETE, url).idempotent())
            .await?;
        Ok(self.written(&response))
    }

    /// The outcome of a write. An answer in the 2xx class whose envelope says `success: false`
    /// is a refusal.
    fn written(&self, response: &Response) -> Written {
        if response.is_success() {
            let failed = serde_json::from_slice::<Envelope<serde_json::Value>>(response.body())
                .is_ok_and(|e| e.success == Some(false));
            return if failed {
                Written::Refused(self.http.reject(response))
            } else {
                Written::Done
            };
        }
        if response.status() == 404 {
            return Written::NotFound;
        }
        Written::Refused(self.refusal(response))
    }

    /// Reads every page of a listing. `url` builds the URL of a page. A `404` is
    /// `Error::ZoneNotFound` for `zone` when one is given, else a refusal.
    async fn list<T, U>(&self, url: U, zone: Option<&DomainName>) -> Result<Vec<T>, Error>
    where
        T: DeserializeOwned,
        U: Fn(u32) -> Result<Url, Error>,
    {
        pager::collect(1u32, |page| {
            let url = url(page);
            async move { self.page(url?, page, zone).await }
        })
        .await
    }

    async fn page<T: DeserializeOwned>(
        &self,
        url: Url,
        page: u32,
        zone: Option<&DomainName>,
    ) -> Result<Page<T, u32>, Error> {
        let response = self.http.send(&Request::get(url)).await?;
        if response.status() == 404
            && let Some(zone) = zone
        {
            return Err(Error::zone_not_found(zone.clone()));
        }
        let (items, total_pages) = self.listing::<T>(&response)?;
        // A page that brings nothing before the last is a listing that ended early, and a page
        // with items beyond a stated total of zero pages contradicts itself: neither is
        // returned as a shorter list.
        let ended_early = items.is_empty() && u64::from(page) < total_pages;
        let contradiction = !items.is_empty() && total_pages == 0;
        if ended_early || contradiction {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider's listing ended before the number of pages it stated",
                ),
            });
        }
        let next = u32::try_from(total_pages).map_or(Some(page.saturating_add(1)), |total| {
            pager::next_page_of_total(page, total)
        });
        Ok(Page { items, next })
    }

    /// The items and the page count of one listing answer: the envelope must say `success`,
    /// carry the `result` array and `result_info.total_pages`.
    fn listing<T: DeserializeOwned>(&self, response: &Response) -> Result<(Vec<T>, u64), Error> {
        if !response.is_success() {
            return Err(self.refusal(response));
        }
        let envelope: Envelope<Vec<T>> =
            response.json("the provider's listing is not in the expected form")?;
        match envelope.success {
            Some(true) => {}
            Some(false) => return Err(self.http.reject(response)),
            // `success` is required in every answer; without it this is not the envelope.
            None => {
                return Err(Error::Protocol {
                    detail: Detail::constant("the provider's listing lacks the success flag"),
                });
            }
        }
        let (Some(items), Some(total_pages)) = (
            envelope.result,
            envelope.result_info.and_then(|info| info.total_pages),
        ) else {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider's listing lacks the result list or the page count",
                ),
            });
        };
        Ok((items, total_pages))
    }

    /// An answer the client does not expect. 401, 403, 429 and 5xx were mapped by the
    /// transport already. A refusal of the 4xx class is documented only as the failure
    /// envelope, so it is `Rejected` with the provider's message; anything else is an answer
    /// the client cannot interpret.
    // Source: the schema, the failure response of every call (`4XX`, `api-response-common-failure`).
    fn refusal(&self, response: &Response) -> Error {
        match response.status() {
            400..=499 => self.http.reject(response),
            status => Error::Protocol {
                detail: self.http.detail(&format!(
                    "status {status}: {}",
                    self.http.body_detail(response)
                )),
            },
        }
    }
}

/// The provider's error message: `code: message` of every entry of `errors`, joined by `; `.
// Source: the schema, `dns-records_messages` (`code`, `message`, both required).
pub(super) fn error_message(body: &str) -> Option<String> {
    let envelope: Envelope<serde_json::Value> = serde_json::from_str(body).ok()?;
    let parts: Vec<String> = envelope
        .errors
        .iter()
        .filter_map(|e| match (e.code, e.message.as_deref()) {
            (Some(code), Some(message)) => Some(format!("{code}: {message}")),
            (None, Some(message)) => Some(message.to_owned()),
            (Some(code), None) => Some(code.to_string()),
            (None, None) => None,
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// The provider's error code: the `code` of the first entry of `errors` that has one, in
/// decimal.
// Source: the schema, `dns-records_messages` (`code`, an integer, required in every entry).
pub(super) fn error_code(body: &str) -> Option<String> {
    let envelope: Envelope<serde_json::Value> = serde_json::from_str(body).ok()?;
    envelope
        .errors
        .iter()
        .find_map(|e| e.code)
        .map(|code| code.to_string())
}

#[cfg(test)]
mod tests {
    use super::{error_code, error_message};

    #[test]
    fn error_codes_are_the_first_code() {
        assert_eq!(
            error_code(r#"{"success":false,"errors":[{"message":"x"},{"code":81057,"message":"y"},{"code":1}]}"#)
                .as_deref(),
            Some("81057")
        );
        assert_eq!(error_code(r#"{"success":false,"errors":[]}"#), None);
        assert_eq!(error_code("<html>oops</html>"), None);
    }

    #[test]
    fn error_messages_join_codes_and_texts() {
        for (body, expected) in [
            (
                r#"{"success":false,"errors":[{"code":1001,"message":"first"},{"code":1002,"message":"second"}],"result":null}"#,
                Some("1001: first; 1002: second"),
            ),
            (r#"{"errors":[{"message":"only text"}]}"#, Some("only text")),
            (r#"{"success":false,"errors":[]}"#, None),
            ("<html>oops</html>", None),
        ] {
            assert_eq!(error_message(body).as_deref(), expected, "{body}");
        }
    }
}
