//! The VK Cloud public DNS API (v2) as this client uses it: authentication, one function per
//! endpoint, the wire types and the classification of answers. Nothing here knows the value
//! layer or the zone cache; `client.rs` and `txt.rs` build on these calls.
//!
//! Sources (hard rule 3):
//!
//! - The provider's API page,
//!   <https://cloud.vk.ru/docs/ru/tools-for-using-services/api/api-spec/network-api/api-dns>, and
//!   the OpenAPI description it embeds,
//!   <https://cloud.vk.ru/docs/_docs/ru/tools-for-using-services/api/api-spec/network-api/api-dns/assets/public-dns-api.json>
//!   ("the OpenAPI" below, version 2.0.0, read on 2026-11-14): paths, request and answer
//!   schemas, status codes. It documents no error body and no paging.
//! - The provider's token documentation,
//!   <https://cloud.vk.ru/docs/ru/tools-for-using-services/api/rest-api/case-keystone-token>: the
//!   Keystone password exchange scoped to a project ID; the token arrives in `X-Subject-Token`
//!   and is sent to the APIs in `X-Auth-Token`.
//! - lego `providers/dns/vkcloud` at commit `1da5445c` (`vkcloud.go`, `internal/client.go`,
//!   `internal/types.go`; line numbers below refer to it).
//!
//! Endpoints used, all below the `dns_url`:
//!
//! | Call          | Request                        | Success                 |
//! | ------------- | ------------------------------ | ----------------------- |
//! | list zones    | `GET /`                        | 200, array of zones     |
//! | list TXT      | `GET /{zone}/txt/`             | 200, array of records   |
//! | create TXT    | `POST /{zone}/txt/`            | 201, the new record     |
//! | delete TXT    | `DELETE /{zone}/txt/{record}`  | 204                     |
//!
//! Both listings return everything in one answer (no paging is documented), so they are
//! bounded by the transport's 4 MiB body limit alone; a larger answer fails, it is never
//! returned in part. The OpenAPI documents `404` ("records not found") for both listings next
//! to `200`; it does not say whether an empty listing is `200 []` or `404`, and for the TXT
//! listing a `404` can also mean that the zone does not exist. [`Api::txt_records`] therefore
//! reports a `404` as such and leaves its meaning to the caller.

use std::fmt;

use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::http::keystone::X_AUTH_TOKEN;
use crate::http::{Endpoint, Http, Keystone, Request, Response, TokenSource};

/// A zone as `GET /` returns it; other fields are ignored.
// Source: the OpenAPI, `Dns_Filter` (`zone`, `tenant`, `status` and the identifier, named
// `DnsUuid`); lego internal/types.go:3-15 (`DNSZone`) names the identifier `uuid`. Both
// spellings are read; `zone` is the name without the trailing dot ("Can contain only digits,
// Latin letters, hyphen and dot").
#[derive(Debug, Deserialize)]
pub(super) struct Zone {
    /// The identifier, as lego reads it.
    #[serde(default)]
    uuid: Option<String>,
    /// The identifier, as the OpenAPI names it.
    #[serde(default, rename = "DnsUuid")]
    dns_uuid: Option<String>,
    /// The zone name.
    pub(super) zone: String,
}

impl Zone {
    /// The zone's identifier: `uuid`, else `DnsUuid`.
    pub(super) fn id(&self) -> Option<&str> {
        self.uuid
            .as_deref()
            .filter(|id| !id.is_empty())
            .or(self.dns_uuid.as_deref().filter(|id| !id.is_empty()))
    }
}

/// A TXT record as `GET /{zone}/txt/` returns it; other fields are ignored. The identifier,
/// the name and the content are required here: a record without them could be neither
/// matched nor deleted, and a listing with one is not a complete read.
// Source: the OpenAPI, `TxtRecord_Filter` (`uuid`, `name`, `dns`, `content`, `ttl`); lego
// internal/types.go:17-23 (`DNSTXTRecord`) and vkcloud.go:215-219, which matches records by
// `Name` and `Content`.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct TxtRecord {
    /// The record's identifier.
    pub(super) uuid: String,
    /// The name relative to the zone; `@` is the apex (the OpenAPI's example of `name`).
    pub(super) name: String,
    /// The value, as written.
    pub(super) content: String,
    /// TTL in seconds.
    #[serde(default)]
    pub(super) ttl: Option<u32>,
}

/// The body of `POST /{zone}/txt/`.
// Source: the OpenAPI, `TxtRecord_Create`: `name`, `content` (at most 255 characters) and `ttl`
// (60 to 2147483648), all three required; lego vkcloud.go:222-226 sends the same three fields,
// the name relative to the zone and the value unquoted.
#[derive(Serialize)]
pub(super) struct NewTxt<'a> {
    /// The name relative to the zone, `@` for the apex.
    pub(super) name: &'a str,
    /// The value, unquoted.
    pub(super) content: &'a str,
    /// TTL in seconds.
    pub(super) ttl: u32,
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

/// The client's handle on the API: the transport, the endpoint and the token.
pub(super) struct Api {
    http: Http,
    base: Endpoint,
    keystone: Keystone,
    tokens: TokenSource,
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
            // Keystone states the expiry of each token in `token.expires_at`; no cap beyond it
            // is needed.
            tokens: TokenSource::new(None),
        }
    }

    /// Exchanges the credentials for a new token, even when a valid one is cached: proves that
    /// they are accepted now. The new token replaces the cached one.
    pub(super) async fn authenticate(&self) -> Result<(), Error> {
        let fetch = || self.keystone.fetch_token(&self.http);
        let lease = self.tokens.get(fetch).await?;
        if !lease.fresh {
            // The cached token proves nothing about the credentials as they are now.
            self.tokens.invalidate(lease.generation).await;
            self.tokens.get(fetch).await?;
        }
        Ok(())
    }

    /// Sends `request` with the project-scoped token in `X-Auth-Token`.
    // Source: the API page ("Получите токен доступа X-Auth-Token. Используйте токен в заголовке
    // при отправке запросов") and its curl example.
    async fn send(&self, request: &Request) -> Result<Response, Error> {
        self.http
            .send_with_token(request, &self.tokens, &X_AUTH_TOKEN, || {
                self.keystone.fetch_token(&self.http)
            })
            .await
    }

    /// Every zone of the project. A `404` is an empty listing.
    // Source: the OpenAPI, `GET /v2/dns/`: 200 with an array of `Dns_Filter`, 404 "records not
    // found"; lego internal/client.go:45-58 (`ListZones`, `JoinPath("/")`, so the path ends in
    // a slash).
    pub(super) async fn zones(&self) -> Result<Vec<Zone>, Error> {
        let url = self.base.url().path("/").build()?;
        let response = self.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(Vec::new());
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        response.json("the provider's zone listing is not in the expected form")
    }

    /// Every TXT record of zone `zone_id`, or `None` for a `404`, which can mean an empty
    /// listing or a zone that does not exist.
    // Source: the OpenAPI, `GET /v2/dns/{DnsUuid}/txt/`: 200 with an array of
    // `TxtRecord_Filter`, 404 "records not found"; lego internal/client.go:60-73
    // (`ListTXTRecords`, `JoinPath(zoneUUID, "txt", "/")`).
    pub(super) async fn txt_records(&self, zone_id: &str) -> Result<Option<Vec<TxtRecord>>, Error> {
        let url = self.base.url().id(zone_id).path("/txt/").build()?;
        let response = self.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        response
            .json("the provider's TXT listing is not in the expected form")
            .map(Some)
    }

    /// Creates a TXT record. Sent once: a create is not idempotent.
    // Source: the OpenAPI, `POST /v2/dns/{DnsUuid}/txt/`: 201 with `TxtRecord_Get`; 400
    // (validation), 401, 409 ("conflict of parameters, duplication or unavailability of the
    // operation"). A 404 is not documented for the create; it is read as a zone that no longer
    // exists, like the 404 of every other call on the zone. lego internal/client.go:75-84.
    pub(super) async fn create_txt(
        &self,
        zone_id: &str,
        record: &NewTxt<'_>,
    ) -> Result<Written, Error> {
        let url = self.base.url().id(zone_id).path("/txt/").build()?;
        let response = self
            .send(&Request::new(Method::POST, url).json(record)?)
            .await?;
        Ok(self.written(&response))
    }

    /// Deletes one TXT record by its identifier. Repeating it is safe, so the transport may.
    // Source: the OpenAPI, `DELETE /v2/dns/{DnsUuid}/txt/{TxtRecordUuid}`: 204; 401, 404
    // ("record not found"). lego internal/client.go:86-90.
    pub(super) async fn delete_txt(
        &self,
        zone_id: &str,
        record_id: &str,
    ) -> Result<Written, Error> {
        let url = self
            .base
            .url()
            .id(zone_id)
            .path("/txt")
            .id(record_id)
            .build()?;
        let response = self
            .send(&Request::new(Method::DELETE, url).idempotent())
            .await?;
        Ok(self.written(&response))
    }

    fn written(&self, response: &Response) -> Written {
        match response.status() {
            _ if response.is_success() => Written::Done,
            404 => Written::NotFound,
            _ => Written::Refused(self.refusal(response)),
        }
    }

    /// An answer the client does not expect. 401, 403, 429, 3xx and 5xx were mapped by the
    /// transport already. The documented refusals are `Rejected`; anything else is an answer
    /// the client cannot interpret.
    // Source: the OpenAPI: 400 ("validation error of the request parameters") on the listings
    // and the create, 409 on the create. No error body is documented, so the message is taken
    // by the transport's default extractor.
    fn refusal(&self, response: &Response) -> Error {
        match response.status() {
            400 | 409 => self.http.reject(response),
            status => Error::Protocol {
                detail: self.http.detail(&format!(
                    "status {status}: {}",
                    self.http.body_detail(response)
                )),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TxtRecord, Zone};

    #[test]
    fn the_zone_identifier_is_read_under_either_name() {
        let lego: Zone =
            serde_json::from_str(r#"{"uuid":"a-1","zone":"example.org","tenant":"t"}"#).unwrap();
        assert_eq!(lego.id(), Some("a-1"));
        let documented: Zone =
            serde_json::from_str(r#"{"DnsUuid":"b-2","zone":"example.org"}"#).unwrap();
        assert_eq!(documented.id(), Some("b-2"));
        let both: Zone =
            serde_json::from_str(r#"{"uuid":"a-1","DnsUuid":"b-2","zone":"example.org"}"#).unwrap();
        assert_eq!(both.id(), Some("a-1"));
        let empty: Zone = serde_json::from_str(r#"{"uuid":"","zone":"example.org"}"#).unwrap();
        assert_eq!(empty.id(), None);
        let none: Zone = serde_json::from_str(r#"{"zone":"example.org"}"#).unwrap();
        assert_eq!(none.id(), None);
    }

    #[test]
    fn a_record_without_identifier_name_or_content_does_not_parse() {
        for body in [
            r#"{"name":"x","content":"v","ttl":60}"#,
            r#"{"uuid":"u","content":"v","ttl":60}"#,
            r#"{"uuid":"u","name":"x","ttl":60}"#,
        ] {
            assert!(serde_json::from_str::<TxtRecord>(body).is_err(), "{body}");
        }
        let record: TxtRecord =
            serde_json::from_str(r#"{"uuid":"u","name":"x","dns":"/v2/dns/z","content":"v"}"#)
                .unwrap();
        assert_eq!(record.ttl, None);
    }
}
