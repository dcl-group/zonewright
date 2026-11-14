//! The DigitalOcean API v2 as this client uses it: one function per endpoint, the wire types,
//! paging and the classification of answers. Nothing here knows the value layer; `client.rs`
//! and `txt.rs` build on these calls.
//!
//! Sources (hard rule 3):
//!
//! - [Domains]: <https://docs.digitalocean.com/reference/api/reference/domains/> ("Domains"
//!   below): list and get, `per_page` 1 to 200 (default 20), `page`, the `meta` object, `404`.
//! - [Domain Records]: <https://docs.digitalocean.com/reference/api/reference/domain-records/>:
//!   list (`name` "a fully qualified record name", `type`, `per_page`, `page`; `200`, `401`,
//!   `404`, `429`, `500`), create (`type` required, `name` and `data` required for TXT, `ttl`
//!   optional; `201`, `401`, `404`, `429`, `500`), delete (`204`; `401`, `404`, `429`, `500`),
//!   the error body `{id, message, request_id}` and the rate-limit headers. The same operations
//!   in the published OpenAPI description, <https://github.com/digitalocean/openapi>
//!   (`specification/resources/domains/`: `domains_list_records.yml`,
//!   `domains_create_record.yml`, `domains_delete_record.yml`, `models/domain_record_types.yml`,
//!   `examples.yml`).
//! - [Account]: <https://docs.digitalocean.com/reference/api/reference/account/>:
//!   `GET /v2/account`, scope `account:read`, answer keyed on `account`.
//! - lego `providers/dns/digitalocean/internal/client.go` and `types.go`: `POST
//!   {base}/v2/domains/{zone}/records` (line 40) and `DELETE {base}/v2/domains/{zone}/records/{id}`
//!   (line 58) with the zone name without its trailing dot; the record fields `id`, `type`,
//!   `name`, `data`, `ttl` (types.go lines 10 to 16); the error fields `id` and `message`
//!   (types.go lines 18 to 21).
//!
//! Endpoints used, all below the `base_url`:
//!
//! | Call          | Request                                          | Success   |
//! | ------------- | ------------------------------------------------ | --------- |
//! | account       | `GET /account`                                   | 200       |
//! | get domain    | `GET /domains/{name}`                            | 200       |
//! | list domains  | `GET /domains?per_page&page`                     | 200, page |
//! | list records  | `GET /domains/{name}/records?type&name&per_page&page` | 200, page |
//! | create record | `POST /domains/{name}/records`                   | 201       |
//! | delete record | `DELETE /domains/{name}/records/{id}`            | 204       |
//!
//! [Domains]: https://docs.digitalocean.com/reference/api/reference/domains/
//! [Domain Records]: https://docs.digitalocean.com/reference/api/reference/domain-records/
//! [Account]: https://docs.digitalocean.com/reference/api/reference/account/

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use reqwest::{Method, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Error;
use crate::http::pager::{self, Page};
use crate::http::url::UrlBuilder;
use crate::http::{Endpoint, Http, Request, Response};
use crate::name::DomainName;
use crate::redact::Detail;

/// Page size of every listing: the documented maximum of `per_page`.
// Source: Domains and Domain Records, query parameter `per_page` (integer, 1 to 200, default
// 20).
const PAGE_SIZE: u32 = 200;

/// The record type name as the API spells it.
pub(super) const TXT: &str = "TXT";

/// A record as `GET /domains/{name}/records` returns it; other fields are ignored.
// Source: Domain Records, record fields (`id` read-only, `name`, `data`, `ttl`, `type`; fields
// that do not apply to a type are `null`); lego types.go lines 10 to 16.
#[derive(Debug, Deserialize)]
pub(super) struct Record {
    /// The record's identifier.
    pub(super) id: u64,
    /// The record type.
    #[serde(rename = "type")]
    pub(super) rtype: String,
    /// The owner name as the API states it. Its form is not documented (see
    /// [`normalize_name`]).
    #[serde(default)]
    pub(super) name: Option<String>,
    /// The value.
    #[serde(default)]
    pub(super) data: Option<String>,
    /// TTL in seconds.
    #[serde(default)]
    pub(super) ttl: Option<u32>,
}

/// A domain as `GET /domains` and `GET /domains/{name}` return it; other fields are ignored.
// Source: Domains, `name` ("the domain, such as example.com").
#[derive(Debug, Deserialize)]
pub(super) struct Domain {
    /// The domain name.
    pub(super) name: String,
}

/// The body of `POST /domains/{name}/records`.
// Source: Domain Records, "Create a Domain Record": `type` required, `name`, `data` and `ttl`
// (optional integer, seconds); lego types.go lines 10 to 16 sends exactly these four fields.
#[derive(Serialize)]
pub(super) struct NewRecord<'a> {
    /// The record type.
    #[serde(rename = "type")]
    pub(super) rtype: &'a str,
    /// The owner name, absolute with its trailing dot. lego sends exactly this form:
    /// providers/dns/digitalocean/digitalocean.go line 129 passes the challenge's
    /// `EffectiveFQDN`, which ends with a dot. The API stores it relative to the domain:
    /// DigitalOcean's own Terraform provider (terraform-provider-digitalocean,
    /// `digitalocean/domain/resource_record.go`, the `name` field's `DiffSuppressFunc`) treats
    /// a configured `<label>.<domain>.` and a stored `<label>`, and `<domain>.` and `@`, as the
    /// same name. The reference's own create example uses the relative form (`www`).
    pub(super) name: &'a str,
    /// The value.
    pub(super) data: &'a str,
    /// TTL in seconds; left out when the caller has none to give.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ttl: Option<u32>,
}

/// The answer to a write.
#[derive(Debug)]
pub(super) enum Written {
    /// The provider accepted the write.
    Done,
    /// `404`: the domain, or for a delete the record, does not exist (any more).
    NotFound,
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
    /// The API at `base`, with the token already part of `http`.
    pub(super) fn new(http: Http, base: Endpoint) -> Api {
        Api { http, base }
    }

    /// `GET /account`: a real authenticated request, so a success proves that the token is
    /// accepted now.
    // Source: Account, `GET /v2/account`, scope `account:read`, "A JSON object keyed on account".
    pub(super) async fn account(&self) -> Result<(), Error> {
        #[derive(Deserialize)]
        struct Account {
            // Only the presence of the key is checked.
            #[serde(rename = "account")]
            _account: serde::de::IgnoredAny,
        }
        let url = self.base.url().path("/account").build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let _: Account =
            response.json("the provider's account answer is not in the expected form")?;
        Ok(())
    }

    /// `GET /domains/{name}`: the domain's name as the API states it, or `None` for `404`.
    // Source: Domains, "Get Domain": 200 with a `domain` object; 404 `not_found`.
    pub(super) async fn domain(&self, zone: &DomainName) -> Result<Option<String>, Error> {
        #[derive(Deserialize)]
        struct One {
            domain: Domain,
        }
        let url = self.domain_url(zone).build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let one: One = response.json("the provider's domain answer is not in the expected form")?;
        Ok(Some(one.domain.name))
    }

    /// Every domain of the account, all pages.
    // Source: Domains, "List Domains": `domains`, `links`, `meta` (required).
    pub(super) async fn domains(&self) -> Result<Vec<Domain>, Error> {
        let url = |page: u32| page_query(self.base.url().path("/domains"), page).build();
        self.list(url, "domains", None).await
    }

    /// Every TXT record whose name matches `name` according to the API's filter, all pages. The
    /// filter's exactness is not documented, so the caller compares names itself. A `404` is
    /// `Error::ZoneNotFound` for `zone`.
    // Source: Domain Records, "List Domain Records": `name` ("A fully qualified record name",
    // example `sub.example.com`, no trailing dot) and `type`; `404` is among the documented
    // answers (OpenAPI `domains_list_records.yml`). The path names the domain only, so a `404`
    // is read as "no such domain".
    pub(super) async fn records(
        &self,
        zone: &DomainName,
        name: &DomainName,
    ) -> Result<Vec<Record>, Error> {
        let url = |page: u32| {
            let url = self
                .domain_url(zone)
                .path("/records")
                .query("type", TXT)
                .query("name", name.without_dot());
            page_query(url, page).build()
        };
        self.list(url, "domain_records", Some(zone)).await
    }

    /// Creates a record. Sent once: a create is not idempotent, and a repeat after an unknown
    /// outcome could add a second copy (design section 5.3). A `404` is [`Written::NotFound`]
    /// (the domain does not exist); another refusal is an error.
    // Source: Domain Records, "Create a Domain Record": 201 with a `domain_record` object that
    // includes the generated `id`; `404` among the documented answers (OpenAPI
    // `domains_create_record.yml`).
    pub(super) async fn create_record(
        &self,
        zone: &DomainName,
        record: &NewRecord<'_>,
    ) -> Result<Written, Error> {
        #[derive(Deserialize)]
        struct Created {
            // Only the presence of the record with its identifier is checked.
            #[serde(rename = "domain_record")]
            _record: Identified,
        }
        #[derive(Deserialize)]
        struct Identified {
            #[serde(rename = "id")]
            _id: u64,
        }
        let url = self.domain_url(zone).path("/records").build()?;
        let response = self
            .http
            .send(&Request::new(Method::POST, url).json(record)?)
            .await?;
        if response.status() == 404 {
            return Ok(Written::NotFound);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let _: Created =
            response.json("the provider's answer to a create is not in the expected form")?;
        Ok(Written::Done)
    }

    /// Deletes one record by its identifier. Idempotent: repeating it leaves the same state, so
    /// the transport may retry it.
    // Source: Domain Records, "Delete a Domain Record": 204, empty body; documented errors 401,
    // 404, 429, 500.
    pub(super) async fn delete_record(&self, zone: &DomainName, id: u64) -> Result<Written, Error> {
        let url = self
            .domain_url(zone)
            .path("/records")
            .id(&id.to_string())
            .build()?;
        let response = self
            .http
            .send(&Request::new(Method::DELETE, url).idempotent())
            .await?;
        if response.status() == 404 {
            return Ok(Written::NotFound);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        Ok(Written::Done)
    }

    /// `/domains/{name}` with the zone name without its trailing dot (lego client.go lines 40
    /// and 58).
    fn domain_url(&self, zone: &DomainName) -> UrlBuilder {
        self.base.url().path("/domains").segment(zone.without_dot())
    }

    /// Reads every page of a listing; `url` builds the URL of a page number, `key` is the
    /// field that holds the items. A `404` is `Error::ZoneNotFound` for `zone` when one is
    /// given, else a refusal.
    ///
    /// Complete or an error. Pages are fetched by number, never by the `links.pages.next` URL
    /// (a URL from an answer is not requested, design section 5.1); the presence of that link
    /// says whether another page follows. The listing is complete when no link follows and the
    /// items received reach `meta.total`; fewer, an absent `meta.total`, an absent list field,
    /// or an empty page with a next link is `Error::Protocol`.
    // Source: Domains and Domain Records, list answers: `links` optional with `pages.next`
    // among the forward links, `meta` required with `total`. Assumption (not documented): that
    // `meta.total` counts the items under the request's filters and that `pages.next` is absent
    // on the last page. Being wrong makes a listing fail, never come back shorter.
    async fn list<T, U>(
        &self,
        url: U,
        key: &'static str,
        zone: Option<&DomainName>,
    ) -> Result<Vec<T>, Error>
    where
        T: DeserializeOwned,
        U: Fn(u32) -> Result<Url, Error>,
    {
        let received = AtomicU64::new(0);
        pager::collect(1u32, |page| {
            let url = url(page);
            let received = &received;
            async move {
                let response = self.http.send(&Request::get(url?)).await?;
                if response.status() == 404
                    && let Some(zone) = zone
                {
                    return Err(Error::zone_not_found(zone.clone()));
                }
                if !response.is_success() {
                    return Err(self.refusal(&response));
                }
                let body: Value =
                    response.json("the provider's listing is not in the expected form")?;
                let items: Vec<T> = body
                    .get(key)
                    .and_then(|list| serde_json::from_value(list.clone()).ok())
                    .ok_or_else(|| protocol("the provider's listing lacks its list of items"))?;
                let total = body
                    .get("meta")
                    .and_then(|meta| meta.get("total"))
                    .and_then(Value::as_u64)
                    .ok_or_else(|| protocol("the provider's listing states no total"))?;
                let has_next = body
                    .get("links")
                    .and_then(|links| links.get("pages"))
                    .and_then(|pages| pages.get("next"))
                    .is_some_and(Value::is_string);
                let count = u64::try_from(items.len()).unwrap_or(u64::MAX);
                let so_far = received
                    .fetch_add(count, Ordering::Relaxed)
                    .saturating_add(count);
                let next = if has_next {
                    if items.is_empty() {
                        return Err(protocol(
                            "the provider's listing has an empty page before its end",
                        ));
                    }
                    Some(page.saturating_add(1))
                } else if so_far < total {
                    return Err(protocol(
                        "the provider's listing ended before the number of items it stated",
                    ));
                } else {
                    None
                };
                Ok(Page { items, next })
            }
        })
        .await
    }

    /// An answer the client does not expect. 401, 403, 429 and 5xx were mapped by the transport
    /// already. A 4xx is the provider refusing the request, with the documented error body;
    /// anything else is an answer the client cannot interpret.
    // Source: Domain Records and Domains, error schema `{id, message, request_id}` for every
    // non-success answer; the statuses named there are 401, 404, 429, 500 and "default".
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

fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

/// Appends `per_page` and `page`.
fn page_query(url: UrlBuilder, page: u32) -> UrlBuilder {
    url.query("per_page", &PAGE_SIZE.to_string())
        .query("page", &page.to_string())
}

/// The owner name a record's `name` states, as an absolute name: `@` is the zone itself, a
/// name with a trailing dot is absolute, any other is relative to the zone (zone-file rules).
// Source: the reference's answer examples state names relative to the domain, `@` for the apex
// (OpenAPI `examples.yml`, `domain_records_all` and `domain_record_created`; the field
// description is only "The host name, alias, or service being defined by the record").
// Assumption (not documented): that an answer's name with a trailing dot is absolute, accepted in case
// an answer ever states that form. A name read wrongly is never taken for ours, so a foreign
// value cannot be removed by it.
pub(super) fn normalize_name(stated: &str, zone: &DomainName) -> Option<DomainName> {
    if stated == "@" {
        return Some(zone.clone());
    }
    if stated.ends_with('.') {
        return DomainName::parse(stated).ok();
    }
    DomainName::parse(&format!("{stated}.{}", zone.as_str())).ok()
}

/// The provider's error message: `id` and `message` of the documented error body.
// Source: Domain Records, error schema (`id` and `message` required, `request_id` optional);
// lego types.go lines 18 to 21.
pub(super) fn error_message(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        #[serde(default)]
        id: Option<String>,
        #[serde(default)]
        message: Option<String>,
    }
    let body: ErrorBody = serde_json::from_str(body).ok()?;
    let message = body.message.filter(|text| !text.is_empty())?;
    Some(match body.id.filter(|id| !id.is_empty()) {
        Some(id) => format!("{id}: {message}"),
        None => message,
    })
}

#[cfg(test)]
mod tests {
    use super::{error_message, normalize_name};
    use crate::name::DomainName;

    #[test]
    fn error_messages_join_id_and_message() {
        for (body, expected) in [
            (
                r#"{"id":"unauthorized","message":"Unable to authenticate you","request_id":"r"}"#,
                Some("unauthorized: Unable to authenticate you"),
            ),
            (r#"{"message":"only this"}"#, Some("only this")),
            (r#"{"id":"x"}"#, None),
            ("<html>oops</html>", None),
        ] {
            assert_eq!(error_message(body).as_deref(), expected, "{body}");
        }
    }

    #[test]
    fn stated_names_are_made_absolute() {
        let zone = DomainName::parse("example.org").unwrap();
        let name = |s: &str| normalize_name(s, &zone).map(|n| n.as_str().to_owned());
        assert_eq!(name("@").as_deref(), Some("example.org."));
        assert_eq!(
            name("_acme-challenge").as_deref(),
            Some("_acme-challenge.example.org.")
        );
        assert_eq!(
            name("_acme-challenge.example.org.").as_deref(),
            Some("_acme-challenge.example.org.")
        );
        // Without the trailing dot a name is relative, whatever it ends with.
        assert_eq!(
            name("a.example.org").as_deref(),
            Some("a.example.org.example.org.")
        );
    }
}
