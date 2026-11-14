//! The Yandex 360 API as this client uses it: one function per endpoint, the wire types, paging
//! and the classification of answers. Nothing here knows the value layer; `client.rs` and
//! `txt.rs` build on these calls.
//!
//! Sources (hard rule 3):
//!
//! - [Create]: <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Create>:
//!   `POST /directory/v1/org/{orgId}/domains/{domain}/dns`; `orgId` an integer, `domain` the full
//!   domain name (Punycode for Cyrillic names); the body fields `type`, `name` ("record name"),
//!   `ttl` (all three required) and `text` ("content for a TXT record"); `200` with the record
//!   and its `recordId`; `400`, `401`, `403`, `404`, `500` with the error body
//!   `{code, message, details}`. The page states no range for `ttl`.
//! - [List]: <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_List>:
//!   `GET` on the same path with `page` (default 1) and `perPage` (default 50, no maximum
//!   stated); `200` with `records`, `page`, `pages`, `perPage`, `total`; a record has
//!   `recordId`, `type`, `name`, `ttl`, `text` and the fields of the other types; the same
//!   error statuses.
//! - [Delete]: <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Delete>:
//!   `DELETE /directory/v1/org/{orgId}/domains/{domain}/dns/{recordId}`; `200` with `{}`; the
//!   same error statuses.
//! - [Domains]: <https://yandex.ru/dev/api360/doc/ru/ref/DomainService/DomainService_List>:
//!   `GET /directory/v1/org/{orgId}/domains` with `page` (default 1) and `perPage` (maximum 10);
//!   `200` with `domains`, `page`, `pages`, `perPage`, `total`; a domain has `name`, `delegated`
//!   ("whether the domain is delegated to Yandex name servers"), `master`, `verified` and more.
//! - [Access]: <https://yandex.ru/dev/api360/doc/ru/access.md>: the header is
//!   `Authorization: OAuth <token>`; the scopes `directory:read_domains` and
//!   `directory:manage_dns`. lego `providers/dns/yandex360/internal/client.go` line 83 sends
//!   the same header; lines 47 to 80 use the create and delete endpoints above.
//!
//! Endpoints used, all below the `base_url`:
//!
//! | Call          | Request                                                 | Success |
//! | ------------- | ------------------------------------------------------- | ------- |
//! | list domains  | `GET /directory/v1/org/{org}/domains?page&perPage`      | 200     |
//! | list records  | `GET /directory/v1/org/{org}/domains/{domain}/dns?page&perPage` | 200 |
//! | create record | `POST /directory/v1/org/{org}/domains/{domain}/dns`     | 200     |
//! | delete record | `DELETE /directory/v1/org/{org}/domains/{domain}/dns/{id}` | 200  |
//!
//! [Create]: https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Create
//! [List]: https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_List
//! [Delete]: https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Delete
//! [Domains]: https://yandex.ru/dev/api360/doc/ru/ref/DomainService/DomainService_List
//! [Access]: https://yandex.ru/dev/api360/doc/ru/access.md

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

/// Page size of the record listing: the documented default of `perPage`; the page states no
/// maximum, so a larger value is not asked for.
// Source: List, query parameter `perPage` (default 50).
const RECORDS_PER_PAGE: u32 = 50;

/// Page size of the domain listing: the documented maximum of `perPage`.
// Source: Domains, query parameter `perPage` ("maximum 10").
const DOMAINS_PER_PAGE: u32 = 10;

/// The record type name as the API spells it.
pub(super) const TXT: &str = "TXT";

/// A record as the listing returns it; other fields are ignored.
// Source: List, record fields (`recordId`, `type`, `name`, `ttl`, `text`).
#[derive(Debug, Deserialize)]
pub(super) struct Record {
    /// The record's identifier.
    #[serde(rename = "recordId")]
    pub(super) record_id: u64,
    /// The record type.
    #[serde(default, rename = "type")]
    pub(super) rtype: String,
    /// The owner name as the API states it. Its form is not settled by the documentation (see
    /// [`names_match`]).
    #[serde(default)]
    pub(super) name: String,
    /// The value of a TXT record.
    #[serde(default)]
    pub(super) text: Option<String>,
    /// TTL in seconds.
    #[serde(default)]
    pub(super) ttl: Option<u32>,
}

/// A domain of the organization as the domain listing returns it; other fields are ignored.
// Source: Domains, domain fields `name` and `delegated`.
#[derive(Debug, Deserialize)]
pub(super) struct Domain {
    /// The domain name, in Punycode.
    pub(super) name: String,
    /// Whether the domain is delegated to Yandex name servers. Absent counts as not delegated.
    #[serde(default)]
    pub(super) delegated: bool,
}

/// The body of the create request.
// Source: Create, request body: `type`, `name`, `ttl` required, `text` for a TXT record; lego
// internal/client.go sends a `Record` with the same four fields.
#[derive(Serialize)]
pub(super) struct NewRecord<'a> {
    /// The record type.
    #[serde(rename = "type")]
    pub(super) rtype: &'a str,
    /// The owner name relative to the domain, the form lego sends (yandex360.go lines 120 and
    /// 128 pass `ExtractSubDomain`).
    pub(super) name: &'a str,
    /// The value.
    pub(super) text: &'a str,
    /// TTL in seconds; required by the API.
    pub(super) ttl: u32,
}

/// The answer to a write.
#[derive(Debug)]
pub(super) enum Written {
    /// The provider accepted the write.
    Done,
    /// `404`: the domain, or for a delete the record, does not exist (any more).
    NotFound,
}

/// The client's handle on the API: the transport, the endpoint and the organization.
pub(super) struct Api {
    http: Http,
    base: Endpoint,
    org_id: String,
}

impl fmt::Debug for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .field("org_id", &self.org_id)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// The API at `base` for the organization `org_id` (decimal digits, checked by the
    /// settings), with the token already part of `http`.
    pub(super) fn new(http: Http, base: Endpoint, org_id: String) -> Api {
        Api { http, base, org_id }
    }

    /// `/directory/v1/org/{orgId}`. The organization is the application's own setting, checked
    /// to be digits; `.id` re-checks it before it goes into the path.
    fn org_url(&self) -> UrlBuilder {
        self.base.url().path("/directory/v1/org").id(&self.org_id)
    }

    /// `…/domains/{domain}/dns` with the zone name without its trailing dot.
    // Source: Create, path parameter `domain`: "the full domain name".
    fn dns_url(&self, zone: &DomainName) -> UrlBuilder {
        self.org_url()
            .path("/domains")
            .segment(zone.without_dot())
            .path("/dns")
    }

    /// Every domain of the organization, all pages, delegated or not.
    pub(super) async fn domains(&self) -> Result<Vec<Domain>, Error> {
        let url =
            |page: u32| page_query(self.org_url().path("/domains"), page, DOMAINS_PER_PAGE).build();
        self.list(url, "domains", None).await
    }

    /// Every record of the zone, all pages. A `404` is `Error::ZoneNotFound` for `zone`.
    // Source: List: the listing has no filter by name or type, so the client filters.
    pub(super) async fn records(&self, zone: &DomainName) -> Result<Vec<Record>, Error> {
        let url = |page: u32| page_query(self.dns_url(zone), page, RECORDS_PER_PAGE).build();
        self.list(url, "records", Some(zone)).await
    }

    /// Reads the first record of the zone, to show that the token may read the zone's records:
    /// `false` for `404`.
    // Source: List: `200` with `records`, `404` "not found".
    pub(super) async fn probe(&self, zone: &DomainName) -> Result<bool, Error> {
        let url = page_query(self.dns_url(zone), 1, 1).build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(false);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let body: Value = response.json("the provider's listing is not in the expected form")?;
        if !body.get("records").is_some_and(Value::is_array) {
            return Err(protocol("the provider's listing lacks its list of items"));
        }
        Ok(true)
    }

    /// Creates a record. Sent once: a create is not idempotent, and a repeat after an unknown
    /// outcome could add a second copy (design section 5.3). A `404` is [`Written::NotFound`].
    // Source: Create: `200` with the record, `recordId` among its fields; `404` among the
    // documented answers.
    pub(super) async fn create_record(
        &self,
        zone: &DomainName,
        record: &NewRecord<'_>,
    ) -> Result<Written, Error> {
        #[derive(Deserialize)]
        struct Created {
            // Only the presence of the identifier is checked.
            #[serde(rename = "recordId")]
            _record_id: u64,
        }
        let url = self.dns_url(zone).build()?;
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
    // Source: Delete: `200` with `{}`; `404` among the documented answers.
    pub(super) async fn delete_record(
        &self,
        zone: &DomainName,
        record_id: u64,
    ) -> Result<Written, Error> {
        let url = self.dns_url(zone).id(&record_id.to_string()).build()?;
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

    /// Reads every page of a listing; `url` builds the URL of a page number, `key` is the
    /// field that holds the items. A `404` is `Error::ZoneNotFound` for `zone` when one is
    /// given, else a refusal.
    ///
    /// Complete or an error. The listing states `pages` and `total`: another page follows while
    /// `page < pages`, and at the last page the items received must reach `total`. Fewer, an
    /// absent `pages` or `total`, an absent list field, or an empty page before the last is
    /// `Error::Protocol`.
    // Source: List and Domains, answer fields `pages` and `total`. Assumption (not documented):
    // that `total` counts every item of the listing and `pages` is at least the number of
    // pages that hold them. Being wrong makes a listing fail, never come back shorter.
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
                let stated = |field: &str| body.get(field).and_then(Value::as_u64);
                let (Some(pages), Some(total)) = (stated("pages"), stated("total")) else {
                    return Err(protocol(
                        "the provider's listing states no page or item count",
                    ));
                };
                let count = u64::try_from(items.len()).unwrap_or(u64::MAX);
                let so_far = received
                    .fetch_add(count, Ordering::Relaxed)
                    .saturating_add(count);
                let next = if u64::from(page) < pages {
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
    // Source: Create, List, Delete and Domains: the statuses named are 200, 400, 401, 403, 404
    // and 500, with the body `{code, message, details}` for every error.
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

/// Appends `page` and `perPage`.
fn page_query(url: UrlBuilder, page: u32, per_page: u32) -> UrlBuilder {
    url.query("page", &page.to_string())
        .query("perPage", &per_page.to_string())
}

/// Whether the owner name a record states is `name`, a name within `zone`.
///
/// The documentation is not explicit about the form: the create page calls the field "record
/// name" and lego sends the name relative to the domain, while the list page describes the
/// field as the "full domain name". Both forms are accepted, with or without a trailing dot,
/// and `@` or an empty name for the zone itself.
// Assumption (not documented): the forms above, and that a stated name equal to the full name
// is the full name rather than a name relative to the zone. A wrong reading can only make one
// owner name look like another, and the client deletes only records whose value equals the value
// being removed, so a foreign value is never taken for ours. The worst cases need a record at a
// lookalike name (a relative name that repeats the zone, such as `_acme-challenge.example.org`
// inside `example.org`) holding exactly our value: an add then reports `AlreadyPresent` without
// writing, or a remove deletes that copy of our value too.
pub(super) fn names_match(stated: &str, zone: &DomainName, name: &DomainName) -> bool {
    let Some(relative) = name.relative_to(zone) else {
        return false;
    };
    let stated = stated.strip_suffix('.').unwrap_or(stated);
    if relative.is_empty() {
        return stated.is_empty()
            || stated == "@"
            || stated.eq_ignore_ascii_case(zone.without_dot());
    }
    stated.eq_ignore_ascii_case(relative) || stated.eq_ignore_ascii_case(name.without_dot())
}

/// The provider's error message: the `message` of the documented error body.
// Source: Create, error body `{code, message, details}`.
pub(super) fn error_message(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        #[serde(default)]
        message: Option<String>,
    }
    let body: ErrorBody = serde_json::from_str(body).ok()?;
    body.message.filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{error_message, names_match};
    use crate::name::DomainName;

    #[test]
    fn error_messages_are_the_message_field() {
        for (body, expected) in [
            (
                r#"{"code":16,"message":"not authorized","details":[]}"#,
                Some("not authorized"),
            ),
            (r#"{"code":3}"#, None),
            (r#"{"message":""}"#, None),
            ("<html>oops</html>", None),
        ] {
            assert_eq!(error_message(body).as_deref(), expected, "{body}");
        }
    }

    #[test]
    fn stated_names_are_compared_in_both_forms() {
        let zone = DomainName::parse("example.org").unwrap();
        let name = DomainName::parse("_acme-challenge.example.org").unwrap();
        let ok = |stated: &str, name: &DomainName| names_match(stated, &zone, name);
        assert!(ok("_acme-challenge", &name));
        assert!(ok("_ACME-challenge", &name));
        assert!(ok("_acme-challenge.example.org", &name));
        assert!(ok("_acme-challenge.example.org.", &name));
        assert!(!ok("_acme-challenge.www", &name));
        assert!(!ok("other", &name));
        assert!(!ok("@", &name));
        assert!(ok("@", &zone));
        assert!(ok("", &zone));
        assert!(ok("example.org", &zone));
        assert!(!ok("_acme-challenge", &zone));
        let outside = DomainName::parse("example.net").unwrap();
        assert!(!ok("example.net", &outside));
    }
}
