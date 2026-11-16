//! The Timeweb Cloud API as this client uses it: one function per endpoint, the wire types,
//! paging and the classification of answers. Nothing here knows the value layer; `client.rs`
//! and `txt.rs` build on these calls.
//!
//! Sources (hard rule 3):
//!
//! - The public API description, <https://timeweb.cloud/api-docs> (the OpenAPI document it is
//!   rendered from, `https://timeweb.cloud/api-docs-data/bundle.json`, version `1.0.0`, read on
//!   2026-11-14; the server is `https://api.timeweb.cloud`, authentication is `http` scheme
//!   `bearer`):
//!   - `GET /api/v1/domains` (`getDomains`, not marked deprecated): `limit` (integer, default
//!     100) and `offset` (integer, default 0); the answer holds `meta.total` and `domains`, each
//!     with `fqdn` (both required by the schema).
//!   - `GET /api/v1/domains/{fqdn}/dns-records` (`getDomainDNSRecords`, not marked deprecated;
//!     the API has no `v2` listing): "all user DNS records of a domain or subdomain", where
//!     `fqdn` is "the full name of a domain or subdomain"; `limit` and `offset` as above; the
//!     answer holds `meta.total` and `dns_records`, each with `type` (`TXT`, `SRV`, `CNAME`,
//!     `AAAA`, `MX`, `A`), `id` (a number, nullable), `ttl` and `data` with `subdomain`
//!     (nullable string, example `sub.somedomain.ru`), `value` and `priority`. Documented
//!     answers: `200`, `400`, `401`, `404`, `429`, `500`.
//!   - `POST /api/v2/domains/{fqdn}/dns-records` (`createDomainDNSRecordV2`): `fqdn` is the
//!     domain's name for a record at the domain itself and the full name of the subdomain for a
//!     record at a subdomain; the description adds that the subdomain must be created
//!     beforehand with `POST /api/v1/domains/{fqdn}/subdomains/{subdomain}`. The TXT body is
//!     `type` and `value` (required) and `ttl` (a number, "the record's lifetime in seconds");
//!     there is no name field. `201` with `dns_record` (`id` a number, nullable; `type`; `fqdn`,
//!     the main domain; `data.value`; `data.subdomain`, the name relative to the main domain,
//!     absent at the domain itself; `ttl`). Documented answers: `201`, `400`, `401`, `404`,
//!     `409`, `429`, `500`.
//!   - `DELETE /api/v2/domains/{fqdn}/dns-records/{record_id}` (`deleteDomainDNSRecordV2`):
//!     `fqdn` as for the create, `record_id` an integer; `204`; `400`, `401`, `404`, `429`,
//!     `500`.
//!   - `PATCH /api/v2/domains/{fqdn}/dns-records/{record_id}` (`updateDomainDNSRecordV2`):
//!     "updates the DNS record" with the given attributes; `fqdn` and `record_id` as for the
//!     delete; the body is the create's per-type object (`create-dns-v2`, `type` and `value`
//!     required, `priority` required for MX); `200` with `dns_record`; documented answers `200`,
//!     `400`, `401`, `404`, `409`, `429`, `500`.
//!   - `GET /api/v1/domains/{fqdn}` (`getDomain`, not marked deprecated): the answer holds
//!     `domain` with `fqdn` and `subdomains` (both required), each subdomain with `fqdn`, "the
//!     full name of the subdomain" (required); documented answers `200`, `400`, `401`, `403`,
//!     `404`, `429`, `500`.
//!   - The listing's record (`dns-record`) has `data.priority` ("the record's priority", a
//!     number) beside `data.subdomain` and `data.value`; the record schema's `type` enumerates
//!     `TXT`, `SRV`, `CNAME`, `AAAA`, `MX` and `A`.
//!   - The error body of every non-success answer: `status_code`, `error_code`, `message` (a
//!     string or an array of strings) and `response_id`.
//! - lego `providers/dns/timewebcloud` at commit `012a2c1e01` ("update API client to new API
//!   version", 2026-05-22), unchanged in these respects at `7c184b4d1a` (2026-11-04):
//!   `internal/client.go` `POST {base}/v2/domains/{fqdn}/dns-records` (line 44) and `DELETE
//!   {base}/v2/domains/{fqdn}/dns-records/{id}` (line 64), the name without its trailing dot;
//!   `timewebcloud.go` passes the challenge's full name (`info.EffectiveFQDN`) to both (lines 118
//!   and 147) and sends the body `type` and `value` with the value unquoted (lines 113 to 116),
//!   without creating a subdomain first; `internal/types.go` the `dns_record` key of the answer
//!   (line 23) and the error fields (lines 26 to 31). The change followed lego issue 3119
//!   (2026-05-22), where the deprecated `v1` create answered `400` `bad_subdomain_name` for
//!   `_acme-challenge.<domain>`.
//!
//! The deprecated `v1` create and delete (`createDomainDNSRecord`, `deleteDomainDNSRecord`) are
//! not used (design section 13.4, item 12).
//!
//! Endpoints used, all below the `base_url`:
//!
//! | Call          | Request                                                | Success   |
//! | ------------- | ------------------------------------------------------ | --------- |
//! | probe         | `GET /v1/domains?limit=1&offset=0`                     | 200       |
//! | list domains  | `GET /v1/domains?limit&offset`                         | 200, page |
//! | zone exists   | `GET /v1/domains/{zone}/dns-records?limit=1&offset=0`  | 200       |
//! | subdomains    | `GET /v1/domains/{zone}`                               | 200       |
//! | list records  | `GET /v1/domains/{fqdn}/dns-records?limit&offset`      | 200, page |
//! | create record | `POST /v2/domains/{name}/dns-records`                  | 201       |
//! | update record | `PATCH /v2/domains/{name}/dns-records/{id}`            | 200       |
//! | delete record | `DELETE /v2/domains/{name}/dns-records/{id}`           | 204       |
//!
//! `{name}` is the record's owner name: the zone itself, or the full name below it. `{fqdn}` is
//! the zone, or a subdomain the domain's answer states: every read lists the zone and all its
//! subdomains (see [`Api::zone_listings`]).

use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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

/// Page size of every listing.
// Source: `limit` of both listings is an integer with the default 100. Assumption (not
// documented): that 100 is also the largest value accepted. Being wrong makes a listing fail
// with the provider's refusal, never come back shorter.
const PAGE_SIZE: u64 = 100;

/// The record type name as the API spells it.
pub(super) const TXT: &str = "TXT";

/// A record as `GET .../dns-records` returns it; other fields are ignored.
// Source: the listing's schema (`type`, `id`, `ttl`, `data.subdomain`, `data.value`); `id` is
// nullable there, so a record may be listed without one.
#[derive(Debug, Deserialize)]
pub(super) struct Record {
    /// The record type.
    #[serde(rename = "type")]
    pub(super) rtype: String,
    /// The record's identifier; the schema types it as a number.
    #[serde(default)]
    id: Option<Value>,
    /// TTL in seconds.
    #[serde(default)]
    ttl: Option<Value>,
    /// The record's data.
    #[serde(default)]
    data: Option<RecordData>,
}

/// The `data` object of a record.
#[derive(Debug, Deserialize)]
struct RecordData {
    /// The owner name as the API states it, in one of two forms (see `names.rs`).
    #[serde(default)]
    subdomain: Option<String>,
    /// The value.
    #[serde(default)]
    value: Option<String>,
    /// The priority (an MX preference); the schema types it as a number.
    #[serde(default)]
    priority: Option<Value>,
}

impl Record {
    /// The priority, when the answer states one as a non-negative whole number.
    pub(super) fn priority(&self) -> Option<u64> {
        self.data
            .as_ref()
            .and_then(|data| data.priority.as_ref())
            .and_then(whole)
    }

    /// The priority as the answer states it, for text that keeps an unusual spelling.
    pub(super) fn priority_text(&self) -> Option<String> {
        self.data
            .as_ref()
            .and_then(|data| data.priority.as_ref())
            .filter(|value| !value.is_null())
            .map(Value::to_string)
    }

    /// The record's identifier, when the answer states one.
    pub(super) fn id(&self) -> Option<u64> {
        self.id.as_ref().and_then(whole)
    }

    /// The TTL in seconds, when the answer states one.
    pub(super) fn ttl(&self) -> Option<u32> {
        self.ttl
            .as_ref()
            .and_then(whole)
            .and_then(|secs| u32::try_from(secs).ok())
    }

    /// The value, when the answer states one.
    pub(super) fn value(&self) -> Option<&str> {
        self.data.as_ref().and_then(|data| data.value.as_deref())
    }

    /// The stated owner name, when the answer states one.
    pub(super) fn subdomain(&self) -> Option<&str> {
        self.data
            .as_ref()
            .and_then(|data| data.subdomain.as_deref())
    }
}

/// A domain as `GET /v1/domains` returns it; other fields are ignored.
// Source: `fqdn`, required by the schema.
#[derive(Debug, Deserialize)]
pub(super) struct Domain {
    /// The domain name.
    pub(super) fqdn: String,
}

/// One listing a read gathered: the name it is the listing of and its records.
#[derive(Debug)]
pub(super) struct Listed {
    /// The zone or the subdomain; `None` for a stated subdomain whose name the client cannot
    /// hold, listed by its name as stated.
    pub(super) of: Option<DomainName>,
    /// Its records, all pages.
    pub(super) records: Vec<Record>,
}

/// The body of `POST /v2/domains/{fqdn}/dns-records` and of `PATCH
/// /v2/domains/{fqdn}/dns-records/{record_id}`.
// Source: the per-type request objects of `create-dns-v2`, the body of both calls: `type` and
// `value` required for A, AAAA, TXT and CNAME, `type`, `value` and `priority` for MX, `ttl`
// optional for every type (A also has an optional `app_id`, which this client never sends;
// SRV has other fields and is not written). lego types.go lines 5 to 8 sends `type` and
// `value`. The owner name is the path, not a body field.
#[derive(Serialize)]
pub(super) struct NewRecord<'a> {
    /// The record type.
    #[serde(rename = "type")]
    pub(super) rtype: &'a str,
    /// The value.
    pub(super) value: &'a str,
    /// The MX preference; left out for every other type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) priority: Option<u64>,
    /// TTL in seconds; left out when the caller has none to give.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ttl: Option<u32>,
}

/// The answer to a create.
#[derive(Debug)]
pub(super) enum Created {
    /// The provider accepted the record.
    Done,
    /// `404`: the domain, or the name as a subdomain of it, is unknown to the provider; nothing
    /// was written. Carries the provider's refusal, for when the domain exists.
    NotFound(Error),
}

/// The answer to an update.
#[derive(Debug)]
pub(super) enum Updated {
    /// The provider changed the record.
    Done,
    /// `404`: the record, or the domain with it, does not exist (any more); nothing was
    /// written.
    NotFound,
}

/// The answer to a delete.
#[derive(Debug)]
pub(super) enum Deleted {
    /// The provider deleted the record.
    Done,
    /// `404`: the record, or the domain with it, does not exist (any more).
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

    /// `GET /v1/domains?limit=1&offset=0`: a real authenticated request that names no zone, so
    /// a success proves that the token is accepted now. The answer must have the listing's
    /// shape.
    pub(super) async fn probe(&self) -> Result<(), Error> {
        let url = self.domains_url(1, 0).build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        read_page::<Domain>(&response, "domains").map(|_| ())
    }

    /// Whether the domain exists in the account: `GET /v1/domains/{zone}/dns-records` with
    /// `limit=1&offset=0`, where `404` is "no".
    // Assumption (not documented): that `404` on a domain's listing means that the account has
    // no such domain (the status is documented, its meaning is not). Being wrong reports a zone
    // as missing, or a write as refused; nothing is written either way.
    pub(super) async fn zone_exists(&self, zone: &DomainName) -> Result<bool, Error> {
        let url = paging(self.records_path(zone.without_dot()), 1, 0).build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(false);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        read_page::<Record>(&response, "dns_records").map(|_| true)
    }

    /// Every domain of the account, all pages.
    pub(super) async fn domains(&self) -> Result<Vec<Domain>, Error> {
        let listed = self
            .list(
                |offset| self.domains_url(PAGE_SIZE, offset).build(),
                "domains",
            )
            .await?;
        listed.ok_or_else(|| protocol("the provider answered \"not found\" to its domain listing"))
    }

    /// Every listing a read of the zone needs, in this order: the zone's own listing, then the
    /// listing of every subdomain the domain's answer states (`GET /v1/domains/{zone}`), each
    /// once, all pages. A read of one name and a listing of the zone use the same listings, so
    /// they place every record the same way (`names.rs`).
    ///
    /// A `404` for the domain's answer or for the zone's listing is `Error::ZoneNotFound`. A
    /// subdomain whose name the client cannot hold (or that lies outside the zone) is listed by
    /// its name as stated.
    // Source: the listing's `fqdn` is the full name of a domain or subdomain, and it lists all
    // the records of that domain or subdomain; `getDomain` states every subdomain with its full
    // name; a record below the domain is created at a subdomain (the `v2` create's `fqdn`).
    // Whether the zone's listing includes the records of its subdomains is not stated, hence
    // the subdomains' own listings.
    // Assumption (not documented): that `404` for the listing of a subdomain the domain's answer
    // stated means that the subdomain was deleted after that answer, with its records. Being
    // wrong can make an add create a second copy of our own value, or a removal report
    // `NotPresent` while our record stays; it never deletes or overwrites anything.
    pub(super) async fn zone_listings(&self, zone: &DomainName) -> Result<Vec<Listed>, Error> {
        let subdomains = self.subdomains(zone).await?;
        let own = self
            .records_of(zone.without_dot())
            .await?
            .ok_or_else(|| Error::zone_not_found(zone.clone()))?;
        let mut listings = vec![Listed {
            of: Some(zone.clone()),
            records: own,
        }];
        let mut listed: HashSet<String> = HashSet::new();
        for stated in &subdomains {
            let text = stated.trim();
            let text = text.strip_suffix('.').unwrap_or(text);
            let of = DomainName::parse(text)
                .ok()
                .filter(|name| name.is_within(zone));
            if of.as_ref() == Some(zone) || !listed.insert(text.to_ascii_lowercase()) {
                continue;
            }
            let path = of.as_ref().map_or(text, DomainName::without_dot);
            if let Some(records) = self.records_of(path).await? {
                listings.push(Listed { of, records });
            }
        }
        Ok(listings)
    }

    /// Every record the API lists for the domain or subdomain spelled `fqdn` (without a
    /// trailing dot), all pages; `None` when the first page is answered `404`.
    async fn records_of(&self, fqdn: &str) -> Result<Option<Vec<Record>>, Error> {
        self.list(
            |offset| paging(self.records_path(fqdn), PAGE_SIZE, offset).build(),
            "dns_records",
        )
        .await
    }

    /// The full names of the zone's subdomains as `GET /v1/domains/{zone}` states them. A `404`
    /// is `Error::ZoneNotFound` (the same reading as for the zone's listing, see
    /// [`Api::zone_exists`]); an answer without the required `domain.subdomains` list, or a
    /// subdomain without its `fqdn`, is `Error::Protocol`.
    // Source: `getDomain`; the `domain` schema requires `subdomains`, the `subdomain` schema
    // requires `fqdn`, "the full name of the subdomain".
    pub(super) async fn subdomains(&self, zone: &DomainName) -> Result<Vec<String>, Error> {
        #[derive(Deserialize)]
        struct Answer {
            domain: DomainInfo,
        }
        #[derive(Deserialize)]
        struct DomainInfo {
            subdomains: Vec<Subdomain>,
        }
        #[derive(Deserialize)]
        struct Subdomain {
            fqdn: String,
        }
        let url = self
            .base
            .url()
            .path("/v1/domains")
            .segment(zone.without_dot())
            .build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Err(Error::zone_not_found(zone.clone()));
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let answer: Answer = response.json(
            "the provider's answer about the domain lacks its list of subdomains or their names",
        )?;
        Ok(answer
            .domain
            .subdomains
            .into_iter()
            .map(|subdomain| subdomain.fqdn)
            .collect())
    }

    /// Creates a record at `name`. Sent once: a create is not idempotent, and a repeat after an
    /// unknown outcome could add a second copy (design section 5.3). A `404` is
    /// [`Created::NotFound`]; another refusal is an error.
    pub(super) async fn create_record(
        &self,
        name: &DomainName,
        record: &NewRecord<'_>,
    ) -> Result<Created, Error> {
        #[derive(Deserialize)]
        struct Answer {
            // Only the presence of the record is checked: the schema requires it.
            #[serde(rename = "dns_record")]
            _record: Written,
        }
        #[derive(Deserialize)]
        struct Written {
            // Only the presence of the type is checked: the schema requires it.
            #[serde(rename = "type")]
            _rtype: String,
        }
        let url = self.v2_records_path(name).build()?;
        let response = self
            .http
            .send(&Request::new(Method::POST, url).json(record)?)
            .await?;
        if response.status() == 404 {
            return Ok(Created::NotFound(self.http.reject(&response)));
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let _: Answer =
            response.json("the provider's answer to a create is not in the expected form")?;
        Ok(Created::Done)
    }

    /// Changes the record `id` at `name` to `record`. Sent once (design section 5.3). A `404`
    /// is [`Updated::NotFound`]; another refusal is an error.
    pub(super) async fn update_record(
        &self,
        name: &DomainName,
        id: u64,
        record: &NewRecord<'_>,
    ) -> Result<Updated, Error> {
        #[derive(Deserialize)]
        struct Answer {
            // Only the presence of the record is checked: the schema requires it.
            #[serde(rename = "dns_record")]
            _record: Written,
        }
        #[derive(Deserialize)]
        struct Written {
            // Only the presence of the type is checked: the schema requires it.
            #[serde(rename = "type")]
            _rtype: String,
        }
        let url = self.v2_records_path(name).id(&id.to_string()).build()?;
        let response = self
            .http
            .send(&Request::new(Method::PATCH, url).json(record)?)
            .await?;
        if response.status() == 404 {
            return Ok(Updated::NotFound);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let _: Answer =
            response.json("the provider's answer to an update is not in the expected form")?;
        Ok(Updated::Done)
    }

    /// Deletes the record `id` at `name`. Idempotent: repeating it leaves the same state, so
    /// the transport may retry it.
    pub(super) async fn delete_record(&self, name: &DomainName, id: u64) -> Result<Deleted, Error> {
        let url = self.v2_records_path(name).id(&id.to_string()).build()?;
        let response = self
            .http
            .send(&Request::new(Method::DELETE, url).idempotent())
            .await?;
        if response.status() == 404 {
            return Ok(Deleted::NotFound);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        Ok(Deleted::Done)
    }

    /// `/v1/domains` with `limit` and `offset`.
    fn domains_url(&self, limit: u64, offset: u64) -> UrlBuilder {
        paging(self.base.url().path("/v1/domains"), limit, offset)
    }

    /// `/v1/domains/{fqdn}/dns-records`, `fqdn` a name without its trailing dot.
    fn records_path(&self, fqdn: &str) -> UrlBuilder {
        self.base
            .url()
            .path("/v1/domains")
            .segment(fqdn)
            .path("/dns-records")
    }

    /// `/v2/domains/{name}/dns-records`, the name without its trailing dot (lego client.go lines
    /// 44 and 64).
    fn v2_records_path(&self, name: &DomainName) -> UrlBuilder {
        self.base
            .url()
            .path("/v2/domains")
            .segment(name.without_dot())
            .path("/dns-records")
    }

    /// Reads every page of a listing; `url` builds the URL of an offset, `key` is the field that
    /// holds the items. `None` when the first page is answered `404`.
    ///
    /// Complete or an error. The listing is complete when the items received reach the largest
    /// `meta.total` any page stated; fewer, an absent `meta.total`, an absent list field, an
    /// empty page before the total is reached, or a `404` after the first page is
    /// `Error::Protocol`.
    // Source: both listings' answers require `meta` (with `total`) and the list field.
    // Assumption (not documented): that `meta.total` counts all the items of the listing and
    // that `offset` skips that many of them. Being wrong makes a listing fail, never come back
    // shorter.
    async fn list<T, U>(&self, url: U, key: &'static str) -> Result<Option<Vec<T>>, Error>
    where
        T: DeserializeOwned,
        U: Fn(u64) -> Result<Url, Error>,
    {
        // The largest total any page stated: a later page that states less cannot end the
        // listing early.
        let stated = AtomicU64::new(0);
        let missing = AtomicBool::new(false);
        let items = pager::collect(0u64, |offset| {
            let url = url(offset);
            let (stated, missing) = (&stated, &missing);
            async move {
                let response = self.http.send(&Request::get(url?)).await?;
                if response.status() == 404 {
                    if offset == 0 {
                        missing.store(true, Ordering::Relaxed);
                        return Ok(Page {
                            items: Vec::new(),
                            next: None,
                        });
                    }
                    return Err(protocol(
                        "the provider's listing was answered \"not found\" before its end",
                    ));
                }
                if !response.is_success() {
                    return Err(self.refusal(&response));
                }
                let (items, total) = read_page::<T>(&response, key)?;
                let count = u64::try_from(items.len()).unwrap_or(u64::MAX);
                let so_far = offset.saturating_add(count);
                let total = stated.fetch_max(total, Ordering::Relaxed).max(total);
                let next = if so_far >= total {
                    None
                } else if count == 0 {
                    return Err(protocol(
                        "the provider's listing has an empty page before its end",
                    ));
                } else {
                    Some(so_far)
                };
                Ok(Page { items, next })
            }
        })
        .await?;
        Ok(if missing.load(Ordering::Relaxed) {
            None
        } else {
            Some(items)
        })
    }

    /// An answer the client does not expect. 401, 403, 429 and 5xx were mapped by the transport
    /// already. A 4xx is the provider refusing the request, with the documented error body;
    /// anything else is an answer the client cannot interpret.
    // Source: the statuses named for every operation are 400, 401, 404, 429 and 500, and 409
    // for the create. What a 409 to a create means is not described, so it is a refusal like
    // the other 4xx: nothing is repeated.
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

/// The items of one listing page and the stated total.
fn read_page<T: DeserializeOwned>(
    response: &Response,
    key: &'static str,
) -> Result<(Vec<T>, u64), Error> {
    let body: Value = response.json("the provider's listing is not in the expected form")?;
    let items: Vec<T> = body
        .get(key)
        .and_then(|list| serde_json::from_value(list.clone()).ok())
        .ok_or_else(|| protocol("the provider's listing lacks its list of items"))?;
    let total = body
        .get("meta")
        .and_then(|meta| meta.get("total"))
        .and_then(whole)
        .ok_or_else(|| protocol("the provider's listing states no total"))?;
    Ok((items, total))
}

fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

/// Appends `limit` and `offset`.
fn paging(url: UrlBuilder, limit: u64, offset: u64) -> UrlBuilder {
    url.query("limit", &limit.to_string())
        .query("offset", &offset.to_string())
}

/// A JSON number that is a non-negative whole number, however it is spelled (`42` or `42.0`):
/// the schema types identifiers, TTLs and totals as `number`.
fn whole(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        value
            .as_f64()
            .filter(|f| f.fract() == 0.0 && (0.0..9.0e15).contains(f))
            .and_then(|f| format!("{f:.0}").parse().ok())
    })
}

/// The provider's error message: `error_code` and `message` of the documented error body.
// Source: the error schema; `message` is a string or an array of strings.
pub(super) fn error_message(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Message {
        One(String),
        Many(Vec<String>),
    }
    #[derive(Deserialize)]
    struct ErrorBody {
        #[serde(default)]
        error_code: Option<String>,
        #[serde(default)]
        message: Option<Message>,
    }
    let body: ErrorBody = serde_json::from_str(body).ok()?;
    let message = match body.message? {
        Message::One(text) => text,
        Message::Many(texts) => texts.join("; "),
    };
    if message.is_empty() {
        return None;
    }
    Some(match body.error_code.filter(|code| !code.is_empty()) {
        Some(code) => format!("{code}: {message}"),
        None => message,
    })
}

/// The provider's error code: the `error_code` of the documented error body, such as
/// `bad_request`.
// Source: the error schema (`status_code`, `error_code`, `message`, `response_id`).
pub(super) fn error_code(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        #[serde(default)]
        error_code: Option<String>,
    }
    serde_json::from_str::<ErrorBody>(body).ok()?.error_code
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{error_code, error_message, whole};

    #[test]
    fn error_codes_are_the_error_code() {
        assert_eq!(
            error_code(r#"{"status_code":400,"error_code":"bad_request","message":"m"}"#)
                .as_deref(),
            Some("bad_request")
        );
        assert_eq!(error_code(r#"{"message":"m"}"#), None);
        assert_eq!(error_code("<html>oops</html>"), None);
    }

    #[test]
    fn error_messages_join_code_and_message() {
        for (body, expected) in [
            (
                r#"{"status_code":400,"error_code":"bad_request","message":["a","b"],"response_id":"x"}"#,
                Some("bad_request: a; b"),
            ),
            (
                r#"{"error_code":"unauthorized","message":"No"}"#,
                Some("unauthorized: No"),
            ),
            (r#"{"message":"only this"}"#, Some("only this")),
            (r#"{"error_code":"x"}"#, None),
            ("<html>oops</html>", None),
        ] {
            assert_eq!(error_message(body).as_deref(), expected, "{body}");
        }
    }

    #[test]
    fn whole_numbers_in_any_spelling() {
        assert_eq!(whole(&json!(42)), Some(42));
        assert_eq!(whole(&json!(42.0)), Some(42));
        assert_eq!(whole(&json!(42.5)), None);
        assert_eq!(whole(&json!(-1)), None);
        assert_eq!(whole(&json!("42")), None);
    }
}
