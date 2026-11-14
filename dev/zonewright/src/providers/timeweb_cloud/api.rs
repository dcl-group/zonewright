//! The Timeweb Cloud API as this client uses it: one function per endpoint, the wire types,
//! paging and the classification of answers. Nothing here knows the value layer; `client.rs`
//! and `txt.rs` build on these calls.
//!
//! Sources (hard rule 3):
//!
//! - The public API description, <https://timeweb.cloud/api-docs> (the OpenAPI document it is
//!   rendered from, read on 2026-11-14; the server is `https://api.timeweb.cloud`, authentication
//!   is `http` scheme `bearer`):
//!   - `GET /api/v1/domains` (`getDomains`): `limit` (integer, default 100) and `offset`
//!     (integer, default 0); the answer holds `meta.total` and `domains`, each with `fqdn`
//!     (both required by the schema).
//!   - `GET /api/v1/domains/{fqdn}/dns-records` (`getDomainDNSRecords`, not marked deprecated):
//!     `limit` and `offset` as above; the answer holds `meta.total` and `dns_records`, each with
//!     `type` (`TXT`, `SRV`, `CNAME`, `AAAA`, `MX`, `A`), `id` (a number, nullable), `ttl` and
//!     `data` with `subdomain` (nullable string), `value` and `priority`. Documented answers:
//!     `200`, `400`, `401`, `404`, `429`, `500`.
//!   - `POST /api/v1/domains/{fqdn}/dns-records` (`createDomainDNSRecord`, marked `deprecated`):
//!     body `type` and `value` required, `subdomain`, `priority` and `ttl` optional; `201` with a
//!     `dns_record` object (the record as listed); `400`, `401`, `404`, `429`, `500`.
//!   - `DELETE /api/v1/domains/{fqdn}/dns-records/{record_id}` (`deleteDomainDNSRecord`, marked
//!     `deprecated`): `204`; `400`, `401`, `404`, `429`, `500`.
//!   - The error body of every non-success answer: `status_code`, `error_code`, `message` (a
//!     string or an array of strings) and `response_id`.
//!   - The create's `subdomain` is described as the full name of the subdomain; the listing's
//!     `data.subdomain` is described only as the subdomain, with the example
//!     `sub.somedomain.ru`.
//! - lego `providers/dns/timewebcloud`, as of commit `1991339cc1` ("fix subdomain support",
//!   2026-02-12) and unchanged in these respects up to `c40c0a2a45` (2026-04-30):
//!   `internal/client.go` `POST {base}/v1/domains/{zone}/dns-records` (line 44) and `DELETE
//!   {base}/v1/domains/{zone}/dns-records/{id}` (line 64), the zone without its trailing dot;
//!   `internal/types.go` the record body `type`, `value` and `subdomain` (lines 5 to 12, where
//!   the comment on `SubDomain` says it is "the full name of a subdomain (not only the subdomain
//!   label)"), the answer's `dns_record` key (line 15) and the error fields (lines 18 to 23);
//!   `timewebcloud.go` the value unquoted and the challenge's full name without the trailing dot
//!   in `subdomain` (lines 115 and 116). That commit replaced the relative label lego had sent
//!   before, after a user observed on 2026-02-12 that records for names below a subdomain were
//!   not created with it and were with the full name (lego issue 2844).
//!
//! Why the deprecated endpoints: the create and the delete in use are the v1 ones, which the API
//! description marks as deprecated; the design keeps them as ported (design sections 11.2, 11.3
//! and 13.4, item 12), and a live check decides when to move. The v2 create takes the record's
//! full name in the path and, by its description, needs a subdomain created beforehand with a
//! separate call (`POST /api/v1/domains/{fqdn}/subdomains/{subdomain}`); it has no listing of its
//! own. Note that lego moved to the v2 create and delete on 2026-05-22 (commit `012a2c1e01`)
//! after a user reported the v1 create answering `400` `bad_subdomain_name` for
//! `_acme-challenge.<domain>` (lego issue 3119); a v1 refusal is `Error::Rejected` and writes
//! nothing.
//!
//! Endpoints used, all below the `base_url`:
//!
//! | Call          | Request                                         | Success   |
//! | ------------- | ----------------------------------------------- | --------- |
//! | probe         | `GET /v1/domains?limit=1&offset=0`              | 200       |
//! | list domains  | `GET /v1/domains?limit&offset`                  | 200, page |
//! | zone exists   | `GET /v1/domains/{fqdn}/dns-records?limit=1&offset=0` | 200 |
//! | list records  | `GET /v1/domains/{fqdn}/dns-records?limit&offset` | 200, page |
//! | create record | `POST /v1/domains/{fqdn}/dns-records`           | 201       |
//! | delete record | `DELETE /v1/domains/{fqdn}/dns-records/{id}`    | 204       |

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
    /// The owner name as the API states it. Its form is not documented (see
    /// [`stated_names`]).
    #[serde(default)]
    subdomain: Option<String>,
    /// The value.
    #[serde(default)]
    value: Option<String>,
}

impl Record {
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

/// The body of `POST /v1/domains/{fqdn}/dns-records`.
// Source: the create's request schema (`type` and `value` required; `subdomain`, `ttl`
// optional); lego types.go lines 5 to 12 sends `type`, `value` and `subdomain`.
#[derive(Serialize)]
pub(super) struct NewRecord<'a> {
    /// The record type.
    #[serde(rename = "type")]
    pub(super) rtype: &'a str,
    /// The value.
    pub(super) value: &'a str,
    /// The owner name in full, without the trailing dot: the API description calls the field
    /// the full name of the subdomain, and lego sent the challenge's full name in this form
    /// (providers/dns/timewebcloud/timewebcloud.go line 116 at commit `c40c0a2a45`, see the
    /// module documentation).
    // Assumption (not documented): that the same form names the zone apex. The challenge names
    // this crate writes are never the apex; a wrong reading would put our own record at a
    // different name and never touch another one.
    pub(super) subdomain: &'a str,
    /// TTL in seconds; left out when the caller has none to give.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ttl: Option<u32>,
}

/// The answer to a create.
#[derive(Debug)]
pub(super) enum Created {
    /// The provider accepted the record; its identifier, when the answer states one.
    Done(Option<u64>),
    /// `404`: the domain does not exist (any more); nothing was written.
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

    /// The endpoint as text, the part of a remembered record's key that tells servers apart.
    /// A validated endpoint has no user info and no query, so this holds no secret.
    pub(super) fn endpoint_key(&self) -> &str {
        self.base.as_url().as_str()
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

    /// Whether the domain exists in the account: `GET .../dns-records?limit=1&offset=0`, where
    /// `404` is "no".
    pub(super) async fn zone_exists(&self, zone: &DomainName) -> Result<bool, Error> {
        let url = self.records_url(zone, 1, 0).build()?;
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
        self.list(
            |offset| self.domains_url(PAGE_SIZE, offset).build(),
            "domains",
            None,
        )
        .await
    }

    /// Every record of the zone, of every type, all pages. The API has no filter by type or
    /// name, so the caller selects. A `404` is `Error::ZoneNotFound` for `zone`.
    // Source: the listing's parameters are the path, `limit` and `offset` only.
    pub(super) async fn records(&self, zone: &DomainName) -> Result<Vec<Record>, Error> {
        self.list(
            |offset| self.records_url(zone, PAGE_SIZE, offset).build(),
            "dns_records",
            Some(zone),
        )
        .await
    }

    /// Creates a record. Sent once: a create is not idempotent, and a repeat after an unknown
    /// outcome could add a second copy (design section 5.3). A `404` is [`Created::NotFound`];
    /// another refusal is an error.
    pub(super) async fn create_record(
        &self,
        zone: &DomainName,
        record: &NewRecord<'_>,
    ) -> Result<Created, Error> {
        #[derive(Deserialize)]
        struct Answer {
            dns_record: Written,
        }
        #[derive(Deserialize)]
        struct Written {
            // Only the presence of the type is checked: the schema requires it.
            #[serde(rename = "type")]
            _rtype: String,
            #[serde(default)]
            id: Option<Value>,
        }
        let url = self.zone_url(zone).build()?;
        let response = self
            .http
            .send(&Request::new(Method::POST, url).json(record)?)
            .await?;
        if response.status() == 404 {
            return Ok(Created::NotFound);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let answer: Answer =
            response.json("the provider's answer to a create is not in the expected form")?;
        Ok(Created::Done(answer.dns_record.id.as_ref().and_then(whole)))
    }

    /// Deletes one record by its identifier. Idempotent: repeating it leaves the same state, so
    /// the transport may retry it.
    pub(super) async fn delete_record(&self, zone: &DomainName, id: u64) -> Result<Deleted, Error> {
        let url = self.zone_url(zone).id(&id.to_string()).build()?;
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

    /// `/v1/domains/{fqdn}/dns-records` with the zone name without its trailing dot (lego
    /// client.go lines 44 and 64).
    fn zone_url(&self, zone: &DomainName) -> UrlBuilder {
        self.base
            .url()
            .path("/v1/domains")
            .segment(zone.without_dot())
            .path("/dns-records")
    }

    fn records_url(&self, zone: &DomainName, limit: u64, offset: u64) -> UrlBuilder {
        paging(self.zone_url(zone), limit, offset)
    }

    /// Reads every page of a listing; `url` builds the URL of an offset, `key` is the field that
    /// holds the items. A `404` is `Error::ZoneNotFound` for `zone` when one is given, else a
    /// refusal.
    ///
    /// Complete or an error. The listing is complete when the items received reach
    /// the largest `meta.total` any page stated; fewer, an absent `meta.total`, an absent list field, or an empty page
    /// before the total is reached is `Error::Protocol`.
    // Source: both listings' answers require `meta` (with `total`) and the list field.
    // Assumption (not documented): that `meta.total` counts all the items of the listing and
    // that `offset` skips that many of them. Being wrong makes a listing fail, never come back
    // shorter.
    async fn list<T, U>(
        &self,
        url: U,
        key: &'static str,
        zone: Option<&DomainName>,
    ) -> Result<Vec<T>, Error>
    where
        T: DeserializeOwned,
        U: Fn(u64) -> Result<Url, Error>,
    {
        // The largest total any page stated: a later page that states less cannot end the
        // listing early.
        let stated = AtomicU64::new(0);
        pager::collect(0u64, |offset| {
            let url = url(offset);
            let stated = &stated;
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
        .await
    }

    /// An answer the client does not expect. 401, 403, 429 and 5xx were mapped by the transport
    /// already. A 4xx is the provider refusing the request, with the documented error body;
    /// anything else is an answer the client cannot interpret.
    // Source: the statuses named for every operation are 400, 401, 404, 429 and 500.
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

/// The names a record's stated `subdomain` can denote in `zone`.
///
/// The create takes the full name (see [`NewRecord`]); what a listing states is not specified
/// (the API description's only hint is the example `sub.somedomain.ru`), so both readings are
/// accepted: the full name, and a name relative to the zone (zone-file rules, where an absent
/// or `@` name is the zone itself).
// Assumption (not documented): that a listing states either form. A name read wrongly is
// never taken for ours unless the same text is also the name asked for, and a value is removed
// only when its text equals ours as well.
pub(super) fn stated_names(stated: Option<&str>, zone: &DomainName) -> Vec<DomainName> {
    let stated = stated.map_or("", str::trim);
    let mut names = Vec::with_capacity(2);
    if stated.is_empty() || stated == "@" {
        names.push(zone.clone());
        return names;
    }
    if let Ok(name) = DomainName::parse(stated) {
        names.push(name);
    }
    if let Ok(name) = DomainName::from_relative(stated, zone)
        && !names.contains(&name)
    {
        names.push(name);
    }
    names
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{error_message, stated_names, whole};
    use crate::name::DomainName;

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

    #[test]
    fn stated_names_are_read_in_both_forms() {
        let zone = DomainName::parse("example.org").unwrap();
        let names = |s: Option<&str>| -> Vec<String> {
            stated_names(s, &zone)
                .iter()
                .map(|n| n.as_str().to_owned())
                .collect()
        };
        assert_eq!(names(None), ["example.org."]);
        assert_eq!(names(Some("")), ["example.org."]);
        assert_eq!(names(Some("@")), ["example.org."]);
        assert_eq!(
            names(Some("_acme-challenge")),
            ["_acme-challenge.", "_acme-challenge.example.org."]
        );
        assert_eq!(
            names(Some("_acme-challenge.example.org")),
            [
                "_acme-challenge.example.org.",
                "_acme-challenge.example.org.example.org."
            ]
        );
    }
}
